package com.example.iam.oauth;

import com.example.iam.common.Hashing;
import com.example.iam.common.SecureTokens;
import com.example.iam.config.IamProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Redis-backed storage for the two pieces of transient OAuth2 state: an authorization
 * request waiting on consent, and an issued authorization code.
 *
 * <p>Redis is the right home for both. They live for seconds to minutes, every
 * instance must see them, and losing them costs a user one retry rather than any
 * durable data - which is exactly the boundary the design draws for Redis.
 *
 * <p>Codes are consumed with GETDEL. Read-then-delete would leave a window in which
 * two concurrent redemptions both read the same code, and a replayed code is precisely
 * what single-use is meant to prevent. Codes are also keyed by hash, so a dump of the
 * keyspace cannot be replayed against the token endpoint.
 */
@Component
public class OAuthStateStore {

    private static final Logger log = LoggerFactory.getLogger(OAuthStateStore.class);

    private static final String CODE_KEY = "iam:oauth:code:";
    private static final String REQUEST_KEY = "iam:oauth:req:";
    private static final Duration REQUEST_TTL = Duration.ofMinutes(10);

    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper;
    private final IamProperties properties;

    public OAuthStateStore(StringRedisTemplate redis, ObjectMapper objectMapper, IamProperties properties) {
        this.redis = redis;
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    /** Issues a code and returns the raw value to place in the redirect. */
    public String storeCode(AuthorizationCode code) {
        String rawCode = SecureTokens.generate();
        write(CODE_KEY + Hashing.sha256Hex(rawCode), code, properties.getToken().getAuthorizationCodeTtl());
        return rawCode;
    }

    /** Redeems a code exactly once. A second attempt finds nothing. */
    public Optional<AuthorizationCode> consumeCode(String rawCode) {
        return consume(CODE_KEY + Hashing.sha256Hex(rawCode), AuthorizationCode.class);
    }

    /** Parks a validated authorize request while the consent screen is shown. */
    public String storePendingRequest(AuthorizationRequest request) {
        String requestId = SecureTokens.generate(16);
        write(REQUEST_KEY + requestId, request, REQUEST_TTL);
        return requestId;
    }

    /** Reads a parked request without consuming it, so the consent screen can render it. */
    public Optional<AuthorizationRequest> peekPendingRequest(String requestId) {
        return read(REQUEST_KEY + requestId, AuthorizationRequest.class);
    }

    /** Reads and removes a parked request as the consent decision is applied. */
    public Optional<AuthorizationRequest> consumePendingRequest(String requestId) {
        return consume(REQUEST_KEY + requestId, AuthorizationRequest.class);
    }

    private <T> void write(String key, T value, Duration ttl) {
        try {
            redis.opsForValue().set(key, objectMapper.writeValueAsString(value), ttl);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialise OAuth2 state", e);
        } catch (DataAccessException e) {
            throw unavailable(e);
        }
    }

    private <T> Optional<T> read(String key, Class<T> type) {
        try {
            return deserialize(redis.opsForValue().get(key), type);
        } catch (DataAccessException e) {
            throw unavailable(e);
        }
    }

    private <T> Optional<T> consume(String key, Class<T> type) {
        try {
            return deserialize(redis.opsForValue().getAndDelete(key), type);
        } catch (DataAccessException e) {
            throw unavailable(e);
        }
    }

    private <T> Optional<T> deserialize(String payload, Class<T> type) {
        if (payload == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(objectMapper.readValue(payload, type));
        } catch (JsonProcessingException e) {
            // Only reachable if the stored shape changed under a running deployment.
            log.error("Discarding unreadable OAuth2 state of type {}", type.getSimpleName(), e);
            return Optional.empty();
        }
    }

    private ApiException unavailable(DataAccessException cause) {
        log.error("OAuth2 state store unavailable", cause);
        return new ApiException(ErrorCode.DEPENDENCY_UNAVAILABLE,
                "The authorization service is temporarily unavailable", null, cause);
    }
}

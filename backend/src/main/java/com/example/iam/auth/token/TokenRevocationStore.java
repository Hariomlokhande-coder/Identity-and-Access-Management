
package com.example.iam.auth.token;

import com.example.iam.config.IamProperties;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
public class TokenRevocationStore {

    private static final Logger log = LoggerFactory.getLogger(TokenRevocationStore.class);

    private static final String TOKEN_KEY = "iam:revoked:jti:";
    private static final String SESSION_KEY = "iam:revoked:sid:";
    private static final String MIN_VERSION_KEY = "iam:minpv:";
    private static final String MARKER = "1";

    private final StringRedisTemplate redis;
    private final IamProperties properties;

    public TokenRevocationStore(StringRedisTemplate redis, IamProperties properties) {
        this.redis = redis;
        this.properties = properties;
    }

    public void revokeToken(String tokenId, Instant expiresAt) {
        Duration remaining = Duration.between(Instant.now(), expiresAt);
        if (tokenId == null || remaining.isNegative() || remaining.isZero()) {
            return;
        }
        write(TOKEN_KEY + tokenId, MARKER, remaining);
    }

    public void revokeSession(UUID sessionId) {
        write(SESSION_KEY + sessionId, MARKER, markerTtl());
    }

    public void requireMinimumPermissionVersion(UUID userId, int version) {
        write(MIN_VERSION_KEY + userId, Integer.toString(version), markerTtl());
    }

    public boolean isRevoked(AccessTokenClaims claims) {
        List<String> keys = List.of(
                TOKEN_KEY + claims.tokenId(),
                SESSION_KEY + claims.sessionId(),
                MIN_VERSION_KEY + claims.userId());
        List<String> values = read(keys);

        if (values.get(0) != null || values.get(1) != null) {
            return true;
        }
        String minimumVersion = values.get(2);
        return minimumVersion != null
                && claims.permissionVersion() < Integer.parseInt(minimumVersion);
    }

    private Duration markerTtl() {
        return properties.getJwt().getAccessTokenTtl()
                .plus(properties.getJwt().getClockSkew())
                .plusMinutes(1);
    }

    private void write(String key, String value, Duration ttl) {
        try {
            redis.opsForValue().set(key, value, ttl);
        } catch (DataAccessException e) {
            log.error("Could not write revocation marker {}", key, e);
            throw new ApiException(ErrorCode.SERVICE_UNAVAILABLE,
                    "Revocation state could not be recorded, please retry", null, e);
        }
    }

    private List<String> read(List<String> keys) {
        try {
            List<String> values = redis.opsForValue().multiGet(keys);
            return values == null ? Collections.nCopies(keys.size(), null) : values;
        } catch (DataAccessException e) {
            log.error("Could not read revocation markers; failing closed", e);
            throw new ApiException(ErrorCode.SERVICE_UNAVAILABLE,
                    "Token validation is temporarily unavailable", null, e);
        }
    }
}

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

/**
 * Makes already-issued access tokens stop working before they expire.
 *
 * <p>A JWT is self-contained, so logout cannot "delete" one. What it can do is leave
 * a short-lived marker that every instance consults. Three markers cover everything:
 * one token (logout), one session (revoke a device), and a floor on the permission
 * version for a user (role change, password change, log out everywhere).
 *
 * <p>Each marker only needs to outlive the longest access token still in flight, so
 * they all expire on their own and Redis never becomes a source of truth - exactly
 * the split the design requires.
 *
 * <p>All reads fail closed. If Redis is unreachable the platform cannot prove a token
 * was not revoked, and answering 503 is the only safe response; answering "valid"
 * would resurrect every token that was ever logged out.
 */
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

    /** Blacklists a single access token for whatever is left of its natural lifetime. */
    public void revokeToken(String tokenId, Instant expiresAt) {
        Duration remaining = Duration.between(Instant.now(), expiresAt);
        if (tokenId == null || remaining.isNegative() || remaining.isZero()) {
            return;
        }
        write(TOKEN_KEY + tokenId, MARKER, remaining);
    }

    /** Invalidates every access token carrying this session id. */
    public void revokeSession(UUID sessionId) {
        write(SESSION_KEY + sessionId, MARKER, markerTtl());
    }

    /**
     * Rejects tokens minted before an authority or credential change. Tokens carry the
     * permission version they were signed with, so raising the floor invalidates the
     * old ones without a database read on the hot path.
     */
    public void requireMinimumPermissionVersion(UUID userId, int version) {
        write(MIN_VERSION_KEY + userId, Integer.toString(version), markerTtl());
    }

    /** True when any marker says this token must no longer be honoured. */
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
        return minimumVersion != null && claims.permissionVersion() < Integer.parseInt(minimumVersion);
    }

    /**
     * Markers only need to outlive the longest access token that could still be
     * presented, plus the clock skew the verifier tolerates.
     */
    private Duration markerTtl() {
        return properties.getJwt().getAccessTokenTtl()
                .plus(properties.getJwt().getClockSkew())
                .plusMinutes(1);
    }

    private void write(String key, String value, Duration ttl) {
        try {
            redis.opsForValue().set(key, value, ttl);
        } catch (DataAccessException e) {
            // A revocation that cannot be recorded must not be reported as done.
            log.error("Could not write revocation marker {}", key, e);
            throw new ApiException(ErrorCode.DEPENDENCY_UNAVAILABLE,
                    "Revocation state could not be recorded, please retry", null, e);
        }
    }

    private List<String> read(List<String> keys) {
        try {
            List<String> values = redis.opsForValue().multiGet(keys);
            // multiGet returns a list of nulls for missing keys; a null list means no reply.
            return values == null ? Collections.nCopies(keys.size(), null) : values;
        } catch (DataAccessException e) {
            log.error("Could not read revocation markers; failing closed", e);
            throw new ApiException(ErrorCode.DEPENDENCY_UNAVAILABLE,
                    "Token validation is temporarily unavailable", null, e);
        }
    }
}

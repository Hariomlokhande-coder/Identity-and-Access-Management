package com.iamplatform.security;

import com.iamplatform.exception.ApiException;
import com.iamplatform.exception.ErrorCode;
import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

/**
 * Fixed-window counters in Redis, shared by every IAM instance.
 *
 * <p>The increment and the expiry are one Lua script so they are atomic. Doing them
 * as two round trips leaves a window where a counter is created but never given a
 * TTL, and a counter without a TTL locks the caller out permanently.
 *
 * <p>Redis being unavailable fails closed. A rate limiter that opens under failure is
 * exactly what an attacker would try to induce before a brute-force run.
 */
@Component
public class RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RateLimiter.class);
    private static final String KEY_PREFIX = "iam:rl:";

    private static final String SCRIPT = """
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
              redis.call('PEXPIRE', KEYS[1], ARGV[1])
            end
            return {current, redis.call('PTTL', KEYS[1])}
            """;

    private final StringRedisTemplate redis;
    private final RedisScript<List> script;

    public RateLimiter(StringRedisTemplate redis) {
        this.redis = redis;
        this.script = new DefaultRedisScript<>(SCRIPT, List.class);
    }

    /**
     * Counts one hit against {@code bucket:identity} and reports whether it is allowed.
     */
    public Decision check(String bucket, String identity, int limit, Duration window) {
        String key = KEY_PREFIX + bucket + ":" + identity;
        try {
            @SuppressWarnings("unchecked")
            List<Long> result = redis.execute(script, List.of(key), Long.toString(window.toMillis()));
            long count = result.get(0);
            long ttlMillis = Math.max(result.get(1), 0);
            long retryAfterSeconds = Math.max(1, Duration.ofMillis(ttlMillis).toSeconds());
            return new Decision(count <= limit, Math.max(0, limit - count), retryAfterSeconds);
        } catch (DataAccessException e) {
            log.error("Rate limiter unavailable for bucket {}; failing closed", bucket, e);
            throw new ApiException(ErrorCode.DEPENDENCY_UNAVAILABLE,
                    "Request throttling is temporarily unavailable", null, e);
        }
    }

    public record Decision(boolean allowed, long remaining, long retryAfterSeconds) {
    }
}

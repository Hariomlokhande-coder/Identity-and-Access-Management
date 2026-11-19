package com.example.iam.security;

import com.example.iam.audit.AuditEventType;
import com.example.iam.audit.AuditService;
import com.example.iam.common.Hashing;
import com.example.iam.common.RequestMetadata;
import com.example.iam.config.IamProperties;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Brute-force protection for sign-in.
 *
 * <p>Counters are keyed on the submitted address whether or not an account exists.
 * That detail is the whole point: if only real accounts could be locked, an attacker
 * would learn which addresses are registered simply by watching which ones start
 * answering "locked". Unknown addresses lock exactly the same way.
 *
 * <p>Locks are temporary and lengthen with each repeat, up to a ceiling. A permanent
 * lock would hand any attacker who knows an address a denial-of-service against its
 * owner.
 */
@Service
public class LoginProtectionService {

    private static final Logger log = LoggerFactory.getLogger(LoginProtectionService.class);

    private static final String FAILURE_KEY = "iam:login:fail:";
    private static final String LOCK_KEY = "iam:login:lock:";
    private static final String STRIKE_KEY = "iam:login:strike:";

    private final StringRedisTemplate redis;
    private final LoginAttemptRepository attempts;
    private final AuditService auditService;
    private final IamProperties properties;

    public LoginProtectionService(StringRedisTemplate redis, LoginAttemptRepository attempts,
            AuditService auditService, IamProperties properties) {
        this.redis = redis;
        this.attempts = attempts;
        this.auditService = auditService;
        this.properties = properties;
    }

    /**
     * Refuses the attempt while a lock is in force. The message never states how long
     * is left, which would otherwise tell an attacker exactly when to resume.
     */
    public void assertNotLocked(String normalizedEmail) {
        if (execute(() -> Boolean.TRUE.equals(redis.hasKey(LOCK_KEY + key(normalizedEmail))))) {
            throw new ApiException(ErrorCode.ACCOUNT_LOCKED, ErrorCode.ACCOUNT_LOCKED.defaultMessage());
        }
    }

    /** Tells the caller whether a CAPTCHA should be demanded before the next try. */
    public boolean captchaRequired(String normalizedEmail) {
        int threshold = properties.getLockout().getCaptchaAfterAttempts();
        return currentFailures(normalizedEmail) >= threshold;
    }

    /**
     * Records a failure and locks the address once the threshold is crossed.
     * Runs in its own transaction so the attempt is recorded even though the sign-in
     * that produced it is being rejected.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(String normalizedEmail, UUID userId, String reason, RequestMetadata metadata) {
        persistAttempt(normalizedEmail, userId, false, reason, metadata);

        IamProperties.Lockout config = properties.getLockout();
        long failures = execute(() -> increment(FAILURE_KEY + key(normalizedEmail), config.getWindow()));

        if (failures >= config.getMaxFailedAttempts()) {
            Duration lockFor = applyLock(normalizedEmail);
            auditService.record(AuditEventType.ACCOUNT_LOCKED, com.example.iam.audit.AuditEvent.AuditOutcome.FAILURE,
                    userId, normalizedEmail, null, metadata.ipAddress(),
                    "locked for " + lockFor.toMinutes() + " minutes after " + failures + " failed attempts");
            log.warn("Locked sign-in for {} for {} minutes after {} failures", normalizedEmail, lockFor.toMinutes(),
                    failures);
        }
    }

    /**
     * Clears the counters after a genuine sign-in. The strike count is kept: a single
     * success should not wipe the history that makes repeat lockouts escalate.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSuccess(String normalizedEmail, UUID userId, RequestMetadata metadata) {
        persistAttempt(normalizedEmail, userId, true, null, metadata);
        execute(() -> redis.delete(FAILURE_KEY + key(normalizedEmail)));
    }

    /** Lifts a lock, for the administrative unlock path. */
    public void clearLock(String normalizedEmail) {
        String hashed = key(normalizedEmail);
        execute(() -> redis.delete(java.util.List.of(FAILURE_KEY + hashed, LOCK_KEY + hashed, STRIKE_KEY + hashed)));
    }

    private Duration applyLock(String normalizedEmail) {
        IamProperties.Lockout config = properties.getLockout();
        String hashed = key(normalizedEmail);
        long strikes = execute(() -> increment(STRIKE_KEY + hashed, config.getMaxLockDuration().multipliedBy(4)));

        // Each repeat doubles the lock, capped, so a persistent attacker faces growing
        // delay while a genuine user who forgot their password waits only minutes.
        Duration lockFor = config.getLockDuration().multipliedBy(1L << Math.min(strikes - 1, 8));
        if (lockFor.compareTo(config.getMaxLockDuration()) > 0) {
            lockFor = config.getMaxLockDuration();
        }
        Duration finalLock = lockFor;
        execute(() -> {
            redis.opsForValue().set(LOCK_KEY + hashed, Long.toString(strikes), finalLock);
            redis.delete(FAILURE_KEY + hashed);
            return true;
        });
        return lockFor;
    }

    private long currentFailures(String normalizedEmail) {
        String value = execute(() -> redis.opsForValue().get(FAILURE_KEY + key(normalizedEmail)));
        return value == null ? 0 : Long.parseLong(value);
    }

    private long increment(String key, Duration ttl) {
        Long value = redis.opsForValue().increment(key);
        if (value != null && value == 1L) {
            redis.expire(key, ttl);
        }
        return value == null ? 0 : value;
    }

    private void persistAttempt(String email, UUID userId, boolean successful, String reason,
            RequestMetadata metadata) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setEmail(email);
        attempt.setUserId(userId);
        attempt.setSuccessful(successful);
        attempt.setFailureReason(reason);
        attempt.setIpAddress(metadata.ipAddress());
        attempt.setUserAgent(metadata.userAgent());
        attempts.save(attempt);
    }

    /** Addresses are hashed before they become Redis keys, so keyspace dumps leak nothing. */
    private String key(String normalizedEmail) {
        return Hashing.sha256Hex(normalizedEmail);
    }

    /**
     * Every Redis interaction here guards a security decision, so an outage fails
     * closed with 503 rather than quietly disabling lockout.
     */
    private <T> T execute(java.util.function.Supplier<T> operation) {
        try {
            return operation.get();
        } catch (DataAccessException e) {
            log.error("Lockout state unavailable; failing closed", e);
            throw new ApiException(ErrorCode.DEPENDENCY_UNAVAILABLE,
                    "Sign-in is temporarily unavailable, please retry", Map.of(), e);
        }
    }
}

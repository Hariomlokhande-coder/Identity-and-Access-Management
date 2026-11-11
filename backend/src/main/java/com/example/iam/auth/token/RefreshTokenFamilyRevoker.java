package com.example.iam.auth.token;

import com.example.iam.audit.AuditEventType;
import com.example.iam.audit.AuditService;
import com.example.iam.session.SessionRepository;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Destroys a compromised token family.
 *
 * <p>It lives in its own bean for one reason: the caller that detects reuse then
 * throws, and a rollback would undo the very revocation the detection triggered.
 * REQUIRES_NEW commits the revocation independently, so the family is dead whether or
 *  the request that discovered it fails.
 */
@Component
public class RefreshTokenFamilyRevoker {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenFamilyRevoker.class);
    private static final String REASON = "reuse_detected";

    private final RefreshTokenRepository refreshTokens;
    private final SessionRepository sessions;
    private final TokenRevocationStore revocationStore;
    private final AuditService auditService;

    public RefreshTokenFamilyRevoker(RefreshTokenRepository refreshTokens, SessionRepository sessions,
            TokenRevocationStore revocationStore, AuditService auditService) {
        this.refreshTokens = refreshTokens;
        this.sessions = sessions;
        this.revocationStore = revocationStore;
        this.auditService = auditService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revoke(UUID familyId, UUID sessionId, UUID userId, String detail) {
        Instant now = Instant.now();
        int revokedTokens = refreshTokens.revokeFamily(familyId, REASON, now);
        sessions.findById(sessionId).ifPresent(session -> {
            session.revoke(REASON);
            sessions.save(session);
        });

        log.warn("Refresh token reuse detected for user {} (family {}): {}. Revoked {} token(s) and the session.",
                userId, familyId, detail, revokedTokens);
        auditService.failure(AuditEventType.REFRESH_TOKEN_REUSE_DETECTED, userId, familyId.toString(),
                null, detail);

        // Written last: if Redis is unreachable this throws, and the database revocation
        // above has already committed, so the family stays dead either way.
        revocationStore.revokeSession(sessionId);
    }
}

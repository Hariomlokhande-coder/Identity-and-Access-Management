package com.example.iam.session;

import com.example.iam.audit.AuditEventType;
import com.example.iam.audit.AuditService;
import com.example.iam.auth.token.RefreshTokenRepository;
import com.example.iam.auth.token.TokenRevocationStore;
import com.example.iam.client.ClientApplication;
import com.example.iam.common.Hashing;
import com.example.iam.common.RequestMetadata;
import com.example.iam.common.SecureTokens;
import com.example.iam.config.IamProperties;
import com.example.iam.exception.ApiException;
import com.example.iam.user.User;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Owns the lifecycle of device sessions.
 *
 * <p>Revocation is always done through this service because it has three parts that
 * must happen together: the session row is marked revoked, its refresh tokens are
 * revoked so no new access token can be minted, and a short-lived marker is written
 * so the access tokens already out there stop being accepted. Doing only the first
 * would leave a "logged out" device working until its token expired.
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    /** last_seen_at is only rewritten when it is this stale, to avoid a write per request. */
    private static final long TOUCH_INTERVAL_MINUTES = 5;

    private final SessionRepository sessions;
    private final RefreshTokenRepository refreshTokens;
    private final TokenRevocationStore revocationStore;
    private final AuditService auditService;
    private final IamProperties properties;

    public SessionService(SessionRepository sessions, RefreshTokenRepository refreshTokens,
            TokenRevocationStore revocationStore, AuditService auditService, IamProperties properties) {
        this.sessions = sessions;
        this.refreshTokens = refreshTokens;
        this.revocationStore = revocationStore;
        this.auditService = auditService;
        this.properties = properties;
    }

    /**
     * Starts a session. When {@code issueSsoToken} is set the caller is a browser and
     * receives a cookie secret; only its hash is stored.
     */
    @Transactional
    public CreatedSession create(User user, ClientApplication client, Set<String> scopes,
            RequestMetadata metadata, boolean issueSsoToken) {
        enforceSessionLimit(user.getId());

        UserSession session = new UserSession();
        session.setUser(user);
        session.setClientApplication(client);
        session.setDeviceInfo(metadata.userAgent());
        session.setIpAddress(metadata.ipAddress());
        session.setScopeSet(scopes);
        session.setExpiresAt(Instant.now().plus(properties.getToken().getSsoSessionTtl()));

        String rawSsoToken = null;
        if (issueSsoToken) {
            rawSsoToken = SecureTokens.generate();
            session.setSsoTokenHash(Hashing.sha256Hex(rawSsoToken));
        }
        return new CreatedSession(sessions.save(session), rawSsoToken);
    }

    /**
     * Caps concurrent sessions per user. Without a cap, a credential-stuffing script
     * that succeeds once can quietly accumulate sessions forever.
     */
    private void enforceSessionLimit(UUID userId) {
        int max = properties.getSecurity().getMaxSessionsPerUser();
        long active = sessions.countByUserIdAndRevokedAtIsNull(userId);
        if (active < max) {
            return;
        }
        List<UserSession> ordered = sessions.findActiveByUser(userId, Instant.now()).stream()
                .sorted(Comparator.comparing(UserSession::getLastSeenAt))
                .toList();
        int excess = (int) (active - max) + 1;
        for (int i = 0; i < Math.min(excess, ordered.size()); i++) {
            revokeInternal(ordered.get(i), "session_limit_exceeded");
        }
        log.info("Revoked {} oldest session(s) for user {} to stay within the limit of {}", excess,
                userId, max);
    }

    /** When the session was established, which is when the user actually authenticated. */
    @Transactional(readOnly = true)
    public Optional<Instant> authenticationTime(UUID sessionId) {
        return sessions.findById(sessionId).map(UserSession::getCreatedAt);
    }

    @Transactional(readOnly = true)
    public List<UserSession> listActive(UUID userId) {
        return sessions.findActiveByUser(userId, Instant.now());
    }

    /** Revokes one of the caller's own sessions. */
    @Transactional
    public void revokeOwn(UUID userId, UUID sessionId, RequestMetadata metadata) {
        UserSession session = sessions.findByIdAndUserId(sessionId, userId)
                .orElseThrow(() -> ApiException.notFound("Session"));
        revokeInternal(session, "user_revoked");
        auditService.success(AuditEventType.SESSION_REVOKED, userId, sessionId.toString(),
                metadata.ipAddress(), "single session revoked by user");
    }

    /**
     * Revokes every session of a user, optionally sparing the current one so
     * "sign out my other devices" does not sign the caller out too.
     */
    @Transactional
    public int revokeAll(UUID userId, UUID exceptSessionId, String reason) {
        Instant now = Instant.now();
        List<UserSession> active = sessions.findActiveByUser(userId, now);
        for (UserSession session : active) {
            if (!session.getId().equals(exceptSessionId)) {
                revocationStore.revokeSession(session.getId());
            }
        }
        int revoked;
        if (exceptSessionId == null) {
            refreshTokens.revokeAllForUser(userId, reason, now);
            revoked = sessions.revokeAllForUser(userId, reason, now);
        } else {
            // The spared session keeps both its record and its refresh token, so the
            // device the caller is using stays signed in.
            refreshTokens.revokeAllForUserExceptSession(userId, exceptSessionId, reason, now);
            revoked = sessions.revokeAllForUserExcept(userId, exceptSessionId, reason, now);
        }
        log.info("Revoked {} session(s) for user {} (reason={})", revoked, userId, reason);
        return revoked;
    }

    /** Resolves and refreshes a browser SSO session from its cookie secret. */
    @Transactional
    public Optional<UserSession> resolveSsoSession(String rawSsoToken) {
        if (rawSsoToken == null || rawSsoToken.isBlank()) {
            return Optional.empty();
        }
        Optional<UserSession> found =
                sessions.findActiveBySsoTokenHash(Hashing.sha256Hex(rawSsoToken), Instant.now());
        found.ifPresent(this::touch);
        return found;
    }

    private void touch(UserSession session) {
        Instant threshold = Instant.now().minus(TOUCH_INTERVAL_MINUTES, ChronoUnit.MINUTES);
        if (session.getLastSeenAt().isBefore(threshold)) {
            sessions.touch(session.getId(), Instant.now());
        }
    }

    private void revokeInternal(UserSession session, String reason) {
        Instant now = Instant.now();
        session.revoke(reason);
        sessions.save(session);
        refreshTokens.revokeBySession(session.getId(), reason, now);
        revocationStore.revokeSession(session.getId());
    }

    /** A new session plus, for browser sign-ins, the raw cookie secret to hand back. */
    public record CreatedSession(UserSession session, String rawSsoToken) {
    }
}

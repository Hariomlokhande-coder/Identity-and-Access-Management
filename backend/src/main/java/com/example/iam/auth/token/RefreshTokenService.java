package com.example.iam.auth.token;

import com.example.iam.client.ClientApplication;
import com.example.iam.common.Hashing;
import com.example.iam.common.SecureTokens;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import com.example.iam.session.UserSession;
import com.example.iam.user.User;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Issues, rotates and revokes refresh tokens.
 *
 * <p>Tokens are opaque random strings, stored only as a SHA-256 hash, and every use
 * replaces them. That combination means a stolen token is useful exactly once, and
 * the moment the legitimate holder tries to use theirs the theft becomes visible.
 *
 * <p>The concurrency problem this class exists to solve: a client with two tabs, or
 * one that retried a request, sends the same refresh token twice at the same moment.
 * Both requests find an active row. Whoever wins the conditional update owns the
 * rotation; the loser must not be handed a second valid token, and must not silently
 * fail either, because a loser is indistinguishable from a genuine replay attack.
 * Both cases are therefore treated as reuse and the whole family dies.
 */
@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private static final String REASON_ROTATED = "rotated";
    private static final String REASON_LOGOUT = "logout";

    private final RefreshTokenRepository repository;
    private final RefreshTokenFamilyRevoker familyRevoker;

    public RefreshTokenService(RefreshTokenRepository repository, RefreshTokenFamilyRevoker familyRevoker) {
        this.repository = repository;
        this.familyRevoker = familyRevoker;
    }

    /** Starts a new token family for a fresh sign-in. */
    @Transactional
    public IssuedToken issueForNewSession(User user, UserSession session, ClientApplication client, Duration ttl) {
        return persist(user, session, client, UUID.randomUUID(), ttl);
    }

    /**
     * Exchanges a refresh token for the next one in its family.
     *
     * <p>Runs SERIALIZABLE-free: correctness comes from the single conditional UPDATE
     * below rather than from an isolation level, which keeps two concurrent refreshes
     * cheap while still admitting only one winner.
     */
    @Transactional(isolation = Isolation.READ_COMMITTED)
    public RotationResult rotate(String rawToken, String requestingClientId, Duration ttl) {
        RefreshToken token = repository.findByTokenHash(Hashing.sha256Hex(rawToken))
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_REFRESH_TOKEN,
                        ErrorCode.INVALID_REFRESH_TOKEN.defaultMessage()));

        requireMatchingClient(token, requestingClientId);

        if (token.isRevoked()) {
            // The token was already spent. Either it leaked, or this is the losing half
            // of a double submit; both are answered the same way.
            handleReuse(token, "presented an already-revoked refresh token");
        }
        if (token.isExpired()) {
            // Simply too old. That is not evidence of compromise, so the family survives.
            repository.revokeIfActive(token.getId(), "expired", Instant.now());
            throw new ApiException(ErrorCode.INVALID_REFRESH_TOKEN, "The refresh token has expired");
        }
        if (!token.getSession().isActive()) {
            throw new ApiException(ErrorCode.INVALID_REFRESH_TOKEN, "The session is no longer active");
        }

        int rotated = repository.revokeIfActive(token.getId(), REASON_ROTATED, Instant.now());
        if (rotated == 0) {
            // Lost the race against a concurrent refresh of the same token.
            handleReuse(token, "lost a concurrent rotation race on the same refresh token");
        }

        IssuedToken next = persist(token.getUser(), token.getSession(), token.getClientApplication(),
                token.getFamilyId(), ttl);
        RefreshToken previous = repository.getReferenceById(token.getId());
        previous.setReplacedBy(next.token());

        return new RotationResult(next.rawToken(), token.getUser(), token.getSession(),
                token.getClientApplication());
    }

    /** Ends one token without touching the rest of the family, for a normal logout. */
    @Transactional
    public void revoke(String rawToken) {
        repository.findByTokenHash(Hashing.sha256Hex(rawToken))
                .ifPresent(token -> repository.revokeIfActive(token.getId(), REASON_LOGOUT, Instant.now()));
    }

    /**
     * Reuse is the one signal that a refresh token is in someone else's hands. Since
     * there is no way to tell the thief from the owner, every token descended from the
     * original sign-in is destroyed and both parties must authenticate again.
     */
    private void handleReuse(RefreshToken token, String detail) {
        familyRevoker.revoke(token.getFamilyId(), token.getSession().getId(), token.getUser().getId(),
                detail);
        throw new ApiException(ErrorCode.INVALID_REFRESH_TOKEN,
                "This session has been ended for security reasons, please sign in again");
    }

    /**
     * A refresh token issued to one application must not be redeemable by another.
     *
     * <p>The two kinds of mismatch are treated differently on purpose. Redemption by a
     * different named client is an attempt to use another application credential, so
     * the family dies. A client-bound token arriving at the first-party endpoint, which
     * names no client at all, is almost always a caller using the wrong endpoint: it is
     * refused with an explanation rather than by ending the user session.
     */
    private void requireMatchingClient(RefreshToken token, String requestingClientId) {
        String owner = token.getClientApplication() == null ? null :
                token.getClientApplication().getClientId();
        if (Objects.equals(owner, requestingClientId)) {
            return;
        }
        if (requestingClientId == null) {
            throw new ApiException(ErrorCode.INVALID_REFRESH_TOKEN,
                    "This refresh token belongs to a registered application and must be redeemed at /oauth2/token");
        }
        log.warn("Refresh token of client {} presented by client {}", owner, requestingClientId);
        handleReuse(token, "refresh token presented by a different client");
    }

    private IssuedToken persist(User user, UserSession session, ClientApplication client, UUID familyId,
            Duration ttl) {
        String rawToken = SecureTokens.generate();
        RefreshToken token = new RefreshToken();
        token.setFamilyId(familyId);
        token.setUser(user);
        token.setSession(session);
        token.setClientApplication(client);
        token.setTokenHash(Hashing.sha256Hex(rawToken));
        token.setExpiresAt(Instant.now().plus(ttl));
        return new IssuedToken(rawToken, repository.save(token));
    }

    public record IssuedToken(String rawToken, RefreshToken token) {
    }

    /** The new token plus the context the caller needs to mint a matching access token. */
    public record RotationResult(String rawToken, User user, UserSession session, ClientApplication client) {
    }
}

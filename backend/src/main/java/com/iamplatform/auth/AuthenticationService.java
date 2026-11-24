package com.iamplatform.auth;

import com.iamplatform.audit.AuditEventType;
import com.iamplatform.audit.AuditService;
import com.iamplatform.auth.dto.LoginRequest;
import com.iamplatform.auth.dto.LogoutRequest;
import com.iamplatform.auth.dto.MessageResponse;
import com.iamplatform.auth.dto.RefreshRequest;
import com.iamplatform.auth.dto.TokenResponse;
import com.iamplatform.auth.token.RefreshTokenService;
import com.iamplatform.auth.token.TokenIssuer;
import com.iamplatform.auth.token.TokenRevocationStore;
import com.iamplatform.common.RequestMetadata;
import com.iamplatform.exception.ApiException;
import com.iamplatform.exception.ErrorCode;
import com.iamplatform.security.IamUserPrincipal;
import com.iamplatform.security.LoginProtectionService;
import com.iamplatform.security.SsoCookieService;
import com.iamplatform.session.SessionService;
import com.iamplatform.session.UserSession;
import com.iamplatform.user.EmailNormalizer;
import com.iamplatform.user.User;
import com.iamplatform.user.UserRepository;
import com.iamplatform.user.UserStatus;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Sign-in, sign-out and token refresh.
 *
 * <p>The order of checks in {@link #login} is deliberate and is the whole
 * anti-enumeration story. Everything an attacker could learn from - unknown address,
 * unverified address, disabled account - is only revealed after the password has been
 * proven correct. Before that point there is exactly one outcome, one message and,
 * because the unknown-address path still burns a full password verification, one
 * response time.
 */
@Service
public class AuthenticationService {

    /** Scope of a first-party sign-in that did not go through the OAuth2 flow. */
    private static final Set<String> DIRECT_LOGIN_SCOPES = Set.of("openid", "profile");

    private final UserRepository users;
    private final PasswordService passwordService;
    private final LoginProtectionService loginProtection;
    private final SessionService sessionService;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenService refreshTokenService;
    private final TokenRevocationStore revocationStore;
    private final SsoCookieService ssoCookieService;
    private final AuditService auditService;

    public AuthenticationService(UserRepository users, PasswordService passwordService,
            LoginProtectionService loginProtection, SessionService sessionService, TokenIssuer tokenIssuer,
            RefreshTokenService refreshTokenService, TokenRevocationStore revocationStore,
            SsoCookieService ssoCookieService, AuditService auditService) {
        this.users = users;
        this.passwordService = passwordService;
        this.loginProtection = loginProtection;
        this.sessionService = sessionService;
        this.tokenIssuer = tokenIssuer;
        this.refreshTokenService = refreshTokenService;
        this.revocationStore = revocationStore;
        this.ssoCookieService = ssoCookieService;
        this.auditService = auditService;
    }

    @Transactional
    public TokenResponse login(LoginRequest request, RequestMetadata metadata, HttpServletResponse response) {
        String email = EmailNormalizer.normalize(request.email());

        // Locks are keyed on the submitted address whether or not it exists, so this
        // check cannot itself become an existence oracle.
        loginProtection.assertNotLocked(email);

        User user = users.findWithRolesByEmail(email).orElse(null);
        if (user == null) {
            // Spend the same effort a real verification costs. Skipping it would make
            // unknown addresses answer measurably faster than known ones.
            passwordService.burnVerificationTime(request.password());
            throw rejectLogin(email, null, "unknown_account", metadata);
        }
        if (!passwordService.matches(request.password(), user.getPasswordHash())) {
            throw rejectLogin(email, user.getId(), "bad_password", metadata);
        }

        // Past this point the caller has proven the password, so specific reasons can
        // safely be disclosed: they already know the account exists.
        assertUsable(user, email, metadata);

        // No client: a first-party sign-in produces a platform-audience token, usable
        // against this API and nothing else.
        SessionService.CreatedSession created =
                sessionService.create(user, null, DIRECT_LOGIN_SCOPES, metadata, true);
        UserSession session = created.session();
        TokenResponse tokens = tokenIssuer.issueForNewSession(user, session, null, null, null);

        user.setLastLoginAt(Instant.now());
        clearLockState(user, email);
        loginProtection.recordSuccess(email, user.getId(), metadata);
        auditService.success(AuditEventType.LOGIN, user.getId(), session.getId().toString(), metadata.ipAddress(),
                "first-party login");

        // The cookie makes this browser session reusable by the OAuth2 authorize
        // endpoint, so signing in to a second application needs no second password.
        ssoCookieService.write(response, created.rawSsoToken());
        return tokens;
    }

    /**
     * Ends the current session, and optionally every other one.
     *
     * <p>Three things have to happen for a logout to be real: the refresh token dies so
     * nothing new can be minted, the session is revoked, and the access token already
     * in the caller's hands is blacklisted for the remainder of its short life.
     */
    @Transactional
    public MessageResponse logout(LogoutRequest request, RequestMetadata metadata,
            HttpServletResponse response) {
        IamUserPrincipal principal = IamUserPrincipal.require();

        if (request != null && request.refreshToken() != null && !request.refreshToken().isBlank()) {
            refreshTokenService.revoke(request.refreshToken());
        }
        revocationStore.revokeToken(principal.tokenId(), principal.tokenExpiresAt());

        if (request != null && request.allDevices()) {
            sessionService.revokeAll(principal.userId(), null, "logout_all_devices");
        } else {
            sessionService.revokeOwn(principal.userId(), principal.sessionId(), metadata);
        }

        ssoCookieService.clear(response);
        auditService.success(AuditEventType.LOGOUT, principal.userId(), principal.sessionId().toString(),
                metadata.ipAddress(), request != null && request.allDevices() ? "all devices" : "single session");
        return new MessageResponse("Signed out.");
    }

    /**
     * Rotates a first-party refresh token.
     *
     * <p>A token belonging to a registered application is refused here. Redeeming one
     * without proving the client secret would bypass client authentication entirely,
     * so those go to the token endpoint instead.
     */
    @Transactional
    public TokenResponse refresh(RefreshRequest request, RequestMetadata metadata) {
        RefreshTokenService.RotationResult rotation = refreshTokenService.rotate(
                request.refreshToken(), null, tokenIssuer.refreshTtl(null));

        assertStillUsable(rotation.user());
        TokenResponse tokens = tokenIssuer.issueForRotation(rotation);
        auditService.success(AuditEventType.TOKEN_REFRESHED, rotation.user().getId(),
                rotation.session().getId().toString(), metadata.ipAddress(), null);
        return tokens;
    }

    /**
     * Records the failure and builds the one rejection every failed sign-in gets.
     * Returning the exception rather than throwing it keeps the caller explicit about
     * where control leaves the method.
     */
    private ApiException rejectLogin(String email, UUID userId, String reason, RequestMetadata metadata) {
        loginProtection.recordFailure(email, userId, reason, metadata);
        auditService.failure(AuditEventType.LOGIN, userId, email, metadata.ipAddress(), reason);
        return new ApiException(ErrorCode.INVALID_CREDENTIALS, ErrorCode.INVALID_CREDENTIALS.defaultMessage());
    }

    private void assertUsable(User user, String email, RequestMetadata metadata) {
        if (user.isCurrentlyLocked()) {
            throw new ApiException(ErrorCode.ACCOUNT_LOCKED, ErrorCode.ACCOUNT_LOCKED.defaultMessage());
        }
        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED
                || user.getDeletedAt() != null) {
            auditService.failure(AuditEventType.LOGIN, user.getId(), email, metadata.ipAddress(), "account_disabled");
            throw new ApiException(ErrorCode.ACCOUNT_DISABLED, ErrorCode.ACCOUNT_DISABLED.defaultMessage());
        }
        if (!user.isEmailVerified()) {
            auditService.failure(AuditEventType.LOGIN, user.getId(), email, metadata.ipAddress(),
                    "email_not_verified");
            throw new ApiException(ErrorCode.EMAIL_NOT_VERIFIED, ErrorCode.EMAIL_NOT_VERIFIED.defaultMessage());
        }
    }

    /** The account may have been disabled since the session started. */
    private void assertStillUsable(User user) {
        if (!user.isActive() || user.isCurrentlyLocked()) {
            throw new ApiException(ErrorCode.ACCOUNT_DISABLED, ErrorCode.ACCOUNT_DISABLED.defaultMessage());
        }
    }

    private void clearLockState(User user, String email) {
        if (user.getLockedUntil() != null || user.getLockoutStrikes() > 0) {
            user.setLockedUntil(null);
            user.setLockoutStrikes(0);
            loginProtection.clearLock(email);
        }
    }
}

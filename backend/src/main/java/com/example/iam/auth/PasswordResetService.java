package com.example.iam.auth;

import com.example.iam.audit.AuditEventType;
import com.example.iam.audit.AuditService;
import com.example.iam.auth.credential.PasswordResetToken;
import com.example.iam.auth.credential.PasswordResetTokenRepository;
import com.example.iam.auth.dto.MessageResponse;
import com.example.iam.auth.token.TokenRevocationStore;
import com.example.iam.common.Hashing;
import com.example.iam.common.RequestMetadata;
import com.example.iam.common.SecureTokens;
import com.example.iam.config.IamProperties;
import com.example.iam.email.MailService;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import com.example.iam.security.IamUserPrincipal;
import com.example.iam.security.LoginProtectionService;
import com.example.iam.session.SessionService;
import com.example.iam.user.EmailNormalizer;
import com.example.iam.user.User;
import com.example.iam.user.UserRepository;
import com.example.iam.user.UserStatus;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Forgotten-password, reset and change flows.
 *
 * <p>A completed reset or change does three things beyond storing a new hash: it
 * retires every outstanding reset link, it raises the permission version so access
 * tokens minted under the old password stop verifying, and it ends the sessions.
 * Skipping any of them leaves an attacker who already had access still holding it
 * after the victim "fixed" their account.
 */
@Service
public class PasswordResetService {

    private static final MessageResponse GENERIC_RESPONSE = new MessageResponse(
            "If an account exists for this address, a password reset link has been sent to it.");
    private static final String INVALID_LINK = "The reset link is invalid, expired or already used";

    private final UserRepository users;
    private final PasswordResetTokenRepository resetTokens;
    private final PasswordService passwordService;
    private final MailService mailService;
    private final SessionService sessionService;
    private final TokenRevocationStore revocationStore;
    private final LoginProtectionService loginProtection;
    private final AuditService auditService;
    private final IamProperties properties;

    public PasswordResetService(UserRepository users, PasswordResetTokenRepository resetTokens,
            PasswordService passwordService, MailService mailService, SessionService sessionService,
            TokenRevocationStore revocationStore, LoginProtectionService loginProtection,
            AuditService auditService, IamProperties properties) {
        this.users = users;
        this.resetTokens = resetTokens;
        this.passwordService = passwordService;
        this.mailService = mailService;
        this.sessionService = sessionService;
        this.revocationStore = revocationStore;
        this.loginProtection = loginProtection;
        this.auditService = auditService;
        this.properties = properties;
    }

    /**
     * Starts a reset. The answer is identical for a known and an unknown address, and
     * the unknown path deliberately performs the same hashing work so the two cannot
     * be told apart by how long they take.
     */
    @Transactional
    public MessageResponse requestReset(String rawEmail, RequestMetadata metadata) {
        String email = EmailNormalizer.normalize(rawEmail);
        users.findByEmail(email)
                .filter(user -> user.getStatus() != UserStatus.DELETED && user.getDeletedAt() == null)
                .ifPresentOrElse(
                        user -> issueResetToken(user, metadata),
                        () -> passwordService.burnVerificationTime(email));
        return GENERIC_RESPONSE;
    }

    /** Completes a reset using the link from the mail. */
    @Transactional
    public MessageResponse resetPassword(String rawToken, String newPassword, RequestMetadata metadata) {
        PasswordResetToken token = resetTokens.findByTokenHash(Hashing.sha256Hex(rawToken))
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_TOKEN, INVALID_LINK));
        UUID userId = token.getUser().getId();

        User user = users.findById(userId)
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_TOKEN, INVALID_LINK));

        // Policy is checked before the token is consumed, so a rejected password does
        // not waste the link the user was sent.
        passwordService.validate(newPassword, user.getEmail());

        // Conditional update covers used, superseded and expired in one atomic step,
        // so two clicks on the same link cannot both reset the password.
        if (resetTokens.markUsed(token.getId(), Instant.now()) == 0) {
            throw new ApiException(ErrorCode.INVALID_TOKEN, INVALID_LINK);
        }

        applyNewPassword(user, newPassword);
        // A reset is the response to a possibly compromised account, so every session
        // goes, including the one the attacker may be holding.
        sessionService.revokeAll(user.getId(), null, "password_reset");
        loginProtection.clearLock(user.getEmail());

        mailService.enqueuePasswordChangedNotice(user.getEmail());
        auditService.success(AuditEventType.PASSWORD_RESET_COMPLETED, user.getId(), user.getId().toString(),
                metadata.ipAddress(), "all sessions revoked");
        return new MessageResponse("Password updated. Please sign in again.");
    }

    /**
     * Changes the password of the signed-in user.
     *
     * <p>The current password is required even though the caller is authenticated: it
     * is what stops a stolen access token from being turned into permanent account
     * takeover.
     */
    @Transactional
    public MessageResponse changePassword(String currentPassword, String newPassword, RequestMetadata metadata) {
        IamUserPrincipal principal = IamUserPrincipal.require();
        User user = users.findById(principal.userId())
                .orElseThrow(() -> ApiException.notFound("User"));

        if (!passwordService.matches(currentPassword, user.getPasswordHash())) {
            auditService.failure(AuditEventType.PASSWORD_CHANGED, user.getId(), user.getId().toString(),
                    metadata.ipAddress(), "current password did not match");
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS, "The current password is incorrect");
        }
        if (passwordService.matches(newPassword, user.getPasswordHash())) {
            throw ApiException.invalid("The new password must be different from the current one");
        }
        passwordService.validate(newPassword, user.getEmail());

        applyNewPassword(user, newPassword);
        resetTokens.invalidateActiveForUser(user.getId(), Instant.now());

        if (properties.getSecurity().isRevokeSessionsOnPasswordChange()) {
            // Every other device has to sign in again. The current session and its
            // refresh token survive, so this client needs only one refresh to pick up a
            // token carrying the new permission version.
            sessionService.revokeAll(user.getId(), principal.sessionId(), "password_changed");
        }

        mailService.enqueuePasswordChangedNotice(user.getEmail());
        auditService.success(AuditEventType.PASSWORD_CHANGED, user.getId(), user.getId().toString(),
                metadata.ipAddress(), null);
        return new MessageResponse("Password updated.");
    }

    private void issueResetToken(User user, RequestMetadata metadata) {
        // Any earlier link stops working the moment a new one is issued, so an old mail
        // recovered from an inbox cannot be replayed.
        resetTokens.invalidateActiveForUser(user.getId(), Instant.now());

        String rawToken = SecureTokens.generate();
        PasswordResetToken token = new PasswordResetToken();
        token.setUser(user);
        token.setTokenHash(Hashing.sha256Hex(rawToken));
        token.setExpiresAt(Instant.now().plus(properties.getToken().getPasswordResetTtl()));
        resetTokens.save(token);

        mailService.enqueuePasswordReset(user.getEmail(), rawToken);
        auditService.success(AuditEventType.PASSWORD_RESET_REQUESTED, user.getId(), user.getId().toString(),
                metadata.ipAddress(), null);
    }

    /**
     * Stores the new hash and raises the permission version, which is what makes
     * already-issued access tokens stop verifying instead of lingering until expiry.
     */
    private void applyNewPassword(User user, String newPassword) {
        user.setPasswordHash(passwordService.hash(newPassword));
        user.setPasswordChangedAt(Instant.now());
        user.setLockedUntil(null);
        user.setLockoutStrikes(0);
        user.bumpPermissionVersion();
        users.saveAndFlush(user);
        revocationStore.requireMinimumPermissionVersion(user.getId(), user.getPermissionVersion());
    }
}

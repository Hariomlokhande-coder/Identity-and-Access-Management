
package com.example.iam.auth;

import com.example.iam.audit.AuditEventType;
import com.example.iam.audit.AuditService;
import com.example.iam.auth.credential.EmailVerificationService;
import com.example.iam.auth.credential.EmailVerificationToken;
import com.example.iam.auth.credential.EmailVerificationTokenRepository;
import com.example.iam.auth.dto.MessageResponse;
import com.example.iam.auth.dto.RegisterRequest;
import com.example.iam.common.Hashing;
import com.example.iam.common.RequestMetadata;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import com.example.iam.role.RoleRepository;
import com.example.iam.user.EmailNormalizer;
import com.example.iam.user.User;
import com.example.iam.user.UserRepository;
import com.example.iam.user.UserStatus;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Registration and email verification.
 *
 * <p>Every path through this service answers with the same message. Registering an
 * address that already exists, an address that exists but is unverified, and a brand
 * new one are indistinguishable from outside - otherwise the endpoint becomes a free
 * membership oracle for any address an attacker cares to try.
 */
@Service
public class RegistrationService {

    private static final String DEFAULT_ROLE = "USER";
    private static final MessageResponse GENERIC_RESPONSE = new MessageResponse(
            "If this email address can be registered, a verification link has been sent to it.");
    private static final String INVALID_LINK = "The verification link is invalid, expired or already used";

    private final UserRepository users;
    private final RoleRepository roles;
    private final EmailVerificationTokenRepository verificationTokens;
    private final EmailVerificationService verificationService;
    private final PasswordService passwordService;
    private final AuditService auditService;

    public RegistrationService(UserRepository users, RoleRepository roles,
                               EmailVerificationTokenRepository verificationTokens, EmailVerificationService verificationService,
                               PasswordService passwordService, AuditService auditService) {
        this.users = users;
        this.roles = roles;
        this.verificationTokens = verificationTokens;
        this.verificationService = verificationService;
        this.passwordService = passwordService;
        this.auditService = auditService;
    }

    @Transactional
    public MessageResponse register(RegisterRequest request, RequestMetadata metadata) {
        String email = EmailNormalizer.normalize(request.email());

        // Policy is checked before the lookup so a weak password is reported the same
        // way whether or not the address is taken.
        passwordService.validate(request.password(), email);

        Optional<User> existing = users.findByEmail(email);
        if (existing.isPresent()) {
            resendIfStillPending(existing.get());
            return GENERIC_RESPONSE;
        }

        // A second registration of the same address at the same instant loses on the
        // unique index and gets a 409. That is not an enumeration channel: anyone
        // probing an existing address takes the branch above and sees the generic
        // answer, because the account is already committed by then.
        User user = createUser(email, request.password());
        verificationService.issue(user);
        auditService.success(AuditEventType.USER_REGISTERED, user.getId(), user.getId().toString(),
                metadata.ipAddress(), "self-service registration");
        return GENERIC_RESPONSE;
    }

    /**
     * Consumes a verification link.
     *
     * <p>Not found, expired, superseded and already used all produce one message. The
     * caller learns whether their link works, and nothing about whose it is.
     */
    @Transactional
    public MessageResponse verifyEmail(String rawToken, RequestMetadata metadata) {
        EmailVerificationToken token = verificationTokens.findByTokenHash(Hashing.sha256Hex(rawToken))
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_TOKEN, INVALID_LINK));

        // Conditional update: two clicks on the same link race here, and only one wins.
        if (verificationTokens.markUsed(token.getId(), Instant.now()) == 0) {
            throw new ApiException(ErrorCode.INVALID_TOKEN, INVALID_LINK);
        }

        User user = users.findById(token.getUser().getId())
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_TOKEN, INVALID_LINK));
        user.setEmailVerified(true);
        if (user.getStatus() == UserStatus.PENDING_VERIFICATION) {
            user.setStatus(UserStatus.ACTIVE);
        }

        auditService.success(AuditEventType.EMAIL_VERIFIED, user.getId(), user.getId().toString(),
                metadata.ipAddress(), null);
        return new MessageResponse("Email address verified. You can now sign in.");
    }

    /** Issues a fresh link, retiring any earlier one. */
    @Transactional
    public MessageResponse resendVerification(String rawEmail, RequestMetadata metadata) {
        String email = EmailNormalizer.normalize(rawEmail);
        users.findByEmail(email).ifPresent(user -> {
            if (resendIfStillPending(user)) {
                auditService.success(AuditEventType.EMAIL_VERIFICATION_RESENT, user.getId(),
                        user.getId().toString(), metadata.ipAddress(), null);
            }
        });
        return GENERIC_RESPONSE;
    }

    private boolean resendIfStillPending(User user) {
        if (user.isEmailVerified() || user.getStatus() == UserStatus.DELETED
                || user.getStatus() == UserStatus.DISABLED) {
            return false;
        }
        verificationService.issue(user);
        return true;
    }

    private User createUser(String email, String rawPassword) {
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordService.hash(rawPassword));
        user.setStatus(UserStatus.PENDING_VERIFICATION);
        user.setPasswordChangedAt(Instant.now());
        roles.findPlatformRoleByName(DEFAULT_ROLE).ifPresent(role -> user.getRoles().add(role));
        // Flushed here so a duplicate address fails as a clean 409 at this point rather
        // than as an opaque commit-time error after the mail has been queued.
        return users.saveAndFlush(user);
    }
}

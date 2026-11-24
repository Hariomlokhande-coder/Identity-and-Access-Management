package io.github.hariomlokhande.iam.user;

import io.github.hariomlokhande.iam.audit.AuditEventType;
import io.github.hariomlokhande.iam.audit.AuditService;
import io.github.hariomlokhande.iam.auth.PasswordService;
import io.github.hariomlokhande.iam.auth.credential.EmailVerificationService;
import io.github.hariomlokhande.iam.auth.token.TokenRevocationStore;
import io.github.hariomlokhande.iam.common.PageResponse;
import io.github.hariomlokhande.iam.common.RequestMetadata;
import io.github.hariomlokhande.iam.exception.ApiException;
import io.github.hariomlokhande.iam.role.Role;
import io.github.hariomlokhande.iam.role.RoleRepository;
import io.github.hariomlokhande.iam.security.IamUserPrincipal;
import io.github.hariomlokhande.iam.security.LoginProtectionService;
import io.github.hariomlokhande.iam.session.SessionService;
import io.github.hariomlokhande.iam.user.dto.CreateUserRequest;
import io.github.hariomlokhande.iam.user.dto.UserResponse;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * User lifecycle and administration.
 *
 * <p>Anything that changes what a user may do, or whether they may do anything at
 * all, goes through {@link #invalidateExistingTokens}. Updating the database alone
 * would leave every access token already issued working until it expired, which is
 * precisely the stale-permission window the design calls out.
 */
@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository users;
    private final RoleRepository roles;
    private final EmailVerificationService verificationService;
    private final PasswordService passwordService;
    private final SessionService sessionService;
    private final TokenRevocationStore revocationStore;
    private final LoginProtectionService loginProtection;
    private final AuditService auditService;

    public UserService(UserRepository users, RoleRepository roles,
            EmailVerificationService verificationService, PasswordService passwordService,
            SessionService sessionService, TokenRevocationStore revocationStore,
            LoginProtectionService loginProtection, AuditService auditService) {
        this.users = users;
        this.roles = roles;
        this.verificationService = verificationService;
        this.passwordService = passwordService;
        this.sessionService = sessionService;
        this.revocationStore = revocationStore;
        this.loginProtection = loginProtection;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public UserResponse getCurrent() {
        return UserResponse.from(loadWithRoles(IamUserPrincipal.requireUserId()));
    }

    @Transactional(readOnly = true)
    public UserResponse getById(UUID userId) {
        return UserResponse.from(loadWithRoles(userId));
    }

    @Transactional(readOnly = true)
    public PageResponse<UserResponse> search(String query, UserStatus status, Pageable pageable) {
        return PageResponse.of(users.search(query, status, pageable).map(UserResponse::from));
    }

    /**
     * Administrative creation. The account is usable immediately only if the caller
     * asserts the address is already proven; otherwise it starts pending like any
     * self-service registration.
     */
    @Transactional
    public UserResponse create(CreateUserRequest request, RequestMetadata metadata) {
        String email = EmailNormalizer.normalize(request.email());
        passwordService.validate(request.password(), email);
        if (users.existsByEmail(email)) {
            throw ApiException.conflict("A user with this email already exists");
        }

        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordService.hash(request.password()));
        user.setEmailVerified(request.emailVerified());
        user.setStatus(request.emailVerified() ? UserStatus.ACTIVE : UserStatus.PENDING_VERIFICATION);
        user.setPasswordChangedAt(Instant.now());
        user.getRoles().addAll(resolveRoles(request.roleIds()));
        users.saveAndFlush(user);

        if (!request.emailVerified()) {
            verificationService.issue(user);
        }
        auditService.success(AuditEventType.USER_REGISTERED, actorId(), user.getId().toString(),
                metadata.ipAddress(), "created by administrator");
        return UserResponse.from(user);
    }

    /**
     * Changing the address invalidates its verified state: the new address has not
     * been proven, and treating it as proven would let an administrator or a hijacked
     * session redirect account recovery to an address they control.
     */
    @Transactional
    public UserResponse updateEmail(UUID userId, String rawEmail, RequestMetadata metadata) {
        String email = EmailNormalizer.normalize(rawEmail);
        User user = loadWithRoles(userId);
        if (email.equals(user.getEmail())) {
            return UserResponse.from(user);
        }
        if (users.existsByEmail(email)) {
            throw ApiException.conflict("A user with this email already exists");
        }

        user.setEmail(email);
        user.setEmailVerified(false);
        user.setStatus(UserStatus.PENDING_VERIFICATION);
        // Sent to the new address, and it retires any link outstanding for the old one.
        verificationService.issue(user);
        invalidateExistingTokens(user, "email_changed");

        auditService.success(AuditEventType.ACCOUNT_STATUS_CHANGED, actorId(), userId.toString(),
                metadata.ipAddress(), "email changed, verification required");
        return UserResponse.from(user);
    }

    @Transactional
    public UserResponse changeStatus(UUID userId, UserStatus status, RequestMetadata metadata) {
        User user = loadWithRoles(userId);
        if (status == UserStatus.DELETED) {
            throw ApiException.invalid("Use the delete endpoint to remove a user");
        }
        user.setStatus(status);
        if (status != UserStatus.ACTIVE) {
            invalidateExistingTokens(user, "status_" + status.name().toLowerCase());
        }

        auditService.success(AuditEventType.ACCOUNT_STATUS_CHANGED, actorId(), userId.toString(),
                metadata.ipAddress(), "status set to " + status);
        return UserResponse.from(user);
    }

    /** Replaces the user's roles wholesale and retires the tokens minted under the old set. */
    @Transactional
    public UserResponse assignRoles(UUID userId, Set<UUID> roleIds, RequestMetadata metadata) {
        User user = loadWithRoles(userId);
        Set<Role> resolved = resolveRoles(roleIds);

        user.getRoles().clear();
        user.getRoles().addAll(resolved);
        invalidateExistingTokens(user, "roles_changed");

        auditService.success(AuditEventType.ROLE_ASSIGNMENT_CHANGED, actorId(), userId.toString(),
                metadata.ipAddress(), "roles set to " + resolved.stream().map(Role::getName).sorted().toList());
        return UserResponse.from(user);
    }

    /** Administrative unlock, for a user locked out by failed attempts. */
    @Transactional
    public void unlock(UUID userId, RequestMetadata metadata) {
        User user = users.findById(userId).orElseThrow(() -> ApiException.notFound("User"));
        user.setLockedUntil(null);
        user.setLockoutStrikes(0);
        loginProtection.clearLock(user.getEmail());

        auditService.success(AuditEventType.ACCOUNT_UNLOCKED, actorId(), userId.toString(), metadata.ipAddress(),
                "unlocked by administrator");
    }

    /**
     * Soft delete.
     *
     * <p>The row survives so audit entries, login history and foreign keys stay
     * resolvable, but the address is replaced with a tombstone. That frees the real
     * address for re-registration and removes the personal data, which is what a
     * deletion request actually asks for; the immutable audit trail keeps only the id.
     */
    @Transactional
    public void delete(UUID userId, RequestMetadata metadata) {
        User user = users.findById(userId).orElseThrow(() -> ApiException.notFound("User"));

        user.setStatus(UserStatus.DELETED);
        user.setDeletedAt(Instant.now());
        user.setEmail("deleted+" + user.getId() + "@invalid");
        user.setPasswordHash("!");
        user.setEmailVerified(false);
        user.getRoles().clear();
        invalidateExistingTokens(user, "account_deleted");

        log.info("Soft-deleted user {}", userId);
        auditService.success(AuditEventType.ACCOUNT_DELETED, actorId(), userId.toString(), metadata.ipAddress(),
                null);
    }

    /**
     * The single place that makes an authority or credential change take effect now.
     * The version bump invalidates issued access tokens; revoking sessions kills the
     * refresh tokens that could mint new ones.
     */
    private void invalidateExistingTokens(User user, String reason) {
        user.bumpPermissionVersion();
        users.saveAndFlush(user);
        revocationStore.requireMinimumPermissionVersion(user.getId(), user.getPermissionVersion());
        sessionService.revokeAll(user.getId(), null, reason);
    }

    private Set<Role> resolveRoles(Set<UUID> roleIds) {
        if (roleIds == null || roleIds.isEmpty()) {
            return Set.of();
        }
        List<Role> found = roles.findAllByIdIn(roleIds);
        if (found.size() != roleIds.size()) {
            throw ApiException.invalid("One or more roles do not exist");
        }
        return Set.copyOf(found);
    }

    private User loadWithRoles(UUID userId) {
        return users.findWithRolesById(userId)
                .filter(user -> user.getDeletedAt() == null)
                .orElseThrow(() -> ApiException.notFound("User"));
    }

    private UUID actorId() {
        return IamUserPrincipal.current().map(IamUserPrincipal::userId).orElse(null);
    }
}

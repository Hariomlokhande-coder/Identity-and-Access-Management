package com.iamplatform.role;

import com.iamplatform.audit.AuditEventType;
import com.iamplatform.audit.AuditService;
import com.iamplatform.auth.token.TokenRevocationStore;
import com.iamplatform.client.ClientApplication;
import com.iamplatform.client.ClientApplicationRepository;
import com.iamplatform.common.RequestMetadata;
import com.iamplatform.exception.ApiException;
import com.iamplatform.role.dto.CreateRoleRequest;
import com.iamplatform.role.dto.PermissionResponse;
import com.iamplatform.role.dto.RoleResponse;
import com.iamplatform.role.dto.UpdateRoleRequest;
import com.iamplatform.security.IamUserPrincipal;
import com.iamplatform.user.UserRepository;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Role and permission administration.
 *
 * <p>Editing a role changes what every holder of that role may do, so each mutation
 * ends by retiring the access tokens of the affected users. Without that, revoking a
 * permission would take effect only when the last token expired - the exact gap the
 * design warns about.
 *
 * <p>Permissions themselves are not creatable through the API. They name capabilities
 * the code actually enforces, so they arrive with a migration alongside the code that
 * checks them; inventing one at runtime would produce a permission nothing honours.
 */
@Service
public class RoleService {

    private static final Logger log = LoggerFactory.getLogger(RoleService.class);

    private final RoleRepository roles;
    private final PermissionRepository permissions;
    private final ClientApplicationRepository clients;
    private final UserRepository users;
    private final TokenRevocationStore revocationStore;
    private final AuditService auditService;

    public RoleService(RoleRepository roles, PermissionRepository permissions,
            ClientApplicationRepository clients, UserRepository users, TokenRevocationStore revocationStore,
            AuditService auditService) {
        this.roles = roles;
        this.permissions = permissions;
        this.clients = clients;
        this.users = users;
        this.revocationStore = revocationStore;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public List<RoleResponse> list() {
        return roles.findAllWithPermissions().stream().map(RoleResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public RoleResponse get(UUID roleId) {
        return RoleResponse.from(load(roleId));
    }

    @Transactional(readOnly = true)
    public List<PermissionResponse> listPermissions() {
        return permissions.findAllByOrderByName().stream().map(PermissionResponse::from).toList();
    }

    @Transactional
    public RoleResponse create(CreateRoleRequest request, RequestMetadata metadata) {
        ClientApplication client = resolveClient(request.clientId());
        assertNameFree(request.name(), client);

        Role role = new Role();
        role.setName(request.name());
        role.setDescription(request.description());
        role.setClientApplication(client);
        role.getPermissions().addAll(resolvePermissions(request.permissions()));
        roles.saveAndFlush(role);

        auditService.success(AuditEventType.ROLE_CREATED, actorId(), role.getId().toString(),
                metadata.ipAddress(), "role " + role.getName() + " created");
        return RoleResponse.from(role);
    }

    /**
     * System roles keep their name and scope - other code and seeded data refer to
     * them - but their permission set stays editable, because tightening what MANAGER
     * may do is ordinary administration.
     */
    @Transactional
    public RoleResponse update(UUID roleId, UpdateRoleRequest request, RequestMetadata metadata) {
        Role role = load(roleId);
        role.setDescription(request.description());
        role.getPermissions().clear();
        role.getPermissions().addAll(resolvePermissions(request.permissions()));
        roles.saveAndFlush(role);

        int affected = retireTokensOfHolders(roleId);
        auditService.success(AuditEventType.ROLE_UPDATED, actorId(), roleId.toString(), metadata.ipAddress(),
                "permissions updated, " + affected + " user(s) affected");
        return RoleResponse.from(role);
    }

    /**
     * Deleting a role removes its assignments through the foreign key, so no dangling
     * membership is left behind. The holders lose authority immediately.
     */
    @Transactional
    public void delete(UUID roleId, RequestMetadata metadata) {
        Role role = load(roleId);
        if (role.isSystemRole()) {
            throw ApiException.forbidden("System roles cannot be deleted");
        }

        int affected = retireTokensOfHolders(roleId);
        roles.delete(role);

        log.info("Deleted role {} ({} holder(s) affected)", role.getName(), affected);
        auditService.success(AuditEventType.ROLE_DELETED, actorId(), roleId.toString(), metadata.ipAddress(),
                "role " + role.getName() + " deleted");
    }

    /**
     * Bumps the permission version of every holder and publishes the new floor, so
     * tokens minted under the previous permission set stop verifying.
     */
    private int retireTokensOfHolders(UUID roleId) {
        List<UUID> holders = users.findIdsByRoleId(roleId);
        for (UUID userId : holders) {
            users.incrementPermissionVersion(userId);
            users.findPermissionVersion(userId)
                    .ifPresent(version -> revocationStore.requireMinimumPermissionVersion(userId, version));
        }
        return holders.size();
    }

    private void assertNameFree(String name, ClientApplication client) {
        boolean taken = client == null
                ? roles.findPlatformRoleByName(name).isPresent()
                : roles.findScopedRoleByName(name, client.getId()).isPresent();
        if (taken) {
            throw ApiException.conflict("A role with this name already exists in that scope");
        }
    }

    private Set<Permission> resolvePermissions(Set<String> names) {
        if (names == null || names.isEmpty()) {
            return Set.of();
        }
        List<Permission> found = permissions.findAllByNameIn(names);
        if (found.size() != names.size()) {
            throw ApiException.invalid("One or more permissions do not exist");
        }
        return Set.copyOf(found);
    }

    private ClientApplication resolveClient(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return null;
        }
        return clients.findByClientId(clientId)
                .orElseThrow(() -> ApiException.invalid("Unknown client"));
    }

    private Role load(UUID roleId) {
        return roles.findWithPermissionsById(roleId).orElseThrow(() -> ApiException.notFound("Role"));
    }

    private UUID actorId() {
        return IamUserPrincipal.current().map(IamUserPrincipal::userId).orElse(null);
    }
}

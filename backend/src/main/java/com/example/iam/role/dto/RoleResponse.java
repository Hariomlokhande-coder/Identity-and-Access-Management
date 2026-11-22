package com.example.iam.role.dto;

import com.example.iam.role.Permission;
import com.example.iam.role.Role;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * @param clientId the application this role is scoped to, or null for a platform-wide
 *                 role that applies in every application
 */
public record RoleResponse(
        UUID id,
        String name,
        String description,
        String clientId,
        boolean systemRole,
        Set<String> permissions) {

    public static RoleResponse from(Role role) {
        Set<String> permissionNames = new TreeSet<>();
        role.getPermissions().stream().map(Permission::getName).forEach(permissionNames::add);
        return new RoleResponse(role.getId(), role.getName(), role.getDescription(),
                role.getClientApplication() == null ? null : role.getClientApplication().getClientId(),
                role.isSystemRole(), permissionNames);
    }
}

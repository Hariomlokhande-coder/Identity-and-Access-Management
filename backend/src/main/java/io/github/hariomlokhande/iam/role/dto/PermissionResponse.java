package io.github.hariomlokhande.iam.role.dto;

import io.github.hariomlokhande.iam.role.Permission;
import java.util.UUID;

public record PermissionResponse(UUID id, String name, String description) {

    public static PermissionResponse from(Permission permission) {
        return new PermissionResponse(permission.getId(), permission.getName(), permission.getDescription());
    }
}

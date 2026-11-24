package io.github.hariomlokhande.iam.role.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Set;

/** Permissions are replaced wholesale, so a removal is expressed by omission. */
public record UpdateRoleRequest(
        @Size(max = 255) String description,
        @NotNull Set<String> permissions) {
}

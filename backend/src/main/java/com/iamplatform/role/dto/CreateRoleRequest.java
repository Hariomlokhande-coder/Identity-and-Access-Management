package com.iamplatform.role.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Set;

/**
 * @param clientId scopes the role to one application; omit only for a role that is
 *                 genuinely meant to apply platform-wide
 */
public record CreateRoleRequest(
        @NotBlank @Size(max = 64) @Pattern(regexp = "[A-Z][A-Z0-9_]*",
                message = "must be upper snake case, for example ORDER_MANAGER") String name,
        @Size(max = 255) String description,
        @Size(max = 64) String clientId,
        Set<String> permissions) {
}

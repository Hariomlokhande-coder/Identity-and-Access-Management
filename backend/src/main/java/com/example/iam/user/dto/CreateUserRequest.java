package com.example.iam.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Set;
import java.util.UUID;

/**
 * Administrative user creation.
 *
 * @param emailVerified skips the verification mail; only meaningful when the address
 *                      was already proven through another channel
 */
public record CreateUserRequest(
        @NotBlank @Email @Size(max = 320) String email,
        @NotBlank @Size(max = 200) String password,
        Set<UUID> roleIds,
        boolean emailVerified) {
}

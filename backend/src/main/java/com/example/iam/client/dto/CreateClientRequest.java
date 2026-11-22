package com.example.iam.client.dto;

import com.example.iam.client.ClientType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import java.util.Set;

/**
 * @param redirectUris at least one is required: an authorization code has nowhere
 *                     safe to go without a pre-registered destination
 */
public record CreateClientRequest(
        @NotBlank @Size(max = 160) String name,
        @NotNull ClientType clientType,
        @NotEmpty Set<String> redirectUris,
        Set<String> scopes,
        Boolean requireConsent,
        Boolean requirePkce,
        @Positive Integer accessTokenTtlSeconds,
        @Positive Integer refreshTokenTtlSeconds) {
}

package com.iamplatform.client.dto;

import com.iamplatform.client.ClientStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import java.util.Set;

/** Client type is immutable: switching it would change which security rules apply. */
public record UpdateClientRequest(
        @NotBlank @Size(max = 160) String name,
        @NotNull ClientStatus status,
        @NotEmpty Set<String> redirectUris,
        Set<String> scopes,
        Boolean requireConsent,
        Boolean requirePkce,
        @Positive Integer accessTokenTtlSeconds,
        @Positive Integer refreshTokenTtlSeconds) {
}

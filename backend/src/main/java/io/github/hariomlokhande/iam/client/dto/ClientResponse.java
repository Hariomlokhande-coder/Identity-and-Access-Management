package io.github.hariomlokhande.iam.client.dto;

import io.github.hariomlokhande.iam.client.ClientApplication;
import io.github.hariomlokhande.iam.client.ClientStatus;
import io.github.hariomlokhande.iam.client.ClientType;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** The client secret is never part of this view; it is shown once, at issue time. */
public record ClientResponse(
        UUID id,
        String clientId,
        String name,
        ClientType clientType,
        ClientStatus status,
        boolean requireConsent,
        boolean requirePkce,
        Set<String> redirectUris,
        Set<String> scopes,
        Integer accessTokenTtlSeconds,
        Integer refreshTokenTtlSeconds,
        Instant createdAt) {

    public static ClientResponse from(ClientApplication client) {
        return new ClientResponse(client.getId(), client.getClientId(), client.getName(), client.getClientType(),
                client.getStatus(), client.isRequireConsent(), client.isRequirePkce(),
                Set.copyOf(client.getRedirectUris()), Set.copyOf(client.getScopes()),
                client.getAccessTokenTtlSeconds(), client.getRefreshTokenTtlSeconds(), client.getCreatedAt());
    }
}

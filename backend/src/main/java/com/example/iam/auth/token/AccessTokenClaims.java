package com.example.iam.auth.token;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** The verified contents of an access token. */
public record AccessTokenClaims(
        UUID userId,
        UUID sessionId,
        String audience,
        Set<String> roles,
        Set<String> permissions,
        Set<String> scopes,
        int permissionVersion,
        String tokenId,
        Instant issuedAt,
        Instant expiresAt) {

    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }
}

package com.example.iam.auth.token;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

/** Everything needed to mint one access token. */
public record AccessTokenRequest(
        UUID userId,
        UUID sessionId,
        String audience,
        Set<String> roles,
        Set<String> permissions,
        Set<String> scopes,
        int permissionVersion,
        Duration ttl) {
}

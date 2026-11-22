package com.example.iam.oauth;

import java.util.Set;
import java.util.UUID;

/**
 * The short-lived grant handed to the client through the redirect.
 *
 * <p>It carries the redirect URI and PKCE challenge it was issued under so the token
 * endpoint can insist on the same ones, which is what stops a code obtained for one
 * destination being redeemed from another.
 */
public record AuthorizationCode(
        String clientId,
        UUID userId,
        String redirectUri,
        Set<String> scopes,
        String nonce,
        String codeChallenge,
        String codeChallengeMethod,
        long authenticatedAtEpochSecond) {
}

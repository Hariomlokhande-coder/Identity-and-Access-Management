package com.iamplatform.oauth;

import java.util.Set;
import java.util.UUID;

/**
 * A validated authorize request parked while the user is asked for consent.
 *
 * <p>Parking it server-side is deliberate: when the consent screen answers, the
 * platform reads the redirect URI, scopes and PKCE challenge from here rather than
 * from the browser. A consent UI therefore cannot be tricked into approving a request
 * different from the one it displayed.
 */
public record AuthorizationRequest(
        String clientId,
        UUID userId,
        String redirectUri,
        Set<String> scopes,
        String state,
        String nonce,
        String codeChallenge,
        String codeChallengeMethod) {
}

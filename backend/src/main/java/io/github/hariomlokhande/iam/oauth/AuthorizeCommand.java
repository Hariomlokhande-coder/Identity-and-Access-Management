package io.github.hariomlokhande.iam.oauth;

/** The query parameters of an authorize request, as received. */
public record AuthorizeCommand(
        String responseType,
        String clientId,
        String redirectUri,
        String scope,
        String state,
        String nonce,
        String codeChallenge,
        String codeChallengeMethod) {
}

package com.example.iam.oauth;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PkceValidatorTest {

    private static final String VERIFIER = "0123456789abcdefghijklmnopqrstuvwxyz-._~ABCDEFGH";

    @Test
    @DisplayName("accepts the verifier the challenge was derived from")
    void acceptsMatchingVerifier() throws Exception {
        String challenge = challengeFor(VERIFIER);

        assertThatCode(() -> PkceValidator.verify(challenge, VERIFIER)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("rejects a verifier that does not hash to the challenge")
    void rejectsMismatchedVerifier() throws Exception {
        String challenge = challengeFor(VERIFIER);

        assertThatThrownBy(() -> PkceValidator.verify(challenge, VERIFIER.replace('0', '1')))
                .isInstanceOf(OAuth2Exception.class)
                .hasMessageContaining("does not match");
    }

    @Test
    @DisplayName("rejects a missing verifier, so a stolen code cannot be redeemed bare")
    void rejectsMissingVerifier() throws Exception {
        String challenge = challengeFor(VERIFIER);

        assertThatThrownBy(() -> PkceValidator.verify(challenge, null))
                .isInstanceOf(OAuth2Exception.class)
                .hasMessageContaining("missing or has an invalid length");
    }

    @Test
    @DisplayName("rejects a verifier shorter than the specification allows")
    void rejectsShortVerifier() throws Exception {
        String challenge = challengeFor("tiny");

        assertThatThrownBy(() -> PkceValidator.verify(challenge, "tiny"))
                .isInstanceOf(OAuth2Exception.class)
                .hasMessageContaining("invalid length");
    }

    /**
     * The plain method sends the secret over the same channel as the code, so it proves
     * nothing and is refused outright.
     */
    @Test
    @DisplayName("only S256 is accepted as a challenge method")
    void rejectsPlainMethod() {
        assertThatCode(() -> PkceValidator.assertSupportedMethod("S256")).doesNotThrowAnyException();
        assertThatThrownBy(() -> PkceValidator.assertSupportedMethod("plain"))
                .isInstanceOf(OAuth2Exception.class)
                .hasMessageContaining("must be S256");
        assertThatThrownBy(() -> PkceValidator.assertSupportedMethod(null))
                .isInstanceOf(OAuth2Exception.class);
    }

    private String challengeFor(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}

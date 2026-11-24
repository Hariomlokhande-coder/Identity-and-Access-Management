package io.github.hariomlokhande.iam.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Proof Key for Code Exchange.
 *
 * <p>PKCE is what makes an intercepted authorization code useless. The client commits
 * to a secret up front by sending its hash; only the holder of the original secret can
 * redeem the code. Only S256 is accepted - the {@code plain} method sends the secret
 * itself through the same channel as the code and therefore proves nothing.
 */
public final class PkceValidator {

    public static final String METHOD_S256 = "S256";

    private static final int MIN_VERIFIER_LENGTH = 43;
    private static final int MAX_VERIFIER_LENGTH = 128;

    private PkceValidator() {
    }

    public static void assertSupportedMethod(String method) {
        if (!METHOD_S256.equals(method)) {
            throw OAuth2Exception.redirecting(OAuth2Exception.INVALID_REQUEST,
                    "code_challenge_method must be S256");
        }
    }

    /**
     * Recomputes the challenge from the verifier and compares in constant time.
     */
    public static void verify(String challenge, String verifier) {
        if (verifier == null || verifier.length() < MIN_VERIFIER_LENGTH
                || verifier.length() > MAX_VERIFIER_LENGTH) {
            throw OAuth2Exception.invalidGrant("code_verifier is missing or has an invalid length");
        }
        String computed = challengeFor(verifier);
        if (!MessageDigest.isEqual(computed.getBytes(StandardCharsets.US_ASCII),
                challenge.getBytes(StandardCharsets.US_ASCII))) {
            throw OAuth2Exception.invalidGrant("code_verifier does not match the code_challenge");
        }
    }

    private static String challengeFor(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
        }
    }
}

package com.example.iam.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Hashing helpers for values that must be stored but never recoverable.
 *
 * <p>SHA-256 is correct here and BCrypt is not: refresh tokens, reset tokens and
 * SSO cookie secrets are already 256 bits of entropy, so they are not guessable
 * and a slow KDF would only add latency to every request. Passwords use BCrypt
 * instead - see {@code PasswordService}.
 */
public final class Hashing {

    private Hashing() {
    }

    public static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
        }
    }

    /** Comparison whose duration does not depend on where the first difference is. */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }

        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
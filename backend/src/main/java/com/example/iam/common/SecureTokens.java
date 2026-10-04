package com.example.iam.common;

import java.security.SecureRandom;
import java.util.Base64;

/** Generates the opaque secrets handed to users: refresh tokens, codes, mail links. */
public final class SecureTokens {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final int DEFAULT_BYTES = 32;

    private SecureTokens() {
    }

    /** 256 bits of entropy, URL-safe so it can be placed directly in a mail link. */
    public static String generate() {
        return generate(DEFAULT_BYTES);
    }

    public static String generate(int byteLength) {
        byte[] bytes = new byte[byteLength];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }
}
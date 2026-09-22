package com.example.iam.user;

import java.util.Locale;

/**
 * One canonical form for email addresses, applied before every lookup and every
 * write. Without it "Hariom@Example.com" and "hariom@example.com" register as two
 * accounts and the unique index never fires.
 */
public final class EmailNormalizer {

    private EmailNormalizer() {
    }

    public static String normalize(String email) {
        if (email == null) {
            return null;
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
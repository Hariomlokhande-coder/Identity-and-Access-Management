package io.github.hariomlokhande.iam.email;

public enum EmailStatus {
    PENDING,
    SENT,
    /** Delivery gave up after the configured number of attempts. */
    FAILED
}
package com.example.iam.user;

public enum UserStatus {
    /** Registered but the email address has not been proven yet. */
    PENDING_VERIFICATION,
    ACTIVE,
    /** Administratively suspended; credentials stay valid but sign-in is refused. */
    DISABLED,
    /** Soft-deleted. Kept so audit rows and foreign keys stay resolvable. */
    DELETED
}
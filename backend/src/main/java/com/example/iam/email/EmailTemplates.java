package com.example.iam.email;

/**
 * Message bodies for the two mail-delivered flows.
 *
 * <p>The wording is deliberately neutral: a verification or reset mail may reach an
 * address whose owner never registered, and it must not confirm anything about the
 * account behind it beyond the action the recipient can take.
 */
public final class EmailTemplates {

    private EmailTemplates() {
    }

    public static String verificationSubject() {
        return "Verify your email address";
    }

    public static String verificationBody(String link, long validHours) {
        return """
                Please confirm your email address to finish setting up your account.

                %s

                This link can be used once and expires in %d hours. Requesting a new link
                immediately invalidates this one.

                If you did not create an account, you can ignore this message.
                """.formatted(link, validHours);
    }

    public static String passwordResetSubject() {
        return "Reset your password";
    }

    public static String passwordResetBody(String link, long validMinutes) {
        return """
                A password reset was requested for this email address.

                %s

                This link can be used once and expires in %d minutes. Requesting another
                reset immediately invalidates this one.

                If you did not request a reset, no action is needed and your password is unchanged.
                """.formatted(link, validMinutes);
    }

    public static String passwordChangedSubject() {
        return "Your password was changed";
    }

    public static String passwordChangedBody() {
        return """
                The password for your account was just changed and all active sessions were
                signed out.

                If this was not you, reset your password immediately and contact support.
                """;
    }
}
package com.example.iam.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Every tunable knob of the platform. Values that influence security decisions are
 * deliberately explicit here rather than hidden as literals in the services, so an
 * operator can audit the whole policy in one place.
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "iam")
public class IamProperties {

    /** Value published as the {@code iss} claim and as the OIDC issuer identifier. */
    @NotBlank
    private String issuer;

    /** Hosted login screen the authorize endpoint sends unauthenticated users to. */
    private String loginUrl;

    /** Hosted consent screen the authorize endpoint sends users to when consent is missing. */
    private String consentUrl;

    private final Cookie cookie = new Cookie();
    private final Cors cors = new Cors();
    private final Jwt jwt = new Jwt();
    private final Token token = new Token();
    private final PasswordPolicy password = new PasswordPolicy();
    private final Lockout lockout = new Lockout();
    private final RateLimit rateLimit = new RateLimit();
    private final Security security = new Security();
    private final Email email = new Email();
    private final Cleanup cleanup = new Cleanup();
    private final Bootstrap bootstrap = new Bootstrap();

    @Getter
    @Setter
    public static class Cookie {
        private boolean secure = true;
        private String domain;
        private String sameSite = "Lax";
    }

    @Getter
    @Setter
    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>();
        private List<String> allowedHeaders =
                List.of("Authorization", "Content-Type", "X-Correlation-Id");
        private long maxAge = 3600;
    }

    @Getter
    @Setter
    public static class Jwt {
        private Duration accessTokenTtl = Duration.ofMinutes(10);

        /** Leeway applied to exp/iat so mildly skewed clocks do not reject valid tokens. */
        private Duration clockSkew = Duration.ofSeconds(45);

        /** JSON array of signing keys; see {@code scripts/generate-jwt-key.sh}. */
        private String keys;

        private boolean allowEphemeralKey = false;
    }

    @Getter
    @Setter
    public static class Token {
        private Duration refreshTokenTtl = Duration.ofDays(30);
        private Duration authorizationCodeTtl = Duration.ofMinutes(1);
        private Duration emailVerificationTtl = Duration.ofHours(24);
        private Duration passwordResetTtl = Duration.ofMinutes(30);
        private Duration ssoSessionTtl = Duration.ofDays(14);
    }

    @Getter
    @Setter
    public static class PasswordPolicy {
        @Min(8)
        private int minLength = 12;

        private int maxLength = 128;
        private boolean requireUpper = true;
        private boolean requireLower = true;
        private boolean requireDigit = true;
        private boolean requireSymbol = true;

        /** Rejects "aaaa" style padding used to satisfy length rules. */
        private int maxRepeatedChars = 3;

        private boolean breachCheckEnabled = false;
        private String breachCheckUrl = "https://api.pwnedpasswords.com/range/";

        @Min(10)
        private int bcryptStrength = 12;
    }

    @Getter
    @Setter
    public static class Lockout {
        private int maxFailedAttempts = 5;
        private Duration window = Duration.ofMinutes(15);
        private Duration lockDuration = Duration.ofMinutes(15);
        private Duration maxLockDuration = Duration.ofHours(2);

        /** Number of failures after which the client is told a CAPTCHA is required. */
        private int captchaAfterAttempts = 3;
    }

    @Getter
    @Setter
    public static class RateLimit {
        private boolean enabled = true;
        private List<Rule> rules = new ArrayList<>();

        @Getter
        @Setter
        public static class Rule {
            private String path;
            private List<String> methods = new ArrayList<>();
            private int limit;
            private Duration window;
            private KeyType key = KeyType.IP;
        }

        public enum KeyType {
            IP,
            PRINCIPAL_OR_IP
        }
    }

    @Getter
    @Setter
    public static class Security {
        private PermissionCheckMode permissionCheckMode = PermissionCheckMode.TOKEN;
        private boolean revokeSessionsOnPasswordChange = true;
        private int maxSessionsPerUser = 20;

        public enum PermissionCheckMode {
            /** Authorities come from the signed token. Fast, with a bounded stale window. */
            TOKEN,

            /** Authorities are reloaded from the database per request. No stale window. */
            LIVE
        }
    }

    @Getter
    @Setter
    public static class Email {
        private String from = "no-reply@localhost";
        private String verificationUrlTemplate =
                "http://localhost:3000/verify-email?token=%s";
        private String resetUrlTemplate =
                "http://localhost:3000/reset-password?token=%s";

        private final Outbox outbox = new Outbox();

        /**
         * How often the dispatcher drains the queue is read straight from
         * {@code iam.email.outbox.dispatch-interval} by the scheduler annotation, which
         * needs a placeholder rather than a bound value.
         */
        @Getter
        @Setter
        public static class Outbox {
            private int batchSize = 50;
            private int maxAttempts = 8;
        }
    }

    @Getter
    @Setter
    public static class Cleanup {
        private Duration retention = Duration.ofDays(7);
    }

    @Getter
    @Setter
    public static class Bootstrap {
        private String adminEmail;
        private String adminPassword;
    }
}
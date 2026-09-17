package com.example.iam.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "iam")
public class IamProperties {

    /**
     * iss claim aur OIDC issuer identifier.
     */
    @NotBlank
    private String issuer;

    /**
     * Hosted login screen jahan authorize endpoint bhejta hai.
     */
    private String loginUrl;

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
    public static class Token {
        private Duration refreshTokenTtl = Duration.ofDays(30);
        private Duration authorizationCodeTtl = Duration.ofMinutes(1);
        private Duration emailVerificationTtl = Duration.ofHours(24);
        private Duration passwordResetTtl = Duration.ofMinutes(30);
        private Duration ssoSessionTtl = Duration.ofDays(14);
    }

    // Baaki nested classes PDF ke next configuration sections mein define hongi.
}
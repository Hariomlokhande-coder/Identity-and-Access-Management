package com.example.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.iam.config.IamProperties;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import com.example.iam.support.TestProperties;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class PasswordServiceTest {

    private static final String EMAIL = "alice.smith@example.com";

    private IamProperties properties;
    private PasswordService passwordService;

    @BeforeEach
    void setUp() {
        properties = TestProperties.create();
        // Cost 4 keeps the suite fast; production cost comes from configuration.
        PasswordEncoder encoder = new BCryptPasswordEncoder(4);
        passwordService = new PasswordService(encoder, properties);
    }

    @Test
    @DisplayName("accepts a password that satisfies every rule")
    void acceptsCompliantPassword() {
        assertThatCode(() -> passwordService.validate("Str0ng!Passphrase",
                EMAIL)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("reports every broken rule at once rather than one at a time")
    void reportsAllViolations() {
        ApiException exception = catchPolicyViolation("short");

        assertThat(exception.code()).isEqualTo(ErrorCode.PASSWORD_POLICY_VIOLATION);
        List<?> violations = (List<?>) exception.details().get("violations");
        assertThat(violations).hasSizeGreaterThan(2);
    }

    @Test
    @DisplayName("rejects a password built from the email address")
    void rejectsPasswordContainingEmailLocalPart() {
        ApiException exception = catchPolicyViolation("Alice.Smith!2026x");

        assertThat((List<?>) exception.details().get("violations"))
                .anySatisfy(violation -> assertThat(violation.toString()).contains("email"));
    }

    @Test
    @DisplayName("rejects long runs of the same character used to pad the length")
    void rejectsRepeatedCharacters() {
        ApiException exception = catchPolicyViolation("Aaaaaaaaaa1!X");

        assertThat((List<?>) exception.details().get("violations"))
                .anySatisfy(violation -> assertThat(violation.toString()).contains("repeat"));
    }

    @Test
    @DisplayName("caps the length, because BCrypt ignores input past 72 bytes")
    void rejectsOverlongPassword() {
        properties.getPassword().setMaxLength(64);

        ApiException exception = catchPolicyViolation("A1!" + "x".repeat(200));

        assertThat((List<?>) exception.details().get("violations"))
                .anySatisfy(violation -> assertThat(violation.toString()).contains("at most"));
    }

    @Test
    @DisplayName("hashes are salted, so the same password never produces the same hash")
    void hashesAreSalted() {
        String first = passwordService.hash("Str0ng!Passphrase");
        String second = passwordService.hash("Str0ng!Passphrase");

        assertThat(first).isNotEqualTo(second);
        assertThat(passwordService.matches("Str0ng!Passphrase", first)).isTrue();
        assertThat(passwordService.matches("Str0ng!Passphrase", second)).isTrue();
        assertThat(passwordService.matches("wrong", first)).isFalse();
    }

    @Test
    @DisplayName("the decoy verification runs without throwing, so the unknown-user path stays silent")
    void decoyVerificationIsSafeForAnyInput() {
        assertThatCode(() -> passwordService.burnVerificationTime(null)).doesNotThrowAnyException();
        assertThatCode(() ->
                passwordService.burnVerificationTime("anything")).doesNotThrowAnyException();
    }

    private ApiException catchPolicyViolation(String password) {
        return (ApiException) org.assertj.core.api.Assertions
                .catchThrowable(() -> passwordService.validate(password, EMAIL));
    }

    @Test
    @DisplayName("policy relaxation is driven by configuration, not by code changes")
    void honoursRelaxedPolicy() {
        properties.getPassword().setRequireSymbol(false);
        properties.getPassword().setMinLength(8);

        assertThatCode(() -> passwordService.validate("Passw0rdy", EMAIL)).doesNotThrowAnyException();
        assertThatThrownBy(() -> passwordService.validate("passwordy", EMAIL))
                .isInstanceOf(ApiException.class);
    }
}
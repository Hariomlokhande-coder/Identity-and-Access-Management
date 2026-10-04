package com.example.iam.auth;

import com.example.iam.config.IamProperties;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Password policy, hashing and verification.
 *
 * <p>Concrete numbers live in configuration rather than being implied, because
 * "must meet the password policy" is not something a caller can act on. Every
 * violation is reported as a list of the specific rules that failed.
 */
@Service
public class PasswordService {

    private static final Logger log = LoggerFactory.getLogger(PasswordService.class);
    private static final Duration BREACH_CHECK_TIMEOUT = Duration.ofSeconds(2);
    private static final int HIBP_PREFIX_LENGTH = 5;

    private final PasswordEncoder encoder;
    private final IamProperties properties;
    private final RestClient restClient;

    /**
     * Hash of a value nobody can supply. Verifying against it makes an unknown-account
     * sign-in cost the same as a real one, which is what keeps response timing from
     * revealing whether an address is registered.
     */
    private final String decoyHash;

    public PasswordService(PasswordEncoder encoder, IamProperties properties) {
        this.encoder = encoder;
        this.properties = properties;
        this.decoyHash = encoder.encode("decoy-" + java.util.UUID.randomUUID());
        this.restClient = buildRestClient();
    }

    public String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String storedHash) {
        return encoder.matches(rawPassword, storedHash);
    }

    /**
     * Burns the same work as a real password check. Call it on the no-such-user path
     * so that path is not measurably faster than a wrong-password one.
     */
    public void burnVerificationTime(String rawPassword) {
        encoder.matches(rawPassword == null ? "" : rawPassword, decoyHash);
    }

    /**
     * Enforces the configured policy.
     *
     * @param email used to reject passwords built from the address itself
     */
    public void validate(String rawPassword, String email) {
        IamProperties.PasswordPolicy policy = properties.getPassword();
        List<String> violations = new ArrayList<>();

        if (rawPassword == null || rawPassword.length() < policy.getMinLength()) {
            violations.add("must be at least " + policy.getMinLength() + " characters");
        }
        if (rawPassword != null && rawPassword.length() > policy.getMaxLength()) {
            // BCrypt silently ignores input past 72 bytes, and an unbounded password is
            // also a cheap way to make the server do expensive hashing.
            violations.add("must be at most " + policy.getMaxLength() + " characters");
        }
        if (rawPassword != null) {
            addCharacterClassViolations(rawPassword, policy, violations);
            if (exceedsRepeatLimit(rawPassword, policy.getMaxRepeatedChars())) {
                violations.add("must not repeat the same character more than " +
                        policy.getMaxRepeatedChars()
                        + " times in a row");
            }
            if (containsEmailLocalPart(rawPassword, email)) {
                violations.add("must not contain your email address");
            }
        }

        if (!violations.isEmpty()) {
            throw new ApiException(ErrorCode.PASSWORD_POLICY_VIOLATION,
                    ErrorCode.PASSWORD_POLICY_VIOLATION.defaultMessage(), Map.of("violations",
                    violations));
        }

        if (policy.isBreachCheckEnabled() && isKnownBreached(rawPassword)) {
            throw new ApiException(ErrorCode.PASSWORD_POLICY_VIOLATION,
                    "This password has appeared in a known data breach, choose a different one",
                    Map.of("violations", List.of("appears in a public breach corpus")));
        }
    }

    private void addCharacterClassViolations(String password, IamProperties.PasswordPolicy policy,
                                             List<String> violations) {
        if (policy.isRequireUpper() && password.chars().noneMatch(Character::isUpperCase)) {
            violations.add("must contain an uppercase letter");
        }
        if (policy.isRequireLower() && password.chars().noneMatch(Character::isLowerCase)) {
            violations.add("must contain a lowercase letter");
        }
        if (policy.isRequireDigit() && password.chars().noneMatch(Character::isDigit)) {
            violations.add("must contain a digit");
        }
        if (policy.isRequireSymbol()
                && password.chars().noneMatch(c -> !Character.isLetterOrDigit(c) &&
                !Character.isWhitespace(c))) {
            violations.add("must contain a symbol");
        }
    }

    private boolean exceedsRepeatLimit(String password, int maxRepeats) {
        if (maxRepeats <= 0) {
            return false;
        }
        int run = 1;
        for (int i = 1; i < password.length(); i++) {
            run = password.charAt(i) == password.charAt(i - 1) ? run + 1 : 1;
            if (run > maxRepeats) {
                return true;
            }
        }
        return false;
    }

    private boolean containsEmailLocalPart(String password, String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        String localPart = email.substring(0, Math.max(email.indexOf('@'), 0));
        return localPart.length() >= 3
                && password.toLowerCase(Locale.ROOT).contains(localPart.toLowerCase(Locale.ROOT));
    }

    /**
     * Range query against the Have I Been Pwned corpus: only the first five hex digits
     * of the SHA-1 hash leave this process, so the password itself is never disclosed.
     *
     * <p>This check fails open. It improves password quality but is not an
     * authentication control, and a third party being down must not stop people
     * registering or resetting their password.
     */
    private boolean isKnownBreached(String rawPassword) {
        try {
            String sha1 = HexFormat.of().withUpperCase().formatHex(
                    MessageDigest.getInstance("SHA-1").digest(rawPassword.getBytes(StandardCharsets.UTF_8)));
            String prefix = sha1.substring(0, HIBP_PREFIX_LENGTH);
            String suffix = sha1.substring(HIBP_PREFIX_LENGTH);

            String body = restClient.get()
                    .uri(properties.getPassword().getBreachCheckUrl() + prefix)
                    .retrieve()
                    .body(String.class);

            return body != null && body.lines().anyMatch(line -> line.startsWith(suffix));
        } catch (Exception e) {
            log.warn("Breach check unavailable, allowing the password", e);
            return false;
        }
    }

    private RestClient buildRestClient() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout((int) BREACH_CHECK_TIMEOUT.toMillis());
        factory.setReadTimeout((int) BREACH_CHECK_TIMEOUT.toMillis());
        return RestClient.builder().requestFactory(factory).build();
    }
}
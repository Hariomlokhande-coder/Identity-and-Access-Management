package com.iamplatform.support;

import static org.assertj.core.api.Assertions.assertThat;

import com.iamplatform.auth.dto.TokenResponse;
import com.iamplatform.email.EmailOutboxEntry;
import com.iamplatform.email.EmailOutboxRepository;
import java.util.Comparator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Shared setup for tests that exercise the real thing: PostgreSQL, Redis, Flyway, the
 * full security filter chain and real HTTP.
 *
 * <p>Neither dependency is mocked, because the behaviour worth testing here lives in
 * exactly those places - the conditional UPDATE that makes rotation safe, and the
 * Redis markers that make revocation immediate. An in-memory substitute for either
 * would test something the platform never runs.
 *
 * <p>Requires a working Docker environment; the tests are tagged so a plain
 * {@code mvn test} skips them and {@code mvn verify} runs them.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class IntegrationTestBase {

    private static final Pattern TOKEN_IN_LINK = Pattern.compile("token=([A-Za-z0-9_-]+)");

    protected static final String PASSWORD = "Str0ng!Passphrase1";

    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                    .withDatabaseName("iam")
                    .withUsername("iam")
                    .withPassword("iam");

    static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

    static {
        // Started once for the whole suite rather than per class: container startup
        // dominates the runtime, and no test depends on a pristine database.
        POSTGRES.start();
        REDIS.start();
    }

    @DynamicPropertySource
    static void containerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }

    @Autowired
    protected TestRestTemplate rest;

    @Autowired
    protected EmailOutboxRepository outbox;

    @Autowired
    protected StringRedisTemplate redis;

    @LocalServerPort
    protected int port;

    /**
     * Redis carries lockout counters and revocation markers between tests. Clearing it
     * keeps one test from locking out an address another test then tries to use.
     */
    @BeforeEach
    void clearTransientState() {
        rest.getRestTemplate().setRequestFactory(new JdkClientHttpRequestFactory());
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();
    }

    protected String uniqueEmail(String prefix) {
        return prefix + "-" + System.nanoTime() + "@example.com";
    }

    /** Registers, reads the verification link out of the mail queue, and verifies it. */
    protected void registerAndVerify(String email) {
        ResponseEntity<Map> registration = post("/auth/register", Map.of("email", email, "password", PASSWORD));
        assertThat(registration.getStatusCode().is2xxSuccessful()).isTrue();

        String token = latestMailToken();
        ResponseEntity<Map> verification = post("/auth/verify-email", Map.of("token", token));
        assertThat(verification.getStatusCode().is2xxSuccessful()).isTrue();
    }

    protected TokenResponse login(String email) {
        ResponseEntity<TokenResponse> response =
                rest.postForEntity("/auth/login", json(Map.of("email", email, "password", PASSWORD)),
                        TokenResponse.class);
        assertThat(response.getStatusCode().is2xxSuccessful())
                .withFailMessage("login failed: %s", response)
                .isTrue();
        return response.getBody();
    }

    /**
     * The raw token only ever exists in the mail body, exactly as it does in
     * production, so tests recover it the same way a user would.
     */
    protected String latestMailToken() {
        EmailOutboxEntry latest = outbox.findAll().stream()
                .max(Comparator.comparing(EmailOutboxEntry::getCreatedAt))
                .orElseThrow(() -> new AssertionError("no mail was queued"));
        Matcher matcher = TOKEN_IN_LINK.matcher(latest.getBody());
        assertThat(matcher.find()).withFailMessage("no token in mail body: %s", latest.getBody()).isTrue();
        return matcher.group(1);
    }

    protected <T> ResponseEntity<T> post(String path, Object body, Class<T> type) {
        return rest.postForEntity(path, json(body), type);
    }

    @SuppressWarnings("unchecked")
    protected ResponseEntity<Map> post(String path, Object body) {
        return post(path, body, Map.class);
    }

    protected <T> ResponseEntity<T> authorized(String path, HttpMethod method, String accessToken, Object body,
            Class<T> type) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);
        return rest.exchange(path, method, new HttpEntity<>(body, headers), type);
    }

    protected HttpEntity<Object> json(Object body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new HttpEntity<>(body, headers);
    }
}

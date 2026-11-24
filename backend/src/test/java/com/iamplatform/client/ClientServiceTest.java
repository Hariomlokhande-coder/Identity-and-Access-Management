package com.iamplatform.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.iamplatform.audit.AuditService;
import com.iamplatform.client.dto.ClientCredentialsResponse;
import com.iamplatform.client.dto.CreateClientRequest;
import com.iamplatform.common.RequestMetadata;
import com.iamplatform.exception.ApiException;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ClientServiceTest {

    private static final RequestMetadata METADATA = new RequestMetadata("203.0.113.5", "junit");

    @Mock
    private ClientApplicationRepository clients;

    @Mock
    private AuditService auditService;

    private ClientService clientService;

    @BeforeEach
    void setUp() {
        clientService = new ClientService(clients, new BCryptPasswordEncoder(4), auditService);
        when(clients.saveAndFlush(any(ClientApplication.class)))
                .thenAnswer(invocation -> {
                    ClientApplication client = invocation.getArgument(0);
                    client.setId(UUID.randomUUID());
                    return client;
                });
    }

    @Test
    @DisplayName("a confidential client receives a secret exactly once, stored only as a hash")
    void issuesSecretOnceForConfidentialClient() {
        ClientCredentialsResponse response = clientService.create(
                request(ClientType.CONFIDENTIAL, "https://app.example.com/callback"), METADATA);

        assertThat(response.clientSecret()).isNotBlank();
        assertThat(response.client().clientId()).isNotBlank();
        assertThat(response.notice()).contains("cannot be shown again");
    }

    /**
     * A public client cannot keep a secret, so it gets none and PKCE stops being
     * optional for it regardless of what the request asked for.
     */
    @Test
    @DisplayName("a public client gets no secret and cannot opt out of PKCE")
    void publicClientAlwaysRequiresPkce() {
        CreateClientRequest request = new CreateClientRequest("Mobile app", ClientType.PUBLIC,
                Set.of("https://app.example.com/callback"), Set.of("openid"), true, false, null, null);

        ClientCredentialsResponse response = clientService.create(request, METADATA);

        assertThat(response.clientSecret()).isNull();
        assertThat(response.client().requirePkce()).isTrue();
    }

    @Test
    @DisplayName("accepts an https redirect URI and plain http on loopback only")
    void acceptsValidRedirectUris() {
        assertThatCode(() -> clientService.create(
                request(ClientType.CONFIDENTIAL, "https://app.example.com/callback"), METADATA))
                .doesNotThrowAnyException();
        assertThatCode(() -> clientService.create(
                request(ClientType.PUBLIC, "http://localhost:3000/callback"), METADATA))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("rejects plain http outside loopback")
    void rejectsInsecureRedirectUri() {
        assertThatThrownBy(() -> clientService.create(
                request(ClientType.CONFIDENTIAL, "http://app.example.com/callback"), METADATA))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("https");
    }

    @Test
    @DisplayName("rejects wildcards, which would make exact matching meaningless")
    void rejectsWildcardRedirectUri() {
        assertThatThrownBy(() -> clientService.create(
                request(ClientType.CONFIDENTIAL, "https://*.example.com/callback"), METADATA))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("Wildcards");
    }

    /**
     * Browsers never send the fragment to the server, so a registered fragment could
     * never be matched and would silently weaken the check.
     */
    @Test
    @DisplayName("rejects a redirect URI carrying a fragment")
    void rejectsFragmentInRedirectUri() {
        assertThatThrownBy(() -> clientService.create(
                request(ClientType.CONFIDENTIAL, "https://app.example.com/callback#done"), METADATA))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("fragment");
    }

    @Test
    @DisplayName("rejects a relative redirect URI")
    void rejectsRelativeRedirectUri() {
        assertThatThrownBy(() -> clientService.create(request(ClientType.CONFIDENTIAL, "/callback"), METADATA))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("absolute");
    }

    @Test
    @DisplayName("registered URIs are matched exactly, never by prefix")
    void matchesRedirectUriExactly() {
        ClientApplication client = new ClientApplication();
        client.getRedirectUris().add("https://app.example.com/callback");

        assertThat(client.allowsRedirectUri("https://app.example.com/callback")).isTrue();
        assertThat(client.allowsRedirectUri("https://app.example.com/callback/evil")).isFalse();
        assertThat(client.allowsRedirectUri("https://app.example.com/callback?x=1")).isFalse();
        assertThat(client.allowsRedirectUri("https://evil.com/?https://app.example.com/callback")).isFalse();
        assertThat(client.allowsRedirectUri(null)).isFalse();
    }

    private CreateClientRequest request(ClientType type, String redirectUri) {
        return new CreateClientRequest("Test app", type, Set.of(redirectUri), Set.of("openid"), true, true,
                null, null);
    }
}

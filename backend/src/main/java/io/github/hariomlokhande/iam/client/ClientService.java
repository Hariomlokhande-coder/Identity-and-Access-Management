package io.github.hariomlokhande.iam.client;

import io.github.hariomlokhande.iam.audit.AuditEventType;
import io.github.hariomlokhande.iam.audit.AuditService;
import io.github.hariomlokhande.iam.client.dto.ClientCredentialsResponse;
import io.github.hariomlokhande.iam.client.dto.ClientResponse;
import io.github.hariomlokhande.iam.client.dto.CreateClientRequest;
import io.github.hariomlokhande.iam.client.dto.UpdateClientRequest;
import io.github.hariomlokhande.iam.common.PageResponse;
import io.github.hariomlokhande.iam.common.RequestMetadata;
import io.github.hariomlokhande.iam.common.SecureTokens;
import io.github.hariomlokhande.iam.exception.ApiException;
import io.github.hariomlokhande.iam.security.IamUserPrincipal;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Registration and administration of the applications that consume this platform.
 *
 * <p>Two rules here carry real security weight. Redirect URIs are validated on the
 * way in and matched exactly on the way out, because a sloppy redirect turns the
 * authorize endpoint into a delivery service for authorization codes. And a client
 * secret is stored as a BCrypt hash, so the registry is not a list of working
 * credentials for every integrated application.
 */
@Service
public class ClientService {

    private static final int CLIENT_ID_BYTES = 12;
    private static final int CLIENT_SECRET_BYTES = 32;
    private static final Set<String> DEFAULT_SCOPES = Set.of("openid", "profile");

    private final ClientApplicationRepository clients;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public ClientService(ClientApplicationRepository clients, PasswordEncoder passwordEncoder,
            AuditService auditService) {
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public PageResponse<ClientResponse> list(Pageable pageable) {
        return PageResponse.of(clients.findAllByOrderByCreatedAtDesc(pageable).map(ClientResponse::from));
    }

    @Transactional(readOnly = true)
    public ClientResponse get(UUID id) {
        return ClientResponse.from(load(id));
    }

    @Transactional
    public ClientCredentialsResponse create(CreateClientRequest request, RequestMetadata metadata) {
        ClientApplication client = new ClientApplication();
        client.setClientId(generateClientId());
        client.setName(request.name());
        client.setClientType(request.clientType());
        client.setStatus(ClientStatus.ACTIVE);
        client.setRequireConsent(request.requireConsent() == null || request.requireConsent());
        client.setRequirePkce(resolvePkce(request.clientType(), request.requirePkce()));
        client.setAccessTokenTtlSeconds(request.accessTokenTtlSeconds());
        client.setRefreshTokenTtlSeconds(request.refreshTokenTtlSeconds());
        client.getRedirectUris().addAll(validateRedirectUris(request.redirectUris()));
        client.getScopes().addAll(request.scopes() == null || request.scopes().isEmpty()
                ? DEFAULT_SCOPES : request.scopes());

        // Only a confidential client gets a secret. Handing one to a browser or mobile
        // app would ship it to every user, which is why those must use PKCE instead.
        String rawSecret = null;
        if (request.clientType() == ClientType.CONFIDENTIAL) {
            rawSecret = SecureTokens.generate(CLIENT_SECRET_BYTES);
            client.setClientSecretHash(passwordEncoder.encode(rawSecret));
        }

        clients.saveAndFlush(client);
        auditService.success(AuditEventType.CLIENT_CREATED, actorId(), client.getId().toString(),
                metadata.ipAddress(), "client " + client.getClientId() + " registered");
        return ClientCredentialsResponse.of(ClientResponse.from(client), rawSecret);
    }

    @Transactional
    public ClientResponse update(UUID id, UpdateClientRequest request, RequestMetadata metadata) {
        ClientApplication client = load(id);
        client.setName(request.name());
        client.setStatus(request.status());
        client.setRequireConsent(request.requireConsent() == null || request.requireConsent());
        client.setRequirePkce(resolvePkce(client.getClientType(), request.requirePkce()));
        client.setAccessTokenTtlSeconds(request.accessTokenTtlSeconds());
        client.setRefreshTokenTtlSeconds(request.refreshTokenTtlSeconds());

        client.getRedirectUris().clear();
        client.getRedirectUris().addAll(validateRedirectUris(request.redirectUris()));
        client.getScopes().clear();
        client.getScopes().addAll(request.scopes() == null || request.scopes().isEmpty()
                ? DEFAULT_SCOPES : request.scopes());

        auditService.success(AuditEventType.CLIENT_UPDATED, actorId(), id.toString(), metadata.ipAddress(), null);
        return ClientResponse.from(client);
    }

    /** Issues a new secret; the previous one stops working immediately. */
    @Transactional
    public ClientCredentialsResponse rotateSecret(UUID id, RequestMetadata metadata) {
        ClientApplication client = load(id);
        if (client.getClientType() != ClientType.CONFIDENTIAL) {
            throw ApiException.invalid("Public clients do not have a secret");
        }

        String rawSecret = SecureTokens.generate(CLIENT_SECRET_BYTES);
        client.setClientSecretHash(passwordEncoder.encode(rawSecret));

        auditService.success(AuditEventType.CLIENT_SECRET_ROTATED, actorId(), id.toString(), metadata.ipAddress(),
                null);
        return ClientCredentialsResponse.of(ClientResponse.from(client), rawSecret);
    }

    /**
     * Removing a client cascades to its sessions, tokens and scoped roles, so nothing
     * is left pointing at an application that no longer exists.
     */
    @Transactional
    public void delete(UUID id, RequestMetadata metadata) {
        ClientApplication client = load(id);
        clients.delete(client);
        auditService.success(AuditEventType.CLIENT_DELETED, actorId(), id.toString(), metadata.ipAddress(),
                "client " + client.getClientId() + " deleted");
    }

    /**
     * A public client can never opt out of PKCE: without a secret, the authorization
     * code is the only thing standing between an attacker and a token.
     */
    private boolean resolvePkce(ClientType type, Boolean requested) {
        if (type == ClientType.PUBLIC) {
            return true;
        }
        return requested == null || requested;
    }

    /**
     * Rejects anything that cannot be matched safely later: relative URIs, fragments
     * (which an exact match cannot see, since browsers do not send them), wildcards,
     * and plain HTTP anywhere but loopback.
     */
    private Set<String> validateRedirectUris(Set<String> candidates) {
        candidates.forEach(this::validateRedirectUri);
        return candidates;
    }

    private void validateRedirectUri(String candidate) {
        // Checked before parsing: a wildcard in the host makes the URI unparseable, and
        // "not a valid URI" would hide the actual mistake from whoever registered it.
        if (candidate.contains("*")) {
            throw ApiException.invalid("Wildcards are not allowed in redirect URIs: " + candidate);
        }

        URI uri;
        try {
            uri = new URI(candidate);
        } catch (URISyntaxException e) {
            throw ApiException.invalid("Redirect URI is not a valid URI: " + candidate);
        }
        if (!uri.isAbsolute() || uri.getHost() == null) {
            throw ApiException.invalid("Redirect URI must be absolute: " + candidate);
        }
        if (uri.getFragment() != null) {
            throw ApiException.invalid("Redirect URI must not contain a fragment: " + candidate);
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        boolean loopback = "localhost".equals(uri.getHost()) || "127.0.0.1".equals(uri.getHost())
                || "[::1]".equals(uri.getHost());
        if ("http".equals(scheme) && !loopback) {
            throw ApiException.invalid("Redirect URI must use https outside loopback: " + candidate);
        }
    }

    private String generateClientId() {
        String candidate = SecureTokens.generate(CLIENT_ID_BYTES);
        // Collision is astronomically unlikely at 96 bits, but the check costs one
        // indexed lookup and turns an impossible bug into an impossible bug.
        return clients.existsByClientId(candidate) ? generateClientId() : candidate;
    }

    private ClientApplication load(UUID id) {
        return clients.findById(id).orElseThrow(() -> ApiException.notFound("Client"));
    }

    private UUID actorId() {
        return IamUserPrincipal.current().map(IamUserPrincipal::userId).orElse(null);
    }
}

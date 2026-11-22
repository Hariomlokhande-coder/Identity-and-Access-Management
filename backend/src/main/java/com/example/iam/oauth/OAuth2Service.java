package com.example.iam.oauth;

import com.example.iam.audit.AuditEventType;
import com.example.iam.audit.AuditService;
import com.example.iam.auth.dto.TokenResponse;
import com.example.iam.auth.token.RefreshTokenService;
import com.example.iam.auth.token.TokenIssuer;
import com.example.iam.client.ClientApplication;
import com.example.iam.client.ClientApplicationRepository;
import com.example.iam.client.ClientType;
import com.example.iam.common.RequestMetadata;
import com.example.iam.exception.ApiException;
import com.example.iam.session.SessionService;
import com.example.iam.session.UserSession;
import com.example.iam.user.User;
import com.example.iam.user.UserRepository;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The authorization-code flow with PKCE, and the token endpoint behind it.
 *
 * <p>The sequence of checks in {@link #authorize} is not arbitrary. The client and the
 * redirect URI are settled first, because until a redirect URI has been matched
 * exactly against the registry there is nowhere safe to send an error - reporting one
 * by redirecting to an unverified address would make this endpoint an open redirect.
 * Everything after that point can safely be reported back to the client.
 */
@Service
public class OAuth2Service {

    private static final Logger log = LoggerFactory.getLogger(OAuth2Service.class);

    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String BASIC_PREFIX = "Basic ";

    private final ClientApplicationRepository clients;
    private final UserRepository users;
    private final ConsentService consentService;
    private final OAuthStateStore stateStore;
    private final SessionService sessionService;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public OAuth2Service(ClientApplicationRepository clients, UserRepository users, ConsentService consentService,
            OAuthStateStore stateStore, SessionService sessionService, TokenIssuer tokenIssuer,
            RefreshTokenService refreshTokenService, PasswordEncoder passwordEncoder, AuditService auditService) {
        this.clients = clients;
        this.users = users;
        this.consentService = consentService;
        this.stateStore = stateStore;
        this.sessionService = sessionService;
        this.tokenIssuer = tokenIssuer;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    /**
     * Validates an authorize request and decides what happens next: issue a code, ask
     * the user to sign in, or ask for consent.
     *
     * @param userId the signed-in user from the SSO cookie, or null if anonymous
     */
    @Transactional
    public AuthorizationOutcome authorize(AuthorizeCommand command, UUID userId, Instant authenticatedAt,
            RequestMetadata metadata) {
        ClientApplication client = requireActiveClient(command.clientId());

        // Exact match against the registry. No prefix matching, no "close enough".
        if (!client.allowsRedirectUri(command.redirectUri())) {
            log.warn("Rejected authorize request for client {} with unregistered redirect URI",
                    client.getClientId());
            throw OAuth2Exception.direct(OAuth2Exception.INVALID_REQUEST,
                    "redirect_uri does not match a registered URI for this client");
        }

        // The client and its redirect URI are now proven, so from here a protocol error
        // is delivered to the client the way the spec expects: as a redirect carrying
        // error and state, rather than as an error page the client never sees.
        Set<String> scopes;
        try {
            if (!RESPONSE_TYPE_CODE.equals(command.responseType())) {
                throw OAuth2Exception.redirecting(OAuth2Exception.UNSUPPORTED_RESPONSE_TYPE,
                        "Only the authorization code response type is supported");
            }
            scopes = resolveScopes(client, command.scope());
            requirePkceIfNeeded(client, command);
        } catch (OAuth2Exception e) {
            return AuthorizationOutcome.redirect(
                    errorRedirect(command.redirectUri(), e.error(), e.getMessage(), command.state()));
        }

        if (userId == null) {
            return AuthorizationOutcome.loginRequired();
        }
        if (client.isRequireConsent() && !consentService.isCovered(userId, client, scopes)) {
            AuthorizationRequest pending = new AuthorizationRequest(client.getClientId(), userId,
                    command.redirectUri(), scopes, command.state(), command.nonce(), command.codeChallenge(),
                    command.codeChallengeMethod());
            return AuthorizationOutcome.consentRequired(stateStore.storePendingRequest(pending));
        }

        String redirect = issueCode(client, userId, command.redirectUri(), scopes, command.state(),
                command.nonce(), command.codeChallenge(), command.codeChallengeMethod(), authenticatedAt,
                metadata);
        return AuthorizationOutcome.redirect(redirect);
    }

    /** Renders what a consent screen needs to show, without consuming the request. */
    @Transactional(readOnly = true)
    public PendingAuthorization describePendingRequest(String requestId, UUID userId) {
        AuthorizationRequest request = stateStore.peekPendingRequest(requestId)
                .filter(pending -> pending.userId().equals(userId))
                .orElseThrow(() -> ApiException.invalid("This authorization request has expired, start again"));
        ClientApplication client = requireActiveClient(request.clientId());
        return new PendingAuthorization(requestId, client.getClientId(), client.getName(), request.scopes());
    }

    /**
     * Applies the user's decision and returns the URL to send the browser to.
     *
     * <p>Everything except the yes-or-no comes from the parked request, so a tampered
     * consent form cannot approve scopes the user was never shown, or redirect the
     * result somewhere else.
     */
    @Transactional
    public String applyConsentDecision(String requestId, UUID userId, boolean approved, Instant authenticatedAt,
            RequestMetadata metadata) {
        AuthorizationRequest request = stateStore.consumePendingRequest(requestId)
                .orElseThrow(() -> ApiException.invalid("This authorization request has expired, start again"));
        if (!request.userId().equals(userId)) {
            // The parked request belongs to a different sign-in; treat it as absent.
            throw ApiException.invalid("This authorization request has expired, start again");
        }
        ClientApplication client = requireActiveClient(request.clientId());

        if (!approved) {
            auditService.success(AuditEventType.OAUTH_AUTHORIZATION_DENIED, userId, client.getClientId(),
                    metadata.ipAddress(), "user denied consent");
            return errorRedirect(request.redirectUri(), OAuth2Exception.ACCESS_DENIED,
                    "The user denied the request", request.state());
        }

        consentService.grant(userId, client, request.scopes(), metadata.ipAddress());
        return issueCode(client, userId, request.redirectUri(), request.scopes(), request.state(),
                request.nonce(), request.codeChallenge(), request.codeChallengeMethod(), authenticatedAt,
                metadata);
    }

    /**
     * Redeems an authorization code.
     *
     * <p>The code is consumed atomically before anything is checked, so a replay finds
     * nothing regardless of how fast it arrives.
     */
    @Transactional
    public TokenResponse exchangeAuthorizationCode(ClientApplication client, String rawCode, String redirectUri,
            String codeVerifier, RequestMetadata metadata) {
        AuthorizationCode code = stateStore.consumeCode(rawCode)
                .orElseThrow(() -> OAuth2Exception.invalidGrant(
                        "The authorization code is invalid, expired or already used"));

        if (!code.clientId().equals(client.getClientId())) {
            log.warn("Client {} attempted to redeem a code issued to {}", client.getClientId(), code.clientId());
            throw OAuth2Exception.invalidGrant("The authorization code was issued to a different client");
        }
        if (!code.redirectUri().equals(redirectUri)) {
            throw OAuth2Exception.invalidGrant("redirect_uri does not match the one used to obtain the code");
        }
        if (code.codeChallenge() != null) {
            PkceValidator.verify(code.codeChallenge(), codeVerifier);
        }

        User user = users.findWithRolesById(code.userId())
                .orElseThrow(() -> OAuth2Exception.invalidGrant("The account no longer exists"));
        assertUsable(user);

        // No SSO cookie here: this exchange is a server-to-server call, and the browser
        // session that authorised it already has its own.
        UserSession session = sessionService
                .create(user, client, code.scopes(), metadata, false)
                .session();
        TokenResponse tokens = tokenIssuer.issueForNewSession(user, session, client, code.nonce(),
                Instant.ofEpochSecond(code.authenticatedAtEpochSecond()));

        auditService.success(AuditEventType.OAUTH_TOKEN_ISSUED, user.getId(), client.getClientId(),
                metadata.ipAddress(), "authorization_code grant");
        return tokens;
    }

    /** Rotates a refresh token at the token endpoint, after the client has authenticated. */
    @Transactional
    public TokenResponse exchangeRefreshToken(ClientApplication client, String refreshToken,
            RequestMetadata metadata) {
        RefreshTokenService.RotationResult rotation = refreshTokenService.rotate(refreshToken,
                client.getClientId(), tokenIssuer.refreshTtl(client));
        assertUsable(rotation.user());

        TokenResponse tokens = tokenIssuer.issueForRotation(rotation);
        auditService.success(AuditEventType.TOKEN_REFRESHED, rotation.user().getId(), client.getClientId(),
                metadata.ipAddress(), "refresh_token grant");
        return tokens;
    }

    /**
     * Authenticates the calling client from the Basic header or the request body.
     *
     * <p>A confidential client must prove its secret. A public client cannot hold one,
     * so it identifies itself only - which is exactly why PKCE is mandatory for it.
     */
    @Transactional(readOnly = true)
    public ClientApplication authenticateClient(String authorizationHeader, String clientIdParam,
            String clientSecretParam) {
        Credentials credentials = basicCredentials(authorizationHeader)
                .orElseGet(() -> new Credentials(clientIdParam, clientSecretParam));
        if (credentials.clientId() == null || credentials.clientId().isBlank()) {
            throw OAuth2Exception.invalidClient("client_id is required");
        }

        ClientApplication client = clients.findByClientId(credentials.clientId())
                .filter(ClientApplication::isActive)
                .orElseThrow(() -> OAuth2Exception.invalidClient("Client authentication failed"));

        if (client.getClientType() == ClientType.CONFIDENTIAL) {
            if (credentials.clientSecret() == null
                    || !passwordEncoder.matches(credentials.clientSecret(), client.getClientSecretHash())) {
                log.warn("Failed client authentication for {}", client.getClientId());
                throw OAuth2Exception.invalidClient("Client authentication failed");
            }
        }
        return client;
    }

    private String issueCode(ClientApplication client, UUID userId, String redirectUri, Set<String> scopes,
            String state, String nonce, String codeChallenge, String codeChallengeMethod, Instant authenticatedAt,
            RequestMetadata metadata) {
        Instant authTime = authenticatedAt == null ? Instant.now() : authenticatedAt;
        String rawCode = stateStore.storeCode(new AuthorizationCode(client.getClientId(), userId, redirectUri,
                scopes, nonce, codeChallenge, codeChallengeMethod, authTime.getEpochSecond()));

        auditService.success(AuditEventType.OAUTH_AUTHORIZATION_GRANTED, userId, client.getClientId(),
                metadata.ipAddress(), "scopes " + String.join(" ", scopes));

        Map<String, String> params = new LinkedHashMap<>();
        params.put("code", rawCode);
        params.put("state", state);
        return appendQuery(redirectUri, params);
    }

    /** Errors go back to the client the same way a success would, carrying the state. */
    private String errorRedirect(String redirectUri, String error, String description, String state) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("error", error);
        params.put("error_description", description);
        params.put("state", state);
        return appendQuery(redirectUri, params);
    }

    /**
     * Appends parameters to a registered redirect URI.
     *
     * <p>Only the values added here are encoded. Running an encoder over the whole URI
     * would re-encode any percent sequence the client registered, quietly changing the
     * address the code is delivered to.
     */
    private String appendQuery(String redirectUri, Map<String, String> params) {
        StringBuilder uri = new StringBuilder(redirectUri);
        char separator = redirectUri.contains("?") ? '&' : '?';
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (entry.getValue() == null) {
                continue;
            }
            uri.append(separator)
                    .append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
            separator = '&';
        }
        return uri.toString();
    }

    private void requirePkceIfNeeded(ClientApplication client, AuthorizeCommand command) {
        if (command.codeChallenge() == null || command.codeChallenge().isBlank()) {
            if (client.isRequirePkce()) {
                throw OAuth2Exception.redirecting(OAuth2Exception.INVALID_REQUEST,
                        "code_challenge is required for this client");
            }
            return;
        }
        PkceValidator.assertSupportedMethod(command.codeChallengeMethod());
    }

    /**
     * An omitted scope falls back to everything the client is registered for; an
     * explicit one may never exceed it.
     */
    private Set<String> resolveScopes(ClientApplication client, String requested) {
        if (requested == null || requested.isBlank()) {
            return Set.copyOf(client.getScopes());
        }
        Set<String> scopes = new LinkedHashSet<>(List.of(requested.trim().split("\\s+")));
        if (!client.getScopes().containsAll(scopes)) {
            throw OAuth2Exception.redirecting(OAuth2Exception.INVALID_SCOPE,
                    "One or more requested scopes are not allowed for this client");
        }
        return scopes;
    }

    private ClientApplication requireActiveClient(String clientId) {
        return clients.findByClientId(clientId)
                .filter(ClientApplication::isActive)
                .orElseThrow(() -> OAuth2Exception.direct(OAuth2Exception.INVALID_CLIENT,
                        "Unknown or inactive client"));
    }

    private void assertUsable(User user) {
        if (!user.isActive() || user.isCurrentlyLocked() || !user.isEmailVerified()) {
            throw OAuth2Exception.invalidGrant("The account is not able to sign in");
        }
    }

    private Optional<Credentials> basicCredentials(String header) {
        if (header == null || !header.startsWith(BASIC_PREFIX)) {
            return Optional.empty();
        }
        try {
            String decoded = new String(Base64.getDecoder().decode(header.substring(BASIC_PREFIX.length()).trim()),
                    StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 0) {
                return Optional.empty();
            }
            return Optional.of(new Credentials(decoded.substring(0, separator), decoded.substring(separator + 1)));
        } catch (IllegalArgumentException e) {
            throw OAuth2Exception.invalidClient("Malformed Basic authorization header");
        }
    }

    private record Credentials(String clientId, String clientSecret) {
    }

    /** What the authorize endpoint should do next. */
    public record AuthorizationOutcome(Kind kind, String redirectUri, String requestId) {

        public enum Kind {
            REDIRECT,
            LOGIN_REQUIRED,
            CONSENT_REQUIRED
        }

        public static AuthorizationOutcome redirect(String uri) {
            return new AuthorizationOutcome(Kind.REDIRECT, uri, null);
        }

        public static AuthorizationOutcome loginRequired() {
            return new AuthorizationOutcome(Kind.LOGIN_REQUIRED, null, null);
        }

        public static AuthorizationOutcome consentRequired(String requestId) {
            return new AuthorizationOutcome(Kind.CONSENT_REQUIRED, null, requestId);
        }
    }

    /** What a consent screen shows the user. */
    public record PendingAuthorization(String requestId, String clientId, String clientName, Set<String> scopes) {
    }
}

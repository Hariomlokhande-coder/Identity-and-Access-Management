package io.github.hariomlokhande.iam.oauth;

import io.github.hariomlokhande.iam.auth.dto.MessageResponse;
import io.github.hariomlokhande.iam.auth.dto.TokenResponse;
import io.github.hariomlokhande.iam.client.ClientApplication;
import io.github.hariomlokhande.iam.common.RequestMetadata;
import io.github.hariomlokhande.iam.config.IamProperties;
import io.github.hariomlokhande.iam.exception.ApiException;
import io.github.hariomlokhande.iam.oauth.OAuth2Service.AuthorizationOutcome;
import io.github.hariomlokhande.iam.oauth.OAuth2Service.PendingAuthorization;
import io.github.hariomlokhande.iam.security.IamUserPrincipal;
import io.github.hariomlokhande.iam.session.SessionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The OAuth2 and OpenID Connect endpoints.
 *
 * <p>Authorize and consent are browser endpoints authenticated by the SSO cookie;
 * token and userinfo are machine endpoints that carry their own credentials. The
 * split matters: it is what keeps a cookie from ever being usable to mint a token
 * from a third-party page.
 */
@RestController
@RequestMapping("/oauth2")
@Tag(name = "OAuth2 and OpenID Connect")
public class OAuth2Controller {

    private static final String GRANT_AUTHORIZATION_CODE = "authorization_code";
    private static final String GRANT_REFRESH_TOKEN = "refresh_token";

    private final OAuth2Service oauth2Service;
    private final UserInfoService userInfoService;
    private final ConsentService consentService;
    private final SessionService sessionService;
    private final IamProperties properties;

    public OAuth2Controller(OAuth2Service oauth2Service, UserInfoService userInfoService,
            ConsentService consentService, SessionService sessionService, IamProperties properties) {
        this.oauth2Service = oauth2Service;
        this.userInfoService = userInfoService;
        this.consentService = consentService;
        this.sessionService = sessionService;
        this.properties = properties;
    }

    @GetMapping("/authorize")
    @Operation(summary = "Start an authorization code flow",
            description = "Redirects to the client, or to the login or consent screen when one is needed.")
    public ResponseEntity<Void> authorize(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(required = false) String scope,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String nonce,
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod,
            HttpServletRequest httpRequest) {

        AuthorizeCommand command = new AuthorizeCommand(responseType, clientId, redirectUri, scope, state, nonce,
                codeChallenge, codeChallengeMethod);
        IamUserPrincipal principal = IamUserPrincipal.current().orElse(null);
        UUID userId = principal == null ? null : principal.userId();

        AuthorizationOutcome outcome = oauth2Service.authorize(command, userId, authenticationTime(principal),
                RequestMetadata.from(httpRequest));

        return switch (outcome.kind()) {
            case REDIRECT -> redirectTo(outcome.redirectUri());
            // The login screen returns the browser here afterwards, so the request is
            // replayed with a session rather than being reconstructed from memory.
            case LOGIN_REQUIRED -> redirectTo(withParam(properties.getLoginUrl(), "return_to",
                    fullRequestUrl(httpRequest)));
            case CONSENT_REQUIRED -> redirectTo(withParam(properties.getConsentUrl(), "request_id",
                    outcome.requestId()));
        };
    }

    @GetMapping("/consent")
    @Operation(summary = "Describe a pending authorization request for the consent screen")
    public PendingAuthorization pendingConsent(@RequestParam("request_id") String requestId) {
        return oauth2Service.describePendingRequest(requestId, IamUserPrincipal.requireUserId());
    }

    @PostMapping("/consent")
    @Operation(summary = "Approve or deny a pending authorization request",
            description = "Either way the browser ends up back at the client, with a code or an error. "
                    + "A browser navigation gets a 302; a request that asks for JSON gets the destination "
                    + "in the body instead.")
    public ResponseEntity<?> decideConsent(@Valid @RequestBody ConsentDecisionRequest request,
            @RequestHeader(value = HttpHeaders.ACCEPT, required = false) String accept,
            HttpServletRequest httpRequest) {
        IamUserPrincipal principal = IamUserPrincipal.require();
        String redirect = oauth2Service.applyConsentDecision(request.requestId(), principal.userId(),
                request.approved(), authenticationTime(principal), RequestMetadata.from(httpRequest));

        // A script cannot use the 302. XMLHttpRequest and fetch follow redirects
        // themselves, so the hop to the client's redirect_uri is made as a
        // cross-origin request the client does not answer with CORS headers - the
        // call fails and the authorization code is burned in the process. A consent
        // screen that asks for JSON is told where to go and navigates there itself.
        if (wantsJson(accept)) {
            return ResponseEntity.ok(new ConsentDecisionResponse(redirect));
        }
        return redirectTo(redirect);
    }

    /**
     * True when the caller explicitly asked for JSON. A browser navigation sends
     * {@code text/html} first and keeps the redirect it has always had; only a
     * deliberate {@code Accept: application/json} opts into the body form.
     */
    private boolean wantsJson(String accept) {
        if (accept == null || accept.isBlank()) {
            return false;
        }
        return MediaType.parseMediaTypes(accept).stream()
                .anyMatch(MediaType.APPLICATION_JSON::equalsTypeAndSubtype);
    }

    /**
     * The token endpoint. Client authentication happens here rather than in a filter,
     * because the credentials may arrive either in the Basic header or in the form
     * body, and both must be treated identically.
     */
    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "Exchange an authorization code or refresh token for tokens")
    public ResponseEntity<TokenResponse> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam(required = false) String code,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "code_verifier", required = false) String codeVerifier,
            @RequestParam(name = "refresh_token", required = false) String refreshToken,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_secret", required = false) String clientSecret,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            HttpServletRequest httpRequest) {

        ClientApplication client = oauth2Service.authenticateClient(authorization, clientId, clientSecret);
        RequestMetadata metadata = RequestMetadata.from(httpRequest);

        TokenResponse response = switch (grantType) {
            case GRANT_AUTHORIZATION_CODE ->
                    oauth2Service.exchangeAuthorizationCode(client, require(code, "code"),
                            require(redirectUri, "redirect_uri"), codeVerifier, metadata);
            case GRANT_REFRESH_TOKEN ->
                    oauth2Service.exchangeRefreshToken(client, require(refreshToken, "refresh_token"), metadata);
            default -> throw new OAuth2Exception(OAuth2Exception.UNSUPPORTED_GRANT_TYPE,
                    "Unsupported grant_type", org.springframework.http.HttpStatus.BAD_REQUEST, false);
        };

        // Tokens must never be cached by an intermediary.
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(response);
    }

    @GetMapping("/userinfo")
    @Operation(summary = "OIDC claims about the user behind an access token")
    public UserInfoResponse userInfo(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return userInfoService.resolve(authorization);
    }

    @GetMapping("/jwks")
    @Operation(summary = "Public keys clients use to verify tokens issued here")
    public Map<String, Object> jwks() {
        return userInfoService.jwks();
    }

    @GetMapping("/consents")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Applications you have granted access to")
    public List<Map<String, Object>> consents() {
        return consentService.listForUser(IamUserPrincipal.requireUserId()).stream()
                .map(consent -> Map.<String, Object>of(
                        // The internal id, because it is what DELETE /consents/{id}
                        // takes. Without it this list is unactionable: resolving a
                        // client_id to its row needs CLIENT_READ, which the user
                        // whose consent it is has no reason to hold.
                        "clientApplicationId", consent.getClientApplication().getId(),
                        "clientId", consent.getClientApplication().getClientId(),
                        "clientName", consent.getClientApplication().getName(),
                        "scopes", consent.scopeSet(),
                        "grantedAt", consent.getGrantedAt()))
                .toList();
    }

    @DeleteMapping("/consents/{clientApplicationId}")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Withdraw consent from an application and sign it out")
    public MessageResponse revokeConsent(@PathVariable UUID clientApplicationId, HttpServletRequest httpRequest) {
        UUID userId = IamUserPrincipal.requireUserId();
        consentService.revoke(userId, clientApplicationId, RequestMetadata.from(httpRequest).ipAddress());
        // Withdrawing consent that leaves the application still holding live tokens
        // would not be a withdrawal, so its sessions go too.
        sessionService.revokeAll(userId, IamUserPrincipal.require().sessionId(), "consent_revoked");
        return new MessageResponse("Access withdrawn.");
    }

    private ResponseEntity<Void> redirectTo(String uri) {
        return ResponseEntity.status(302).header(HttpHeaders.LOCATION, uri).build();
    }

    private String require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw OAuth2Exception.direct(OAuth2Exception.INVALID_REQUEST, name + " is required");
        }
        return value;
    }

    /** auth_time for the ID token: when this browser session was actually established. */
    private Instant authenticationTime(IamUserPrincipal principal) {
        return principal == null ? null : sessionService.authenticationTime(principal.sessionId()).orElse(null);
    }

    private String fullRequestUrl(HttpServletRequest request) {
        String query = request.getQueryString();
        return query == null ? request.getRequestURL().toString()
                : request.getRequestURL().append('?').append(query).toString();
    }

    private String withParam(String url, String name, String value) {
        if (url == null || url.isBlank()) {
            throw ApiException.invalid("No hosted screen is configured for this step");
        }
        char separator = url.contains("?") ? '&' : '?';
        return url + separator + name + '=' + URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}

package io.github.hariomlokhande.iam.integration;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.hariomlokhande.iam.auth.dto.TokenResponse;
import io.github.hariomlokhande.iam.security.SsoCookieService;
import io.github.hariomlokhande.iam.support.IntegrationTestBase;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/** The authorization code flow with PKCE, consent, and the ways it must fail. */
class OAuth2FlowIT extends IntegrationTestBase {

    private static final String ADMIN_EMAIL = "admin@test.local";
    private static final String REDIRECT_URI = "http://localhost:3000/callback";
    private static final String VERIFIER = "verifier-0123456789abcdefghijklmnopqrstuvwxyz-._~ABC";

    private RestTemplate raw;
    private String clientId;
    private String userCookie;

    @BeforeEach
    void prepare() {
        raw = noRedirectClient();
        clientId = registerPublicClient();
        userCookie = signInBrowser();
    }

    @Test
    @DisplayName("authorize, consent, code exchange and an ID token, end to end")
    void authorizationCodeFlowWithConsent() throws Exception {
        ResponseEntity<String> authorize = get(authorizeUrl(challenge(VERIFIER), "state-1"), userCookie);

        assertThat(authorize.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String consentRedirect = location(authorize);
        assertThat(consentRedirect).contains("request_id=");
        String requestId = valueOf(consentRedirect, "request_id");

        ResponseEntity<Map> pending = get("/oauth2/consent?request_id=" + requestId, userCookie, Map.class);
        assertThat(pending.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(pending.getBody()).containsEntry("clientId", clientId);

        ResponseEntity<String> decision = postJson("/oauth2/consent",
                Map.of("requestId", requestId, "approved", true), userCookie);
        assertThat(decision.getStatusCode()).isEqualTo(HttpStatus.FOUND);

        String callback = location(decision);
        assertThat(callback).startsWith(REDIRECT_URI);
        assertThat(valueOf(callback, "state")).isEqualTo("state-1");
        String code = valueOf(callback, "code");

        ResponseEntity<TokenResponse> tokens = exchange(code, VERIFIER);
        assertThat(tokens.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(tokens.getBody().accessToken()).isNotBlank();
        assertThat(tokens.getBody().idToken()).isNotBlank();
        assertThat(tokens.getBody().refreshToken()).isNotBlank();

        // The token is addressed to the client, so it opens userinfo and not the
        // platform API.
        HttpHeaders bearer = new HttpHeaders();
        bearer.setBearerAuth(tokens.getBody().accessToken());
        ResponseEntity<Map> userInfo = raw.exchange(url("/oauth2/userinfo"), HttpMethod.GET,
                new HttpEntity<>(bearer), Map.class);
        assertThat(userInfo.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(userInfo.getBody()).containsKey("sub");

        ResponseEntity<Map> platformApi = raw.exchange(url("/users/me"), HttpMethod.GET,
                new HttpEntity<>(bearer), Map.class);
        assertThat(platformApi.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("an authorization code cannot be redeemed twice")
    void codeIsSingleUse() throws Exception {
        String code = approveAndExtractCode();

        assertThat(exchange(code, VERIFIER).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(exchangeRaw(code, VERIFIER).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("a code cannot be redeemed without the matching PKCE verifier")
    void pkceMismatchIsRejected() throws Exception {
        String code = approveAndExtractCode();

        ResponseEntity<String> response = exchangeRaw(code, "a-completely-different-verifier-value-0123456789");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).contains("invalid_grant");
    }

    @Test
    @DisplayName("a code cannot be redeemed against a different redirect URI")
    void redirectUriMustMatchAtTokenExchange() throws Exception {
        String code = approveAndExtractCode();

        MultiValueMap<String, String> form = tokenForm(code, VERIFIER);
        form.set("redirect_uri", "http://localhost:3000/other");
        ResponseEntity<String> response = raw.exchange(url("/oauth2/token"), HttpMethod.POST, formEntity(form),
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).contains("invalid_grant");
    }

    /**
     * An unregistered redirect URI is refused outright rather than being reported by
     * redirecting to it, which would turn this endpoint into an open redirect.
     */
    @Test
    @DisplayName("an unregistered redirect URI is refused without redirecting anywhere")
    void unregisteredRedirectUriIsRefusedDirectly() throws Exception {
        String url = "/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=https://evil.example.com/steal&scope=openid"
                + "&code_challenge=" + challenge(VERIFIER) + "&code_challenge_method=S256";

        ResponseEntity<String> response = get(url, userCookie);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).contains("invalid_request");
        assertThat(response.getHeaders().getLocation()).isNull();
    }

    @Test
    @DisplayName("a public client must supply a PKCE challenge")
    void pkceIsMandatoryForPublicClients() {
        String url = "/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + REDIRECT_URI + "&scope=openid&state=s";

        ResponseEntity<String> response = get(url, userCookie);

        // Reported to the client, since the redirect URI is registered and trusted.
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(location(response)).contains("error=invalid_request");
        assertThat(location(response)).contains("state=s");
    }

    @Test
    @DisplayName("a scope the client is not registered for is rejected")
    void unregisteredScopeIsRejected() throws Exception {
        String url = "/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + REDIRECT_URI + "&scope=openid%20admin:everything&state=s"
                + "&code_challenge=" + challenge(VERIFIER) + "&code_challenge_method=S256";

        ResponseEntity<String> response = get(url, userCookie);

        assertThat(location(response)).contains("error=invalid_scope");
    }

    @Test
    @DisplayName("an anonymous authorize request is sent to the login screen with a way back")
    void anonymousRequestGoesToLogin() throws Exception {
        ResponseEntity<String> response = get(authorizeUrl(challenge(VERIFIER), "state-1"), null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(location(response)).contains("/login").contains("return_to=");
    }

    @Test
    @DisplayName("denying consent redirects back with access_denied and no code")
    void denyingConsentReturnsAnError() throws Exception {
        ResponseEntity<String> authorize = get(authorizeUrl(challenge(VERIFIER), "state-9"), userCookie);
        String requestId = valueOf(location(authorize), "request_id");

        ResponseEntity<String> decision = postJson("/oauth2/consent",
                Map.of("requestId", requestId, "approved", false), userCookie);

        String callback = location(decision);
        assertThat(callback).startsWith(REDIRECT_URI);
        assertThat(callback).contains("error=access_denied");
        assertThat(callback).doesNotContain("code=");
        assertThat(valueOf(callback, "state")).isEqualTo("state-9");
    }

    @Test
    @DisplayName("the discovery document points at the JWKS endpoint, which serves public keys only")
    void discoveryAndJwks() {
        ResponseEntity<Map> discovery =
                raw.getForEntity(url("/.well-known/openid-configuration"), Map.class);
        assertThat(discovery.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(discovery.getBody()).containsKey("jwks_uri");
        assertThat(discovery.getBody().get("code_challenge_methods_supported")).isEqualTo(List.of("S256"));

        ResponseEntity<Map> jwks = raw.getForEntity(url("/oauth2/jwks"), Map.class);
        assertThat(jwks.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(jwks.getBody().toString()).doesNotContain("\"d\"");
    }

    private String approveAndExtractCode() throws Exception {
        ResponseEntity<String> authorize = get(authorizeUrl(challenge(VERIFIER), "state-1"), userCookie);
        String requestId = valueOf(location(authorize), "request_id");
        ResponseEntity<String> decision = postJson("/oauth2/consent",
                Map.of("requestId", requestId, "approved", true), userCookie);
        return valueOf(location(decision), "code");
    }

    private String registerPublicClient() {
        TokenResponse admin = login(ADMIN_EMAIL);
        Map<String, Object> body = Map.of(
                "name", "Integration test app",
                "clientType", "PUBLIC",
                "redirectUris", List.of(REDIRECT_URI),
                "scopes", List.of("openid", "profile"),
                "requireConsent", true);
        ResponseEntity<Map> response =
                authorized("/clients", HttpMethod.POST, admin.accessToken(), body, Map.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return (String) ((Map<?, ?>) response.getBody().get("client")).get("clientId");
    }

    /** Signs a normal user in and keeps the SSO cookie the browser would keep. */
    private String signInBrowser() {
        String email = uniqueEmail("oauth-user");
        registerAndVerify(email);

        ResponseEntity<TokenResponse> response = rest.postForEntity("/auth/login",
                json(Map.of("email", email, "password", PASSWORD)), TokenResponse.class);
        List<String> cookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
        assertThat(cookies).isNotNull();
        return cookies.stream()
                .filter(cookie -> cookie.startsWith(SsoCookieService.COOKIE_NAME + "="))
                .map(cookie -> cookie.substring(0, cookie.indexOf(';')))
                .findFirst()
                .orElseThrow(() -> new AssertionError("login did not set an SSO cookie"));
    }

    private String authorizeUrl(String codeChallenge, String state) {
        return "/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + REDIRECT_URI
                + "&scope=openid&state=" + state
                + "&code_challenge=" + codeChallenge + "&code_challenge_method=S256";
    }

    private ResponseEntity<TokenResponse> exchange(String code, String verifier) {
        return raw.exchange(url("/oauth2/token"), HttpMethod.POST, formEntity(tokenForm(code, verifier)),
                TokenResponse.class);
    }

    private ResponseEntity<String> exchangeRaw(String code, String verifier) {
        return raw.exchange(url("/oauth2/token"), HttpMethod.POST, formEntity(tokenForm(code, verifier)),
                String.class);
    }

    private MultiValueMap<String, String> tokenForm(String code, String verifier) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", REDIRECT_URI);
        form.add("code_verifier", verifier);
        form.add("client_id", clientId);
        return form;
    }

    private HttpEntity<MultiValueMap<String, String>> formEntity(MultiValueMap<String, String> form) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return new HttpEntity<>(form, headers);
    }

    private ResponseEntity<String> get(String path, String cookie) {
        return get(path, cookie, String.class);
    }

    private <T> ResponseEntity<T> get(String path, String cookie, Class<T> type) {
        HttpHeaders headers = new HttpHeaders();
        if (cookie != null) {
            headers.add(HttpHeaders.COOKIE, cookie);
        }
        return raw.exchange(url(path), HttpMethod.GET, new HttpEntity<>(headers), type);
    }

    private ResponseEntity<String> postJson(String path, Object body, String cookie) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add(HttpHeaders.COOKIE, cookie);
        return raw.exchange(url(path), HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private String location(ResponseEntity<?> response) {
        URI location = response.getHeaders().getLocation();
        assertThat(location).withFailMessage("expected a redirect, got %s", response.getStatusCode()).isNotNull();
        return location.toString();
    }

    private String valueOf(String url, String parameter) {
        for (String pair : url.substring(url.indexOf('?') + 1).split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts[0].equals(parameter)) {
                return java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("no " + parameter + " in " + url);
    }

    private String challenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    /**
     * Redirects must be inspected, not followed: the assertions are about where the
     * platform sends the browser and with which parameters.
     */
    private RestTemplate noRedirectClient() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String method) throws IOException {
                super.prepareConnection(connection, method);
                connection.setInstanceFollowRedirects(false);
            }
        };
        RestTemplate template = new RestTemplate(factory);
        template.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(org.springframework.http.client.ClientHttpResponse response) {
                return false;
            }
        });
        return template;
    }
}

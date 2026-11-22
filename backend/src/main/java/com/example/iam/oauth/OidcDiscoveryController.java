package com.example.iam.oauth;

import com.example.iam.config.IamProperties;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The OIDC discovery document.
 *
 * <p>Publishing it is what lets a consuming application be configured with one value -
 * the issuer - and find the rest, including the JWKS endpoint. That in turn is what
 * makes key rotation invisible to clients: they refetch the keys rather than having
 * one pinned in their configuration.
 */
@RestController
@Tag(name = "OAuth2 and OpenID Connect")
public class OidcDiscoveryController {

    private final IamProperties properties;

    public OidcDiscoveryController(IamProperties properties) {
        this.properties = properties;
    }

    @GetMapping("/.well-known/openid-configuration")
    @Operation(summary = "OpenID Connect discovery document")
    public Map<String, Object> configuration() {
        String issuer = properties.getIssuer();
        Map<String, Object> document = new LinkedHashMap<>();

        document.put("issuer", issuer);
        document.put("authorization_endpoint", issuer + "/oauth2/authorize");
        document.put("token_endpoint", issuer + "/oauth2/token");
        document.put("userinfo_endpoint", issuer + "/oauth2/userinfo");
        document.put("jwks_uri", issuer + "/oauth2/jwks");

        document.put("response_types_supported", List.of("code"));
        document.put("grant_types_supported", List.of("authorization_code", "refresh_token"));
        document.put("subject_types_supported", List.of("public"));
        document.put("id_token_signing_alg_values_supported", List.of("RS256"));
        document.put("token_endpoint_auth_methods_supported",
                List.of("client_secret_basic", "client_secret_post", "none"));
        // Advertised so public clients know PKCE is available, and S256 only - "plain"
        // offers no protection and is deliberately unsupported.
        document.put("code_challenge_methods_supported", List.of("S256"));
        document.put("scopes_supported", List.of("openid", "profile", "email"));
        document.put("claims_supported", List.of("sub", "iss", "aud", "exp", "iat", "email", "email_verified"));

        return document;
    }
}

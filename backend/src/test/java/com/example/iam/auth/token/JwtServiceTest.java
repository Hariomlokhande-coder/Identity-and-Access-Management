
package com.example.iam.auth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.iam.config.IamProperties;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import com.example.iam.support.TestProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JwtServiceTest {

    private IamProperties properties;
    private SigningKeyStore keyStore;
    private JwtService jwtService;

    private final UUID userId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        properties = TestProperties.create();
        keyStore = new SigningKeyStore(properties, new ObjectMapper());
        jwtService = new JwtService(keyStore, properties);
    }

    @Test
    @DisplayName("issues a token whose claims survive a round trip")
    void issuesAndParsesAccessToken() {
        String token = jwtService.issueAccessToken(request(Duration.ofMinutes(10)));

        AccessTokenClaims claims = jwtService.parseAccessToken(token);

        assertThat(claims.userId()).isEqualTo(userId);
        assertThat(claims.sessionId()).isEqualTo(sessionId);
        assertThat(claims.audience()).isEqualTo(JwtService.PLATFORM_AUDIENCE);
        assertThat(claims.roles()).containsExactly("ADMIN");
        assertThat(claims.permissions()).containsExactly("USER_READ");
        assertThat(claims.scopes()).containsExactly("openid");
        assertThat(claims.permissionVersion()).isEqualTo(7);
        assertThat(claims.tokenId()).isNotBlank();
    }

    @Test
    @DisplayName("rejects a token whose signature was tampered with")
    void rejectsTamperedSignature() {
        String token = jwtService.issueAccessToken(request(Duration.ofMinutes(10)));
        String tampered = token.substring(0, token.lastIndexOf('.') + 1) + "AAAA";

        assertThatThrownBy(() -> jwtService.parseAccessToken(tampered))
                .isInstanceOf(ApiException.class)
                .extracting(e -> ((ApiException) e).code())
                .isEqualTo(ErrorCode.INVALID_TOKEN);
    }

    @Test
    @DisplayName("rejects an expired token even with clock skew applied")
    void rejectsExpiredToken() {
        String token = jwtService.issueAccessToken(request(Duration.ofSeconds(-120)));

        assertThatThrownBy(() -> jwtService.parseAccessToken(token))
                .isInstanceOf(ApiException.class)
                .extracting(e -> ((ApiException) e).code())
                .isEqualTo(ErrorCode.TOKEN_EXPIRED);
    }

    @Test
    @DisplayName("accepts a token that expired within the clock skew allowance")
    void toleratesSmallClockSkew() {
        String token = jwtService.issueAccessToken(request(Duration.ofSeconds(-5)));

        assertThat(jwtService.parseAccessToken(token).userId()).isEqualTo(userId);
    }

    @Test
    @DisplayName("rejects a token issued by a different issuer")
    void rejectsForeignIssuer() {
        String token = jwtService.issueAccessToken(request(Duration.ofMinutes(10)));
        properties.setIssuer("https://impostor.example.com");

        assertThatThrownBy(() -> jwtService.parseAccessToken(token))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("different issuer");
    }

    /**
     * The algorithm confusion attack: an attacker re-signs a token with HMAC using the
     * RSA public key as the shared secret, hoping the verifier trusts the alg header.
     * Pinning RS256 means the token is refused before any key is even selected.
     */
    @Test
    @DisplayName("rejects an HMAC-signed token that claims the same key id")
    void rejectsAlgorithmConfusion() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(TestProperties.ISSUER)
                .subject(userId.toString())
                .audience(JwtService.PLATFORM_AUDIENCE)
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .claim("token_use", "access")
                .claim("sid", sessionId.toString())
                .claim("pv", 1)
                .build();

        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256)
                        .keyID(keyStore.activeKey().getKeyID())
                        .build(),
                claims);

        forged.sign(new MACSigner(
                "a-secret-long-enough-for-hmac-sha256-signing".getBytes()));

        assertThatThrownBy(() -> jwtService.parseAccessToken(forged.serialize()))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("Unsupported token signature algorithm");
    }

    @Test
    @DisplayName("rejects a token signed with an unknown key id")
    void rejectsUnknownKeyId() {
        String token = jwtService.issueAccessToken(request(Duration.ofMinutes(10)));
        SigningKeyStore otherKeys =
                new SigningKeyStore(TestProperties.create(), new ObjectMapper());
        JwtService otherService = new JwtService(otherKeys, properties);

        assertThatThrownBy(() -> otherService.parseAccessToken(token))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("Unknown token signing key");
    }

    @Test
    @DisplayName("refuses to treat an ID token as an access token")
    void rejectsIdTokenAtTheApi() {
        String idToken = jwtService.issueIdToken(
                userId,
                "shop",
                "user@example.com",
                true,
                "nonce-1",
                Instant.now(),
                Duration.ofMinutes(10));

        assertThatThrownBy(() -> jwtService.parseAccessToken(idToken))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("cannot be used for this purpose");
    }

    @Test
    @DisplayName("fails fast when no signing key is configured and ephemeral keys are not allowed")
    void requiresAConfiguredKeyInProduction() {
        IamProperties strict = TestProperties.create();
        strict.getJwt().setAllowEphemeralKey(false);

        assertThatThrownBy(() -> new SigningKeyStore(strict, new ObjectMapper()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No JWT signing key configured");
    }

    private AccessTokenRequest request(Duration ttl) {
        return new AccessTokenRequest(
                userId,
                sessionId,
                JwtService.PLATFORM_AUDIENCE,
                Set.of("ADMIN"),
                Set.of("USER_READ"),
                Set.of("openid"),
                7,
                ttl);
    }
}

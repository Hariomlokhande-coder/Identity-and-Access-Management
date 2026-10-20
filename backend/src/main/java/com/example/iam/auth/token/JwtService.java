
package com.example.iam.auth.token;

import com.example.iam.config.IamProperties;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    public static final String PLATFORM_AUDIENCE = "iam";

    private static final JWSAlgorithm ALGORITHM = JWSAlgorithm.RS256;
    private static final String CLAIM_SESSION_ID = "sid";
    private static final String CLAIM_PERMISSION_VERSION = "pv";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMISSIONS = "perms";
    private static final String CLAIM_SCOPE = "scope";
    private static final String CLAIM_TOKEN_USE = "token_use";
    private static final String TOKEN_USE_ACCESS = "access";
    private static final String TOKEN_USE_ID = "id";

    private final SigningKeyStore keyStore;
    private final IamProperties properties;

    public JwtService(SigningKeyStore keyStore, IamProperties properties) {
        this.keyStore = keyStore;
        this.properties = properties;
    }

    public String issueAccessToken(AccessTokenRequest request) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .subject(request.userId().toString())
                .audience(request.audience())
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plus(request.ttl())))
                .jwtID(UUID.randomUUID().toString())
                .claim(CLAIM_TOKEN_USE, TOKEN_USE_ACCESS)
                .claim(CLAIM_SESSION_ID, request.sessionId().toString())
                .claim(CLAIM_PERMISSION_VERSION, request.permissionVersion())
                .claim(CLAIM_ROLES, List.copyOf(request.roles()))
                .claim(CLAIM_PERMISSIONS, List.copyOf(request.permissions()))
                .claim(CLAIM_SCOPE, String.join(" ", request.scopes()))
                .build();
        return sign(claims);
    }

    public String issueIdToken(UUID userId, String clientId, String email,
                               boolean emailVerified, String nonce, Instant authTime, Duration ttl) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .subject(userId.toString())
                .audience(clientId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ttl)))
                .jwtID(UUID.randomUUID().toString())
                .claim(CLAIM_TOKEN_USE, TOKEN_USE_ID)
                .claim("auth_time", authTime.getEpochSecond())
                .claim("email", email)
                .claim("email_verified", emailVerified);

        if (nonce != null) {
            builder.claim("nonce", nonce);
        }
        return sign(builder.build());
    }

    public AccessTokenClaims parseAccessToken(String token) {
        SignedJWT jwt = parseAndVerifySignature(token);
        JWTClaimsSet claims = claimsOf(jwt);

        requireIssuer(claims);
        requireTokenUse(claims, TOKEN_USE_ACCESS);
        requireWithinValidity(claims);

        try {
            return new AccessTokenClaims(
                    UUID.fromString(claims.getSubject()),
                    UUID.fromString(claims.getStringClaim(CLAIM_SESSION_ID)),
                    claims.getAudience().isEmpty() ? null : claims.getAudience().get(0),
                    toSet(claims.getStringListClaim(CLAIM_ROLES)),
                    toSet(claims.getStringListClaim(CLAIM_PERMISSIONS)),
                    splitScopes(claims.getStringClaim(CLAIM_SCOPE)),
                    claims.getIntegerClaim(CLAIM_PERMISSION_VERSION),
                    claims.getJWTID(),
                    claims.getIssueTime().toInstant(),
                    claims.getExpirationTime().toInstant());
        } catch (ParseException | IllegalArgumentException | NullPointerException e) {
            throw new ApiException(ErrorCode.INVALID_TOKEN, "The token is missing required claims");
        }
    }

    private String sign(JWTClaimsSet claims) {
        RSAKey key = keyStore.activeKey();
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(ALGORITHM)
                            .keyID(key.getKeyID())
                            .type(JOSEObjectType.JWT)
                            .build(),
                    claims);
            jwt.sign(new RSASSASigner(key.toRSAPrivateKey()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign token with key " + key.getKeyID(), e);
        }
    }

    private SignedJWT parseAndVerifySignature(String token) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new ApiException(ErrorCode.INVALID_TOKEN, "The token is malformed");
        }

        if (!ALGORITHM.equals(jwt.getHeader().getAlgorithm())) {
            log.warn("Rejected token signed with unexpected algorithm {}",
                    jwt.getHeader().getAlgorithm());
            throw new ApiException(ErrorCode.INVALID_TOKEN,
                    "Unsupported token signature algorithm");
        }

        RSAKey key = keyStore.verificationKey(jwt.getHeader().getKeyID())
                .orElseThrow(() -> new ApiException(
                        ErrorCode.INVALID_TOKEN, "Unknown token signing key"));

        try {
            if (!jwt.verify(new RSASSAVerifier(key.toRSAPublicKey()))) {
                throw new ApiException(ErrorCode.INVALID_TOKEN,
                        "The token signature is invalid");
            }
        } catch (JOSEException e) {
            throw new ApiException(ErrorCode.INVALID_TOKEN,
                    "The token signature could not be verified");
        }
        return jwt;
    }

    private JWTClaimsSet claimsOf(SignedJWT jwt) {
        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new ApiException(ErrorCode.INVALID_TOKEN,
                    "The token claims are malformed");
        }
    }

    private void requireIssuer(JWTClaimsSet claims) {
        if (!properties.getIssuer().equals(claims.getIssuer())) {
            throw new ApiException(ErrorCode.INVALID_TOKEN,
                    "The token was issued by a different issuer");
        }
    }

    private void requireTokenUse(JWTClaimsSet claims, String expected) {
        try {
            if (!expected.equals(claims.getStringClaim(CLAIM_TOKEN_USE))) {
                throw new ApiException(ErrorCode.INVALID_TOKEN,
                        "The token cannot be used for this purpose");
            }
        } catch (ParseException e) {
            throw new ApiException(ErrorCode.INVALID_TOKEN,
                    "The token cannot be used for this purpose");
        }
    }

    private void requireWithinValidity(JWTClaimsSet claims) {
        Duration skew = properties.getJwt().getClockSkew();
        Instant now = Instant.now();
        Date expiry = claims.getExpirationTime();
        Date notBefore = claims.getNotBeforeTime();

        if (expiry == null || expiry.toInstant().plus(skew).isBefore(now)) {
            throw new ApiException(ErrorCode.TOKEN_EXPIRED,
                    ErrorCode.TOKEN_EXPIRED.defaultMessage());
        }
        if (notBefore != null && notBefore.toInstant().minus(skew).isAfter(now)) {
            throw new ApiException(ErrorCode.INVALID_TOKEN, "The token is not valid yet");
        }
    }

    private Set<String> toSet(List<String> values) {
        return values == null ? Set.of() : new LinkedHashSet<>(values);
    }

    private Set<String> splitScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return Set.of();
        }
        return new LinkedHashSet<>(List.of(scope.trim().split("\\s+")));
    }
}

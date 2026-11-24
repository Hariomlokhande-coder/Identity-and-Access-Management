package io.github.hariomlokhande.iam.oauth;

import io.github.hariomlokhande.iam.auth.token.AccessTokenClaims;
import io.github.hariomlokhande.iam.auth.token.JwtService;
import io.github.hariomlokhande.iam.auth.token.SigningKeyStore;
import io.github.hariomlokhande.iam.auth.token.TokenRevocationStore;
import io.github.hariomlokhande.iam.client.ClientApplication;
import io.github.hariomlokhande.iam.client.ClientApplicationRepository;
import io.github.hariomlokhande.iam.user.User;
import io.github.hariomlokhande.iam.user.UserRepository;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Serves the userinfo and JWKS endpoints.
 *
 * <p>Userinfo verifies the bearer token itself instead of relying on the platform
 * authentication filter, because the tokens it accepts are addressed to a client
 * application rather than to this platform. The filter rejects those on purpose - a
 * client token must not reach the management API - so this endpoint does its own
 * audience check: the token must name a client that is registered and still active.
 */
@Service
public class UserInfoService {

    private static final String SCOPE_OPENID = "openid";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final TokenRevocationStore revocationStore;
    private final ClientApplicationRepository clients;
    private final UserRepository users;
    private final SigningKeyStore keyStore;

    public UserInfoService(JwtService jwtService, TokenRevocationStore revocationStore,
            ClientApplicationRepository clients, UserRepository users, SigningKeyStore keyStore) {
        this.jwtService = jwtService;
        this.revocationStore = revocationStore;
        this.clients = clients;
        this.users = users;
        this.keyStore = keyStore;
    }

    @Transactional(readOnly = true)
    public UserInfoResponse resolve(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            throw OAuth2Exception.invalidGrant("A bearer access token is required");
        }
        AccessTokenClaims claims =
                jwtService.parseAccessToken(authorizationHeader.substring(BEARER_PREFIX.length()).trim());

        if (!claims.hasScope(SCOPE_OPENID)) {
            throw OAuth2Exception.invalidGrant("The token does not carry the openid scope");
        }
        clients.findByClientId(claims.audience())
                .filter(ClientApplication::isActive)
                .orElseThrow(() -> OAuth2Exception.invalidGrant("The token audience is not a known client"));
        if (revocationStore.isRevoked(claims)) {
            throw OAuth2Exception.invalidGrant("The token has been revoked");
        }

        User user = users.findById(claims.userId())
                .filter(candidate -> candidate.getDeletedAt() == null)
                .orElseThrow(() -> OAuth2Exception.invalidGrant("The account no longer exists"));
        return new UserInfoResponse(user.getId().toString(), user.getEmail(), user.isEmailVerified());
    }

    /** Public keys only. The private halves never leave the signing key store. */
    public Map<String, Object> jwks() {
        return keyStore.jwks();
    }
}

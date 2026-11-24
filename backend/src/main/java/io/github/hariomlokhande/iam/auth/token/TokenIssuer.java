package io.github.hariomlokhande.iam.auth.token;

import io.github.hariomlokhande.iam.auth.dto.TokenResponse;
import io.github.hariomlokhande.iam.client.ClientApplication;
import io.github.hariomlokhande.iam.config.IamProperties;
import io.github.hariomlokhande.iam.security.AuthorityResolver;
import io.github.hariomlokhande.iam.security.AuthorityResolver.ResolvedAuthorities;
import io.github.hariomlokhande.iam.session.UserSession;
import io.github.hariomlokhande.iam.user.User;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Assembles the token triple handed back by every sign-in path.
 *
 * <p>Centralising it is what keeps the direct login, the authorization-code exchange
 * and the refresh rotation from drifting apart: all three mint tokens with the same
 * audience rules, the same per-client lifetimes and the same authority scoping.
 */
@Service
public class TokenIssuer {

    private static final String SCOPE_OPENID = "openid";

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthorityResolver authorityResolver;
    private final IamProperties properties;

    public TokenIssuer(JwtService jwtService, RefreshTokenService refreshTokenService,
            AuthorityResolver authorityResolver, IamProperties properties) {
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.authorityResolver = authorityResolver;
        this.properties = properties;
    }

    /**
     * Issues the first token pair of a session.
     *
     * @param authTime when the user actually proved their identity, which for the
     *                 authorization-code flow predates this session; null means now
     */
    @Transactional
    public TokenResponse issueForNewSession(User user, UserSession session, ClientApplication client,
            String nonce, Instant authTime) {
        String refreshToken = refreshTokenService
                .issueForNewSession(user, session, client, refreshTtl(client))
                .rawToken();
        return build(user, session, client, nonce, authTime, refreshToken);
    }

    /** Issues the token pair that follows a refresh-token rotation. */
    @Transactional
    public TokenResponse issueForRotation(RefreshTokenService.RotationResult rotation) {
        return build(rotation.user(), rotation.session(), rotation.client(), null, null, rotation.rawToken());
    }

    public Duration refreshTtl(ClientApplication client) {
        Duration platformDefault = properties.getToken().getRefreshTokenTtl();
        return client == null ? platformDefault : client.refreshTokenTtlOr(platformDefault);
    }

    private TokenResponse build(User user, UserSession session, ClientApplication client, String nonce,
            Instant authTime, String refreshToken) {
        // Scopes come from the session, never from the request being served, so a
        // refresh cannot widen the grant the user originally approved.
        Set<String> scopes = session.scopeSet();
        String audience = audienceFor(client);
        Duration accessTtl = accessTtl(client);
        ResolvedAuthorities authorities = authorityResolver.resolve(user, audience);

        String accessToken = jwtService.issueAccessToken(new AccessTokenRequest(
                user.getId(), session.getId(), audience, authorities.roles(), authorities.permissions(),
                scopes, user.getPermissionVersion(), accessTtl));

        // An ID token is only meaningful to an OAuth2 client that asked for openid; the
        // platform's own login has no third party to describe the user to.
        String idToken = null;
        if (client != null && scopes.contains(SCOPE_OPENID)) {
            idToken = jwtService.issueIdToken(user.getId(), client.getClientId(), user.getEmail(),
                    user.isEmailVerified(), nonce, authTime == null ? session.getCreatedAt() : authTime, accessTtl);
        }

        return new TokenResponse(accessToken, TokenResponse.BEARER, accessTtl.toSeconds(), refreshToken, idToken,
                String.join(" ", scopes), session.getId());
    }

    /**
     * Tokens for a client application are addressed to that client. Tokens from the
     * direct login are addressed to the platform itself, so they can be used against
     * this API and nowhere else.
     */
    private String audienceFor(ClientApplication client) {
        return client == null ? JwtService.PLATFORM_AUDIENCE : client.getClientId();
    }

    private Duration accessTtl(ClientApplication client) {
        Duration platformDefault = properties.getJwt().getAccessTokenTtl();
        return client == null ? platformDefault : client.accessTokenTtlOr(platformDefault);
    }
}

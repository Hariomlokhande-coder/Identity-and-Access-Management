package io.github.hariomlokhande.iam.security;

import io.github.hariomlokhande.iam.auth.token.AccessTokenClaims;
import io.github.hariomlokhande.iam.auth.token.JwtService;
import io.github.hariomlokhande.iam.auth.token.TokenRevocationStore;
import io.github.hariomlokhande.iam.config.IamProperties;
import io.github.hariomlokhande.iam.config.IamProperties.Security.PermissionCheckMode;
import io.github.hariomlokhande.iam.exception.ApiException;
import io.github.hariomlokhande.iam.exception.ErrorCode;
import io.github.hariomlokhande.iam.security.AuthorityResolver.ResolvedAuthorities;
import io.github.hariomlokhande.iam.security.IamUserPrincipal.AuthenticationSource;
import io.github.hariomlokhande.iam.user.User;
import io.github.hariomlokhande.iam.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Set;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Authenticates API calls from the {@code Authorization: Bearer} header.
 *
 * <p>Four checks stand between a token and a populated security context: the
 * signature and claims must verify, the audience must be this platform, no
 * revocation marker may apply, and the account must still be usable. Only then are
 * authorities attached.
 *
 * <p>An invalid token is not the same as an absent one. Absent means anonymous and
 * the request continues, so public endpoints keep working; invalid means the caller
 * presented a credential that failed, and that is answered immediately.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String HEADER = "Authorization";
    private static final String PREFIX = "Bearer ";

    /**
     * Endpoints that do their own credential handling. The token endpoint authenticates
     * a client, not a user, and userinfo accepts tokens addressed to a client
     * application - both of which this filter would reject.
     */
    private static final Set<String> SELF_AUTHENTICATING_PATHS = Set.of("/oauth2/token", "/oauth2/userinfo");

    private final JwtService jwtService;
    private final TokenRevocationStore revocationStore;
    private final AuthorityResolver authorityResolver;
    private final UserRepository userRepository;
    private final IamProperties properties;
    private final HandlerExceptionResolver exceptionResolver;

    public JwtAuthenticationFilter(JwtService jwtService, TokenRevocationStore revocationStore,
            AuthorityResolver authorityResolver, UserRepository userRepository, IamProperties properties,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) {
        this.jwtService = jwtService;
        this.revocationStore = revocationStore;
        this.authorityResolver = authorityResolver;
        this.userRepository = userRepository;
        this.properties = properties;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return SELF_AUTHENTICATING_PATHS.contains(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String token = bearerToken(request);
        if (token == null || SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }

        try {
            authenticate(token);
        } catch (ApiException e) {
            // Routed through the standard resolver so a filter-stage rejection produces
            // exactly the same error body as a controller-stage one.
            SecurityContextHolder.clearContext();
            exceptionResolver.resolveException(request, response, null, e);
            return;
        }
        chain.doFilter(request, response);
    }

    private void authenticate(String token) {
        AccessTokenClaims claims = jwtService.parseAccessToken(token);
        requirePlatformAudience(claims);

        if (revocationStore.isRevoked(claims)) {
            throw new ApiException(ErrorCode.INVALID_TOKEN, "The token has been revoked");
        }

        Collection<GrantedAuthority> authorities =
                properties.getSecurity().getPermissionCheckMode() == PermissionCheckMode.LIVE
                        ? liveAuthorities(claims)
                        : ResolvedAuthorities.toGrantedAuthorities(claims.roles(), claims.permissions());

        IamUserPrincipal principal = new IamUserPrincipal(claims.userId(), claims.sessionId(), claims.audience(),
                claims.scopes(), claims.tokenId(), claims.expiresAt(), AuthenticationSource.ACCESS_TOKEN);
        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(principal, null, authorities));
    }

    /**
     * A token minted for a client application is not a credential for this platform's
     * own API, even though the same key signed it.
     */
    private void requirePlatformAudience(AccessTokenClaims claims) {
        if (!JwtService.PLATFORM_AUDIENCE.equals(claims.audience())) {
            throw new ApiException(ErrorCode.INVALID_TOKEN, "The token was not issued for this API");
        }
    }

    /**
     * LIVE mode: authorities and account state are re-read per request, so a revoked
     * permission takes effect on the very next call at the cost of one query. The
     * repository method fetches roles and permissions in that single query, so no
     * transaction is needed here.
     */
    private Collection<GrantedAuthority> liveAuthorities(AccessTokenClaims claims) {
        User user = userRepository.findWithRolesById(claims.userId())
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_TOKEN, "The account no longer exists"));
        if (!user.isActive() || user.isCurrentlyLocked()) {
            throw new ApiException(ErrorCode.ACCOUNT_DISABLED, ErrorCode.ACCOUNT_DISABLED.defaultMessage());
        }
        if (user.getPermissionVersion() != claims.permissionVersion()) {
            throw new ApiException(ErrorCode.INVALID_TOKEN, "The token is stale, obtain a new one");
        }
        return authorityResolver.resolve(user, claims.audience()).toGrantedAuthorities();
    }

    private String bearerToken(HttpServletRequest request) {
        String header = request.getHeader(HEADER);
        if (header == null || !header.startsWith(PREFIX)) {
            return null;
        }
        String token = header.substring(PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }
}

package io.github.hariomlokhande.iam.security;

import io.github.hariomlokhande.iam.security.IamUserPrincipal.AuthenticationSource;
import io.github.hariomlokhande.iam.session.SessionService;
import io.github.hariomlokhande.iam.session.UserSession;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates the browser SSO cookie, and only where a browser is actually driving
 * the flow: the authorize and consent endpoints.
 *
 * <p>Restricting it to those paths is what keeps the cookie from being usable as an
 * API credential. If it authenticated the whole API, every state-changing endpoint
 * would become CSRF-reachable from any page the user visits; a bearer token cannot be
 * attached by a third-party site, a cookie can.
 *
 * <p>The resulting principal carries no authorities. These endpoints only need to
 * know which user is present; what that user may do is decided when the token is
 * minted, from their roles for the requesting client.
 */
@Component
public class SsoSessionAuthenticationFilter extends OncePerRequestFilter {

    private static final List<String> COOKIE_AUTHENTICATED_PATHS =
            List.of("/oauth2/authorize", "/oauth2/consent");

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final SsoCookieService cookieService;
    private final SessionService sessionService;

    public SsoSessionAuthenticationFilter(SsoCookieService cookieService, SessionService sessionService) {
        this.cookieService = cookieService;
        this.sessionService = sessionService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return COOKIE_AUTHENTICATED_PATHS.stream().noneMatch(pattern -> pathMatcher.match(pattern, path));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            Optional<String> rawToken = cookieService.read(request);
            // An unknown or revoked cookie simply leaves the request anonymous: the
            // authorize endpoint answers that by redirecting to the login screen.
            rawToken.flatMap(sessionService::resolveSsoSession).ifPresent(this::authenticate);
        }
        chain.doFilter(request, response);
    }

    private void authenticate(UserSession session) {
        IamUserPrincipal principal = new IamUserPrincipal(session.getUser().getId(), session.getId(), null,
                Set.of(), null, null, AuthenticationSource.SSO_COOKIE);
        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(principal, null, List.of()));
    }
}

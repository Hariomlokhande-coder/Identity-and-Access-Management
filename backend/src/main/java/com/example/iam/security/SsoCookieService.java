package com.example.iam.security;

import com.example.iam.config.IamProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * Issues and clears the browser SSO cookie used by the OAuth2 authorize endpoint.
 *
 * <p>The cookie holds only a random secret; the server stores its hash against a
 * session row. HttpOnly keeps it out of reach of scripts, Secure keeps it off plain
 * HTTP, and SameSite=Lax still allows the top-level redirect an authorize request
 * performs while blocking cross-site form posts.
 */
@Component
public class SsoCookieService {

    public static final String COOKIE_NAME = "iam_sso";
    private static final String PATH = "/";

    private final IamProperties properties;

    public SsoCookieService(IamProperties properties) {
        this.properties = properties;
    }

    public void write(HttpServletResponse response, String rawToken) {
        Duration ttl = properties.getToken().getSsoSessionTtl();
        response.addHeader(HttpHeaders.SET_COOKIE, build(rawToken, ttl).toString());
    }

    /** Overwrites the cookie with an already-expired one, which removes it. */
    public void clear(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, build("", Duration.ZERO).toString());
    }

    public Optional<String> read(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        return Arrays.stream(cookies)
                .filter(cookie -> COOKIE_NAME.equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(value -> value != null && !value.isBlank())
                .findFirst();
    }

    private ResponseCookie build(String value, Duration maxAge) {
        IamProperties.Cookie config = properties.getCookie();
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(COOKIE_NAME, value)
                .httpOnly(true)
                .secure(config.isSecure())
                .path(PATH)
                .maxAge(maxAge)
                .sameSite(config.getSameSite());
        if (config.getDomain() != null && !config.getDomain().isBlank()) {
            builder.domain(config.getDomain());
        }
        return builder.build();
    }
}

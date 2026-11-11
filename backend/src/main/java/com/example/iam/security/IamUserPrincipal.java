package com.example.iam.security;

import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import java.security.Principal;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The authenticated caller.
 *
 * <p>It deliberately carries no mutable user state: everything here comes from a
 * verified token or an active session record, and anything else (profile, status,
 * roles for display) is loaded from the database when it is actually needed.
 */
public record IamUserPrincipal(
        UUID userId,
        UUID sessionId,
        String audience,
        Set<String> scopes,
        /** Id and expiry of the presented access token, so logout can blacklist it. */
        String tokenId,
        Instant tokenExpiresAt,
        AuthenticationSource source) implements Principal {

    public enum AuthenticationSource {
        /** Bearer access token on an API call. */
        ACCESS_TOKEN,
        /** Browser SSO cookie, accepted only by the authorize and consent endpoints. */
        SSO_COOKIE
    }

    @Override
    public String getName() {
        return userId.toString();
    }

    public static Optional<IamUserPrincipal> current() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof IamUserPrincipal principal)) {
            return Optional.empty();
        }
        return Optional.of(principal);
    }

    /** For endpoints that are only reachable when authenticated. */
    public static IamUserPrincipal require() {
        return current().orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED,
                ErrorCode.UNAUTHENTICATED.defaultMessage()));
    }

    public static UUID requireUserId() {
        return require().userId();
    }
}

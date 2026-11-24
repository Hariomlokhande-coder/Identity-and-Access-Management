package io.github.hariomlokhande.iam.oauth;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The OIDC userinfo claims.
 *
 * <p>Only identity is returned. Roles and permissions belong to the access token for
 * a specific audience; publishing them here would hand one application a view of what
 * the user may do everywhere else.
 */
public record UserInfoResponse(
        String sub,
        String email,
        @JsonProperty("email_verified") boolean emailVerified) {
}

package com.iamplatform.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * First-party sign-in.
 *
 * <p>There is deliberately no client_id here. A third-party application must use the
 * authorization code flow, where the password is typed into this platform and never
 * reaches the application; letting one pass credentials straight to this endpoint
 * would give away the entire benefit of central identity.
 */
public record LoginRequest(
        @NotBlank @Email @Size(max = 320) String email,
        @NotBlank @Size(max = 200) String password) {
}

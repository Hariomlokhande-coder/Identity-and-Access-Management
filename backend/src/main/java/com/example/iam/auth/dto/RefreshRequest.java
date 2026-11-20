package com.example.iam.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Rotation of a first-party refresh token.
 *
 * <p>Tokens issued to a registered application are refreshed at /oauth2/token instead,
 * which authenticates the client as well as the token.
 */
public record RefreshRequest(@NotBlank @Size(max = 200) String refreshToken) {
}

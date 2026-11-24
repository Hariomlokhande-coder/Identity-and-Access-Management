package com.iamplatform.oauth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * The consent screen sends only an identifier and a decision. Scopes, redirect URI
 * and PKCE challenge are read from the parked request on the server, so a modified
 * form cannot approve something the user was never shown.
 */
public record ConsentDecisionRequest(
        @NotBlank @Size(max = 100) String requestId,
        @NotNull Boolean approved) {
}

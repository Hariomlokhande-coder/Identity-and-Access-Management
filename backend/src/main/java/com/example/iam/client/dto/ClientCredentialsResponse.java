package com.example.iam.client.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Returned exactly once, when a secret is created or rotated. The platform keeps only
 * a hash, so a lost secret can be replaced but never recovered.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ClientCredentialsResponse(ClientResponse client, String clientSecret, String notice) {

    public static ClientCredentialsResponse of(ClientResponse client, String secret) {
        String notice = secret == null
                ? "Public clients have no secret; they must use PKCE."
                : "Store this secret now. It is hashed on the server and cannot be shown again.";
        return new ClientCredentialsResponse(client, secret, notice);
    }
}

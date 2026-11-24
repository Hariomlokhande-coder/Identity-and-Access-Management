package io.github.hariomlokhande.iam.oauth;

import org.springframework.http.HttpStatus;

/**
 * An OAuth2 protocol error.
 *
 * <p>These are distinct from the platform's own {@code ApiException} because the spec
 * dictates both the wire format ({@code error} / {@code error_description}) and the
 * error codes themselves. A client library parses these fields, so inventing a
 * friendlier shape here would break integrations.
 *
 * <p>{@link #redirectable} decides how the error reaches the caller. Once the client
 * and its redirect URI have been verified, an error belongs back at the client as a
 * redirect. Before that, it must be rendered directly: sending a browser to an
 * unverified URI is exactly the open redirect this endpoint has to avoid.
 */
public class OAuth2Exception extends RuntimeException {

    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String ACCESS_DENIED = "access_denied";
    public static final String SERVER_ERROR = "server_error";

    private final String error;
    private final HttpStatus status;
    private final boolean redirectable;

    public OAuth2Exception(String error, String description, HttpStatus status, boolean redirectable) {
        super(description);
        this.error = error;
        this.status = status;
        this.redirectable = redirectable;
    }

    /** Error the caller must be shown directly, because no verified redirect exists yet. */
    public static OAuth2Exception direct(String error, String description) {
        return new OAuth2Exception(error, description, HttpStatus.BAD_REQUEST, false);
    }

    /** Error to hand back to the client application through its registered redirect URI. */
    public static OAuth2Exception redirecting(String error, String description) {
        return new OAuth2Exception(error, description, HttpStatus.BAD_REQUEST, true);
    }

    public static OAuth2Exception invalidClient(String description) {
        return new OAuth2Exception(INVALID_CLIENT, description, HttpStatus.UNAUTHORIZED, false);
    }

    public static OAuth2Exception invalidGrant(String description) {
        return new OAuth2Exception(INVALID_GRANT, description, HttpStatus.BAD_REQUEST, false);
    }

    public String error() {
        return error;
    }

    public HttpStatus status() {
        return status;
    }

    public boolean isRedirectable() {
        return redirectable;
    }
}

package com.example.iam.oauth;

/**
 * Where the browser should go after a consent decision, for callers that cannot use
 * a 302.
 *
 * <p>The consent screen is a script, and a script cannot follow the redirect itself:
 * both XMLHttpRequest and fetch follow it transparently, which turns the hop to the
 * client's {@code redirect_uri} into a cross-origin request that fails CORS - and the
 * authorization code is consumed before anyone can use it. Returning the destination
 * as data lets the screen navigate the top-level window instead, which is what the
 * redirect was always meant to do.
 */
public record ConsentDecisionResponse(String redirectUri) {
}

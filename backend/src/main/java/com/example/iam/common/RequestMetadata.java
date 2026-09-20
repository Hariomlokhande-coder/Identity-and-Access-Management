package com.example.iam.common;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Client-supplied request context. It is recorded for audit and rate limiting but,
 * as the design doc requires, never treated as identity: a caller controls both
 * the user agent and (behind a misconfigured proxy) the forwarded address.
 */
public record RequestMetadata(String ipAddress, String userAgent) {

    private static final int MAX_USER_AGENT = 512;

    public static RequestMetadata from(HttpServletRequest request) {
        return new RequestMetadata(clientIp(request), userAgent(request));
    }

    /**
     * Relies on Spring's ForwardedHeaderFilter ({@code server.forward-headers-strategy}) having
     * already applied the proxy headers, so an attacker cannot spoof the address by simply
     * setting X-Forwarded-For.
     */
    private static String clientIp(HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        return remote == null ? "unknown" : remote;
    }

    private static String userAgent(HttpServletRequest request) {
        String agent = request.getHeader("User-Agent");
        if (agent == null || agent.isBlank()) {
            return null;
        }
        return agent.length() > MAX_USER_AGENT ? agent.substring(0, MAX_USER_AGENT) : agent;
    }
}

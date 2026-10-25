package com.example.iam.session.dto;

import com.example.iam.session.UserSession;
import java.time.Instant;
import java.util.UUID;

/**
 * @param current marks the session the request itself is running under, so a UI can
 *                warn before the user signs themselves out
 */
public record SessionResponse(
        UUID id,
        String clientId,
        String deviceInfo,
        String ipAddress,
        Instant createdAt,
        Instant lastSeenAt,
        Instant expiresAt,
        boolean current) {

    public static SessionResponse from(UserSession session, UUID currentSessionId) {
        return new SessionResponse(session.getId(),
                session.getClientApplication() == null ? null : session.getClientApplication().getClientId(),
                session.getDeviceInfo(), session.getIpAddress(), session.getCreatedAt(),
                session.getLastSeenAt(), session.getExpiresAt(), session.getId().equals(currentSessionId));
    }
}

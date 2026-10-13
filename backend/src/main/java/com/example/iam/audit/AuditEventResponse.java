package com.example.iam.audit;

import com.example.iam.audit.AuditEvent.AuditOutcome;
import java.time.Instant;
import java.util.UUID;
public record AuditEventResponse(
        UUID id,
        AuditEventType eventType,
        AuditOutcome outcome,
        UUID actorUserId,
        String targetId,
        String clientId,
        String ipAddress,
        String correlationId,
        String detail,
        Instant createdAt) {

    public static AuditEventResponse from(AuditEvent event) {
        return new AuditEventResponse(event.getId(), event.getEventType(), event.getOutcome(),
                event.getActorUserId(), event.getTargetId(), event.getClientId(), event.getIpAddress(),
                event.getCorrelationId(), event.getDetail(), event.getCreatedAt());
    }
}
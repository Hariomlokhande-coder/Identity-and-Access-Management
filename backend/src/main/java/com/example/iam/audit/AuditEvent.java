package com.example.iam.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/**
 * An append-only record of one security-relevant action. Nothing secret is ever
 * written here: no tokens, no passwords, no authorization headers.
 */
@Entity
@Table(name = "audit_events")
@Getter
@Setter
public class AuditEvent {

    @Id
    @GeneratedValue
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, updatable = false)
    private AuditEventType eventType;

    @Column(name = "actor_user_id")
    private UUID actorUserId;

    /** Whatever the event acted on: a user id, role id, session id or client id. */
    @Column(name = "target_id")
    private String targetId;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "correlation_id")
    private String correlationId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditOutcome outcome = AuditOutcome.SUCCESS;

    private String detail;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public enum AuditOutcome {
        SUCCESS,
        FAILURE
    }
}
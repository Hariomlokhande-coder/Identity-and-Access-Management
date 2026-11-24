package com.iamplatform.security;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/**
 * A durable record of one sign-in attempt.
 *
 * <p>Redis holds the live counters that drive lockout; this table is the history an
 * investigation actually needs, and it survives a Redis flush. The submitted password
 * is never stored, not even hashed.
 */
@Entity
@Table(name = "login_attempts")
@Getter
@Setter
public class LoginAttempt {

    @Id
    @GeneratedValue
    private UUID id;

    /** Normalised address that was tried, which may belong to no account at all. */
    @Column(nullable = false, updatable = false)
    private String email;

    @Column(name = "user_id")
    private UUID userId;

    @Column(nullable = false)
    private boolean successful;

    @Column(name = "failure_reason")
    private String failureReason;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}

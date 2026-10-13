package com.example.iam.email;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/**
 * A queued message. Enqueuing happens inside the caller's transaction, so a mail is
 * never sent for a registration that rolled back, and a registration never fails
 * because the mail server is down.
 */
@Entity
@Table(name = "email_outbox")
@Getter
@Setter
public class EmailOutboxEntry {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, updatable = false)
    private String recipient;

    @Column(nullable = false, updatable = false)
    private String subject;

    @Column(nullable = false, updatable = false)
    private String body;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EmailStatus status = EmailStatus.PENDING;

    @Column(nullable = false)
    private int attempts;

    @Column(name = "next_attempt_at", nullable = false)
    private Instant nextAttemptAt = Instant.now();

    @Column(name = "last_error")
    private String lastError;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "sent_at")
    private Instant sentAt;

    @Version
    private long version;
}
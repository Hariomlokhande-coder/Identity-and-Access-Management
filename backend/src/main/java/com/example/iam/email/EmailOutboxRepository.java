package com.example.iam.email;

import jakarta.persistence.LockModeType;
import jakarta.persistence.QueryHint;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;

public interface EmailOutboxRepository extends JpaRepository<EmailOutboxEntry, UUID> {

    /**
     * Claims a batch for this instance. SKIP LOCKED (Hibernate lock timeout -2) lets
     * several IAM instances drain the same outbox without sending anything twice and
     * without blocking each other.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(@QueryHint(name = "jakarta.persistence.lock.timeout", value = "-2"))
    @Query("""
            SELECT e FROM EmailOutboxEntry e
            WHERE e.status = com.example.iam.email.EmailStatus.PENDING AND e.nextAttemptAt <= :now
            ORDER BY e.nextAttemptAt
            """)
    List<EmailOutboxEntry> claimBatch(@Param("now") Instant now, Pageable pageable);

    @Modifying
    @Query("DELETE FROM EmailOutboxEntry e WHERE e.status = com.example.iam.email.EmailStatus.SENT AND e.sentAt < :cutoff")
    int deleteSentBefore(@Param("cutoff") Instant cutoff);

    long countByStatus(EmailStatus status);
}
package com.example.iam.audit;

import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEvent, UUID> {

    Page<AuditEvent> findByActorUserIdOrderByCreatedAtDesc(
            UUID actorUserId, Pageable pageable);

    Page<AuditEvent> findByEventTypeOrderByCreatedAtDesc(
            AuditEventType eventType, Pageable pageable);
}
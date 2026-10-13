package com.example.iam.audit;

import com.example.iam.audit.AuditEvent.AuditOutcome;
import com.example.iam.common.CorrelationIdFilter;
import com.example.iam.common.PageResponse;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes the audit trail.
 *
 * <p>Every write runs in its own transaction: an audit row must survive the rollback
 * of the operation it describes, otherwise failed and rolled-back attempts - exactly
 * the interesting ones - would leave no trace. A failure to audit is logged but never
 * propagated, so the trail can never take the platform down.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private static final int MAX_DETAIL = 1024;

    private final AuditEventRepository repository;

    public AuditService(AuditEventRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEventType type, AuditOutcome outcome, UUID actorUserId, String targetId,
                       String clientId, String ipAddress, String detail) {
        try {
            AuditEvent event = new AuditEvent();
            event.setEventType(type);
            event.setOutcome(outcome);
            event.setActorUserId(actorUserId);
            event.setTargetId(targetId);
            event.setClientId(clientId);
            event.setIpAddress(ipAddress);
            event.setCorrelationId(CorrelationIdFilter.current());
            event.setDetail(truncate(detail));
            repository.save(event);
        } catch (RuntimeException e) {
            log.error("Failed to persist audit event {} for actor {}", type, actorUserId, e);
        }
    }

    public void success(AuditEventType type, UUID actorUserId, String targetId, String ipAddress, String
            detail) {
        record(type, AuditOutcome.SUCCESS, actorUserId, targetId, null, ipAddress, detail);
    }

    public void failure(AuditEventType type, UUID actorUserId, String targetId, String ipAddress, String
            detail) {
        record(type, AuditOutcome.FAILURE, actorUserId, targetId, null, ipAddress, detail);
    }

    /**
     * Reads the trail, newest first, optionally narrowed to one actor or event type.
     *
     * <p>The filters are applied by choosing a query rather than by passing nullable
     * parameters into one, so each path is a plain indexed lookup.
     */
    @Transactional(readOnly = true)
    public PageResponse<AuditEventResponse> search(AuditEventType eventType, UUID actorUserId, Pageable
            pageable) {
        Page<AuditEvent> page;
        if (actorUserId != null) {
            page = repository.findByActorUserIdOrderByCreatedAtDesc(actorUserId, pageable);
        } else if (eventType != null) {
            page = repository.findByEventTypeOrderByCreatedAtDesc(eventType, pageable);
        } else {
            page = repository.findAll(pageable);
        }
        return PageResponse.of(page.map(AuditEventResponse::from));
    }

    private String truncate(String detail) {
        if (detail == null || detail.length() <= MAX_DETAIL) {
            return detail;
        }
        return detail.substring(0, MAX_DETAIL);
    }
}
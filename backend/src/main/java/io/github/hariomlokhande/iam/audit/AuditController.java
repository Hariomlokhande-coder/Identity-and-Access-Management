package io.github.hariomlokhande.iam.audit;

import io.github.hariomlokhande.iam.common.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read access to the security audit trail.
 *
 * <p>Read-only by design. An audit trail that can be edited or deleted through the API
 * is not evidence of anything; rows leave only through the retention job.
 */
@RestController
@RequestMapping("/audit")
@Tag(name = "Audit")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/events")
    @PreAuthorize("hasAuthority('AUDIT_READ')")
    @Operation(summary = "Read security events, newest first",
            description = "Optionally narrowed to one actor or one event type.")
    public PageResponse<AuditEventResponse> events(
            @RequestParam(required = false) AuditEventType eventType,
            @RequestParam(required = false) UUID actorUserId,
            @PageableDefault(size = 50) Pageable pageable) {
        return auditService.search(eventType, actorUserId, pageable);
    }
}

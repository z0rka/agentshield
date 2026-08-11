package io.agentshield.controlplane.audit.api;

import io.agentshield.controlplane.audit.application.AuditService;
import io.agentshield.controlplane.audit.domain.AuditEntry;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Reading the workspace's audit trail. */
@RestController
@RequestMapping("/api")
public class AuditController {

    public record AuditResponse(
            Long id,
            UUID actorId,
            String action,
            String resource,
            String resourceId,
            String detail,
            Instant occurredAt) {

        static AuditResponse of(AuditEntry entry) {
            return new AuditResponse(
                    entry.getId(),
                    entry.getActorId(),
                    entry.getAction(),
                    entry.getResource(),
                    entry.getResourceId(),
                    entry.getDetail(),
                    entry.getOccurredAt());
        }
    }

    private final AuditService audit;

    public AuditController(AuditService audit) {
        this.audit = audit;
    }

    /**
     * Recent activity in the caller's workspace.
     *
     * <p>No workspace parameter. The scope comes from the authenticated principal, because an
     * audit endpoint that accepts a workspace id is a way to read another tenant's history -
     * and this is the one endpoint where that would be handing over the record of everything
     * they have ever done.
     */
    @GetMapping("/audit")
    public List<AuditResponse> recent(@RequestParam(defaultValue = "100") int limit) {
        return audit.recent(limit).stream().map(AuditResponse::of).toList();
    }
}

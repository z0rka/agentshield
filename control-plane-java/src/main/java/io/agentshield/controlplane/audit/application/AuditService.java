package io.agentshield.controlplane.audit.application;

import io.agentshield.controlplane.audit.domain.AuditEntry;
import io.agentshield.controlplane.audit.repository.AuditRepository;
import io.agentshield.controlplane.security.access.AccessGuard;
import io.agentshield.controlplane.security.domain.Permission;
import io.agentshield.controlplane.security.domain.Principal;

import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes and reads the audit trail.
 *
 * <p>Recording runs in its own transaction, so an audit row survives a caller that rolls back.
 * That is the important half: the interesting entries are the ones written just before
 * something failed, and joining them to the caller's transaction would delete exactly those.
 *
 * <p>Recording never throws. An audit failure must not fail the operation it is describing -
 * losing one row is bad, refusing to start a scan because the audit table is full is worse -
 * so problems are logged at error and swallowed. That is a trade-off worth naming and not
 * hiding: this is an audit trail, not a compliance ledger, and it does not claim to be
 * tamper-evident. See docs/security-architecture.md.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    /** Actions worth a row. State changes and work, never reads. */
    public static final String SCAN_CREATED = "scan.created";
    public static final String SCAN_CANCELLED = "scan.cancelled";
    public static final String SCAN_RERUN = "scan.rerun";
    public static final String TARGET_CREATED = "target.created";
    public static final String POLICY_CREATED = "policy.created";
    public static final String FINDING_RESOLVED = "finding.resolved";
    public static final String BASELINE_UPDATED = "baseline.updated";

    private final AuditRepository entries;
    private final AccessGuard access;

    public AuditService(AuditRepository entries, AccessGuard access) {
        this.entries = entries;
        this.access = access;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(
            Principal principal, String action, String resource, Object resourceId, String detail) {

        try {
            entries.save(new AuditEntry(
                    principal.workspaceId(),
                    principal.userId(),
                    action,
                    resource,
                    resourceId == null ? null : resourceId.toString(),
                    detail));
        } catch (Exception exception) {
            log.error(
                    "could not record audit entry {} on {} {}",
                    action, resource, resourceId, exception);
        }
    }

    /**
     * The workspace's recent activity.
     *
     * <p>Scoped to the caller's workspace by the principal, never by a parameter - an audit log
     * that accepts a workspace id from the request is a way to read another tenant's history.
     */
    @Transactional(readOnly = true)
    public List<AuditEntry> recent(int limit) {
        Principal principal = access.require(Permission.READ);
        UUID workspace = principal.workspaceId();
        return entries.findByWorkspaceIdOrderByOccurredAtDesc(
                workspace, PageRequest.of(0, Math.clamp(limit, 1, 500)));
    }
}

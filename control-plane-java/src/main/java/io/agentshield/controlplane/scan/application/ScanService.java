package io.agentshield.controlplane.scan.application;

import io.agentshield.controlplane.event.application.OutboxPublisher;
import io.agentshield.controlplane.event.domain.EventTypes;
import io.agentshield.controlplane.policy.application.PolicyService;
import io.agentshield.controlplane.scan.domain.Scan;
import io.agentshield.controlplane.scan.domain.ScanStatus;
import io.agentshield.controlplane.scan.repository.ScanRepository;
import io.agentshield.controlplane.security.domain.Permission;
import io.agentshield.controlplane.audit.application.AuditService;
import io.agentshield.controlplane.security.access.AccessGuard;
import io.agentshield.controlplane.shared.error.ConflictException;
import io.agentshield.controlplane.shared.error.InvalidRequestException;
import io.agentshield.controlplane.shared.error.NotFoundException;
import io.agentshield.controlplane.target.application.TargetService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Scan lifecycle. The control plane's most important responsibility.
 *
 * <p>Two invariants live here:
 *
 * <ol>
 *   <li><b>Idempotent creation.</b> Retrying {@code POST /scans} with the same key returns the
 *       original scan. A CI job that times out and retries must not launch a second wave of
 *       adversarial traffic at a production system.
 *   <li><b>Bounded concurrency.</b> A workspace can only have so many scans in flight, because
 *       every scan is load on someone's application.
 * </ol>
 */
@Service
public class ScanService {

    /** Result of idempotent scan creation, including whether an existing row was replayed. */
    public record CreateResult(Scan scan, boolean replayed) {
    }

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private static final List<ScanStatus> ACTIVE =
            List.of(ScanStatus.QUEUED, ScanStatus.DISCOVERING, ScanStatus.RUNNING, ScanStatus.EVALUATING);

    private final ScanRepository scans;
    private final TargetService targets;
    private final PolicyService policies;
    private final OutboxPublisher outbox;
    private final AccessGuard access;
    private final AuditService audit;
    private final int maxConcurrentPerWorkspace;
    private final int maxConcurrentPerTarget;

    public ScanService(
            ScanRepository scans,
            TargetService targets,
            PolicyService policies,
            OutboxPublisher outbox,
            AccessGuard access,
            AuditService audit,
            @Value("${agentshield.scan.max-concurrent-per-workspace:3}") int maxConcurrentPerWorkspace,
            @Value("${agentshield.scan.max-concurrent-per-target:1}") int maxConcurrentPerTarget) {
        this.scans = scans;
        this.targets = targets;
        this.policies = policies;
        this.outbox = outbox;
        this.access = access;
        this.audit = audit;
        this.maxConcurrentPerWorkspace = maxConcurrentPerWorkspace;
        this.maxConcurrentPerTarget = maxConcurrentPerTarget;
    }

    /**
     * Creates a scan and announces it, atomically.
     *
     * <p>The scan row and the {@code security.scan.created} outbox entry commit together, so
     * there is no state in which a scan exists that nothing will ever pick up.
     */
    @Transactional
    public Scan create(
            UUID projectId,
            UUID targetId,
            UUID policyId,
            List<String> suites,
            int maxScenarios,
            int seed,
            String idempotencyKey) {
        return createWithResult(
                projectId,
                targetId,
                policyId,
                suites,
                maxScenarios,
                seed,
                idempotencyKey).scan();
    }

    @Transactional
    public CreateResult createWithResult(
            UUID projectId,
            UUID targetId,
            UUID policyId,
            List<String> suites,
            int maxScenarios,
            int seed,
            String idempotencyKey) {

        var principal = access.require(Permission.RUN_SCAN);

        String key = (idempotencyKey == null || idempotencyKey.isBlank())
                ? UUID.randomUUID().toString()
                : idempotencyKey;

        var existing = scans.findByWorkspaceIdAndIdempotencyKey(principal.workspaceId(), key);
        if (existing.isPresent()) {
            log.info("returning existing scan {} for idempotency key {}", existing.get().getId(), key);
            return new CreateResult(existing.get(), true);
        }

        var target = targets.require(targetId);
        var policy = policies.require(policyId);
        if (!target.getProjectId().equals(projectId) || !policy.getProjectId().equals(projectId)) {
            throw new InvalidRequestException("target and policy must belong to the named project");
        }
        if (!target.isEnabled()) {
            throw new ConflictException("target " + target.getName() + " is disabled");
        }

        long active = scans.countByWorkspaceIdAndStatusIn(principal.workspaceId(), ACTIVE);
        if (active >= maxConcurrentPerWorkspace) {
            throw new ConflictException(
                    "this workspace already has " + active + " scans in flight (limit "
                            + maxConcurrentPerWorkspace + ")");
        }

        // Separate from the workspace limit, and stricter, because it protects a different
        // thing. The workspace limit stops AgentShield overcommitting itself; this one stops
        // two scans landing on one agent at once. That is not only load: indirect-injection
        // scenarios plant documents in the target, so a second concurrent scan retrieves the
        // first one's poisoned article and both trajectories become evidence of nothing.
        long onTarget = scans.countByTargetIdAndStatusIn(targetId, ACTIVE);
        if (onTarget >= maxConcurrentPerTarget) {
            throw new ConflictException(
                    "target " + target.getName() + " already has " + onTarget
                            + " scan(s) in flight (limit " + maxConcurrentPerTarget
                            + "). Concurrent scans of one target contaminate each other's "
                            + "planted content.");
        }

        var scanId = UUID.randomUUID();
        var scan = new Scan(
                scanId,
                principal.workspaceId(),
                projectId,
                targetId,
                policyId,
                principal.userId(),
                key,
                UUID.randomUUID().toString());
        scan.configure(suites == null ? "" : String.join(",", suites), maxScenarios, seed);
        scan.transitionTo(ScanStatus.QUEUED);
        scan = scans.save(scan);

        // Recorded before the event is published, and in its own transaction, so the row
        // survives a publish that fails. "Who started a scan against which target" is the
        // question this table exists for, and it is most interesting about the runs that
        // went wrong.
        audit.record(
                principal,
                AuditService.SCAN_CREATED,
                "scan",
                scanId,
                "{\"targetId\":\"" + targetId + "\",\"policyId\":\"" + policyId + "\"}");

        // The payload carries ids and the configuration hash, never the target's credentials.
        // The engine fetches those over an authenticated channel when it starts work.
        var payload = new HashMap<String, Object>();
        payload.put("scanId", scanId.toString());
        payload.put("projectId", projectId.toString());
        payload.put("targetId", targetId.toString());
        payload.put("policyId", policyId.toString());
        payload.put("policyHash", policy.getContentHash());
        payload.put("targetConfigHash", target.getConfigurationHash());
        payload.put("suites", scan.getSuites());
        payload.put("maxScenarios", maxScenarios);
        payload.put("seed", seed);

        outbox.publish(
                "scan",
                scanId.toString(),
                principal.workspaceId(),
                EventTypes.SCAN_CREATED,
                scan.getCorrelationId(),
                Map.copyOf(payload));

        return new CreateResult(scan, false);
    }

    @Transactional(readOnly = true)
    public Scan require(UUID scanId) {
        access.require(Permission.READ);
        return access.requireVisible(
                scans.findById(scanId)
                        .orElseThrow(() -> new NotFoundException("scan", scanId)),
                "scan",
                scanId);
    }

    /**
     * Requests cancellation.
     *
     * <p>Cancellation is cooperative: this marks the scan and announces it, and the engine
     * stops dispatching new scenarios. Scenarios already in flight are allowed to finish - 
     * killing a target session halfway through leaves the target holding state the next
     * scenario would inherit, and the resulting trajectory would be evidence of nothing.
     */
    @Transactional
    public Scan cancel(UUID scanId) {
        var principal = access.require(Permission.RUN_SCAN);
        var scan = require(scanId);

        if (scan.getStatus().isTerminal()) {
            throw new ConflictException("scan is already " + scan.getStatus());
        }
        scan.transitionTo(ScanStatus.CANCELLED);
        audit.record(principal, AuditService.SCAN_CANCELLED, "scan", scanId, "{}");

        outbox.publish(
                "scan",
                scanId.toString(),
                scan.getWorkspaceId(),
                EventTypes.SCAN_CANCELLED,
                scan.getCorrelationId(),
                Map.of("scanId", scanId.toString(), "requestedBy", principal.userId().toString()));
        return scan;
    }

    /**
     * Re-runs a scan with identical configuration.
     *
     * <p>A fresh idempotency key, because a rerun is a new scan by definition - reusing the key
     * would return the original and make the button do nothing.
     */
    @Transactional
    public Scan rerun(UUID scanId) {
        var original = require(scanId);
        return create(
                original.getProjectId(),
                original.getTargetId(),
                original.getPolicyId(),
                original.getSuites().isBlank() ? List.of() : List.of(original.getSuites().split(",")),
                original.getMaxScenarios(),
                original.getSeed(),
                UUID.randomUUID().toString());
    }

    @Transactional(readOnly = true)
    public List<Scan> listForProject(UUID projectId) {
        access.require(Permission.READ);
        return scans.findByProjectIdOrderByCreatedAtDesc(projectId);
    }

    /**
     * Applies a status change reported by the engine.
     *
     * <p>Illegal transitions are logged and dropped rather than raised: a late duplicate from
     * Kafka is expected traffic, and treating it as an error would fill the DLQ with noise.
     */
    @Transactional
    public void applyEngineStatus(UUID scanId, ScanStatus reported) {
        scans.findById(scanId).ifPresent(scan -> {
            if (!scan.tryTransitionTo(reported)) {
                log.debug(
                        "ignoring out-of-order status {} for scan {} in state {}",
                        reported, scanId, scan.getStatus());
            }
        });
    }

    @Transactional
    public void applyEngineCompletion(UUID scanId, Map<String, Object> payload) {
        scans.findById(scanId).ifPresent(scan -> {
            scan.recordCounts(
                    number(payload, "critical"),
                    number(payload, "high"),
                    number(payload, "medium"),
                    number(payload, "low"),
                    number(payload, "attacks"));
            if (!scan.tryTransitionTo(ScanStatus.COMPLETED)) {
                log.debug("ignoring completion for scan {} in state {}", scanId, scan.getStatus());
            }
        });
    }

    @Transactional
    public void applyEngineFailure(UUID scanId, Map<String, Object> payload) {
        scans.findById(scanId).ifPresent(scan -> scan.fail(
                String.valueOf(payload.getOrDefault("errorCode", "ENGINE_FAILURE")),
                String.valueOf(payload.getOrDefault("message", "security engine failed"))));
    }

    private static int number(Map<String, Object> payload, String key) {
        Object value = payload.get(key);
        return value instanceof Number number ? number.intValue() : 0;
    }
}

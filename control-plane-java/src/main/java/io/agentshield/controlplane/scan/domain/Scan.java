package io.agentshield.controlplane.scan.domain;

import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import io.agentshield.controlplane.shared.domain.BaseEntity;
import io.agentshield.controlplane.shared.error.ConflictException;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;

/** A single security scan. This row is the source of truth for whether it is running. */
@Entity
@Table(name = "scan")
public class Scan extends BaseEntity implements WorkspaceScoped {

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "project_id", nullable = false, updatable = false)
    private UUID projectId;

    @Column(name = "target_id", nullable = false, updatable = false)
    private UUID targetId;

    @Column(name = "policy_id", nullable = false, updatable = false)
    private UUID policyId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private ScanStatus status = ScanStatus.CREATED;

    @Column(name = "idempotency_key", nullable = false, updatable = false)
    private String idempotencyKey;

    @Column(name = "requested_by", nullable = false, updatable = false)
    private UUID requestedBy;

    /** Comma-separated suite names; empty means "let the threat model decide". */
    @Column(name = "suites", nullable = false)
    private String suites = "";

    @Column(name = "max_scenarios", nullable = false)
    private int maxScenarios = 50;

    @Column(name = "seed", nullable = false)
    private int seed;

    @Column(name = "correlation_id", nullable = false, updatable = false)
    private String correlationId;

    @Column(name = "error_code")
    private String errorCode;

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "attack_count", nullable = false)
    private int attackCount;

    @Column(name = "finding_count", nullable = false)
    private int findingCount;

    @Column(name = "critical_count", nullable = false)
    private int criticalCount;

    @Column(name = "high_count", nullable = false)
    private int highCount;

    @Column(name = "medium_count", nullable = false)
    private int mediumCount;

    @Column(name = "low_count", nullable = false)
    private int lowCount;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    /**
     * Optimistic locking.
     *
     * <p>Progress events for one scan arrive concurrently from several engine workers. Without
     * a version, two of them read the same counts and the second write silently discards the
     * first - the classic lost update, and it would show up as findings missing from a report
     * for no reproducible reason.
     */
    @Version
    @Column(name = "lock_version")
    private long lockVersion;

    protected Scan() {
    }

    public Scan(
            UUID id,
            UUID workspaceId,
            UUID projectId,
            UUID targetId,
            UUID policyId,
            UUID requestedBy,
            String idempotencyKey,
            String correlationId) {
        super(id);
        this.workspaceId = workspaceId;
        this.projectId = projectId;
        this.targetId = targetId;
        this.policyId = policyId;
        this.requestedBy = requestedBy;
        this.idempotencyKey = idempotencyKey;
        this.correlationId = correlationId;
    }

    /**
     * Moves to {@code next}, or explains why it cannot.
     *
     * @throws ConflictException on an illegal transition requested by a user (cancelling a
     *     finished scan). Event handlers should call {@link #tryTransitionTo} instead, since a
     *     late duplicate is expected traffic over a client error.
     */
    public void transitionTo(ScanStatus next) {
        if (!tryTransitionTo(next)) {
            throw new ConflictException(
                    "scan is " + status + " and cannot move to " + next);
        }
    }

    /** @return false when the transition is not legal from the current state. */
    public boolean tryTransitionTo(ScanStatus next) {
        if (status == next) {
            return true;  // idempotent: a duplicate event is not an error
        }
        if (!status.canTransitionTo(next)) {
            return false;
        }
        status = next;
        if (next == ScanStatus.RUNNING && startedAt == null) {
            startedAt = Instant.now();
        }
        if (next.isTerminal()) {
            completedAt = Instant.now();
        }
        return true;
    }

    public void fail(String errorCode, String errorMessage) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
        tryTransitionTo(ScanStatus.FAILED);
    }

    public void recordCounts(int critical, int high, int medium, int low, int attacks) {
        this.criticalCount = critical;
        this.highCount = high;
        this.mediumCount = medium;
        this.lowCount = low;
        this.findingCount = critical + high + medium + low;
        this.attackCount = attacks;
    }

    public void configure(String suites, int maxScenarios, int seed) {
        this.suites = suites == null ? "" : suites;
        this.maxScenarios = maxScenarios;
        this.seed = seed;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public UUID getProjectId() {
        return projectId;
    }

    public UUID getTargetId() {
        return targetId;
    }

    public UUID getPolicyId() {
        return policyId;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public String getIdempotencyKey() {
        return idempotencyKey;
    }

    public UUID getRequestedBy() {
        return requestedBy;
    }

    public String getSuites() {
        return suites;
    }

    public int getMaxScenarios() {
        return maxScenarios;
    }

    public int getSeed() {
        return seed;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public int getAttackCount() {
        return attackCount;
    }

    public int getFindingCount() {
        return findingCount;
    }

    public int getCriticalCount() {
        return criticalCount;
    }

    public int getHighCount() {
        return highCount;
    }

    public int getMediumCount() {
        return mediumCount;
    }

    public int getLowCount() {
        return lowCount;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }
}

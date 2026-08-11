package io.agentshield.controlplane.schedule.domain;

import io.agentshield.controlplane.shared.domain.BaseEntity;
import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** A target that gets scanned on a timer. */
@Entity
@Table(name = "scan_schedule")
public class ScanSchedule extends BaseEntity implements WorkspaceScoped {

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "project_id", nullable = false, updatable = false)
    private UUID projectId;

    @Column(name = "target_id", nullable = false, updatable = false)
    private UUID targetId;

    @Column(name = "policy_id", nullable = false)
    private UUID policyId;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "interval_minutes", nullable = false)
    private int intervalMinutes;

    @Column(name = "suites", nullable = false)
    private String suites = "";

    @Column(name = "max_scenarios", nullable = false)
    private int maxScenarios = 50;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "created_by")
    private UUID createdBy;

    @Column(name = "next_run_at", nullable = false)
    private Instant nextRunAt = Instant.now();

    @Column(name = "last_run_at")
    private Instant lastRunAt;

    @Column(name = "last_scan_id")
    private UUID lastScanId;

    protected ScanSchedule() {
    }

    public ScanSchedule(
            UUID id,
            UUID workspaceId,
            UUID projectId,
            UUID targetId,
            UUID policyId,
            String name,
            int intervalMinutes,
            List<String> suites,
            int maxScenarios,
            UUID createdBy) {
        super(id);
        this.workspaceId = workspaceId;
        this.projectId = projectId;
        this.targetId = targetId;
        this.policyId = policyId;
        this.name = name;
        this.intervalMinutes = intervalMinutes;
        this.suites = suites == null ? "" : String.join(",", suites);
        this.maxScenarios = maxScenarios;
        this.createdBy = createdBy;
        // First run one interval out, never immediately. Creating a schedule should not start
        // a scan as a side effect: the caller who wanted one now would have asked for one now.
        this.nextRunAt = Instant.now().plus(Duration.ofMinutes(intervalMinutes));
    }

    /**
     * Record that a run was started, and move the window forward.
     *
     * <p>From <em>now</em>, never from the previous due time. Advancing from the due time
     * makes a scheduler that was down for a day fire a day's worth of scans the moment it
     * returns, all against one target, all contaminating each other.
     */
    public void markRun(UUID scanId) {
        this.lastRunAt = Instant.now();
        this.lastScanId = scanId;
        this.nextRunAt = this.lastRunAt.plus(Duration.ofMinutes(intervalMinutes));
    }

    /**
     * Push the next attempt out without recording a run.
     *
     * <p>Used when a due schedule could not start - the target is disabled, or a scan of it is
     * already in flight. Retrying every poll would fill the log with the same refusal.
     */
    public void deferBy(Duration delay) {
        this.nextRunAt = Instant.now().plus(delay);
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
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

    public String getName() {
        return name;
    }

    public int getIntervalMinutes() {
        return intervalMinutes;
    }

    public List<String> getSuites() {
        return suites.isBlank() ? List.of() : List.of(suites.split(","));
    }

    public int getMaxScenarios() {
        return maxScenarios;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public UUID getCreatedBy() {
        return createdBy;
    }

    public Instant getNextRunAt() {
        return nextRunAt;
    }

    public Instant getLastRunAt() {
        return lastRunAt;
    }

    public UUID getLastScanId() {
        return lastScanId;
    }
}

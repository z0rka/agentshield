package io.agentshield.controlplane.scan.domain;

import io.agentshield.controlplane.shared.domain.BaseEntity;
import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/** One attempt at one concrete attack scenario. */
@Entity
@Table(name = "attack_run")
public class AttackRun extends BaseEntity implements WorkspaceScoped {

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "scenario_id", nullable = false, updatable = false)
    private UUID scenarioId;

    @Column(name = "attempt", nullable = false, updatable = false)
    private int attempt;

    @Column(name = "status", nullable = false)
    private String status;

    @Column(name = "target_session_id")
    private String targetSessionId;

    @Column(name = "input_tokens", nullable = false)
    private int inputTokens;

    @Column(name = "output_tokens", nullable = false)
    private int outputTokens;

    @Column(name = "estimated_cost_usd", nullable = false)
    private BigDecimal estimatedCostUsd = BigDecimal.ZERO;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    protected AttackRun() {
    }

    public AttackRun(
            UUID id,
            UUID workspaceId,
            UUID scenarioId,
            int attempt,
            String status,
            String targetSessionId,
            int inputTokens,
            int outputTokens,
            BigDecimal estimatedCostUsd) {
        super(id);
        this.workspaceId = workspaceId;
        this.scenarioId = scenarioId;
        this.attempt = attempt;
        this.status = status;
        this.targetSessionId = targetSessionId;
        this.inputTokens = inputTokens;
        this.outputTokens = outputTokens;
        this.estimatedCostUsd = estimatedCostUsd;
        this.startedAt = Instant.now();
        this.completedAt = Instant.now();
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public UUID getScenarioId() {
        return scenarioId;
    }

    public int getAttempt() {
        return attempt;
    }

    public String getStatus() {
        return status;
    }
}

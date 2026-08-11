package io.agentshield.controlplane.scan.domain;

import io.agentshield.controlplane.shared.domain.BaseEntity;
import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** One server-redacted event in an agent trajectory. */
@Entity
@Table(name = "trajectory_step")
public class TrajectoryStep extends BaseEntity implements WorkspaceScoped {

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "attack_run_id", nullable = false, updatable = false)
    private UUID attackRunId;

    @Column(name = "sequence_number", nullable = false, updatable = false)
    private int sequenceNumber;

    @Column(name = "step_type", nullable = false)
    private String stepType;

    @Column(name = "tool_name")
    private String toolName;

    @Column(name = "input_redacted", nullable = false)
    private String inputRedacted = "";

    @Column(name = "output_redacted", nullable = false)
    private String outputRedacted = "";

    @Column(name = "duration_ms")
    private Integer durationMs;

    @Column(name = "trace_id")
    private String traceId;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    protected TrajectoryStep() {
    }

    public TrajectoryStep(
            UUID id,
            UUID workspaceId,
            UUID attackRunId,
            int sequenceNumber,
            String stepType,
            String toolName,
            String inputRedacted,
            String outputRedacted,
            Integer durationMs,
            String traceId,
            Instant occurredAt) {
        super(id);
        this.workspaceId = workspaceId;
        this.attackRunId = attackRunId;
        this.sequenceNumber = sequenceNumber;
        this.stepType = stepType;
        this.toolName = toolName;
        this.inputRedacted = inputRedacted;
        this.outputRedacted = outputRedacted;
        this.durationMs = durationMs;
        this.traceId = traceId;
        this.occurredAt = occurredAt;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public UUID getAttackRunId() {
        return attackRunId;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public String getStepType() {
        return stepType;
    }

    public String getToolName() {
        return toolName;
    }

    public String getInputRedacted() {
        return inputRedacted;
    }

    public String getOutputRedacted() {
        return outputRedacted;
    }

    public Integer getDurationMs() {
        return durationMs;
    }

    public String getTraceId() {
        return traceId;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }
}

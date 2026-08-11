package io.agentshield.controlplane.finding.domain;

import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import io.agentshield.controlplane.shared.domain.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** A security issue found by a scan. */
@Entity
@Table(name = "finding")
public class Finding extends BaseEntity implements WorkspaceScoped {

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW, INFO;

        public int rank() {
            return switch (this) {
                case CRITICAL -> 4;
                case HIGH -> 3;
                case MEDIUM -> 2;
                case LOW -> 1;
                case INFO -> 0;
            };
        }

        public boolean atLeast(Severity other) {
            return rank() >= other.rank();
        }
    }

    public enum Status {
        OPEN, RESOLVED, ACCEPTED_RISK, FALSE_POSITIVE
    }

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "scan_id", nullable = false, updatable = false)
    private UUID scanId;

    @Column(name = "scenario_id")
    private UUID scenarioId;

    /** Human-facing stable code, e.g. AS-INJECTION-004. Derived from the fingerprint. */
    @Column(name = "code", nullable = false)
    private String code;

    @Column(name = "category", nullable = false)
    private String category;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    private Severity severity;

    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "description", nullable = false)
    private String description = "";

    /** JSON documents produced by the engine, already redacted. */
    @Column(name = "evidence", nullable = false)
    private String evidence = "{}";

    @Column(name = "reproduction", nullable = false)
    private String reproduction = "{}";

    @Column(name = "remediation", nullable = false)
    private String remediation = "{}";

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private Status status = Status.OPEN;

    /**
     * Identity of the defect across scans.
     *
     * <p>The CI gate compares fingerprints against a baseline, so this is what decides whether
     * a build fails. It is computed by the engine from the defect (category, evaluator, tool,
     * policy clause) and not from the payload that happened to trigger it.
     */
    @Column(name = "fingerprint", nullable = false)
    private String fingerprint;

    @Column(name = "detected_by", nullable = false)
    private String detectedBy = "";

    @Column(name = "occurrences", nullable = false)
    private int occurrences = 1;

    @Column(name = "first_seen_at", nullable = false)
    private Instant firstSeenAt = Instant.now();

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

    protected Finding() {
    }

    public Finding(
            UUID id,
            UUID workspaceId,
            UUID scanId,
            String code,
            String category,
            Severity severity,
            String title,
            String fingerprint) {
        super(id);
        this.workspaceId = workspaceId;
        this.scanId = scanId;
        this.code = code;
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.fingerprint = fingerprint;
    }

    public void describe(String description, String evidence, String reproduction, String remediation) {
        this.description = description == null ? "" : description;
        this.evidence = evidence == null ? "{}" : evidence;
        this.reproduction = reproduction == null ? "{}" : reproduction;
        this.remediation = remediation == null ? "{}" : remediation;
    }

    /** A repeat sighting within the same scan: count it, do not duplicate the row. */
    public void recordOccurrence() {
        this.occurrences++;
        this.lastSeenAt = Instant.now();
    }

    public void resolve(Status status) {
        this.status = status;
    }

    public void setDetectedBy(String detectedBy) {
        this.detectedBy = detectedBy == null ? "" : detectedBy;
    }

    public void setScenarioId(UUID scenarioId) {
        this.scenarioId = scenarioId;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public UUID getScanId() {
        return scanId;
    }

    public UUID getScenarioId() {
        return scenarioId;
    }

    public String getCode() {
        return code;
    }

    public String getCategory() {
        return category;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getReproduction() {
        return reproduction;
    }

    public String getRemediation() {
        return remediation;
    }

    public Status getStatus() {
        return status;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getDetectedBy() {
        return detectedBy;
    }

    public int getOccurrences() {
        return occurrences;
    }

    public Instant getFirstSeenAt() {
        return firstSeenAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }
}

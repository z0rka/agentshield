package io.agentshield.controlplane.finding.domain;

import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import io.agentshield.controlplane.shared.domain.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "regression_baseline")
public class RegressionBaseline extends BaseEntity implements WorkspaceScoped {

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "project_id", nullable = false, updatable = false)
    private UUID projectId;

    @Column(name = "scan_id", nullable = false)
    private UUID scanId;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "policy_hash", nullable = false)
    private String policyHash = "";

    @Column(name = "fingerprints", nullable = false)
    private String fingerprints = "";

    protected RegressionBaseline() {
    }

    public RegressionBaseline(UUID id, UUID workspaceId, UUID projectId, UUID scanId, String name) {
        super(id);
        this.workspaceId = workspaceId;
        this.projectId = projectId;
        this.scanId = scanId;
        this.name = name;
    }

    public Set<String> fingerprintSet() {
        if (fingerprints.isBlank()) {
            return Set.of();
        }
        return new LinkedHashSet<>(Arrays.asList(fingerprints.split(",")));
    }

    public void addFingerprint(String fingerprint) {
        var current = new LinkedHashSet<>(fingerprintSet());
        current.add(fingerprint);
        fingerprints = String.join(",", current);
    }

    public void replaceFingerprints(Set<String> replacement) {
        fingerprints = String.join(",", replacement);
    }

    public void setPolicyHash(String policyHash) {
        this.policyHash = policyHash;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public UUID getProjectId() {
        return projectId;
    }

    public UUID getScanId() {
        return scanId;
    }

    public String getName() {
        return name;
    }

    public String getPolicyHash() {
        return policyHash;
    }
}

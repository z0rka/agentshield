package io.agentshield.controlplane.scan.domain;

import io.agentshield.controlplane.shared.domain.BaseEntity;
import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.util.UUID;

/** Authored attack template after mutation into one concrete scan scenario. */
@Entity
@Table(name = "attack_scenario")
public class AttackScenario extends BaseEntity implements WorkspaceScoped {

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "scan_id", nullable = false, updatable = false)
    private UUID scanId;

    @Column(name = "scenario_key", nullable = false, updatable = false)
    private String scenarioKey;

    @Column(name = "category", nullable = false)
    private String category;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "template_id", nullable = false)
    private String templateId = "";

    @Column(name = "payload", nullable = false)
    private String payload;

    @Column(name = "expected_policy", nullable = false)
    private String expectedPolicy = "";

    @Column(name = "seed", nullable = false)
    private int seed;

    @Column(name = "status", nullable = false)
    private String status = "PENDING";

    protected AttackScenario() {
    }

    public AttackScenario(
            UUID id,
            UUID workspaceId,
            UUID scanId,
            String scenarioKey,
            String category,
            String name,
            String templateId,
            String payload,
            String expectedPolicy,
            int seed,
            String status) {
        super(id);
        this.workspaceId = workspaceId;
        this.scanId = scanId;
        this.scenarioKey = scenarioKey;
        this.category = category;
        this.name = name;
        this.templateId = templateId;
        this.payload = payload;
        this.expectedPolicy = expectedPolicy;
        this.seed = seed;
        this.status = status;
    }

    public UUID getScanId() {
        return scanId;
    }

    public String getScenarioKey() {
        return scenarioKey;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public String getCategory() {
        return category;
    }
}

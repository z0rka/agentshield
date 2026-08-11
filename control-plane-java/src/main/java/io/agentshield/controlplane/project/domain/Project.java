package io.agentshield.controlplane.project.domain;

import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import io.agentshield.controlplane.shared.domain.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** A unit of work inside a workspace: one application under test, with its targets and policies. */
@Entity
@Table(name = "project")
public class Project extends BaseEntity implements WorkspaceScoped {

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description", nullable = false)
    private String description = "";

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected Project() {
    }

    public Project(UUID id, UUID workspaceId, String name, String description) {
        super(id);
        this.workspaceId = workspaceId;
        this.name = name;
        this.description = description == null ? "" : description;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public void update(String name, String description) {
        if (name != null && !name.isBlank()) {
            this.name = name;
        }
        if (description != null) {
            this.description = description;
        }
        this.updatedAt = Instant.now();
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}

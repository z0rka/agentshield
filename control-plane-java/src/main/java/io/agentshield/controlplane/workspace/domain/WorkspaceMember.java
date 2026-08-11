package io.agentshield.controlplane.workspace.domain;

import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import io.agentshield.controlplane.security.domain.Role;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Membership of a user in a workspace, with the role that governs everything they can do. */
@Entity
@Table(name = "workspace_member")
public class WorkspaceMember implements WorkspaceScoped {

    @Embeddable
    public record Id(
            @Column(name = "workspace_id") UUID workspaceId,
            @Column(name = "user_id") UUID userId) implements Serializable {
    }

    @EmbeddedId
    private Id id;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Role role;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected WorkspaceMember() {
    }

    public WorkspaceMember(UUID workspaceId, UUID userId, Role role) {
        this.id = new Id(
                Objects.requireNonNull(workspaceId, "workspaceId"),
                Objects.requireNonNull(userId, "userId"));
        this.role = Objects.requireNonNull(role, "role");
    }

    public UUID getWorkspaceId() {
        return id.workspaceId();
    }

    public UUID getUserId() {
        return id.userId();
    }

    public Role getRole() {
        return role;
    }

    public void changeRole(Role role) {
        this.role = role;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}

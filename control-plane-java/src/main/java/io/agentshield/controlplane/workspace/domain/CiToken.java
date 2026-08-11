package io.agentshield.controlplane.workspace.domain;

import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import io.agentshield.controlplane.shared.domain.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * A credential a CI pipeline uses to run scans.
 *
 * <p>Only the SHA-256 hash is stored. The token itself is returned once, at creation, and is
 * then unrecoverable - a leaked database must not hand an attacker working credentials for
 * every customer's pipeline.
 */
@Entity
@Table(name = "ci_token")
public class CiToken extends BaseEntity implements WorkspaceScoped {

    @Column(name = "workspace_id", nullable = false)
    private UUID workspaceId;

    @Column(name = "project_id")
    private UUID projectId;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected CiToken() {
    }

    public CiToken(
            UUID id,
            UUID workspaceId,
            UUID projectId,
            String name,
            String tokenHash,
            UUID createdBy,
            Instant expiresAt) {
        super(id);
        this.workspaceId = workspaceId;
        this.projectId = projectId;
        this.name = name;
        this.tokenHash = tokenHash;
        this.createdBy = createdBy;
        this.expiresAt = expiresAt;
    }

    public boolean isUsable(Instant now) {
        return revokedAt == null && (expiresAt == null || expiresAt.isAfter(now));
    }

    public void revoke() {
        this.revokedAt = Instant.now();
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public UUID getProjectId() {
        return projectId;
    }

    public String getName() {
        return name;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }
}

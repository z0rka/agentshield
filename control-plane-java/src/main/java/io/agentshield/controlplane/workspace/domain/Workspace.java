package io.agentshield.controlplane.workspace.domain;

import io.agentshield.controlplane.shared.domain.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** The tenant boundary. Every other tenant-scoped row carries this id. */
@Entity
@Table(name = "workspace")
public class Workspace extends BaseEntity {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "slug", nullable = false, unique = true)
    private String slug;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected Workspace() {
    }

    public Workspace(UUID id, String name, String slug) {
        super(id);
        this.name = name;
        this.slug = slug;
    }

    public String getName() {
        return name;
    }

    public void rename(String name) {
        this.name = name;
        this.updatedAt = Instant.now();
    }

    public String getSlug() {
        return slug;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}

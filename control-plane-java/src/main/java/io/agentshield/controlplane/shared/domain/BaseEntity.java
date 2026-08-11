package io.agentshield.controlplane.shared.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Base for entities with a client-assignable UUID primary key.
 *
 * <p>Ids are generated in the application, not by the database. A scan's id therefore exists
 * before the transaction commits, so the outbox event written in that same transaction can
 * already reference it. The row and the event about it have to commit together, which a
 * database-assigned key would make impossible.
 */
@MappedSuperclass
public abstract class BaseEntity {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected BaseEntity() {
        // JPA
    }

    protected BaseEntity(UUID id) {
        this.id = Objects.requireNonNull(id, "id");
    }

    @PrePersist
    void onPersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    public UUID getId() {
        return id;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    protected void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * Identity by primary key, and only once the key exists.
     *
     * <p>Comparing unsaved entities by field values makes two distinct new scans look equal
     * and quietly collapses them inside a {@code Set}.
     */
    @Override
    public final boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof BaseEntity entity) || id == null) {
            return false;
        }
        return getClass().equals(entity.getClass()) && id.equals(entity.id);
    }

    @Override
    public final int hashCode() {
        return getClass().hashCode();
    }
}

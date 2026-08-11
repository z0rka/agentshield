package io.agentshield.controlplane.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * One thing somebody did, and who they were when they did it.
 *
 * <p>The table has existed since the first migration and nothing wrote to it. That is worse
 * than not having one: a schema implies a feature, and anyone reading the migration would have
 * concluded the platform kept an audit trail.
 *
 * <p>What goes in it is narrow by design - actions that change state or start work, never
 * reads. An audit log that records every {@code GET} is a log nobody greps, and the question it
 * exists to answer is "who started this scan against that target", not "who looked".
 *
 * <p>No entity relationships. An audit row must survive the deletion of everything it refers
 * to, so the target id is a string and the actor a bare UUID; a foreign key here would let a
 * cascade erase the evidence that the thing ever existed.
 */
@Entity
@Table(name = "audit_log")
public class AuditEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    /** Null for actions taken by the platform itself, with no person behind them. */
    @Column(name = "actor_id", updatable = false)
    private UUID actorId;

    @Column(name = "action", nullable = false, updatable = false)
    private String action;

    @Column(name = "resource", nullable = false, updatable = false)
    private String resource;

    @Column(name = "resource_id", updatable = false)
    private String resourceId;

    @Column(name = "detail", nullable = false, updatable = false)
    private String detail = "{}";

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt = Instant.now();

    protected AuditEntry() {
    }

    public AuditEntry(
            UUID workspaceId,
            UUID actorId,
            String action,
            String resource,
            String resourceId,
            String detail) {
        this.workspaceId = workspaceId;
        this.actorId = actorId;
        this.action = action;
        this.resource = resource;
        this.resourceId = resourceId;
        this.detail = detail == null || detail.isBlank() ? "{}" : detail;
        this.occurredAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public UUID getActorId() {
        return actorId;
    }

    public String getAction() {
        return action;
    }

    public String getResource() {
        return resource;
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getDetail() {
        return detail;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }
}

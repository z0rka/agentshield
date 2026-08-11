package io.agentshield.controlplane.event.domain;

import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/** One event awaiting publication, written in the same transaction as the state it describes. */
@Entity
@Table(name = "outbox_entry")
public class OutboxEntry implements WorkspaceScoped {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "aggregate_type", nullable = false)
    private String aggregateType;

    @Column(name = "aggregate_id", nullable = false)
    private String aggregateId;

    @Column(name = "workspace_id", nullable = false)
    private UUID workspaceId;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(name = "event_version", nullable = false)
    private int eventVersion = EventTypes.CURRENT_VERSION;

    @Column(name = "topic", nullable = false)
    private String topic;

    /** The serialised {@link EventEnvelope}. */
    @Column(name = "payload", nullable = false)
    private String payload;

    @Column(name = "correlation_id", nullable = false)
    private String correlationId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "published_at")
    private Instant publishedAt;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "next_attempt_at", nullable = false)
    private Instant nextAttemptAt = Instant.now();

    @Column(name = "last_error")
    private String lastError;

    protected OutboxEntry() {
    }

    public OutboxEntry(
            UUID id,
            String aggregateType,
            String aggregateId,
            UUID workspaceId,
            String eventType,
            String topic,
            String payload,
            String correlationId) {
        this.id = id;
        this.aggregateType = aggregateType;
        this.aggregateId = aggregateId;
        this.workspaceId = workspaceId;
        this.eventType = eventType;
        this.topic = topic;
        this.payload = payload;
        this.correlationId = correlationId;
    }

    public void markPublished() {
        this.publishedAt = Instant.now();
        this.lastError = null;
    }

    /**
     * Records a failed publish and schedules the next attempt.
     *
     * <p>Exponential backoff capped at five minutes. Uncapped backoff on a broker outage means
     * the first event after recovery waits hours; no backoff means a hot loop against a broker
     * that is already struggling.
     */
    public void markFailed(String error, int maxAttempts) {
        this.attempts++;
        this.lastError = error == null ? null : error.substring(0, Math.min(error.length(), 500));
        long delaySeconds = Math.min((long) Math.pow(2, Math.min(attempts, 8)), 300);
        this.nextAttemptAt = Instant.now().plus(Duration.ofSeconds(delaySeconds));
    }

    public boolean isExhausted(int maxAttempts) {
        return attempts >= maxAttempts;
    }

    public UUID getId() {
        return id;
    }

    public String getAggregateId() {
        return aggregateId;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public String getEventType() {
        return eventType;
    }

    public String getTopic() {
        return topic;
    }

    public String getPayload() {
        return payload;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public int getAttempts() {
        return attempts;
    }

    public Instant getPublishedAt() {
        return publishedAt;
    }

    public String getLastError() {
        return lastError;
    }
}

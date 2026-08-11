package io.agentshield.controlplane.event.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "dead_letter")
public class DeadLetter {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "event_id")
    private UUID eventId;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(name = "topic", nullable = false)
    private String topic;

    @Column(name = "workspace_id")
    private UUID workspaceId;

    @Column(name = "payload", nullable = false)
    private String payload;

    @Column(name = "error", nullable = false)
    private String error;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected DeadLetter() {
    }

    public DeadLetter(
            UUID eventId,
            String eventType,
            String topic,
            UUID workspaceId,
            String payload,
            String error,
            int attempts) {
        id = UUID.randomUUID();
        this.eventId = eventId;
        this.eventType = eventType;
        this.topic = topic;
        this.workspaceId = workspaceId;
        this.payload = payload;
        this.error = error;
        this.attempts = attempts;
    }

    public UUID getId() {
        return id;
    }

    public UUID getEventId() {
        return eventId;
    }

    public String getEventType() {
        return eventType;
    }

    public String getError() {
        return error;
    }
}

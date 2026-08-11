package io.agentshield.controlplane.event.application;

import io.agentshield.controlplane.event.domain.EventEnvelope;
import io.agentshield.controlplane.event.domain.EventTypes;
import io.agentshield.controlplane.event.domain.OutboxEntry;
import io.agentshield.controlplane.event.repository.OutboxRepository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Records an event for publication.
 *
 * <p>{@link #publish} must be called inside the transaction that changes the state the event
 * describes. That is the whole mechanism: the row and the intent to announce it commit
 * together, so there is no window where one exists without the other.
 *
 * <p>{@code Propagation.MANDATORY} enforces it. Calling this outside a transaction is a bug,
 * and it is the kind of bug that only shows up under load months later - better to fail
 * immediately and loudly.
 */
@Component
public class OutboxPublisher {

    private final OutboxRepository outbox;
    private final ObjectMapper objectMapper;
    private final TraceContextCapture traceContext;

    public OutboxPublisher(
            OutboxRepository outbox,
            ObjectMapper objectMapper,
            TraceContextCapture traceContext) {
        this.outbox = outbox;
        this.objectMapper = objectMapper;
        this.traceContext = traceContext;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public EventEnvelope publish(
            String aggregateType,
            String aggregateId,
            UUID workspaceId,
            String eventType,
            String correlationId,
            Map<String, Object> payload) {

        var envelope = new EventEnvelope(
                UUID.randomUUID(),
                eventType,
                EventTypes.CURRENT_VERSION,
                aggregateId,
                workspaceId,
                correlationId,
                Instant.now(),
                traceContext.currentTraceparent(),
                payload == null ? Map.of() : payload);

        outbox.save(new OutboxEntry(
                envelope.eventId(),
                aggregateType,
                aggregateId,
                workspaceId,
                eventType,
                EventTypes.topicFor(eventType),
                serialise(envelope),
                correlationId));
        return envelope;
    }

    private String serialise(EventEnvelope envelope) {
        try {
            return objectMapper.writeValueAsString(envelope);
        } catch (JsonProcessingException exception) {
            // Failing the whole transaction is correct: an event that cannot be serialised
            // would leave the state change silently unannounced.
            throw new IllegalStateException(
                    "event " + envelope.eventType() + " could not be serialised", exception);
        }
    }
}

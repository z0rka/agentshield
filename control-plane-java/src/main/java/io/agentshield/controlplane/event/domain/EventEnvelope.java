package io.agentshield.controlplane.event.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * The envelope every AgentShield event carries.
 *
 * <p>Contract, not convenience - {@code contracts/events/envelope.schema.json} is the shared
 * definition, and the Python engine validates against the same file.
 *
 * <ul>
 *   <li>{@code eventId} is the idempotency key. Consumers deduplicate on it, so it must be
 *       generated once when the event is created and never regenerated on retry. An id
 *       created at publish time would defeat the entire mechanism.
 *   <li>{@code eventVersion} lets a consumer recognise a payload shape it does not understand
 *       and route it to the DLQ instead of silently misreading it.
 *   <li>{@code correlationId} threads one trace from the API call through Kafka to the engine.
 *   <li>{@code traceparent} carries W3C trace context so the engine's spans become children of
 *       the request that asked for the scan. Nullable: an event without one starts a fresh
 *       trace on the consumer instead of being rejected.
 * </ul>
 *
 * <p>Unknown fields are ignored on read so a producer running a newer version can add payload
 * fields without stopping every consumer - additive changes must not require lockstep deploys.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record EventEnvelope(
        UUID eventId,
        String eventType,
        int eventVersion,
        String aggregateId,
        UUID workspaceId,
        String correlationId,
        Instant occurredAt,
        String traceparent,
        Map<String, Object> payload) {

    public static EventEnvelope of(
            String eventType,
            String aggregateId,
            UUID workspaceId,
            String correlationId,
            Map<String, Object> payload) {
        return new EventEnvelope(
                UUID.randomUUID(),
                eventType,
                EventTypes.CURRENT_VERSION,
                aggregateId,
                workspaceId,
                correlationId,
                Instant.now(),
                null,
                payload == null ? Map.of() : payload);
    }

    public String stringPayload(String key) {
        Object value = payload.get(key);
        return value == null ? null : value.toString();
    }

    public int intPayload(String key, int fallback) {
        Object value = payload.get(key);
        return value instanceof Number number ? number.intValue() : fallback;
    }
}

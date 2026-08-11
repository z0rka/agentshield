package io.agentshield.controlplane.event.application;

import io.agentshield.controlplane.event.domain.DeadLetter;
import io.agentshield.controlplane.event.domain.EventEnvelope;
import io.agentshield.controlplane.event.domain.EventTypes;
import io.agentshield.controlplane.event.domain.OutboxEntry;
import io.agentshield.controlplane.event.repository.DeadLetterRepository;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Events that could not be delivered or processed, recorded in PostgreSQL.
 *
 * <p>The row is the half a human reads. A dead letter is something somebody has to look at,
 * and "install a Kafka client and learn the console consumer" is enough friction that nobody
 * ever does - so the rows are queryable from the same place as everything else, and carry the
 * error and the attempt count that the topic alone would not.
 *
 * <p>The other half is the {@code .dlq} topic itself, written by {@link
 * io.agentshield.controlplane.event.messaging.RetryRouter}. That is the half tooling reads:
 * replaying a parked event means republishing it, which needs the message and not a row.
 *
 * <p>This class used to claim it wrote both and wrote only the row. Saying so was worse than
 * the gap: anyone reading it would have assumed a replay path existed.
 */
@Component
public class DeadLetterRecorder {

    private final DeadLetterRepository deadLetters;

    public DeadLetterRecorder(DeadLetterRepository deadLetters) {
        this.deadLetters = deadLetters;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(OutboxEntry entry, String error) {
        deadLetters.save(new DeadLetter(
                entry.getId(),
                entry.getEventType(),
                EventTypes.Topics.dlqOf(entry.getTopic()),
                entry.getWorkspaceId(),
                entry.getPayload(),
                error == null ? "unknown" : error,
                entry.getAttempts()));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(EventEnvelope envelope, String topic, String rawPayload, String error) {
        deadLetters.save(new DeadLetter(
                envelope == null ? null : envelope.eventId(),
                envelope == null ? "unknown" : envelope.eventType(),
                EventTypes.Topics.dlqOf(topic),
                envelope == null ? null : envelope.workspaceId(),
                rawPayload,
                error,
                0));
    }
}

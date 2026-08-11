package io.agentshield.controlplane.event.application;

import io.agentshield.controlplane.event.domain.OutboxEntry;
import io.agentshield.controlplane.event.repository.OutboxRepository;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Moves committed outbox entries onto Kafka.
 *
 * <p>Delivery is at-least-once, deliberately. Making it exactly-once would require the broker
 * ack and the {@code published_at} update to be one atomic operation across two systems, which
 * is not available; the honest design is to accept duplicates and make every consumer
 * idempotent. {@link ProcessedEventGuard} is the other half of that bargain.
 *
 * <p>The entry is marked published only after the broker acknowledges. A crash between the two
 * republishes the event on the next poll - a duplicate, which consumers already handle, rather
 * than a loss, which nothing handles.
 */
@Component
public class OutboxRelay {

    private static final Logger log = LoggerFactory.getLogger(OutboxRelay.class);

    private final OutboxRepository outbox;
    private final KafkaTemplate<String, String> kafka;
    private final DeadLetterRecorder deadLetters;
    private final Counter published;
    private final Counter failed;
    private final int batchSize;
    private final int maxAttempts;

    public OutboxRelay(
            OutboxRepository outbox,
            KafkaTemplate<String, String> kafka,
            DeadLetterRecorder deadLetters,
            MeterRegistry meters,
            @Value("${agentshield.outbox.batch-size:100}") int batchSize,
            @Value("${agentshield.outbox.max-attempts:8}") int maxAttempts) {
        this.outbox = outbox;
        this.kafka = kafka;
        this.deadLetters = deadLetters;
        this.batchSize = batchSize;
        this.maxAttempts = maxAttempts;
        this.published = Counter.builder("agentshield.outbox.published").register(meters);
        this.failed = Counter.builder("agentshield.outbox.failed").register(meters);
    }

    @Scheduled(fixedDelayString = "${agentshield.outbox.poll-interval-ms:500}")
    @Transactional
    public void relay() {
        var pending = outbox.claimPending(batchSize);
        if (pending.isEmpty()) {
            return;
        }

        for (OutboxEntry entry : pending) {
            try {
                // Partitioned by aggregate id, so every event about one scan lands on the same
                // partition and is consumed in order. Ordering across scans is not needed and
                // paying for it would cost all the parallelism.
                kafka.send(entry.getTopic(), entry.getAggregateId(), entry.getPayload())
                        .get(10, TimeUnit.SECONDS);
                entry.markPublished();
                published.increment();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                entry.markFailed("interrupted", maxAttempts);
                return;
            } catch (Exception exception) {
                failed.increment();
                entry.markFailed(exception.getMessage(), maxAttempts);
                if (entry.isExhausted(maxAttempts)) {
                    log.error(
                            "outbox entry {} exhausted {} attempts, moving to dead letters",
                            entry.getId(), maxAttempts, exception);
                    deadLetters.record(entry, exception.getMessage());
                    // Marked published so the relay stops retrying; the dead_letter row is now
                    // the record of it. Leaving it pending would block nothing but would grow
                    // the partial index forever.
                    entry.markPublished();
                } else {
                    log.warn(
                            "outbox entry {} failed (attempt {}), retrying: {}",
                            entry.getId(), entry.getAttempts(), exception.getMessage());
                }
            }
        }
    }

    /** Backlog size, exported for alerting: a growing backlog means the broker is unreachable. */
    @Transactional(readOnly = true)
    public long pendingCount() {
        return outbox.countByPublishedAtIsNull();
    }

    /** Test seam: publish one entry synchronously. */
    UUID relayOne(OutboxEntry entry) throws Exception {
        kafka.send(entry.getTopic(), entry.getAggregateId(), entry.getPayload())
                .get(10, TimeUnit.SECONDS);
        entry.markPublished();
        return entry.getId();
    }
}

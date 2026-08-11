package io.agentshield.controlplane.event.application;

import io.agentshield.controlplane.event.domain.EventEnvelope;
import io.agentshield.controlplane.event.repository.ProcessedEventRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Consumer idempotency.
 *
 * <p>The relay delivers at least once, so every consumer will eventually see the same event
 * twice. Without this, a duplicate {@code security.finding.created} becomes a second finding
 * row, the CI gate reports a phantom regression, and someone stops trusting the tool.
 *
 * <p>Enforced by the database rather than by a read-then-write check: two consumers processing
 * the same duplicate concurrently would both pass a {@code SELECT} and both proceed. A unique
 * primary key cannot be raced.
 */
@Component
public class ProcessedEventGuard {

    private static final Logger log = LoggerFactory.getLogger(ProcessedEventGuard.class);

    private final ProcessedEventRepository processed;

    public ProcessedEventGuard(ProcessedEventRepository processed) {
        this.processed = processed;
    }

    /**
     * Claims an event for processing.
     *
     * @return true when this delivery is the first; false when it is a duplicate and the
     *     handler should do nothing.
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public boolean claim(EventEnvelope envelope, String consumer) {
        boolean claimed = processed.claim(
                envelope.eventId(),
                envelope.eventType(),
                consumer,
                envelope.workspaceId()) == 1;
        if (!claimed) {
            log.debug(
                    "skipping duplicate delivery of {} ({})",
                    envelope.eventType(), envelope.eventId());
        }
        return claimed;
    }
}

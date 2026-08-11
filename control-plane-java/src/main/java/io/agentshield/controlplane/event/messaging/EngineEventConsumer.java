package io.agentshield.controlplane.event.messaging;

import io.agentshield.controlplane.event.application.DeadLetterRecorder;
import io.agentshield.controlplane.event.application.EngineEventHandler;
import io.agentshield.controlplane.event.domain.EventEnvelope;
import io.agentshield.controlplane.event.domain.EventTypes;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.function.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;

/**
 * Kafka entry point for events reported by the security engine.
 *
 * <p>Intentionally thin: parse, version-check, delegate, acknowledge. All state changes live in
 * {@link EngineEventHandler} so they run inside a real transaction.
 *
 * <p>Offsets are acknowledged only after the handler returns. Acknowledging first would turn a
 * crash into silent loss - the scan would sit at RUNNING forever, with the event that would
 * have completed it already consumed.
 *
 * <p><b>Failures leave the partition.</b> A message that cannot be processed is republished by
 * {@link RetryRouter} onto {@code <topic>.retry} and, once its attempts are spent, onto
 * {@code <topic>.dlq} - then acknowledged. Retrying in place would hold the partition and
 * every event behind it, which for a scan means the completion event waiting behind the one
 * that will never succeed.
 */
@Component
public class EngineEventConsumer {

    private static final Logger log = LoggerFactory.getLogger(EngineEventConsumer.class);

    private final ObjectMapper objectMapper;
    private final EngineEventHandler handler;
    private final DeadLetterRecorder deadLetters;
    private final RetryRouter retries;

    public EngineEventConsumer(
            ObjectMapper objectMapper,
            EngineEventHandler handler,
            DeadLetterRecorder deadLetters,
            RetryRouter retries) {
        this.objectMapper = objectMapper;
        this.handler = handler;
        this.deadLetters = deadLetters;
        this.retries = retries;
    }

    @KafkaListener(
            topics = {EventTypes.Topics.SCAN_LIFECYCLE, EventTypes.Topics.ATTACK_EXECUTION},
            groupId = "control-plane-lifecycle")
    public void onLifecycleEvent(ConsumerRecord<String, String> record, Acknowledgment ack) {
        dispatch(record, ack, handler::applyLifecycle);
    }

    @KafkaListener(topics = EventTypes.Topics.FINDINGS, groupId = "control-plane-findings")
    public void onFinding(ConsumerRecord<String, String> record, Acknowledgment ack) {
        dispatch(record, ack, handler::applyFinding);
    }

    /**
     * The retry topics, consumed by the same handlers.
     *
     * <p>A separate listener and a separate group, so a backlog of retries cannot slow the
     * main flow. The handler is unchanged: a retry is the same event, and an event that
     * behaves differently on its second delivery is not idempotent, which is a defect rather
     * than something to design around.
     */
    @KafkaListener(
            topics = {
                EventTypes.Topics.SCAN_LIFECYCLE + EventTypes.Topics.RETRY_SUFFIX,
                EventTypes.Topics.ATTACK_EXECUTION + EventTypes.Topics.RETRY_SUFFIX,
                EventTypes.Topics.FINDINGS + EventTypes.Topics.RETRY_SUFFIX
            },
            groupId = "control-plane-retry")
    public void onRetry(ConsumerRecord<String, String> record, Acknowledgment ack) {
        Consumer<EventEnvelope> apply =
                record.topic().startsWith(EventTypes.Topics.FINDINGS)
                        ? handler::applyFinding
                        : handler::applyLifecycle;
        dispatch(record, ack, apply);
    }

    private void dispatch(
            ConsumerRecord<String, String> record, Acknowledgment ack, Consumer<EventEnvelope> apply) {

        EventEnvelope envelope = null;
        try {
            envelope = objectMapper.readValue(record.value(), EventEnvelope.class);

            if (envelope.eventVersion() > EventTypes.CURRENT_VERSION) {
                // A newer producer sent a shape this build does not understand. Parking it is
                // safer than guessing: a misread security event is a wrong verdict, and a wrong
                // verdict from a security tool is worse than no verdict.
                //
                // Straight to the DLQ, skipping the retry topic: retrying cannot help, because
                // nothing about this build will understand the shape on the fourth attempt
                // either. Spending the attempts would only delay the alert.
                String reason = "unsupported eventVersion " + envelope.eventVersion();
                deadLetters.record(envelope, record.topic(), record.value(), reason);
                retries.park(record, reason);
                ack.acknowledge();
                return;
            }

            apply.accept(envelope);
            ack.acknowledge();

        } catch (Exception exception) {
            log.error(
                    "failed to process {} from {}: {}",
                    envelope == null ? "unparseable event" : envelope.eventType(),
                    record.topic(),
                    exception.getMessage(),
                    exception);
            // The database row is written on the last attempt only. Recording every retry
            // would turn one broker hiccup into four rows a human has to triage.
            if (retries.isExhausted(record)) {
                deadLetters.record(envelope, record.topic(), record.value(), exception.toString());
            }
            retries.route(record, exception.toString());
            // Acknowledged after routing. Leaving the offset uncommitted would replay the same
            // poison message forever and block every event behind it on that partition.
            ack.acknowledge();
        }
    }
}

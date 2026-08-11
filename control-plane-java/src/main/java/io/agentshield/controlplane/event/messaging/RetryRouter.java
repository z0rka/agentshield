package io.agentshield.controlplane.event.messaging;

import io.agentshield.controlplane.event.domain.EventTypes;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.header.Header;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

/**
 * Moves a message that failed processing onto the retry topic, and eventually the DLQ.
 *
 * <p>A poison message must not block the partition behind it. The consumer therefore always
 * acknowledges and re-publishes elsewhere, which converts "this partition is stuck" into "this
 * one message is somewhere a human can find it".
 *
 * <p>Attempts travel in the {@code x-attempt} header and never in the payload, because the
 * payload is the event contract and retry bookkeeping is not part of it. A consumer that does
 * not know about retries reads the same event either way.
 *
 * <p><b>Why a topic and not a sleep.</b> Retrying in place holds the consumer thread and the
 * partition with it. Republishing hands the message back to the broker and lets the next one
 * through, which is the entire point of a retry topic - the delay is a side effect, the
 * unblocking is the feature.
 */
@Component
public class RetryRouter {

    private static final Logger log = LoggerFactory.getLogger(RetryRouter.class);

    /** Attempt counter, one-based on first publish to the retry topic. */
    public static final String ATTEMPT_HEADER = "x-attempt";

    /** The topic the message failed on, so the DLQ row can name where it came from. */
    public static final String ORIGIN_HEADER = "x-origin-topic";

    private final KafkaTemplate<String, String> kafka;
    private final int maxAttempts;

    public RetryRouter(
            KafkaTemplate<String, String> kafka,
            @Value("${agentshield.consumer.max-attempts:4}") int maxAttempts) {
        this.kafka = kafka;
        this.maxAttempts = maxAttempts;
    }

    /**
     * Route a failed record onward.
     *
     * @return the topic it was sent to, for logging and tests
     */
    public String route(ConsumerRecord<String, String> record, String reason) {
        int attempt = attemptOf(record) + 1;
        String origin = originOf(record);

        String destination = attempt >= maxAttempts
                ? EventTypes.Topics.dlqOf(origin)
                : EventTypes.Topics.retryOf(origin);

        publish(destination, record.key(), record.value(), attempt, origin);

        if (attempt >= maxAttempts) {
            log.error(
                    "event from {} exhausted {} attempts, parked on {}: {}",
                    origin, maxAttempts, destination, reason);
        } else {
            log.warn("event from {} failed attempt {}, retrying via {}: {}",
                    origin, attempt, destination, reason);
        }
        return destination;
    }

    /** Park a record on the DLQ without spending the remaining attempts. */
    public String park(ConsumerRecord<String, String> record, String reason) {
        String origin = originOf(record);
        String destination = EventTypes.Topics.dlqOf(origin);
        publish(destination, record.key(), record.value(), attemptOf(record), origin);
        log.error("event from {} parked on {} without retry: {}", origin, destination, reason);
        return destination;
    }

    /** Whether this record has already used up its attempts. */
    public boolean isExhausted(ConsumerRecord<String, String> record) {
        return attemptOf(record) + 1 >= maxAttempts;
    }

    public static int attemptOf(ConsumerRecord<String, String> record) {
        Header header = record.headers().lastHeader(ATTEMPT_HEADER);
        if (header == null) {
            return 0;
        }
        try {
            return Integer.parseInt(new String(header.value(), StandardCharsets.UTF_8));
        } catch (NumberFormatException exception) {
            // A malformed counter means an unknown number of previous attempts. Treating it as
            // exhausted is the safe reading: better a parked message than an infinite loop.
            return Integer.MAX_VALUE - 1;
        }
    }

    /**
     * The topic this message started on.
     *
     * <p>Read from the header when present, because after one hop {@code record.topic()} is
     * already {@code security.scan.lifecycle.retry} and suffixing that again would produce
     * {@code ....retry.retry}.
     */
    private static String originOf(ConsumerRecord<String, String> record) {
        Header header = record.headers().lastHeader(ORIGIN_HEADER);
        if (header != null) {
            return new String(header.value(), StandardCharsets.UTF_8);
        }
        return record.topic();
    }

    private void publish(String topic, String key, String payload, int attempt, String origin) {
        var message = new org.apache.kafka.clients.producer.ProducerRecord<>(topic, key, payload);
        message.headers().add(ATTEMPT_HEADER, String.valueOf(attempt).getBytes(StandardCharsets.UTF_8));
        message.headers().add(ORIGIN_HEADER, origin.getBytes(StandardCharsets.UTF_8));
        try {
            kafka.send(message).get(10, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted routing a failed event", exception);
        } catch (Exception exception) {
            // The DB row was written first, so the event is not lost. Failing here would leave
            // the offset uncommitted and replay a message we have already recorded.
            log.error("could not route a failed event to {}", topic, exception);
        }
    }
}

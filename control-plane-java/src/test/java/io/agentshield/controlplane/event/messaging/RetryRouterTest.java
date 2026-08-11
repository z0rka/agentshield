package io.agentshield.controlplane.event.messaging;

import io.agentshield.controlplane.event.domain.EventTypes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * Routing a message that could not be processed.
 *
 * <p>These exist because the topic helpers were written, documented in detail, and never
 * called. {@code retryOf} and {@code dlqOf} were dead code while the javadoc described a
 * retry-then-park flow, and {@code DeadLetterRecorder} claimed to write the DLQ topic while
 * writing only a database row. Nothing failed, which is what made it survive three stages.
 */
class RetryRouterTest {

    private final KafkaTemplate<String, String> kafka = mockTemplate();

    @SuppressWarnings("unchecked")
    private static KafkaTemplate<String, String> mockTemplate() {
        KafkaTemplate<String, String> template = mock(KafkaTemplate.class);
        when(template.send(any(ProducerRecord.class)))
                .thenReturn(CompletableFuture.completedFuture(null));
        return template;
    }

    private static ConsumerRecord<String, String> record(String topic, Integer attempt) {
        var consumed = new ConsumerRecord<>(topic, 0, 0L, "scan-1", "{}");
        if (attempt != null) {
            consumed.headers().add(
                    RetryRouter.ATTEMPT_HEADER,
                    String.valueOf(attempt).getBytes(StandardCharsets.UTF_8));
            consumed.headers().add(
                    RetryRouter.ORIGIN_HEADER,
                    EventTypes.Topics.SCAN_LIFECYCLE.getBytes(StandardCharsets.UTF_8));
        }
        return consumed;
    }

    @SuppressWarnings("unchecked")
    private ProducerRecord<String, String> lastSent() {
        var captor = ArgumentCaptor.forClass(ProducerRecord.class);
        verify(kafka).send(captor.capture());
        return captor.getValue();
    }

    @Test
    @DisplayName("a first failure goes to the retry topic, not the dead-letter queue")
    void firstFailureRetries() {
        var router = new RetryRouter(kafka, 4);

        String destination = router.route(record(EventTypes.Topics.SCAN_LIFECYCLE, null), "boom");

        assertThat(destination).isEqualTo(EventTypes.Topics.SCAN_LIFECYCLE + ".retry");
        assertThat(lastSent().topic()).isEqualTo(destination);
    }

    @Test
    @DisplayName("the attempt counter travels in a header, never in the payload")
    void attemptTravelsInAHeader() {
        var router = new RetryRouter(kafka, 4);

        router.route(record(EventTypes.Topics.SCAN_LIFECYCLE, null), "boom");

        var sent = lastSent();
        assertThat(sent.value()).isEqualTo("{}");
        assertThat(new String(
                sent.headers().lastHeader(RetryRouter.ATTEMPT_HEADER).value(),
                StandardCharsets.UTF_8))
                .isEqualTo("1");
    }

    @Test
    @DisplayName("the last attempt lands on the dead-letter topic")
    void exhaustedAttemptsPark() {
        var router = new RetryRouter(kafka, 4);

        String destination = router.route(
                record(EventTypes.Topics.SCAN_LIFECYCLE + ".retry", 3), "still broken");

        assertThat(destination).isEqualTo(EventTypes.Topics.SCAN_LIFECYCLE + ".dlq");
    }

    @Test
    @DisplayName("a retried message keeps its original topic, so suffixes never stack")
    void originIsCarried() {
        var router = new RetryRouter(kafka, 4);

        router.route(record(EventTypes.Topics.SCAN_LIFECYCLE + ".retry", 1), "boom");

        // Without the origin header this would be `security.scan.lifecycle.retry.retry`, and
        // the second hop would land on a topic nothing consumes.
        assertThat(lastSent().topic()).isEqualTo(EventTypes.Topics.SCAN_LIFECYCLE + ".retry");
    }

    @Test
    @DisplayName("an unparseable attempt counter is treated as exhausted")
    void malformedAttemptCounterParks() {
        var consumed = new ConsumerRecord<>(EventTypes.Topics.FINDINGS, 0, 0L, "scan-1", "{}");
        consumed.headers().add(
                RetryRouter.ATTEMPT_HEADER, "not-a-number".getBytes(StandardCharsets.UTF_8));
        var router = new RetryRouter(kafka, 4);

        // An unknown number of previous attempts has to read as "too many". The alternative is
        // a message that loops forever because its counter never parses.
        assertThat(router.isExhausted(consumed)).isTrue();
        assertThat(router.route(consumed, "boom"))
                .isEqualTo(EventTypes.Topics.FINDINGS + ".dlq");
    }

    @Test
    @DisplayName("parking skips the retry topic entirely")
    void parkGoesStraightToTheDeadLetterQueue() {
        var router = new RetryRouter(kafka, 4);

        String destination = router.park(
                record(EventTypes.Topics.ATTACK_EXECUTION, null), "unsupported eventVersion 9");

        // Retrying an event this build cannot parse would fail three more times and delay the
        // alert by exactly nothing.
        assertThat(destination).isEqualTo(EventTypes.Topics.ATTACK_EXECUTION + ".dlq");
    }

    @Test
    @DisplayName("a broker failure while routing does not throw")
    void brokerFailureIsSwallowed() {
        @SuppressWarnings("unchecked")
        KafkaTemplate<String, String> broken = mock(KafkaTemplate.class);
        when(broken.send(any(ProducerRecord.class)))
                .thenReturn(CompletableFuture.failedFuture(new IllegalStateException("no broker")));
        var router = new RetryRouter(broken, 4);

        // The database row is already written, so the event is not lost. Throwing here would
        // leave the offset uncommitted and replay a message we have recorded.
        assertThat(router.route(record(EventTypes.Topics.FINDINGS, null), "boom"))
                .isEqualTo(EventTypes.Topics.FINDINGS + ".retry");
    }
}

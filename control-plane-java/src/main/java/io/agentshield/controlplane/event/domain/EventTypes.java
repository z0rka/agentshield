package io.agentshield.controlplane.event.domain;

/**
 * Event types and the topics that carry them.
 *
 * <p>Topics are split by lifecycle over lumped into one stream: scan lifecycle events
 * are low-volume and ordered per scan, attack events are high-volume and independent, and
 * findings are the only ones a downstream integration is likely to want on its own. One topic
 * for everything would force every consumer to read all three.
 */
public final class EventTypes {

    private EventTypes() {
    }

    public static final int CURRENT_VERSION = 1;

    // -- scan lifecycle (produced by the control plane) --------------------------------
    public static final String SCAN_CREATED = "security.scan.created";
    public static final String SCAN_STARTED = "security.scan.started";
    public static final String SCAN_COMPLETED = "security.scan.completed";
    public static final String SCAN_FAILED = "security.scan.failed";
    public static final String SCAN_CANCELLED = "security.scan.cancelled";
    public static final String SCAN_EVALUATION_REQUESTED = "security.scan.evaluation.requested";

    // -- attack execution (control plane requests, engine reports) ---------------------
    public static final String ATTACK_REQUESTED = "security.attack.requested";
    public static final String ATTACK_COMPLETED = "security.attack.completed";
    public static final String ATTACK_FAILED = "security.attack.failed";

    // -- results (produced by the engine) ----------------------------------------------
    public static final String FINDING_CREATED = "security.finding.created";

    public static final class Topics {
        private Topics() {
        }

        public static final String SCAN_LIFECYCLE = "security.scan.lifecycle";
        public static final String ATTACK_EXECUTION = "security.attack.execution";
        public static final String FINDINGS = "security.findings";

        /**
         * Retry and dead-letter topics.
         *
         * <p>A poison message must not block the partition behind it. Failed processing moves
         * the message to the retry topic with a delay; after the configured attempts it lands
         * in the DLQ, where it waits for a human instead of spinning forever.
         */
        public static final String RETRY_SUFFIX = ".retry";
        public static final String DLQ_SUFFIX = ".dlq";

        public static String retryOf(String topic) {
            return topic + RETRY_SUFFIX;
        }

        public static String dlqOf(String topic) {
            return topic + DLQ_SUFFIX;
        }
    }

    /** The topic an event type belongs on. */
    public static String topicFor(String eventType) {
        if (eventType.startsWith("security.attack.")) {
            return Topics.ATTACK_EXECUTION;
        }
        if (eventType.startsWith("security.finding.")) {
            return Topics.FINDINGS;
        }
        return Topics.SCAN_LIFECYCLE;
    }
}

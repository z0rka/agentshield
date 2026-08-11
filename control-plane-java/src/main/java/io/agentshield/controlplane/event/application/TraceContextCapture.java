package io.agentshield.controlplane.event.application;

import io.micrometer.tracing.Tracer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Renders the active span as a W3C {@code traceparent}.
 *
 * <p>Captured when the outbox row is written, not when the relay publishes it. By publish time
 * the request that created the scan has long since returned and its span is closed, so a
 * traceparent read there would either be absent or belong to the relay's scheduled task. The
 * envelope is serialised inside the request transaction, which is the one moment the right
 * context is on the thread.
 *
 * <p>The tracer is optional. With {@code management.tracing.enabled=false} - which is how the
 * integration tests run - no bean exists, and events simply carry no trace context.
 */
@Component
public class TraceContextCapture {

    private static final String VERSION = "00";
    private static final String SAMPLED = "01";
    private static final String NOT_SAMPLED = "00";

    private final ObjectProvider<Tracer> tracers;

    public TraceContextCapture(ObjectProvider<Tracer> tracers) {
        this.tracers = tracers;
    }

    /** The current trace context, or null when tracing is off or no span is active. */
    public String currentTraceparent() {
        Tracer tracer = tracers.getIfAvailable();
        if (tracer == null) {
            return null;
        }

        var span = tracer.currentSpan();
        if (span == null) {
            return null;
        }

        var context = span.context();
        if (context.traceId() == null || context.spanId() == null) {
            return null;
        }

        String flags = Boolean.TRUE.equals(context.sampled()) ? SAMPLED : NOT_SAMPLED;
        return String.join("-", VERSION, context.traceId(), context.spanId(), flags);
    }
}

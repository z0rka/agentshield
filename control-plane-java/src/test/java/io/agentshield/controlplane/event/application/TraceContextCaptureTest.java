package io.agentshield.controlplane.event.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.micrometer.tracing.Span;
import io.micrometer.tracing.TraceContext;
import io.micrometer.tracing.Tracer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

/**
 * Rendering the active span as a traceparent.
 *
 * <p>The cases that matter are the absent ones. Tracing is off in the integration tests and in
 * any deployment that has not configured a collector, and an exception thrown here would take
 * down scan creation itself.
 */
class TraceContextCaptureTest {

    @Test
    @DisplayName("no tracer bean means no trace context, not a failure")
    void withoutATracer() {
        var capture = new TraceContextCapture(providerOf(null));

        assertThat(capture.currentTraceparent()).isNull();
    }

    @Test
    @DisplayName("a tracer with no active span yields nothing")
    void withoutASpan() {
        var tracer = mock(Tracer.class);
        when(tracer.currentSpan()).thenReturn(null);

        assertThat(new TraceContextCapture(providerOf(tracer)).currentTraceparent()).isNull();
    }

    @Test
    @DisplayName("a sampled span renders as a W3C traceparent")
    void sampledSpan() {
        var capture = new TraceContextCapture(
                providerOf(tracerWith("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", true)));

        assertThat(capture.currentTraceparent())
                .isEqualTo("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
    }

    @Test
    @DisplayName("an unsampled span is still propagated, with the flag cleared")
    void unsampledSpan() {
        var capture = new TraceContextCapture(
                providerOf(tracerWith("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", false)));

        assertThat(capture.currentTraceparent()).endsWith("-00");
    }

    @Test
    @DisplayName("a span with an incomplete context is skipped rather than half-rendered")
    void incompleteContext() {
        var capture = new TraceContextCapture(providerOf(tracerWith(null, "00f067aa0ba902b7", true)));

        assertThat(capture.currentTraceparent()).isNull();
    }

    private static Tracer tracerWith(String traceId, String spanId, boolean sampled) {
        var context = mock(TraceContext.class);
        when(context.traceId()).thenReturn(traceId);
        when(context.spanId()).thenReturn(spanId);
        when(context.sampled()).thenReturn(sampled);

        var span = mock(Span.class);
        when(span.context()).thenReturn(context);

        var tracer = mock(Tracer.class);
        when(tracer.currentSpan()).thenReturn(span);
        return tracer;
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<Tracer> providerOf(Tracer tracer) {
        var provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(tracer);
        return (ObjectProvider<Tracer>) provider;
    }
}

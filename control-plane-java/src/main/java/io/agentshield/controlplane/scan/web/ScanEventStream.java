package io.agentshield.controlplane.scan.web;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/**
 * Live scan progress over Server-Sent Events.
 *
 * <p>SSE rather than WebSockets: the traffic is one-directional, it is plain HTTP so it
 * survives every proxy in the way, and browsers reconnect on their own. A duplex protocol
 * would be strictly more machinery for a stream that never carries anything upstream.
 *
 * <p>This is a *view*, never a source of truth. A dropped connection loses updates, and a
 * reconnecting client re-reads the scan from PostgreSQL. Making the UI's correctness depend on
 * receiving every event would make a network blip look like a failed scan.
 *
 * <p>In a multi-instance deployment each instance holds only its own subscribers, so progress
 * events must reach every instance - hence the Kafka consumer that feeds this having a unique
 * group per instance. That is a stage-5 concern and is noted in docs/adr/0003.
 */
@Component
public class ScanEventStream {

    private static final Logger log = LoggerFactory.getLogger(ScanEventStream.class);
    private static final long TIMEOUT_MS = 30 * 60 * 1000L;

    private final Map<UUID, CopyOnWriteArrayList<SseEmitter>> subscribers = new ConcurrentHashMap<>();

    public SseEmitter subscribe(UUID scanId) {
        var emitter = new SseEmitter(TIMEOUT_MS);
        subscribers.computeIfAbsent(scanId, key -> new CopyOnWriteArrayList<>()).add(emitter);

        emitter.onCompletion(() -> remove(scanId, emitter));
        emitter.onTimeout(() -> remove(scanId, emitter));
        emitter.onError(error -> remove(scanId, emitter));

        try {
            // An immediate event flushes headers, so the client knows it is connected rather
            // than waiting on a proxy that buffers until the first byte.
            emitter.send(SseEmitter.event().name("subscribed").data(Map.of("scanId", scanId)));
        } catch (IOException exception) {
            remove(scanId, emitter);
        }
        return emitter;
    }

    public void emit(UUID scanId, String eventName, Object payload) {
        var emitters = subscribers.get(scanId);
        if (emitters == null || emitters.isEmpty()) {
            return;
        }
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().name(eventName).data(payload));
            } catch (IOException | IllegalStateException exception) {
                // A client that went away is ordinary, not an error worth a stack trace.
                log.debug("dropping SSE subscriber for scan {}: {}", scanId, exception.getMessage());
                remove(scanId, emitter);
            }
        }
    }

    /** Closes the stream once the scan reaches a terminal state. */
    public void complete(UUID scanId) {
        var emitters = subscribers.remove(scanId);
        if (emitters == null) {
            return;
        }
        emitters.forEach(SseEmitter::complete);
    }

    public int subscriberCount(UUID scanId) {
        var emitters = subscribers.get(scanId);
        return emitters == null ? 0 : emitters.size();
    }

    private void remove(UUID scanId, SseEmitter emitter) {
        var emitters = subscribers.get(scanId);
        if (emitters == null) {
            return;
        }
        emitters.remove(emitter);
        if (emitters.isEmpty()) {
            subscribers.remove(scanId, emitters);
        }
    }
}

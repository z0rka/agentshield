package io.agentshield.controlplane.event.application;

import io.agentshield.controlplane.event.domain.EventEnvelope;
import io.agentshield.controlplane.event.domain.EventTypes;
import io.agentshield.controlplane.finding.domain.Finding;
import io.agentshield.controlplane.finding.repository.FindingRepository;
import io.agentshield.controlplane.scan.application.ScanService;
import io.agentshield.controlplane.scan.application.TrajectoryPersistenceService;
import io.agentshield.controlplane.scan.domain.ScanStatus;
import io.agentshield.controlplane.scan.web.ScanEventStream;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Applies engine events to control-plane state.
 *
 * <p>Separate from {@link EngineEventConsumer} on purpose. Spring's {@code @Transactional} is
 * implemented with a proxy, so a method called from inside the same bean bypasses it entirely
 * and runs with no transaction - which would break the idempotency guard, since the claim and
 * the state change would no longer commit together. Putting the transactional work in its own
 * bean makes the boundary real, not nominal.
 */
@Component
public class EngineEventHandler {

    private static final Logger log = LoggerFactory.getLogger(EngineEventHandler.class);
    private static final String CONSUMER = "control-plane";

    private final ObjectMapper objectMapper;
    private final ProcessedEventGuard guard;
    private final ScanService scans;
    private final ScanEventStream stream;
    private final FindingRepository findings;
    private final TrajectoryPersistenceService trajectories;

    public EngineEventHandler(
            ObjectMapper objectMapper,
            ProcessedEventGuard guard,
            ScanService scans,
            ScanEventStream stream,
            FindingRepository findings,
            TrajectoryPersistenceService trajectories) {
        this.objectMapper = objectMapper;
        this.guard = guard;
        this.scans = scans;
        this.stream = stream;
        this.findings = findings;
        this.trajectories = trajectories;
    }

    @Transactional
    public void applyLifecycle(EventEnvelope envelope) {
        if (!guard.claim(envelope, CONSUMER)) {
            return;
        }
        var scanId = UUID.fromString(envelope.aggregateId());

        switch (envelope.eventType()) {
            case EventTypes.SCAN_STARTED -> scans.applyEngineStatus(scanId, ScanStatus.RUNNING);
            case EventTypes.SCAN_EVALUATION_REQUESTED ->
                    scans.applyEngineStatus(scanId, ScanStatus.EVALUATING);
            case EventTypes.SCAN_COMPLETED -> {
                scans.applyEngineCompletion(scanId, envelope.payload());
                stream.complete(scanId);
            }
            case EventTypes.SCAN_FAILED -> {
                scans.applyEngineFailure(scanId, envelope.payload());
                stream.complete(scanId);
            }
            case EventTypes.ATTACK_COMPLETED, EventTypes.ATTACK_FAILED -> {
                trajectories.persist(scanId, envelope.workspaceId(), envelope.payload());
                log.debug("persisted attack progress for scan {}", scanId);
            }
            default -> log.debug("no lifecycle handler for {}", envelope.eventType());
        }

        stream.emit(scanId, envelope.eventType(), envelope.payload());
    }

    @Transactional
    public void applyFinding(EventEnvelope envelope) {
        if (!guard.claim(envelope, CONSUMER)) {
            return;
        }
        var scanId = UUID.fromString(envelope.aggregateId());
        Map<String, Object> payload = envelope.payload();
        String fingerprint = String.valueOf(payload.get("fingerprint"));

        // Second line of defence. The event-id guard stops duplicate *deliveries*; this catches
        // the same defect arriving under two different event ids, which happens whenever the
        // engine retries a scenario that had already reported.
        var existing = findings.findByScanIdAndFingerprint(scanId, fingerprint);
        if (existing.isPresent()) {
            existing.get().recordOccurrence();
            return;
        }

        var finding = new Finding(
                UUID.randomUUID(),
                envelope.workspaceId(),
                scanId,
                String.valueOf(payload.getOrDefault("code", "AS-GENERIC-000")),
                String.valueOf(payload.getOrDefault("category", "TOOL_ABUSE")),
                Finding.Severity.valueOf(String.valueOf(payload.getOrDefault("severity", "MEDIUM"))),
                String.valueOf(payload.getOrDefault("title", "unnamed finding")),
                fingerprint);
        finding.describe(
                String.valueOf(payload.getOrDefault("description", "")),
                asJson(payload.get("evidence")),
                asJson(payload.get("reproduction")),
                asJson(payload.get("remediation")));
        finding.setDetectedBy(String.valueOf(payload.getOrDefault("detectedBy", "")));
        String scenarioKey = String.valueOf(payload.getOrDefault("scenarioId", ""));
        trajectories.scenarioId(scanId, scenarioKey).ifPresent(finding::setScenarioId);
        findings.save(finding);

        stream.emit(scanId, EventTypes.FINDING_CREATED, Map.of(
                "code", finding.getCode(),
                "severity", finding.getSeverity(),
                "title", finding.getTitle()));
    }

    private String asJson(Object value) {
        if (value == null) {
            return "{}";
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            return "{}";
        }
    }
}

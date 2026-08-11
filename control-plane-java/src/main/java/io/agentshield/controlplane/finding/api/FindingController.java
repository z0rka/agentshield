package io.agentshield.controlplane.finding.api;

import io.agentshield.controlplane.finding.application.FindingService;
import io.agentshield.controlplane.finding.application.RegressionBaselineService;
import io.agentshield.controlplane.finding.domain.Finding;
import io.agentshield.controlplane.scan.application.TrajectoryQueryService;
import io.agentshield.controlplane.scan.domain.TrajectoryStep;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Reading findings and turning them into regression tests. */
@RestController
@RequestMapping("/api")
public class FindingController {

    public record FindingResponse(
            UUID id,
            String code,
            String category,
            Finding.Severity severity,
            String title,
            String description,
            String evidence,
            String reproduction,
            String remediation,
            Finding.Status status,
            String fingerprint,
            String detectedBy,
            int occurrences,
            Instant firstSeenAt) {

        static FindingResponse of(Finding finding) {
            return new FindingResponse(
                    finding.getId(),
                    finding.getCode(),
                    finding.getCategory(),
                    finding.getSeverity(),
                    finding.getTitle(),
                    finding.getDescription(),
                    finding.getEvidence(),
                    finding.getReproduction(),
                    finding.getRemediation(),
                    finding.getStatus(),
                    finding.getFingerprint(),
                    finding.getDetectedBy(),
                    finding.getOccurrences(),
                    finding.getFirstSeenAt());
        }
    }

    public record ResolveRequest(Finding.Status status, String note) {
    }

    /**
     * One step of a trajectory, as stored.
     *
     * <p>The field names carry the guarantee: {@code inputRedacted} and {@code outputRedacted}
     * are the only content available, because redaction happened in the engine before the step
     * was transmitted. There is no unredacted variant to expose by accident.
     */
    public record TrajectoryStepResponse(
            int sequenceNumber,
            String stepType,
            String toolName,
            String inputRedacted,
            String outputRedacted,
            Integer durationMs,
            String traceId,
            Instant occurredAt) {

        static TrajectoryStepResponse of(TrajectoryStep step) {
            return new TrajectoryStepResponse(
                    step.getSequenceNumber(),
                    step.getStepType(),
                    step.getToolName(),
                    step.getInputRedacted(),
                    step.getOutputRedacted(),
                    step.getDurationMs(),
                    step.getTraceId(),
                    step.getOccurredAt());
        }
    }

    private final FindingService findings;
    private final TrajectoryQueryService trajectories;

    public FindingController(FindingService findings, TrajectoryQueryService trajectories) {
        this.findings = findings;
        this.trajectories = trajectories;
    }

    @GetMapping("/scans/{scanId}/findings")
    public List<FindingResponse> listForScan(@PathVariable UUID scanId) {
        return findings.listForScan(scanId).stream()
                .map(FindingResponse::of)
                .toList();
    }

    @GetMapping("/findings/{findingId}")
    public FindingResponse get(@PathVariable UUID findingId) {
        return FindingResponse.of(findings.require(findingId));
    }

    /**
     * The trajectory this finding was found in.
     *
     * <p>The evidence block cites step indices; this is what they index into. Reading a finding
     * as a timeline - retrieval, tool call, the value that travelled between them - is the
     * difference between "the scanner says this is an injection" and seeing where the argument
     * came from.
     *
     * <p>Empty when the finding has no scenario, or the scenario never produced a run. Empty is
     * reported as empty, never as an error: a scan that never reached the target is a
     * different fact from an agent that did nothing, and the caller is told which.
     */
    @GetMapping("/findings/{findingId}/trajectory")
    public List<TrajectoryStepResponse> trajectory(@PathVariable UUID findingId) {
        var finding = findings.require(findingId);
        if (finding.getScenarioId() == null) {
            return List.of();
        }
        return trajectories.forScenario(finding.getScenarioId()).stream()
                .map(TrajectoryStepResponse::of)
                .toList();
    }

    /**
     * Marks a finding resolved, accepted or a false positive.
     *
     * <p>Resolution is a claim, not a verification. Marking a finding resolved does not stop
     * the next scan reporting it: only the scan that no longer reproduces it can do that. This
     * status exists to record a decision, not to suppress evidence.
     */
    @PostMapping("/findings/{findingId}/mark-resolved")
    public FindingResponse markResolved(
            @PathVariable UUID findingId, @RequestBody(required = false) ResolveRequest request) {
        var status = request == null || request.status() == null
                ? Finding.Status.RESOLVED
                : request.status();
        return FindingResponse.of(findings.resolve(findingId, status));
    }

    /**
     * Adds this finding's fingerprint to a regression baseline.
     *
     * <p>This is the step that turns a one-off discovery into a permanent test: the next scan
     * compares against the baseline, and a known issue stops failing the build while its
     * disappearance is still tracked.
     */
    @PostMapping("/findings/{findingId}/create-regression")
    public ResponseEntity<RegressionBaselineService.BaselineResponse> createRegression(
            @PathVariable UUID findingId) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(findings.createRegression(findingId));
    }
}

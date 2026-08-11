package io.agentshield.controlplane.scan.api;

import io.agentshield.controlplane.project.application.ProjectService;
import io.agentshield.controlplane.scan.application.ScanService;
import io.agentshield.controlplane.scan.web.ScanEventStream;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/** Scan lifecycle API. */
@RestController
@RequestMapping("/api")
public class ScanController {

    public record CreateScanRequest(
            @NotNull UUID targetId,
            @NotNull UUID policyId,
            List<String> suites,
            @Min(1) @Max(1000) Integer maxScenarios,
            Integer seed) {
    }

    private final ScanService scans;
    private final ScanEventStream events;
    private final ProjectService projects;

    public ScanController(ScanService scans, ScanEventStream events, ProjectService projects) {
        this.scans = scans;
        this.events = events;
        this.projects = projects;
    }

    /**
     * Starts a scan.
     *
     * <p>{@code Idempotency-Key} is honoured: replaying the same request returns the original
     * scan with 200 and does not start a second one. Clients that retry on timeout
     * - which is every CI client - depend on this.
     */
    @PostMapping("/projects/{projectId}/scans")
    public ResponseEntity<ScanResponse> create(
            @PathVariable UUID projectId,
            @Valid @RequestBody CreateScanRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey) {

        projects.require(projectId);
        var result = scans.createWithResult(
                projectId,
                request.targetId(),
                request.policyId(),
                request.suites(),
                request.maxScenarios() == null ? 50 : request.maxScenarios(),
                request.seed() == null ? 0 : request.seed(),
                idempotencyKey);

        return ResponseEntity.status(result.replayed() ? HttpStatus.OK : HttpStatus.CREATED)
                .body(ScanResponse.of(result.scan()));
    }

    @GetMapping("/projects/{projectId}/scans")
    public List<ScanResponse> list(@PathVariable UUID projectId) {
        projects.require(projectId);
        return scans.listForProject(projectId).stream().map(ScanResponse::of).toList();
    }

    @GetMapping("/scans/{scanId}")
    public ScanResponse get(@PathVariable UUID scanId) {
        return ScanResponse.of(scans.require(scanId));
    }

    @PostMapping("/scans/{scanId}/cancel")
    public ScanResponse cancel(@PathVariable UUID scanId) {
        return ScanResponse.of(scans.cancel(scanId));
    }

    @PostMapping("/scans/{scanId}/rerun")
    public ResponseEntity<ScanResponse> rerun(@PathVariable UUID scanId) {
        return ResponseEntity.status(HttpStatus.CREATED).body(ScanResponse.of(scans.rerun(scanId)));
    }

    /**
     * Live progress.
     *
     * <p>The workspace check happens before the stream opens, so an unauthorised subscriber
     * never receives a single event.
     */
    @GetMapping(value = "/scans/{scanId}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream(@PathVariable UUID scanId) {
        scans.require(scanId);
        return events.subscribe(scanId);
    }
}

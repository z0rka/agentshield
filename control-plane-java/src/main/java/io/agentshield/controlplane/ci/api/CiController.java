package io.agentshield.controlplane.ci.api;

import io.agentshield.controlplane.finding.application.RegressionBaselineService;
import io.agentshield.controlplane.finding.domain.Finding;
import io.agentshield.controlplane.scan.api.ScanResponse;
import io.agentshield.controlplane.scan.application.ScanService;
import io.agentshield.controlplane.scan.domain.Scan;
import io.agentshield.controlplane.scan.domain.ScanStatus;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The surface a build pipeline talks to.
 *
 * <p>Shaped around what a CI job can actually do: authenticate with a token, start a scan
 * idempotently, poll, and get back a verdict it can turn into an exit code. Everything is
 * flat, so a shell script with {@code curl} and {@code jq} is a first-class client.
 *
 * <p>The gate fails on findings that are <em>new</em> relative to the baseline, never on the
 * accumulated backlog. A gate that goes red on day one because of pre-existing issues is a
 * gate that gets switched off in week one.
 */
@RestController
@RequestMapping("/api/ci")
public class CiController {

    public record CiScanRequest(
            @NotNull UUID projectId,
            @NotNull UUID targetId,
            @NotNull UUID policyId,
            List<String> suites,
            Integer maxScenarios,
            Integer seed,
            String baseline) {
    }

    /** Matches the CLI's `agentshield ci` output, so both paths report the same thing. */
    public record CiResult(
            boolean passed,
            int newCritical,
            int newHigh,
            int resolved,
            int stillOpen,
            int exitCode,
            String scanId,
            ScanStatus status,
            String message) {
    }

    private final ScanService scans;
    private final RegressionBaselineService baselines;

    public CiController(ScanService scans, RegressionBaselineService baselines) {
        this.scans = scans;
        this.baselines = baselines;
    }

    /**
     * Starts a scan from CI.
     *
     * <p>The {@code Idempotency-Key} should be the commit SHA. Re-running a job then reports on
     * the existing scan instead of launching a second wave of adversarial traffic at whatever
     * environment the pipeline points to.
     */
    @PostMapping("/scans")
    public ResponseEntity<ScanResponse> create(
            @Valid @RequestBody CiScanRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey) {

        var scan = scans.create(
                request.projectId(),
                request.targetId(),
                request.policyId(),
                request.suites(),
                request.maxScenarios() == null ? 50 : request.maxScenarios(),
                request.seed() == null ? 0 : request.seed(),
                idempotencyKey);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(ScanResponse.of(scan));
    }

    @GetMapping("/scans/{scanId}")
    public ScanResponse get(@PathVariable UUID scanId) {
        return ScanResponse.of(scans.require(scanId));
    }

    /**
     * The verdict.
     *
     * <p>While the scan is still running this returns {@code passed=false} with exit code 2 - 
     * "not finished" must never be mistaken for "clean". A pipeline polls until {@code status}
     * is terminal.
     */
    @GetMapping("/scans/{scanId}/result")
    public CiResult result(
            @PathVariable UUID scanId,
            @RequestParam(defaultValue = "HIGH") Finding.Severity failOn,
            @RequestParam(defaultValue = RegressionBaselineService.DEFAULT_NAME) String baseline) {

        Scan scan = scans.require(scanId);

        if (!scan.getStatus().isTerminal()) {
            return new CiResult(
                    false, 0, 0, 0, 0, 2, scanId.toString(), scan.getStatus(),
                    "scan is still " + scan.getStatus() + "; poll until it reaches a terminal state");
        }
        if (scan.getStatus() != ScanStatus.COMPLETED) {
            return new CiResult(
                    false, 0, 0, 0, 0, 2, scanId.toString(), scan.getStatus(),
                    "scan did not complete: " + scan.getErrorCode());
        }

        var comparison = baselines.compare(scanId, scan.getProjectId(), baseline);
        boolean blocked = comparison.blocks(failOn);

        return new CiResult(
                !blocked,
                (int) comparison.newFindings().stream()
                        .filter(f -> f.getSeverity() == Finding.Severity.CRITICAL).count(),
                (int) comparison.newFindings().stream()
                        .filter(f -> f.getSeverity() == Finding.Severity.HIGH).count(),
                comparison.resolved().size(),
                comparison.stillOpen().size(),
                blocked ? 1 : 0,
                scanId.toString(),
                scan.getStatus(),
                blocked
                        ? "new findings at or above " + failOn
                        : "no new findings at or above " + failOn);
    }

    /** Records this scan's findings as the accepted baseline. */
    @PostMapping("/scans/{scanId}/baseline")
    public RegressionBaselineService.BaselineResponse capture(
            @PathVariable UUID scanId,
            @RequestParam(defaultValue = RegressionBaselineService.DEFAULT_NAME) String name) {

        var scan = scans.require(scanId);
        return baselines.capture(scan.getProjectId(), scanId, name, scan.getPolicyId().toString());
    }
}

package io.agentshield.controlplane.finding.application;

import io.agentshield.controlplane.security.domain.Permission;

import io.agentshield.controlplane.finding.domain.Finding;
import io.agentshield.controlplane.finding.domain.RegressionBaseline;
import io.agentshield.controlplane.finding.repository.BaselineRepository;
import io.agentshield.controlplane.finding.repository.FindingRepository;
import io.agentshield.controlplane.security.access.AccessGuard;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Regression baselines: the set of findings a project has accepted for now.
 *
 * <p>This is what makes the CI gate usable. Without a baseline, the first scan of an existing
 * system fails the build and keeps failing it until every historical issue is fixed - so the
 * gate gets disabled within a day. With one, the build fails only on findings that are *new*,
 * while the known set stays visible and shrinks over time.
 *
 * <p>A baseline is pinned to a policy hash. Comparing results produced under different
 * policies is meaningless, and a comparison that silently proceeds anyway is worse than one
 * that refuses.
 */
@Service
public class RegressionBaselineService {

    public record BaselineResponse(
            UUID id, String name, String policyHash, int fingerprintCount, Instant createdAt) {

        static BaselineResponse of(RegressionBaseline baseline) {
            return new BaselineResponse(
                    baseline.getId(),
                    baseline.getName(),
                    baseline.getPolicyHash(),
                    baseline.fingerprintSet().size(),
                    baseline.getCreatedAt());
        }
    }

    /** Result of comparing a scan against a baseline. The CI gate's entire input. */
    public record Comparison(
            List<Finding> newFindings, List<String> resolved, List<Finding> stillOpen) {

        public boolean blocks(Finding.Severity failOn) {
            return newFindings.stream().anyMatch(f -> f.getSeverity().atLeast(failOn));
        }
    }

    public static final String DEFAULT_NAME = "default";

    private final BaselineRepository baselines;
    private final FindingRepository findings;
    private final AccessGuard access;

    public RegressionBaselineService(
            BaselineRepository baselines, FindingRepository findings, AccessGuard access) {
        this.baselines = baselines;
        this.findings = findings;
        this.access = access;
    }

    @Transactional
    public BaselineResponse addFinding(UUID projectId, Finding finding) {
        var principal = access.require(Permission.WRITE);
        var baseline = baselines
                .findByProjectIdAndName(projectId, DEFAULT_NAME)
                .orElseGet(() -> baselines.save(new RegressionBaseline(
                        UUID.randomUUID(),
                        principal.workspaceId(),
                        projectId,
                        finding.getScanId(),
                        DEFAULT_NAME)));

        baseline.addFingerprint(finding.getFingerprint());
        return BaselineResponse.of(baseline);
    }

    /** Records every finding of a scan as the accepted set. */
    @Transactional
    public BaselineResponse capture(UUID projectId, UUID scanId, String name, String policyHash) {
        var principal = access.require(Permission.WRITE);
        var baseline = baselines.findByProjectIdAndName(projectId, name)
                .orElseGet(() -> baselines.save(new RegressionBaseline(
                        UUID.randomUUID(), principal.workspaceId(), projectId, scanId, name)));

        var fingerprints = findings.findByScanIdOrderBySeverityAscCodeAsc(scanId).stream()
                .map(Finding::getFingerprint)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        baseline.replaceFingerprints(fingerprints);
        baseline.setPolicyHash(policyHash);
        return BaselineResponse.of(baseline);
    }

    @Transactional(readOnly = true)
    public Comparison compare(UUID scanId, UUID projectId, String baselineName) {
        var known = baselines.findByProjectIdAndName(projectId, baselineName)
                .map(RegressionBaseline::fingerprintSet)
                .orElse(Set.of());

        var current = findings.findByScanIdOrderBySeverityAscCodeAsc(scanId);
        var currentFingerprints = current.stream().map(Finding::getFingerprint).collect(
                java.util.stream.Collectors.toSet());

        var newFindings = current.stream()
                .filter(f -> !known.contains(f.getFingerprint()))
                .toList();
        var stillOpen = current.stream()
                .filter(f -> known.contains(f.getFingerprint()))
                .toList();
        var resolved = known.stream().filter(f -> !currentFingerprints.contains(f)).sorted().toList();

        return new Comparison(newFindings, resolved, stillOpen);
    }
}

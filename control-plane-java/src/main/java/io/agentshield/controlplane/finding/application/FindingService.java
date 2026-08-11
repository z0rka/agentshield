package io.agentshield.controlplane.finding.application;

import io.agentshield.controlplane.finding.domain.Finding;
import io.agentshield.controlplane.finding.repository.FindingRepository;
import io.agentshield.controlplane.scan.application.ScanService;
import io.agentshield.controlplane.security.domain.Permission;
import io.agentshield.controlplane.security.access.AccessGuard;
import io.agentshield.controlplane.shared.error.NotFoundException;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingService {

    private final FindingRepository findings;
    private final ScanService scans;
    private final RegressionBaselineService baselines;
    private final AccessGuard access;

    public FindingService(
            FindingRepository findings,
            ScanService scans,
            RegressionBaselineService baselines,
            AccessGuard access) {
        this.findings = findings;
        this.scans = scans;
        this.baselines = baselines;
        this.access = access;
    }

    @Transactional(readOnly = true)
    public List<Finding> listForScan(UUID scanId) {
        scans.require(scanId);
        return findings.findByScanIdOrderBySeverityAscCodeAsc(scanId);
    }

    @Transactional(readOnly = true)
    public Finding require(UUID findingId) {
        access.require(Permission.READ);
        return access.requireVisible(
                findings.findById(findingId)
                        .orElseThrow(() -> new NotFoundException("finding", findingId)),
                "finding",
                findingId);
    }

    @Transactional
    public Finding resolve(UUID findingId, Finding.Status status) {
        access.require(Permission.WRITE);
        var finding = require(findingId);
        finding.resolve(status == null ? Finding.Status.RESOLVED : status);
        return finding;
    }

    @Transactional
    public RegressionBaselineService.BaselineResponse createRegression(UUID findingId) {
        access.require(Permission.WRITE);
        var finding = require(findingId);
        var scan = scans.require(finding.getScanId());
        return baselines.addFinding(scan.getProjectId(), finding);
    }
}

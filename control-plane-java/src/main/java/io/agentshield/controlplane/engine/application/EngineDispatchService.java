package io.agentshield.controlplane.engine.application;

import io.agentshield.controlplane.engine.domain.EngineScanDispatch;
import io.agentshield.controlplane.policy.repository.PolicyRepository;
import io.agentshield.controlplane.scan.repository.ScanRepository;
import io.agentshield.controlplane.target.application.TargetService;
import io.agentshield.controlplane.target.repository.TargetRepository;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class EngineDispatchService {

    private final ScanRepository scans;
    private final TargetRepository targets;
    private final PolicyRepository policies;
    private final TargetService targetService;

    public EngineDispatchService(
            ScanRepository scans,
            TargetRepository targets,
            PolicyRepository policies,
            TargetService targetService) {
        this.scans = scans;
        this.targets = targets;
        this.policies = policies;
        this.targetService = targetService;
    }

    @Transactional(readOnly = true)
    public EngineScanDispatch load(UUID scanId) {
        var scan = scans.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        var target = targets.findById(scan.getTargetId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        var policy = policies.findById(scan.getPolicyId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        if (!scan.getWorkspaceId().equals(target.getWorkspaceId())
                || !scan.getWorkspaceId().equals(policy.getWorkspaceId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "scan configuration scope mismatch");
        }

        List<String> suites = scan.getSuites().isBlank()
                ? List.of()
                : Arrays.stream(scan.getSuites().split(","))
                        .map(String::trim)
                        .filter(value -> !value.isEmpty())
                        .toList();

        return new EngineScanDispatch(
                scan.getId(),
                scan.getWorkspaceId(),
                scan.getCorrelationId(),
                policy.getContent(),
                targetService.engineConfiguration(target),
                suites,
                scan.getMaxScenarios(),
                scan.getSeed());
    }
}

package io.agentshield.controlplane.scan.api;

import io.agentshield.controlplane.scan.domain.Scan;
import io.agentshield.controlplane.scan.domain.ScanStatus;

import java.time.Instant;
import java.util.UUID;

public record ScanResponse(
        UUID id,
        UUID projectId,
        UUID targetId,
        UUID policyId,
        ScanStatus status,
        String correlationId,
        int attackCount,
        int findingCount,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount,
        String errorCode,
        Instant createdAt,
        Instant startedAt,
        Instant completedAt) {

    public static ScanResponse of(Scan scan) {
        return new ScanResponse(
                scan.getId(),
                scan.getProjectId(),
                scan.getTargetId(),
                scan.getPolicyId(),
                scan.getStatus(),
                scan.getCorrelationId(),
                scan.getAttackCount(),
                scan.getFindingCount(),
                scan.getCriticalCount(),
                scan.getHighCount(),
                scan.getMediumCount(),
                scan.getLowCount(),
                scan.getErrorCode(),
                scan.getCreatedAt(),
                scan.getStartedAt(),
                scan.getCompletedAt());
    }
}

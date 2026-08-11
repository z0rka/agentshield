package io.agentshield.controlplane.scan.repository;

import io.agentshield.controlplane.scan.domain.Scan;
import io.agentshield.controlplane.scan.domain.ScanStatus;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanRepository extends JpaRepository<Scan, UUID> {

    Optional<Scan> findByWorkspaceIdAndIdempotencyKey(UUID workspaceId, String idempotencyKey);

    List<Scan> findByProjectIdOrderByCreatedAtDesc(UUID projectId);

    long countByWorkspaceIdAndStatusIn(UUID workspaceId, List<ScanStatus> statuses);

    long countByTargetIdAndStatusIn(UUID targetId, List<ScanStatus> statuses);

    List<Scan> findByStatusIn(List<ScanStatus> statuses);
}

package io.agentshield.controlplane.finding.repository;

import io.agentshield.controlplane.finding.domain.Finding;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingRepository extends JpaRepository<Finding, UUID> {

    List<Finding> findByScanIdOrderBySeverityAscCodeAsc(UUID scanId);

    Optional<Finding> findByScanIdAndFingerprint(UUID scanId, String fingerprint);

    List<Finding> findByWorkspaceIdAndFingerprint(UUID workspaceId, String fingerprint);
}

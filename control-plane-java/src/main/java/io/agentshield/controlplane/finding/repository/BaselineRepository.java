package io.agentshield.controlplane.finding.repository;

import io.agentshield.controlplane.finding.domain.RegressionBaseline;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BaselineRepository extends JpaRepository<RegressionBaseline, UUID> {

    Optional<RegressionBaseline> findByProjectIdAndName(UUID projectId, String name);

    List<RegressionBaseline> findByProjectId(UUID projectId);
}

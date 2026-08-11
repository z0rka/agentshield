package io.agentshield.controlplane.scan.repository;

import io.agentshield.controlplane.scan.domain.AttackScenario;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScenarioRepository extends JpaRepository<AttackScenario, UUID> {

    Optional<AttackScenario> findByScanIdAndScenarioKey(UUID scanId, String scenarioKey);
}

package io.agentshield.controlplane.scan.repository;

import io.agentshield.controlplane.scan.domain.AttackRun;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RunRepository extends JpaRepository<AttackRun, UUID> {

    Optional<AttackRun> findByScenarioIdAndAttempt(UUID scenarioId, int attempt);

    /**
     * The last attempt, which is the one that produced the finding.
     *
     * <p>A retried scenario has several runs and only the final one reached a verdict. Showing
     * the first would render a trajectory that does not contain the steps the finding cites.
     */
    Optional<AttackRun> findFirstByScenarioIdOrderByAttemptDesc(UUID scenarioId);
}

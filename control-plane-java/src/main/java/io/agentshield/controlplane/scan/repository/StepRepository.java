package io.agentshield.controlplane.scan.repository;

import io.agentshield.controlplane.scan.domain.TrajectoryStep;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StepRepository extends JpaRepository<TrajectoryStep, UUID> {

    boolean existsByAttackRunIdAndSequenceNumber(UUID attackRunId, int sequenceNumber);

    List<TrajectoryStep> findByAttackRunIdOrderBySequenceNumberAsc(UUID attackRunId);
}

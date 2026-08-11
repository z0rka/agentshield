package io.agentshield.controlplane.target.repository;

import io.agentshield.controlplane.target.domain.Target;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TargetRepository extends JpaRepository<Target, UUID> {

    List<Target> findByProjectIdOrderByCreatedAtDesc(UUID projectId);

    boolean existsByProjectIdAndName(UUID projectId, String name);
}

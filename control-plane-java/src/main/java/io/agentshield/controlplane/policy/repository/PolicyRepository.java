package io.agentshield.controlplane.policy.repository;

import io.agentshield.controlplane.policy.domain.SecurityPolicy;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PolicyRepository extends JpaRepository<SecurityPolicy, UUID> {

    List<SecurityPolicy> findByProjectIdOrderByCreatedAtDesc(UUID projectId);

    Optional<SecurityPolicy> findFirstByProjectIdAndNameOrderByVersionDesc(
            UUID projectId, String name);
}

package io.agentshield.controlplane.event.repository;

import io.agentshield.controlplane.event.domain.DeadLetter;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeadLetterRepository extends JpaRepository<DeadLetter, UUID> {

    List<DeadLetter> findByWorkspaceIdOrderByCreatedAtDesc(UUID workspaceId);
}

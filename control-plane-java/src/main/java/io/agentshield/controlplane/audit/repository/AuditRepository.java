package io.agentshield.controlplane.audit.repository;

import io.agentshield.controlplane.audit.domain.AuditEntry;

import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditRepository extends JpaRepository<AuditEntry, Long> {

    List<AuditEntry> findByWorkspaceIdOrderByOccurredAtDesc(UUID workspaceId, Pageable pageable);
}

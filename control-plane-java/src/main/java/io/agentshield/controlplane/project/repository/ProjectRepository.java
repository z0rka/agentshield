package io.agentshield.controlplane.project.repository;

import io.agentshield.controlplane.project.domain.Project;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectRepository extends JpaRepository<Project, UUID> {

    List<Project> findByWorkspaceIdOrderByCreatedAtDesc(UUID workspaceId);

    boolean existsByWorkspaceIdAndName(UUID workspaceId, String name);
}

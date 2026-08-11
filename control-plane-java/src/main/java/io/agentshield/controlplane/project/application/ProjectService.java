package io.agentshield.controlplane.project.application;

import io.agentshield.controlplane.project.domain.Project;
import io.agentshield.controlplane.project.repository.ProjectRepository;
import io.agentshield.controlplane.security.access.AccessGuard;
import io.agentshield.controlplane.security.domain.Permission;
import io.agentshield.controlplane.shared.error.ConflictException;
import io.agentshield.controlplane.shared.error.NotFoundException;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Projects: the unit that owns targets, policies and scans.
 *
 * <p>Every method starts by asking {@link AccessGuard} for the permission it needs and gets
 * the caller back, so the workspace used to scope the query is provably the same one the
 * permission was checked against.
 */
@Service
public class ProjectService {

    private final ProjectRepository projects;
    private final AccessGuard access;

    public ProjectService(ProjectRepository projects, AccessGuard access) {
        this.projects = projects;
        this.access = access;
    }

    @Transactional
    public Project create(String name, String description) {
        var principal = access.require(Permission.WRITE);

        if (projects.existsByWorkspaceIdAndName(principal.workspaceId(), name)) {
            throw new ConflictException(
                    "a project named '" + name + "' already exists in this workspace");
        }

        return projects.save(new Project(
                UUID.randomUUID(), principal.workspaceId(), name, description));
    }

    @Transactional(readOnly = true)
    public List<Project> list() {
        var principal = access.require(Permission.READ);
        return projects.findByWorkspaceIdOrderByCreatedAtDesc(principal.workspaceId());
    }

    /**
     * Loads a project the caller is entitled to see.
     *
     * <p>The only way other features obtain a {@link Project}. Making this the sole entry
     * point is what stops a caller reaching a repository directly and skipping the ownership
     * check.
     */
    @Transactional(readOnly = true)
    public Project require(UUID projectId) {
        access.require(Permission.READ);
        return access.requireVisible(
                projects.findById(projectId)
                        .orElseThrow(() -> new NotFoundException("project", projectId)),
                "project",
                projectId);
    }
}

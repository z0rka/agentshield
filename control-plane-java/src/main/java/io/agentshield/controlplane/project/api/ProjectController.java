package io.agentshield.controlplane.project.api;

import io.agentshield.controlplane.project.application.ProjectService;
import io.agentshield.controlplane.project.domain.Project;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Project CRUD. */
@RestController
@RequestMapping("/api/projects")
public class ProjectController {

    public record CreateProjectRequest(
            @NotBlank @Size(max = 120) String name,
            @Size(max = 2000) String description) {
    }

    public record ProjectResponse(
            UUID id, String name, String description, Instant createdAt) {

        static ProjectResponse of(Project project) {
            return new ProjectResponse(
                    project.getId(),
                    project.getName(),
                    project.getDescription(),
                    project.getCreatedAt());
        }
    }

    private final ProjectService projects;

    public ProjectController(ProjectService projects) {
        this.projects = projects;
    }

    @PostMapping
    public ResponseEntity<ProjectResponse> create(@Valid @RequestBody CreateProjectRequest request) {
        var project = projects.create(request.name(), request.description());
        return ResponseEntity.status(HttpStatus.CREATED).body(ProjectResponse.of(project));
    }

    @GetMapping
    public List<ProjectResponse> list() {
        return projects.list().stream()
                .map(ProjectResponse::of)
                .toList();
    }

    @GetMapping("/{projectId}")
    public ProjectResponse get(@PathVariable UUID projectId) {
        return ProjectResponse.of(projects.require(projectId));
    }
}

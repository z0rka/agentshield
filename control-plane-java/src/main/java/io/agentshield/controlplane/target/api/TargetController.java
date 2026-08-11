package io.agentshield.controlplane.target.api;

import io.agentshield.controlplane.project.application.ProjectService;
import io.agentshield.controlplane.target.api.dto.CreateTargetRequest;
import io.agentshield.controlplane.target.api.dto.TargetResponse;
import io.agentshield.controlplane.target.api.dto.ValidationResponse;
import io.agentshield.controlplane.target.application.TargetService;
import io.agentshield.controlplane.target.application.TargetValidationService;
import jakarta.validation.Valid;
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

/**
 * Target registration and validation.
 *
 * <p>HTTP only: bind, delegate, map to a response. Every authorisation decision and every call
 * to another system happens in the application layer, so this class has nothing in it that
 * would need re-testing if the transport changed.
 */
@RestController
@RequestMapping("/api")
public class TargetController {

    private final TargetService targets;
    private final TargetValidationService validation;
    private final ProjectService projects;

    public TargetController(
            TargetService targets, TargetValidationService validation, ProjectService projects) {
        this.targets = targets;
        this.validation = validation;
        this.projects = projects;
    }

    @PostMapping("/projects/{projectId}/targets")
    public ResponseEntity<TargetResponse> create(
            @PathVariable UUID projectId, @Valid @RequestBody CreateTargetRequest request) {

        projects.require(projectId);  // workspace check before anything is written
        var target = targets.create(
                projectId,
                request.name(),
                request.type(),
                request.adapterTypeOrDefault(),
                request.baseUrl(),
                request.configuration());

        if (request.authenticationType() != null) {
            target.setAuthenticationType(request.authenticationType());
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(TargetResponse.of(target));
    }

    @GetMapping("/projects/{projectId}/targets")
    public List<TargetResponse> list(@PathVariable UUID projectId) {
        projects.require(projectId);
        return targets.listForProject(projectId).stream().map(TargetResponse::of).toList();
    }

    @GetMapping("/targets/{targetId}")
    public TargetResponse get(@PathVariable UUID targetId) {
        return TargetResponse.of(targets.require(targetId));
    }

    @PostMapping("/targets/{targetId}/validate")
    public ValidationResponse validate(@PathVariable UUID targetId) {
        return ValidationResponse.of(validation.validate(targetId));
    }
}

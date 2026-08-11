package io.agentshield.controlplane.policy.api;

import io.agentshield.controlplane.policy.application.PolicyService;
import io.agentshield.controlplane.policy.domain.SecurityPolicy;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
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

/** Policy authoring. Every write creates a new immutable version. */
@RestController
@RequestMapping("/api")
public class PolicyController {

    public record CreatePolicyRequest(@NotBlank String name, @NotBlank String content) {
    }

    public record PolicyResponse(
            UUID id,
            UUID projectId,
            String name,
            int version,
            String contentHash,
            Instant createdAt) {

        static PolicyResponse of(SecurityPolicy policy) {
            return new PolicyResponse(
                    policy.getId(),
                    policy.getProjectId(),
                    policy.getName(),
                    policy.getVersion(),
                    policy.getContentHash(),
                    policy.getCreatedAt());
        }
    }

    private final PolicyService policies;

    public PolicyController(PolicyService policies) {
        this.policies = policies;
    }

    @PostMapping("/projects/{projectId}/policies")
    public ResponseEntity<PolicyResponse> create(
            @PathVariable UUID projectId, @Valid @RequestBody CreatePolicyRequest request) {
        var result = policies.create(projectId, request.name(), request.content());
        return ResponseEntity.status(result.replayed() ? HttpStatus.OK : HttpStatus.CREATED)
                .body(PolicyResponse.of(result.policy()));
    }

    @GetMapping("/projects/{projectId}/policies")
    public List<PolicyResponse> list(@PathVariable UUID projectId) {
        return policies.listForProject(projectId).stream()
                .map(PolicyResponse::of)
                .toList();
    }

    @GetMapping("/policies/{policyId}")
    public PolicyResponse get(@PathVariable UUID policyId) {
        return PolicyResponse.of(policies.require(policyId));
    }
}

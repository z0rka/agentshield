package io.agentshield.controlplane.policy.application;

import io.agentshield.controlplane.policy.domain.SecurityPolicy;
import io.agentshield.controlplane.policy.repository.PolicyRepository;
import io.agentshield.controlplane.project.application.ProjectService;
import io.agentshield.controlplane.security.access.AccessGuard;
import io.agentshield.controlplane.security.domain.Permission;
import io.agentshield.controlplane.shared.error.NotFoundException;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PolicyService {

    public record CreateResult(SecurityPolicy policy, boolean replayed) {
    }

    private final PolicyRepository policies;
    private final ProjectService projects;
    private final AccessGuard access;

    public PolicyService(
            PolicyRepository policies, ProjectService projects, AccessGuard access) {
        this.policies = policies;
        this.projects = projects;
        this.access = access;
    }

    @Transactional
    public CreateResult create(UUID projectId, String name, String content) {
        var principal = access.require(Permission.WRITE);
        projects.require(projectId);

        var previous = policies.findFirstByProjectIdAndNameOrderByVersionDesc(projectId, name);
        if (previous.isPresent()
                && previous.get().getContentHash().equals(SecurityPolicy.hash(content))) {
            return new CreateResult(previous.get(), true);
        }

        int nextVersion = previous.map(policy -> policy.getVersion() + 1).orElse(1);
        var policy = policies.save(new SecurityPolicy(
                UUID.randomUUID(),
                principal.workspaceId(),
                projectId,
                name,
                nextVersion,
                content));
        return new CreateResult(policy, false);
    }

    @Transactional(readOnly = true)
    public List<SecurityPolicy> listForProject(UUID projectId) {
        projects.require(projectId);
        return policies.findByProjectIdOrderByCreatedAtDesc(projectId);
    }

    @Transactional(readOnly = true)
    public SecurityPolicy require(UUID policyId) {
        access.require(Permission.READ);
        return access.requireVisible(
                policies.findById(policyId)
                        .orElseThrow(() -> new NotFoundException("policy", policyId)),
                "policy",
                policyId);
    }
}

package io.agentshield.controlplane.target.api.dto;

import io.agentshield.controlplane.target.domain.Target;
import io.agentshield.controlplane.target.domain.TargetType;
import java.time.Instant;
import java.util.UUID;

/**
 * A target as the API exposes it.
 *
 * <p>Note what is absent: the encrypted configuration and anything derived from it. Only
 * {@code configurationHash} leaves the service, which is enough to correlate a scan with the
 * target shape that produced it and useless to anyone who intercepts it.
 */
public record TargetResponse(
        UUID id,
        UUID projectId,
        String name,
        TargetType type,
        String adapterType,
        String baseUrl,
        String authenticationType,
        String configurationHash,
        boolean enabled,
        Instant createdAt) {

    public static TargetResponse of(Target target) {
        return new TargetResponse(
                target.getId(),
                target.getProjectId(),
                target.getName(),
                target.getType(),
                target.getAdapterType(),
                target.getBaseUrl(),
                target.getAuthenticationType(),
                target.getConfigurationHash(),
                target.isEnabled(),
                target.getCreatedAt());
    }
}

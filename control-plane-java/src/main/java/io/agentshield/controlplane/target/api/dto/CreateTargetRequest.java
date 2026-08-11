package io.agentshield.controlplane.target.api.dto;

import io.agentshield.controlplane.target.domain.TargetType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Map;

/**
 * Registration of a system under test.
 *
 * @param configuration adapter configuration. Secret keys are encrypted at rest and are never
 *     returned by any endpoint - see {@code TargetService.SECRET_KEYS}.
 */
public record CreateTargetRequest(
        @NotBlank String name,
        @NotNull TargetType type,
        String adapterType,
        @NotBlank String baseUrl,
        String authenticationType,
        Map<String, Object> configuration) {

    /** The adapter to use, falling back to the one the target type implies. */
    public String adapterTypeOrDefault() {
        return adapterType == null || adapterType.isBlank() ? type.defaultAdapter() : adapterType;
    }
}

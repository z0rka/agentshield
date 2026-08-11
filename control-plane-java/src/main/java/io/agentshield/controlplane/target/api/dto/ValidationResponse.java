package io.agentshield.controlplane.target.api.dto;

import io.agentshield.controlplane.target.application.TargetValidationService.ValidationResult;
import java.util.List;

/** Result of a connectivity check, as the API exposes it. */
public record ValidationResponse(
        boolean reachable,
        String adapterType,
        List<String> discoveredTools,
        List<String> warnings,
        String message) {

    public static ValidationResponse of(ValidationResult result) {
        return new ValidationResponse(
                result.reachable(),
                result.adapterType(),
                result.discoveredTools(),
                result.warnings(),
                result.message());
    }
}

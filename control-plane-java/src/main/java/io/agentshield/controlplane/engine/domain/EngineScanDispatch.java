package io.agentshield.controlplane.engine.domain;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public record EngineScanDispatch(
        UUID scanId,
        UUID workspaceId,
        String correlationId,
        String policyContent,
        Map<String, Object> targetConfig,
        List<String> suites,
        int maxScenarios,
        int seed) {
}

package io.agentshield.controlplane.engine.application;

import io.agentshield.controlplane.shared.error.DependencyUnavailableException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/** Narrow HTTP client for adapter operations that are owned by the Python engine. */
@Service
public class EngineClient {

    public record Discovery(List<String> tools, List<String> warnings) {
    }

    private final RestClient client;

    public EngineClient(
            RestClient.Builder builder,
            @Value("${agentshield.engine.base-url}") String baseUrl,
            @Value("${agentshield.internal-token}") String internalToken) {
        this.client = builder.baseUrl(baseUrl)
                .defaultHeader("X-AgentShield-Internal-Token", internalToken)
                .build();
    }

    @SuppressWarnings("unchecked")
    public Discovery discover(Map<String, Object> targetConfiguration) {
        try {
            Map<String, Object> response = client.post()
                    .uri("/discover")
                    .body(Map.of("target_config", targetConfiguration))
                    .retrieve()
                    .body(Map.class);
            if (response == null || !(response.get("capabilities") instanceof Map<?, ?> raw)) {
                throw new DependencyUnavailableException("engine returned no capability document");
            }

            Map<String, Object> capabilities = (Map<String, Object>) raw;
            var tools = new ArrayList<String>();
            if (capabilities.get("tools") instanceof List<?> rawTools) {
                for (Object item : rawTools) {
                    if (item instanceof Map<?, ?> tool && tool.get("name") != null) {
                        tools.add(tool.get("name").toString());
                    }
                }
            }

            var warnings = new ArrayList<String>();
            if (!Boolean.TRUE.equals(capabilities.get("supports_trajectory"))) {
                warnings.add("target does not expose trajectory data; tool-level coverage is reduced");
            }
            return new Discovery(List.copyOf(tools), List.copyOf(warnings));
        } catch (RestClientException exception) {
            throw new DependencyUnavailableException("security engine could not validate the target");
        }
    }
}

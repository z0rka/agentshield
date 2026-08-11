package io.agentshield.controlplane.scan.application;

import io.agentshield.controlplane.scan.domain.AttackRun;
import io.agentshield.controlplane.scan.domain.AttackScenario;
import io.agentshield.controlplane.scan.domain.TrajectoryStep;
import io.agentshield.controlplane.scan.repository.RunRepository;
import io.agentshield.controlplane.scan.repository.ScenarioRepository;
import io.agentshield.controlplane.scan.repository.StepRepository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Idempotently persists the already-redacted trajectory carried by an attack event. */
@Service
public class TrajectoryPersistenceService {

    private final ScenarioRepository scenarios;
    private final RunRepository runs;
    private final StepRepository steps;
    private final ObjectMapper objectMapper;

    public TrajectoryPersistenceService(
            ScenarioRepository scenarios,
            RunRepository runs,
            StepRepository steps,
            ObjectMapper objectMapper) {
        this.scenarios = scenarios;
        this.runs = runs;
        this.steps = steps;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public void persist(UUID scanId, UUID workspaceId, Map<String, Object> payload) {
        Map<String, Object> scenarioPayload = map(payload.get("scenario"));
        String scenarioKey = string(scenarioPayload, "key", "");
        if (scenarioKey.isBlank()) {
            return;
        }

        var scenario = scenarios.findByScanIdAndScenarioKey(scanId, scenarioKey)
                .orElseGet(() -> scenarios.save(new AttackScenario(
                        UUID.randomUUID(),
                        workspaceId,
                        scanId,
                        scenarioKey,
                        string(scenarioPayload, "category", "TOOL_ABUSE"),
                        string(scenarioPayload, "name", scenarioKey),
                        string(scenarioPayload, "templateId", ""),
                        json(scenarioPayload.get("payload")),
                        json(scenarioPayload.get("expectedPolicy")),
                        integer(scenarioPayload, "seed", 0),
                        string(scenarioPayload, "status", "PENDING"))));

        Map<String, Object> runPayload = map(payload.get("run"));
        int attempt = integer(runPayload, "attempt", 1);
        var run = runs.findByScenarioIdAndAttempt(scenario.getId(), attempt)
                .orElseGet(() -> runs.save(new AttackRun(
                        UUID.randomUUID(),
                        workspaceId,
                        scenario.getId(),
                        attempt,
                        string(runPayload, "status", "TARGET_ERROR"),
                        nullableString(runPayload.get("targetSessionId")),
                        integer(runPayload, "inputTokens", 0),
                        integer(runPayload, "outputTokens", 0),
                        decimal(runPayload.get("estimatedCostUsd")))));

        Object rawSteps = payload.get("steps");
        if (!(rawSteps instanceof List<?> stepPayloads)) {
            return;
        }
        for (Object rawStep : stepPayloads) {
            Map<String, Object> step = map(rawStep);
            int sequence = integer(step, "sequenceNumber", -1);
            if (sequence < 0 || steps.existsByAttackRunIdAndSequenceNumber(run.getId(), sequence)) {
                continue;
            }
            steps.save(new TrajectoryStep(
                    UUID.randomUUID(),
                    workspaceId,
                    run.getId(),
                    sequence,
                    string(step, "stepType", "ERROR"),
                    nullableString(step.get("toolName")),
                    string(step, "inputRedacted", ""),
                    string(step, "outputRedacted", ""),
                    nullableInteger(step.get("durationMs")),
                    nullableString(step.get("traceId")),
                    instant(step.get("occurredAt"))));
        }
    }

    @Transactional(readOnly = true)
    public Optional<UUID> scenarioId(UUID scanId, String scenarioKey) {
        return scenarios.findByScanIdAndScenarioKey(scanId, scenarioKey).map(AttackScenario::getId);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return value instanceof Map<?, ?> raw ? (Map<String, Object>) raw : Map.of();
    }

    private static String string(Map<String, Object> value, String key, String fallback) {
        Object raw = value.get(key);
        return raw == null ? fallback : raw.toString();
    }

    private static String nullableString(Object value) {
        return value == null ? null : value.toString();
    }

    private static int integer(Map<String, Object> value, String key, int fallback) {
        Object raw = value.get(key);
        return raw instanceof Number number ? number.intValue() : fallback;
    }

    private static Integer nullableInteger(Object value) {
        return value instanceof Number number ? number.intValue() : null;
    }

    private static BigDecimal decimal(Object value) {
        return value instanceof Number number
                ? BigDecimal.valueOf(number.doubleValue())
                : BigDecimal.ZERO;
    }

    private static Instant instant(Object value) {
        try {
            return value == null ? Instant.now() : Instant.parse(value.toString());
        } catch (DateTimeParseException exception) {
            return Instant.now();
        }
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        } catch (JsonProcessingException exception) {
            return "{}";
        }
    }
}

"""Build redacted Kafka payloads from completed scenario executions."""

from __future__ import annotations

import json
from typing import Any

from agentshield.graph.state import ScanState
from agentshield.models.policy import SecurityPolicy
from agentshield.redaction import redact, redact_value


def attack_payload(state: ScanState, execution: Any) -> dict[str, Any]:
    secrets = _known_secrets(state, execution)
    scenario = execution.scenario
    payload: dict[str, Any] = {
        "scanId": state.scan_id,
        "scenario": {
            "key": scenario.id,
            "category": str(scenario.category),
            "name": scenario.name,
            "templateId": scenario.template_id,
            "payload": scenario.payload.model_dump(mode="json"),
            "expectedPolicy": scenario.expected.model_dump(mode="json"),
            "seed": scenario.seed,
            "status": str(execution.status),
        },
        "run": {
            "attempt": execution.attempts,
            "status": str(execution.status),
            "targetSessionId": execution.session_id,
            "inputTokens": execution.trajectory.input_tokens if execution.trajectory else 0,
            "outputTokens": execution.trajectory.output_tokens if execution.trajectory else 0,
            "estimatedCostUsd": (
                execution.trajectory.estimated_cost_usd if execution.trajectory else 0.0
            ),
            "durationSeconds": execution.duration_seconds,
            "error": execution.error,
        },
        "steps": [],
    }
    if execution.trajectory is not None:
        payload["steps"] = [
            {
                "sequenceNumber": step.sequence_number,
                "stepType": str(step.step_type),
                "toolName": step.tool_name,
                "inputRedacted": step.content,
                "outputRedacted": json.dumps(step.data, default=str, sort_keys=True),
                "durationMs": step.duration_ms,
                "traceId": step.trace_id,
                "occurredAt": step.timestamp.isoformat(),
            }
            for step in execution.trajectory.steps
        ]
    return redact_object(payload, state.policy, secrets)


def finding_payload(state: ScanState, finding: Any) -> dict[str, Any]:
    payload = finding.model_dump(mode="json")
    payload.update(
        {
            "scanId": state.scan_id,
            "scenarioId": finding.scenario_id,
            "detectedBy": ",".join(finding.detected_by),
        }
    )
    return redact_object(payload, state.policy, _known_secrets(state, None))


def redact_object(value: Any, policy: SecurityPolicy, secrets: list[str]) -> Any:
    patterns = [(pattern.name, pattern.regex) for pattern in policy.canary_patterns()]
    if isinstance(value, str):
        return redact(redact_value(value, secrets), patterns)
    if isinstance(value, dict):
        return {str(key): redact_object(item, policy, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_object(item, policy, secrets) for item in value]
    return value


def _known_secrets(state: ScanState, execution: Any | None) -> list[str]:
    values: list[str] = []
    for pattern in state.policy.canary_patterns():
        if not any(char in pattern.regex for char in ".*+?[]()|\\^$"):
            values.append(pattern.regex)
    if execution is not None:
        values.extend(execution.scenario.expected.forbidden_values)
    return values

"""Wire-level contracts shared by the worker's transports and orchestration."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

SCAN_CREATED = "security.scan.created"
SCAN_CANCELLED = "security.scan.cancelled"
SCAN_STARTED = "security.scan.started"
SCAN_EVALUATION_REQUESTED = "security.scan.evaluation.requested"
SCAN_COMPLETED = "security.scan.completed"
SCAN_FAILED = "security.scan.failed"
ATTACK_COMPLETED = "security.attack.completed"
ATTACK_FAILED = "security.attack.failed"
FINDING_CREATED = "security.finding.created"

TOPICS = {
    SCAN_CREATED: "security.scan.lifecycle",
    SCAN_CANCELLED: "security.scan.lifecycle",
    SCAN_STARTED: "security.scan.lifecycle",
    SCAN_EVALUATION_REQUESTED: "security.scan.lifecycle",
    SCAN_COMPLETED: "security.scan.lifecycle",
    SCAN_FAILED: "security.scan.lifecycle",
    ATTACK_COMPLETED: "security.attack.execution",
    ATTACK_FAILED: "security.attack.execution",
    FINDING_CREATED: "security.findings",
}


class EventEnvelope(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    event_id: uuid.UUID = Field(alias="eventId")
    event_type: str = Field(alias="eventType")
    event_version: int = Field(default=1, alias="eventVersion")
    aggregate_id: str = Field(alias="aggregateId")
    workspace_id: uuid.UUID = Field(alias="workspaceId")
    correlation_id: str = Field(alias="correlationId")
    occurred_at: datetime = Field(alias="occurredAt")
    #: W3C trace context, so the work this event triggers joins the trace that produced it.
    #: Optional: an event without one starts a fresh trace rather than being dropped.
    traceparent: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    def wire(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, mode="json")


class ScanDispatch(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    scan_id: str = Field(alias="scanId")
    workspace_id: uuid.UUID = Field(alias="workspaceId")
    correlation_id: str = Field(alias="correlationId")
    policy_content: str = Field(alias="policyContent")
    target_config: dict[str, Any] = Field(alias="targetConfig")
    suites: list[str] = Field(default_factory=list)
    max_scenarios: int = Field(default=50, alias="maxScenarios")
    seed: int = 0


class EventPublisher(Protocol):
    async def publish(self, envelope: EventEnvelope) -> None: ...


class DispatchClient(Protocol):
    async def fetch(self, scan_id: str) -> ScanDispatch: ...

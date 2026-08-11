"""Adapter for agents that answer asynchronously.

    POST /jobs                  -> {"job_id": ...}
    GET  /jobs/{id}             -> {"status": ..., "output": ..., "steps": [...]}
    GET  /jobs/{id}/events      -> newline-delimited progress
    POST /jobs/{id}/approval    -> resolve a pending human-approval gate

The protocol matters more than the transport. A synchronous agent finishes inside one request,
so "did it wait for approval?" is answerable from the ordering of steps in a trajectory. An
asynchronous one parks: it emits an approval request, the job sits in `AWAITING_APPROVAL`, and
whether the action was safe depends on what the job did between asking and being answered.

That window is the whole reason this adapter is not just `RestAgentAdapter` with a loop. It
**does not answer** the approval it is offered, by design. A job that proceeds while nobody
has replied has bypassed its own gate, and the only way to observe that is to leave the gate
unanswered and watch. `respond_to_approval()` exists for scenarios that need the opposite - a
granted token, replayed or scoped to the wrong action - and is never called automatically.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import suppress
from typing import Any

import httpx

from agentshield.adapters.base import (
    BaseTargetAdapter,
    TargetCapabilities,
    TargetError,
    ToolDescriptor,
)
from agentshield.models.common import StepType
from agentshield.models.scenario import AttackPayload, SessionContext, TargetResponse
from agentshield.models.trajectory import TrajectoryStep

DEFAULT_TIMEOUT = 30.0

#: How long to wait for a job to leave a non-terminal state before calling it hung. A hung
#: agent is itself a finding, so this returns what it has over raising.
DEFAULT_POLL_SECONDS = 20.0

#: Gap between polls. Long enough not to hammer the target, short enough that a fast job does
#: not pay for the slow case.
POLL_INTERVAL = 0.25

#: States that mean the job stopped. `AWAITING_APPROVAL` is not among them: it is the state
#: this adapter is most interested in, and it is not an ending.
TERMINAL_STATES = frozenset({"completed", "succeeded", "failed", "cancelled", "error"})


class AsyncAgentAdapter(BaseTargetAdapter):
    """Drives a job-based agent and reconstructs its trajectory."""

    adapter_type = "async_agent"

    def __init__(
        self,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.poll_seconds = poll_seconds
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=self.base_url, headers=headers or {}, timeout=timeout
        )
        #: session id -> job id. A session here is one job; the indirection exists so the
        #: engine's session vocabulary works unchanged.
        self._jobs: dict[str, str] = {}
        self._contexts: dict[str, SessionContext] = {}
        self._final: dict[str, dict[str, Any]] = {}

    async def discover_capabilities(self) -> TargetCapabilities:
        """Read the manifest if there is one; assume nothing if there is not."""
        try:
            data = await self._request("GET", "/jobs/capabilities")
        except TargetError:
            # An async agent that publishes no manifest still yields steps, so trajectory
            # support stays true. Claiming tools it never declared would not.
            return TargetCapabilities(supports_trajectory=True, supports_approval=True)

        return TargetCapabilities(
            tools=[ToolDescriptor(**tool) for tool in data.get("tools", [])],
            channels=data.get("channels", []),
            supports_trajectory=True,
            supports_reset=bool(data.get("supports_reset", False)),
            supports_approval=bool(data.get("supports_approval", True)),
            supports_tenant_override=bool(data.get("supports_tenant_override", False)),
            target_version=data.get("version"),
        )

    async def start_session(self, context: SessionContext) -> str:
        """No job yet. A job is created by the input, so this only reserves the id."""
        self._contexts[context.correlation_id] = context
        return context.correlation_id

    async def send_input(self, session_id: str, payload: AttackPayload) -> TargetResponse:
        context = self._contexts.get(session_id)
        started = time.perf_counter()

        body: dict[str, Any] = {
            "input": payload.prompt,
            "metadata": payload.metadata,
            "correlation_id": session_id,
        }
        if context is not None and context.tenant_id:
            body["tenant_id"] = context.tenant_id
        if payload.injections:
            # Planting is part of job creation for this protocol: there is no session to plant
            # into beforehand, so the artifacts travel with the request that starts the work.
            body["artifacts"] = [artifact.model_dump() for artifact in payload.injections]

        created = await self._request("POST", "/jobs", json=body)
        job_id = created.get("job_id") or created.get("id")
        if not job_id:
            raise TargetError("target did not return a job_id", retryable=False)

        self._jobs[session_id] = str(job_id)
        final = await self._await_settled(str(job_id))
        self._final[session_id] = final

        usage = final.get("usage", {}) or {}
        return TargetResponse(
            session_id=session_id,
            output=str(final.get("output", "")),
            raw=final,
            status_code=200,
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            estimated_cost_usd=float(usage.get("estimated_cost_usd", 0.0)),
            duration_seconds=time.perf_counter() - started,
        )

    async def get_trajectory(self, session_id: str) -> list[TrajectoryStep]:
        job_id = self._jobs.get(session_id)
        if job_id is None:
            return []

        final = self._final.get(session_id)
        if final is None or "steps" not in final:
            final = await self._request("GET", f"/jobs/{job_id}")

        return [
            _step_from_dict(index, raw) for index, raw in enumerate(final.get("steps", []) or [])
        ]

    def observed_tenant(self, session_id: str) -> str | None:
        final = self._final.get(session_id) or {}
        tenant = final.get("tenant_id")
        return str(tenant) if isinstance(tenant, (str, int)) and str(tenant).strip() else None

    async def reset(self, session_id: str) -> None:
        job_id = self._jobs.pop(session_id, None)
        self._contexts.pop(session_id, None)
        self._final.pop(session_id, None)
        if job_id is not None:
            # Best effort. A target that keeps finished jobs is not misbehaving, and failing a
            # scenario over cleanup would turn a housekeeping detail into a finding.
            with suppress(TargetError):
                await self._request("POST", f"/jobs/{job_id}/cancel")

    async def respond_to_approval(
        self, session_id: str, *, approved: bool, approval_id: str | None = None
    ) -> dict[str, Any]:
        """Answer a pending gate. Never called by the normal flow.

        Scenarios that test approval *reuse* or *scope* need a genuine grant to misuse, which
        is what this is for. Calling it by default would destroy the more important
        observation: whether the job proceeded while nobody had answered.
        """
        job_id = self._jobs.get(session_id)
        if job_id is None:
            raise TargetError("no job for this session", retryable=False)

        body: dict[str, Any] = {"approved": approved}
        if approval_id:
            body["approval_id"] = approval_id
        return await self._request("POST", f"/jobs/{job_id}/approval", json=body)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- internals -----------------------------------------------------------------

    async def _await_settled(self, job_id: str) -> dict[str, Any]:
        """Poll until the job stops, or until it has clearly parked.

        Two endings, and they are different findings. A job that reaches a terminal state is
        judged on what it did. A job still running when the budget expires is a hung agent,
        which is a finding in its own right - so the trajectory so far is returned rather than
        an exception raised, because a timeout that discards the evidence is a timeout that
        hides the bug.
        """
        deadline = time.monotonic() + self.poll_seconds
        latest: dict[str, Any] = {}

        while time.monotonic() < deadline:
            latest = await self._request("GET", f"/jobs/{job_id}")
            status = str(latest.get("status", "")).lower()

            if status in TERMINAL_STATES:
                return latest

            if status == "awaiting_approval":
                # Parked, waiting for a human who is not coming. That is the state the scan
                # wants to observe, and waiting out the clock would only add latency.
                return latest

            await asyncio.sleep(POLL_INTERVAL)

        latest.setdefault("status", "timeout")
        latest["timed_out"] = True
        return latest

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise TargetError(f"target timed out: {exc}", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise TargetError(f"target unreachable: {exc}", retryable=True) from exc

        if response.status_code >= 500:
            raise TargetError(
                f"target returned {response.status_code}",
                retryable=True,
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise TargetError(
                f"target rejected request: {response.status_code} {response.text[:200]}",
                retryable=False,
                status_code=response.status_code,
            )
        if not response.content:
            return {}
        payload = response.json()
        return payload if isinstance(payload, dict) else {"output": payload}


def _step_from_dict(index: int, raw: dict[str, Any]) -> TrajectoryStep:
    return TrajectoryStep(
        sequence_number=int(raw.get("sequence_number", index)),
        step_type=StepType(raw.get("step_type", StepType.MODEL_OUTPUT)),
        tool_name=raw.get("tool_name"),
        content=str(raw.get("content", "")),
        data=raw.get("data", {}) or {},
        duration_ms=raw.get("duration_ms"),
        trace_id=raw.get("trace_id"),
        source=raw.get("source"),
        error=raw.get("error"),
    )

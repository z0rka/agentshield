"""Adapters for HTTP-exposed agents.

Two levels of fidelity:

* `AgentShieldProtocolAdapter` - for targets that implement the small AgentShield inspection
  protocol (`/agentshield/*`). Gives a full trajectory and content planting, so every suite
  applies. The demo targets implement it; adding it to a real app is roughly 60 lines.
* `RestAgentAdapter` - for any existing HTTP agent, configured with a request template and a
  response path. Output-only fidelity unless the app happens to return its own steps.

The generic adapter exists because requiring instrumentation before you can be scanned is a
non-starter; the protocol adapter exists because output-only testing cannot prove anything
about tool calls.
"""

from __future__ import annotations

import time
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


class AgentShieldProtocolAdapter(BaseTargetAdapter):
    """Talks the AgentShield inspection protocol.

    ```
    GET  /agentshield/manifest                    -> tools, channels, version
    POST /agentshield/sessions                    -> {"session_id": "..."}
    POST /agentshield/sessions/{id}/inject        -> plant artifacts into a channel
    POST /agentshield/sessions/{id}/messages      -> run one turn
    GET  /agentshield/sessions/{id}/trajectory    -> ordered steps
    POST /agentshield/sessions/{id}/reset         -> drop session state
    ```
    """

    adapter_type = "rest_agentshield"

    def __init__(
        self,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=self.base_url, headers=headers or {}, timeout=timeout
        )
        #: Tenant the target reported per session. The protocol has always returned it; this
        #: adapter used to read past it, which left every trajectory unattributed unless the
        #: operator happened to pass `--tenant`.
        self._session_tenants: dict[str, str] = {}

    async def discover_capabilities(self) -> TargetCapabilities:
        data = await self._request("GET", "/agentshield/manifest")
        return TargetCapabilities(
            tools=[ToolDescriptor(**t) for t in data.get("tools", [])],
            channels=data.get("channels", []),
            supports_trajectory=True,
            supports_reset=True,
            supports_approval=bool(data.get("supports_approval", False)),
            supports_tenant_override=bool(data.get("supports_tenant_override", False)),
            target_version=data.get("version"),
        )

    async def start_session(self, context: SessionContext) -> str:
        data = await self._request(
            "POST",
            "/agentshield/sessions",
            json={
                "tenant_id": context.tenant_id,
                "actor": context.actor,
                "correlation_id": context.correlation_id,
                "metadata": context.metadata,
            },
        )
        session_id = data.get("session_id")
        if not session_id:
            raise TargetError("target did not return a session_id", retryable=False)
        self._remember_tenant(str(session_id), data)
        return str(session_id)

    async def send_input(self, session_id: str, payload: AttackPayload) -> TargetResponse:
        # Plant first, then ask an innocent question. Order is the whole point of indirect
        # injection: the malicious content must already be in the corpus when the agent reads it.
        for artifact in payload.injections:
            await self._request(
                "POST",
                f"/agentshield/sessions/{session_id}/inject",
                json=artifact.model_dump(),
            )

        started = time.perf_counter()
        data = await self._request(
            "POST",
            f"/agentshield/sessions/{session_id}/messages",
            json={"message": payload.prompt, "metadata": payload.metadata},
        )
        usage = data.get("usage", {}) or {}
        return TargetResponse(
            session_id=session_id,
            output=str(data.get("output", "")),
            raw=data,
            status_code=200,
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            estimated_cost_usd=float(usage.get("estimated_cost_usd", 0.0)),
            duration_seconds=time.perf_counter() - started,
        )

    async def get_trajectory(self, session_id: str) -> list[TrajectoryStep]:
        data = await self._request("GET", f"/agentshield/sessions/{session_id}/trajectory")
        # Re-read the tenant here as well as at session start: a target that switches principal
        # mid-session should be reported as the tenant it *finished* as, and a target that only
        # attributes its trajectory still gets attributed.
        self._remember_tenant(session_id, data)
        return [_step_from_dict(index, raw) for index, raw in enumerate(data.get("steps", []))]

    def observed_tenant(self, session_id: str) -> str | None:
        return self._session_tenants.get(session_id)

    async def reset(self, session_id: str) -> None:
        self._session_tenants.pop(session_id, None)
        await self._request("POST", f"/agentshield/sessions/{session_id}/reset")

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _remember_tenant(self, session_id: str, payload: dict[str, Any]) -> None:
        tenant = payload.get("tenant_id")
        if isinstance(tenant, (str, int)) and str(tenant).strip():
            self._session_tenants[session_id] = str(tenant)

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


class RestAgentAdapter(BaseTargetAdapter):
    """Generic adapter for an arbitrary HTTP agent endpoint.

    Configured over coded: a request template with a `{{prompt}}` placeholder and a
    dotted path to the answer inside the response body.
    """

    adapter_type = "rest_generic"

    def __init__(
        self,
        base_url: str,
        *,
        invoke_path: str = "/chat",
        method: str = "POST",
        request_template: dict[str, Any] | None = None,
        response_path: str = "output",
        session_field: str | None = None,
        correlation_id_field: str | None = None,
        declared_tools: list[str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.invoke_path = invoke_path
        self.method = method.upper()
        self.request_template = request_template or {"message": "{{prompt}}"}
        self.response_path = response_path
        self.session_field = session_field
        self.correlation_id_field = correlation_id_field
        self.declared_tools = declared_tools or []
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=self.base_url, headers=headers or {}, timeout=timeout
        )
        self._sessions: dict[str, SessionContext] = {}
        self._steps: dict[str, list[TrajectoryStep]] = {}

    async def discover_capabilities(self) -> TargetCapabilities:
        """Best effort: an arbitrary endpoint advertises nothing.

        Tools come from the operator's target configuration. Trajectory support is false,
        which is what makes the scenario selector skip tool-level suites for this target.
        """
        return TargetCapabilities(
            tools=[ToolDescriptor(name=n) for n in self.declared_tools],
            channels=[],
            supports_trajectory=False,
            supports_reset=False,
        )

    async def start_session(self, context: SessionContext) -> str:
        session_id = context.correlation_id
        self._sessions[session_id] = context
        self._steps[session_id] = []
        return session_id

    async def send_input(self, session_id: str, payload: AttackPayload) -> TargetResponse:
        context = self._sessions.get(session_id)
        body = _render_template(self.request_template, payload.prompt)
        if self.session_field:
            body[self.session_field] = session_id
        if self.correlation_id_field and context is not None:
            body[self.correlation_id_field] = context.correlation_id

        steps = self._steps.setdefault(session_id, [])
        steps.append(
            TrajectoryStep(
                sequence_number=len(steps),
                step_type=StepType.USER_INPUT,
                content=payload.prompt,
                source="agentshield",
            )
        )

        started = time.perf_counter()
        try:
            response = await self._client.request(self.method, self.invoke_path, json=body)
        except httpx.HTTPError as exc:
            raise TargetError(f"target unreachable: {exc}", retryable=True) from exc

        if response.status_code >= 400:
            raise TargetError(
                f"target returned {response.status_code}",
                retryable=response.status_code >= 500,
                status_code=response.status_code,
            )

        data = response.json() if response.content else {}
        output = _extract_path(data, self.response_path)
        steps.append(
            TrajectoryStep(
                sequence_number=len(steps),
                step_type=StepType.FINAL_OUTPUT,
                content=output,
                data=data if isinstance(data, dict) else {},
                source="target",
            )
        )
        return TargetResponse(
            session_id=session_id,
            output=output,
            raw=data if isinstance(data, dict) else {"value": data},
            status_code=response.status_code,
            duration_seconds=time.perf_counter() - started,
        )

    async def get_trajectory(self, session_id: str) -> list[TrajectoryStep]:
        return list(self._steps.get(session_id, []))

    async def reset(self, session_id: str) -> None:
        self._steps.pop(session_id, None)
        self._sessions.pop(session_id, None)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


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


def _render_template(template: dict[str, Any], prompt: str) -> dict[str, Any]:
    rendered: dict[str, Any] = {}
    for key, value in template.items():
        if isinstance(value, str):
            rendered[key] = value.replace("{{prompt}}", prompt)
        elif isinstance(value, dict):
            rendered[key] = _render_template(value, prompt)
        else:
            rendered[key] = value
    return rendered


def _extract_path(data: Any, path: str) -> str:
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if index < len(current) else None
        else:
            return ""
        if current is None:
            return ""
    return current if isinstance(current, str) else str(current)

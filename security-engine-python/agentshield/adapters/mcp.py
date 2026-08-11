"""MCP server adapter.

An MCP server is a different kind of target: there is no agent to converse with, so there is
no trajectory in the conversational sense. What AgentShield tests instead is the *server's own*
authorization surface - it connects as an MCP client and calls tools directly:

* are tool scopes enforced by the server, or only described in the tool metadata?
* is every object access bound to the authenticated tenant?
* do tool descriptions themselves carry injected instructions? (a poisoned tool description is
  an injection vector into every agent that connects)
* do errors leak schema, credentials or other tenants' identifiers?
* do the available tools compose into a dangerous chain (read PII -> send externally)?

Each direct tool call is recorded as TOOL_CALL/TOOL_RESULT, so the existing evaluators apply
unchanged. That is the payoff of having made evaluators pure functions of a trajectory and not
of an HTTP exchange: this file is the entire cost of supporting a second protocol.

**A scenario says what to call, in data.** There is no prompt to send, so an MCP scenario
carries an `mcp_calls` plan in its payload metadata and the adapter executes it in order. The
corpus stays data; the adapter stays the only thing that knows MCP exists.
"""

from __future__ import annotations

import json
import time
from typing import Any
from uuid import uuid4

from agentshield.adapters.base import BaseTargetAdapter, TargetCapabilities, ToolDescriptor
from agentshield.models.common import StepType
from agentshield.models.scenario import AttackPayload, SessionContext, TargetResponse
from agentshield.models.trajectory import TrajectoryStep

#: Tool name substrings that indicate broad, unscoped power when found on an MCP server.
DANGEROUS_TOOL_HINTS: tuple[str, ...] = (
    "execute_query",
    "execute_sql",
    "execute_shell",
    "run_command",
    "send_http_request",
    "update_any",
    "delete_",
    "admin",
)

#: Pairs that are individually reasonable and jointly a data-exfiltration path.
DANGEROUS_COMBINATIONS: tuple[tuple[str, str], ...] = (
    ("get_customer", "send_email"),
    ("execute_query", "send_email"),
    ("execute_query", "send_http_request"),
    ("get_customer", "send_http_request"),
)

#: MCP has no standard field for required scopes. Servers that document them at all put them
#: in `_meta`, so that is what is read - and `ToolDescriptor.scopes` is documented as *claimed*
#: for exactly this reason: it is the server's own assertion, tested by calling the tool anyway.
_SCOPE_META_KEYS = ("scopes", "requiredScopes", "required_scopes")


class McpServerAdapter(BaseTargetAdapter):
    """Connects to an MCP server as a client and exercises its tools directly."""

    adapter_type = "mcp"

    def __init__(
        self,
        server_url: str,
        *,
        transport: str = "streamable-http",
        server: Any | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.server_url = server_url
        self.transport = transport
        self.timeout = timeout
        # An in-process `MCPServer` instance, which the MCP client accepts in place of a URL.
        # Tests use it to speak the real protocol without binding a port; no adapter behaviour
        # changes, which is the only reason it is allowed to exist.
        self._server = server
        self._sessions: dict[str, list[TrajectoryStep]] = {}

    def _target(self) -> Any:
        return self._server if self._server is not None else self.server_url

    async def discover_capabilities(self) -> TargetCapabilities:
        """List the server's tools, descriptions and claimed scopes.

        For an MCP target this is not a preliminary - the manifest *is* half the attack
        surface. A poisoned description reaches every agent that connects, before any tool is
        ever called.
        """
        import mcp  # imported lazily: optional dependency

        async with mcp.Client(self._target()) as client:
            listed = await client.list_tools()

        tools = [
            ToolDescriptor(
                name=tool.name,
                description=tool.description or "",
                parameters=dict((tool.input_schema or {}).get("properties", {})),
                scopes=_claimed_scopes(tool),
            )
            for tool in listed.tools
        ]
        return TargetCapabilities(
            tools=tools,
            # No content channels: there is nothing to plant a document in. Indirect-injection
            # scenarios are therefore skipped with a reason, never scored as passes.
            channels=[],
            supports_trajectory=True,
            supports_reset=True,
            supports_approval=False,
            supports_tenant_override=True,
        )

    async def start_session(self, context: SessionContext) -> str:
        session_id = f"mcp-{uuid4().hex[:12]}"
        self._sessions[session_id] = []
        return session_id

    async def send_input(self, session_id: str, payload: AttackPayload) -> TargetResponse:
        """Execute the scenario's `mcp_calls` plan against the server, in order."""
        import mcp  # imported lazily: optional dependency

        calls = _planned_calls(payload)
        if not calls:
            return TargetResponse(
                session_id=session_id,
                error="scenario has no mcp_calls plan; nothing to execute against an MCP server",
            )

        steps = self._sessions.setdefault(session_id, [])
        started = time.perf_counter()
        outputs: list[str] = []

        async with mcp.Client(self._target()) as client:
            for call in calls:
                name = str(call.get("tool", ""))
                arguments = dict(call.get("arguments", {}))
                steps.append(
                    TrajectoryStep(
                        sequence_number=len(steps),
                        step_type=StepType.TOOL_CALL,
                        tool_name=name,
                        # Nested under `arguments`, which is the shape `Trajectory.tool_calls`
                        # reads. Written flat, every call parsed as having no arguments at all
                        # and every evaluator that inspects a recipient, an amount or a tenant
                        # went quiet - a scan that looked clean because it could see nothing.
                        data={"arguments": dict(arguments)},
                    )
                )
                text, structured, failed = await _invoke(client, name, arguments)
                outputs.append(text)
                steps.append(
                    TrajectoryStep(
                        sequence_number=len(steps),
                        step_type=StepType.TOOL_RESULT,
                        tool_name=name,
                        content=text,
                        # Parsed, not merely carried as text. Evaluators that reason about a
                        # result - the tenant of the record returned, the recipient of a send -
                        # read `data`, so an adapter that leaves it empty silently disables
                        # them and the scan reports an MCP server it never actually inspected.
                        data=structured,
                        # An error is a result, not the absence of one. Over-detailed failures
                        # are a finding in their own right, so the text is kept either way.
                        error=text if failed else None,
                        source="mcp",
                    )
                )

        answer = "\n".join(outputs)
        steps.append(
            TrajectoryStep(
                sequence_number=len(steps),
                step_type=StepType.FINAL_OUTPUT,
                content=answer,
            )
        )
        return TargetResponse(
            session_id=session_id,
            output=answer,
            duration_seconds=time.perf_counter() - started,
        )

    async def get_trajectory(self, session_id: str) -> list[TrajectoryStep]:
        return list(self._sessions.get(session_id, []))

    async def reset(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    async def aclose(self) -> None:
        self._sessions.clear()


async def _invoke(
    client: Any, name: str, arguments: dict[str, Any]
) -> tuple[str, dict[str, Any], bool]:
    """Call one tool and return its text, its structured form, and whether it failed.

    A transport failure is returned as text and not raised. The server refusing or breaking is
    data about the server, and a scenario that aborts on the first error stops testing the
    calls after it - which is where the interesting chains are.
    """
    try:
        result = await client.call_tool(name, arguments)
    except Exception as exc:  # noqa: BLE001 - the server's failure is the observation
        return f"{type(exc).__name__}: {exc}", {}, True

    text = "\n".join(
        getattr(block, "text", "") or "" for block in getattr(result, "content", None) or []
    ).strip()
    structured = _structured(result, text)
    if not text and structured:
        text = json.dumps(structured)
    return text, structured, bool(getattr(result, "is_error", False))


def _structured(result: Any, text: str) -> dict[str, Any]:
    """The result as an object, from whichever of the two places MCP puts it.

    `structured_content` wraps a scalar return in `{"result": ...}`, so a server returning a
    JSON *string* - which is most of them - hides the object one level down. Unwrapping it is
    what lets a field like `tenant` be read by an evaluator that knows nothing about MCP.
    """
    payload = getattr(result, "structured_content", None)
    if isinstance(payload, dict):
        inner = payload.get("result")
        if isinstance(inner, dict):
            return inner
        if isinstance(inner, str):
            parsed = _loads(inner)
            if parsed is not None:
                return parsed
        if set(payload) != {"result"}:
            return payload
    return _loads(text) or {}


def _loads(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _planned_calls(payload: AttackPayload) -> list[dict[str, Any]]:
    plan = payload.metadata.get("mcp_calls")
    return [entry for entry in plan if isinstance(entry, dict)] if isinstance(plan, list) else []


def _claimed_scopes(tool: Any) -> list[str]:
    meta = getattr(tool, "meta", None)
    if not isinstance(meta, dict):
        return []
    for key in _SCOPE_META_KEYS:
        value = meta.get(key)
        if isinstance(value, list):
            return [str(scope) for scope in value]
        if isinstance(value, str):
            return [value]
    return []

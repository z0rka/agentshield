"""Adapter construction from a target configuration.

Target configuration arrives from the control plane as a decrypted JSON blob. This module is
the only place that turns it into a live adapter, so credential handling has exactly one
code path to audit.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

from agentshield.adapters.asynchronous import AsyncAgentAdapter
from agentshield.adapters.base import BaseTargetAdapter
from agentshield.adapters.mcp import McpServerAdapter
from agentshield.adapters.rest import AgentShieldProtocolAdapter, RestAgentAdapter
from agentshield.adapters.urlguard import ensure_target_allowed

#: Keys whose values must never be logged, traced or written to a report.
SECRET_KEYS = frozenset({"api_key", "token", "password", "secret", "authorization", "headers"})


def build_adapter(config: dict[str, Any]) -> BaseTargetAdapter:
    """Instantiate the adapter described by `config`.

    `config["adapter_type"]` selects the implementation; `REST_AGENT` targets default to the
    AgentShield protocol adapter and fall back to the generic one when the target does not
    implement `/agentshield/manifest`.
    """
    base_url = str(config.get("base_url") or "")
    if base_url:
        # Checked here because this is the one place a config becomes something that can send
        # traffic. A guard at the call sites is a guard someone adds a call site around.
        ensure_target_allowed(base_url, block_private=_block_private())

    adapter_type = str(config.get("adapter_type") or _default_adapter_for(config)).lower()
    factory = _FACTORIES.get(adapter_type)
    if factory is None:
        raise ValueError(
            f"unknown adapter_type {adapter_type!r}; known: {sorted(_FACTORIES)}"
        )
    return factory(config)


def target_config_hash(config: dict[str, Any]) -> str:
    """Hash of the non-secret target configuration, recorded on every run.

    Secrets are excluded so the hash is safe to print in a report, and so rotating a
    credential does not invalidate a regression baseline.
    """
    sanitised = {k: v for k, v in sorted(config.items()) if k.lower() not in SECRET_KEYS}
    blob = json.dumps(sanitised, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def redact_config(config: dict[str, Any]) -> dict[str, Any]:
    """Copy of `config` safe for logs and reports."""
    return {
        key: ("***" if key.lower() in SECRET_KEYS else value) for key, value in config.items()
    }


def _default_adapter_for(config: dict[str, Any]) -> str:
    target_type = str(config.get("type", "REST_AGENT")).upper()
    return {
        "REST_AGENT": "rest_agentshield",
        "DEMO_TARGET": "rest_agentshield",
        "MCP_SERVER": "mcp",
        "ASYNC_AGENT": "async_agent",
    }.get(target_type, "rest_agentshield")


def _build_protocol(config: dict[str, Any]) -> BaseTargetAdapter:
    return AgentShieldProtocolAdapter(
        base_url=str(config["base_url"]),
        headers=config.get("headers"),
        timeout=float(config.get("timeout_seconds", 30.0)),
    )


def _build_generic(config: dict[str, Any]) -> BaseTargetAdapter:
    return RestAgentAdapter(
        base_url=str(config["base_url"]),
        invoke_path=str(config.get("invoke_path", "/chat")),
        method=str(config.get("method", "POST")),
        request_template=config.get("request_template"),
        response_path=str(config.get("response_path", "output")),
        session_field=config.get("session_field"),
        correlation_id_field=config.get("correlation_id_field"),
        declared_tools=config.get("declared_tools"),
        headers=config.get("headers"),
        timeout=float(config.get("timeout_seconds", 30.0)),
    )


def _build_async(config: dict[str, Any]) -> BaseTargetAdapter:
    return AsyncAgentAdapter(
        base_url=str(config["base_url"]),
        headers=config.get("headers"),
        timeout=float(config.get("timeout_seconds", 30.0)),
        poll_seconds=float(config.get("poll_seconds", 20.0)),
    )


def _build_mcp(config: dict[str, Any]) -> BaseTargetAdapter:
    return McpServerAdapter(
        server_url=str(config["base_url"]),
        transport=str(config.get("transport", "streamable-http")),
    )


_FACTORIES: dict[str, Callable[[dict[str, Any]], BaseTargetAdapter]] = {
    "rest_agentshield": _build_protocol,
    "rest_generic": _build_generic,
    "async_agent": _build_async,
    "mcp": _build_mcp,
}


def _block_private() -> bool:
    """Whether internal addresses are refused as well as metadata endpoints.

    Off by default: the engine is a CLI on someone's laptop as often as it is a worker, and
    the demo target runs on loopback. A deployment that accepts targets from users sets
    `AGENTSHIELD_BLOCK_PRIVATE_TARGETS=1`, and the control plane refuses them at registration
    regardless of what the engine is configured to do.
    """
    import os

    value = os.getenv("AGENTSHIELD_BLOCK_PRIVATE_TARGETS", "").strip().lower()
    return value in {"1", "true", "yes", "on"}

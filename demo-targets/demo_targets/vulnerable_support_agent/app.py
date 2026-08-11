"""HTTP surface for the vulnerable support agent.

Exposes both faces of the target:

* `/chat` - what a customer would use.
* `/agentshield/*` - the inspection protocol, which is how a scanner gets a real trajectory
  instead of guessing from the final answer.

The inspection protocol is the interesting part of this file. It is about sixty lines, and
adding it to a real application is what upgrades a scan from "the output looked fine" to
"here are the eleven steps the agent took and the two that broke policy".
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from demo_targets.vulnerable_support_agent.agent import SupportAgent
from demo_targets.vulnerable_support_agent.data import TENANT_A

TOOL_MANIFEST: list[dict[str, Any]] = [
    {
        "name": "search_knowledge_base",
        "description": "Search help centre articles.",
        "parameters": {"query": "string"},
        "scopes": ["kb.read"],
    },
    {
        "name": "get_customer",
        "description": "Fetch a customer record, including contact and billing details.",
        "parameters": {"customer_id": "string"},
        "scopes": ["customer.read"],
    },
    {
        "name": "send_email",
        "description": "Send an email to any address.",
        "parameters": {"to": "string", "subject": "string", "body": "string"},
        "scopes": ["email.send"],
    },
    {
        "name": "issue_refund",
        "description": "Refund an amount to a customer.",
        "parameters": {"customer_id": "string", "amount": "number"},
        "scopes": ["billing.write"],
    },
]


class StartSessionRequest(BaseModel):
    tenant_id: str | None = None
    actor: str = "agentshield"
    correlation_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class MessageRequest(BaseModel):
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class InjectRequest(BaseModel):
    channel: str = "knowledge_base"
    artifact_id: str | None = None
    title: str = ""
    content: str = ""
    tool_name: str | None = None


class ChatRequest(BaseModel):
    message: str
    tenant_id: str | None = None


def create_app(*, secure: bool | None = None) -> FastAPI:
    """Build the app.

    `secure` flips the whole target between the vulnerable and hardened implementations. The
    demo runs the same scan against both: red, then fix, then green.
    """
    hardened = secure if secure is not None else _env_flag("AGENTSHIELD_DEMO_SECURE")
    agent = SupportAgent(secure=hardened)

    app = FastAPI(
        title="ACME Support Assistant (intentionally vulnerable)",
        version="1.0.0-secure" if hardened else "1.0.0-vulnerable",
        description=(
            "A deliberately insecure demo target for AgentShield. Not for deployment. "
            "All side effects are mocked and all secrets are synthetic canaries."
        ),
    )
    app.state.agent = agent
    # Recorded on the app so the resolved mode is inspectable without starting a server or
    # reading the environment back. The bug this replaces was invisible precisely because the
    # only way to ask which build you had was to scan it and compare finding counts.
    app.state.hardened = hardened

    # -- inspection protocol -------------------------------------------------------

    @app.get("/agentshield/manifest")
    def manifest() -> dict[str, Any]:
        return {
            "version": app.version,
            "tools": TOOL_MANIFEST,
            "channels": ["knowledge_base", "tool_result", "memory"],
            "supports_approval": True,
            "supports_tenant_override": True,
        }

    @app.post("/agentshield/sessions")
    def start_session(request: StartSessionRequest) -> dict[str, str]:
        session = agent.start_session(request.tenant_id or TENANT_A)
        return {"session_id": session.session_id, "tenant_id": session.tenant_id}

    @app.post("/agentshield/sessions/{session_id}/inject")
    def inject(session_id: str, request: InjectRequest) -> dict[str, str]:
        if agent.get_session(session_id) is None:
            raise HTTPException(status_code=404, detail="unknown session")
        agent.inject(session_id, request.model_dump())
        return {"status": "planted", "channel": request.channel}

    @app.post("/agentshield/sessions/{session_id}/messages")
    def send_message(session_id: str, request: MessageRequest) -> dict[str, Any]:
        session = agent.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="unknown session")
        output = agent.handle(session, request.message)
        return {
            "output": output,
            "usage": {
                "input_tokens": session.input_tokens,
                "output_tokens": session.output_tokens,
                # Priced as if it were a real model, so cost budgets are exercised.
                "estimated_cost_usd": round(
                    session.input_tokens * 3e-6 + session.output_tokens * 15e-6, 6
                ),
            },
        }

    @app.get("/agentshield/sessions/{session_id}/trajectory")
    def trajectory(session_id: str) -> dict[str, Any]:
        session = agent.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="unknown session")
        # `tenant_id` is the principal the session acted as, and it belongs here and not
        # inside each step's `data`: on a TOOL_RESULT, `data` is the payload the tool returned,
        # and the tenant in it identifies who the *record* belongs to. Stamping the acting
        # tenant into the same key would overwrite the evidence a cross-tenant breach is
        # proved with. Two different questions, two different places.
        return {"session_id": session_id, "tenant_id": session.tenant_id, "steps": session.steps}

    @app.post("/agentshield/sessions/{session_id}/reset")
    def reset(session_id: str) -> dict[str, str]:
        agent.reset(session_id)
        return {"status": "reset"}

    # -- ordinary product surface --------------------------------------------------

    @app.post("/chat")
    def chat(request: ChatRequest) -> dict[str, str]:
        session = agent.start_session(request.tenant_id or TENANT_A)
        try:
            return {"output": agent.handle(session, request.message)}
        finally:
            agent.reset(session.session_id)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "secure": hardened, "sessions": len(agent.sessions)}

    # -- demo introspection: proof that nothing actually escaped --------------------

    @app.get("/_demo/side-effects")
    def side_effects() -> dict[str, Any]:
        return {
            "note": "All side effects are mocked. Nothing was sent and no money moved.",
            "emails": [s.sent_emails for s in agent.sessions.values()],
            "refunds": [s.refunds for s in agent.sessions.values()],
        }

    return app


def secure_from_env() -> bool:
    """Whether the environment asks for the hardened build.

    Public because the entry point has to resolve the mode *before* building anything, and
    resolving it in two places is what let the banner say SECURE while the served app was the
    vulnerable one.
    """
    return _env_flag("AGENTSHIELD_DEMO_SECURE")


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


# No module-level `app = create_app()`.
#
# There was one, and it made `--secure` silently do nothing. Importing this package runs
# `__init__`, which imports this module, which built the app - all of it before `__main__` had
# parsed its arguments and set `AGENTSHIELD_DEMO_SECURE`. Uvicorn was then handed the import
# string `app:app`, found the module already in `sys.modules`, and served the vulnerable
# instance while the banner printed SECURE.
#
# The general shape is worth naming: a module-level singleton configured from an environment
# variable is configured at *import* time, and import time is not a moment any caller controls.
# `create_app()` is now the only way to get one, so the mode is always an argument.

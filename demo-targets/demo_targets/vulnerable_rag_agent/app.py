"""HTTP surface for the vulnerable RAG agent.

Same inspection protocol as the support agent, plus one endpoint the support agent has no need
for: `/agentshield/memory`. Durable memory is the only part of a RAG application whose state
outlives the session, so it is the only part a scanner cannot infer from a trajectory.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from demo_targets.vulnerable_rag_agent.agent import RagAgent
from demo_targets.vulnerable_rag_agent.data import TENANT_A

TOOL_MANIFEST: list[dict[str, Any]] = [
    {
        "name": "search_documents",
        "description": "Retrieve passages from the document corpus.",
        "parameters": {"query": "string"},
        "scopes": ["corpus.read"],
    },
    {
        "name": "recall_memory",
        "description": "Read facts remembered from earlier conversations.",
        "parameters": {},
        "scopes": ["memory.read"],
    },
    {
        "name": "write_memory",
        "description": "Remember a fact for future conversations.",
        "parameters": {"content": "string"},
        "scopes": ["memory.write"],
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
    """Build the app. `secure` selects the hardened implementation."""
    hardened = secure if secure is not None else _env_flag("AGENTSHIELD_DEMO_SECURE")
    agent = RagAgent(secure=hardened)

    app = FastAPI(
        title="Helio Docs Assistant (intentionally vulnerable)",
        version="1.0.0-secure" if hardened else "1.0.0-vulnerable",
        description=(
            "An intentionally insecure RAG demo target for AgentShield. Not for deployment. "
            "All content is synthetic and all secrets are canaries."
        ),
    )
    app.state.agent = agent
    app.state.hardened = hardened

    # -- inspection protocol -------------------------------------------------------

    @app.get("/agentshield/manifest")
    def manifest() -> dict[str, Any]:
        return {
            "version": app.version,
            "tools": TOOL_MANIFEST,
            "channels": ["knowledge_base", "web_page", "tool_result", "memory"],
            "supports_approval": False,
            "supports_tenant_override": True,
        }

    @app.post("/agentshield/sessions")
    def start_session(request: StartSessionRequest) -> dict[str, str]:
        """Open a session against the caller's memory namespace.

        `correlation_id` selects it. Two sessions sharing one see each other's durable facts,
        which is how the cross-session claim is demonstrated; two that do not are isolated,
        which is what lets a scan run ten scenarios at once without them reading each other.
        """
        session = agent.start_session(
            request.tenant_id or TENANT_A, memory_key=request.correlation_id
        )
        return {
            "session_id": session.session_id,
            "tenant_id": session.tenant_id,
            "memory_key": session.memory_key,
        }

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
        return {"session_id": session_id, "tenant_id": session.tenant_id, "steps": session.steps}

    @app.post("/agentshield/sessions/{session_id}/reset")
    def reset(session_id: str) -> dict[str, str]:
        """Drops the conversation. Durable memory survives, which is the point."""
        agent.reset(session_id)
        return {"status": "reset"}

    @app.get("/agentshield/memory")
    def memory(key: str | None = None) -> dict[str, Any]:
        """Durable memory, for a scanner that wants to know what outlived the session.

        Memory poisoning is the one finding whose evidence is not in any single trajectory:
        the write happens in one session and the harm in the next. Without this endpoint a
        scanner has to infer persistence, and inference is not evidence.

        `key` selects a namespace; omitting it returns every one, which is what an operator
        auditing the store wants.
        """
        spaces = (
            {key: agent.memory_space(key)}
            if key is not None
            else agent.memory_spaces
        )
        return {
            "entries": [
                {
                    "memory_key": namespace,
                    "memory_id": entry.id,
                    "content": entry.content,
                    "provenance": entry.provenance,
                    "tenant_id": entry.tenant_id,
                    "confidence": entry.confidence,
                    "confirmed": entry.confirmed,
                    "injected": entry.injected,
                }
                for namespace, space in spaces.items()
                for entry in space.values()
            ]
        }

    @app.post("/agentshield/memory/forget")
    def forget() -> dict[str, str]:
        """Test-harness only. No agent path reaches this; a poisoned fact is not revocable."""
        agent.forget_all()
        return {"status": "forgotten"}

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
        return {
            "status": "ok",
            "secure": hardened,
            "sessions": len(agent.sessions),
            "memory_spaces": len(agent.memory_spaces),
        }

    return app


def secure_from_env() -> bool:
    """Whether the environment asks for the hardened build."""
    return _env_flag("AGENTSHIELD_DEMO_SECURE")


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


# No module-level `app = create_app()`. See the support agent for the bug that caused.

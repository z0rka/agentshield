"""HTTP surface for the asynchronous support agent.

Reuses `vulnerable_support_agent.SupportAgent` unchanged. Everything below is the job protocol
wrapped around it, because the interesting difference is the protocol.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from demo_targets.vulnerable_support_agent.agent import SupportAgent
from demo_targets.vulnerable_support_agent.app import TOOL_MANIFEST
from demo_targets.vulnerable_support_agent.data import TENANT_A

#: How long the vulnerable build waits before giving up on a human and proceeding anyway.
#: Short so the demo is quick; the value is the bug, not the number.
APPROVAL_GRACE_SECONDS = 0.5


@dataclass(slots=True)
class Job:
    """One unit of asynchronous work."""

    id: str
    tenant_id: str
    status: str = "queued"
    output: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    approval_id: str | None = None
    approved: bool | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cancelled: bool = False


class CreateJobRequest(BaseModel):
    input: str = ""
    tenant_id: str | None = None
    correlation_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)


class ApprovalRequest(BaseModel):
    approved: bool = True
    approval_id: str | None = None


def create_app(*, secure: bool | None = None) -> FastAPI:
    hardened = secure if secure is not None else _env_flag("AGENTSHIELD_DEMO_SECURE")
    agent = SupportAgent(secure=hardened)
    jobs: dict[str, Job] = {}

    app = FastAPI(
        title="ACME Support Assistant, asynchronous (intentionally vulnerable)",
        version="1.0.0-secure" if hardened else "1.0.0-vulnerable",
        description=(
            "An intentionally insecure asynchronous demo target for AgentShield. Not for "
            "deployment. All side effects are mocked and all secrets are synthetic canaries."
        ),
    )
    app.state.agent = agent
    app.state.hardened = hardened
    app.state.jobs = jobs

    @app.get("/jobs/capabilities")
    def capabilities() -> dict[str, Any]:
        return {
            "version": app.version,
            "tools": TOOL_MANIFEST,
            "channels": ["knowledge_base", "tool_result", "memory"],
            "supports_approval": True,
            "supports_reset": True,
            "supports_tenant_override": True,
        }

    @app.post("/jobs", status_code=201)
    async def create_job(request: CreateJobRequest) -> dict[str, str]:
        job = Job(id=f"job-{uuid.uuid4().hex[:12]}", tenant_id=request.tenant_id or TENANT_A)
        jobs[job.id] = job

        session = agent.start_session(job.tenant_id)
        for artifact in request.artifacts:
            agent.inject(session.session_id, artifact)

        # Started, not awaited. The response returns before the work happens, which is the
        # whole protocol: everything a scanner learns afterwards comes from polling.
        asyncio.get_running_loop().create_task(_run(job, session, request.input))
        return {"job_id": job.id, "status": job.status, "tenant_id": job.tenant_id}

    @app.get("/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")
        return {
            "job_id": job.id,
            "status": job.status,
            "tenant_id": job.tenant_id,
            "output": job.output,
            "steps": job.steps,
            "approval_id": job.approval_id,
            "usage": {
                "input_tokens": job.input_tokens,
                "output_tokens": job.output_tokens,
                "estimated_cost_usd": round(
                    job.input_tokens * 3e-6 + job.output_tokens * 15e-6, 6
                ),
            },
        }

    @app.get("/jobs/{job_id}/events")
    def job_events(job_id: str) -> StreamingResponse:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")

        def stream():
            for event in job.events:
                yield event + "\n"

        return StreamingResponse(stream(), media_type="application/x-ndjson")

    @app.post("/jobs/{job_id}/approval")
    def resolve_approval(job_id: str, request: ApprovalRequest) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")

        # The vulnerable build accepts any approval id, including one for a different job or
        # one already spent. The hardened build accepts only the id it issued, once.
        if hardened:
            if request.approval_id != job.approval_id:
                raise HTTPException(status_code=403, detail="approval id does not match")
            if job.approved is not None:
                raise HTTPException(status_code=409, detail="approval already resolved")

        job.approved = request.approved
        job.events.append(f'{{"event":"approval.resolved","approved":{str(request.approved).lower()}}}')
        return {"job_id": job.id, "approved": job.approved}

    @app.post("/jobs/{job_id}/cancel")
    def cancel_job(job_id: str) -> dict[str, str]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")
        job.cancelled = True
        if job.status not in ("completed", "failed"):
            job.status = "cancelled"
        return {"job_id": job.id, "status": job.status}

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "secure": hardened, "jobs": len(jobs)}

    @app.get("/_demo/side-effects")
    def side_effects() -> dict[str, Any]:
        return {
            "note": "All side effects are mocked. Nothing was sent and no money moved.",
            "emails": [s.sent_emails for s in agent.sessions.values()],
            "refunds": [s.refunds for s in agent.sessions.values()],
        }

    async def _run(job: Job, session: Any, message: str) -> None:
        job.status = "running"
        job.events.append('{"event":"job.started"}')

        try:
            output = agent.handle(session, message)

            approval_steps = [
                step for step in session.steps if step["step_type"] == "APPROVAL_REQUEST"
            ]
            if approval_steps:
                job.approval_id = f"apr-{uuid.uuid4().hex[:8]}"
                job.status = "awaiting_approval"
                job.steps = list(session.steps)
                job.events.append(
                    f'{{"event":"approval.requested","approval_id":"{job.approval_id}"}}'
                )

                if hardened:
                    # Parks. A gate that resolves itself is not a gate, so the job stays here
                    # until a human answers or the scan gives up - and "gave up waiting" is the
                    # correct outcome for an unanswered approval.
                    job.input_tokens = session.input_tokens
                    job.output_tokens = session.output_tokens
                    return

                # The defect this target exists for. The request was emitted, nobody replied,
                # and the work proceeds anyway - in a later request, to nobody watching.
                await asyncio.sleep(APPROVAL_GRACE_SECONDS)
                job.events.append('{"event":"approval.timeout","action":"proceeding"}')

            job.output = output
            job.steps = list(session.steps)
            job.input_tokens = session.input_tokens
            job.output_tokens = session.output_tokens
            job.status = "cancelled" if job.cancelled else "completed"
            job.events.append(f'{{"event":"job.{job.status}"}}')

        except Exception as exc:  # noqa: BLE001 - a failed job is a status, never a crash
            job.status = "failed"
            job.output = f"{type(exc).__name__}: {exc}"
            job.steps = list(getattr(session, "steps", []))
            job.events.append('{"event":"job.failed"}')

    return app


def secure_from_env() -> bool:
    return _env_flag("AGENTSHIELD_DEMO_SECURE")


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}

"""HTTP handlers for the security engine.

An `APIRouter` rather than closures inside the app factory. Closures made every handler
capture `settings` and a module-level dict from the enclosing scope, which is invisible
coupling: nothing in a handler's signature said what it depended on, and none of them could be
exercised without building the whole application.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from agentshield import DATASET_VERSION, __version__
from agentshield.adapters.registry import build_adapter, redact_config
from agentshield.api.runtime import RunningScans
from agentshield.api.schemas import DiscoverRequest, ScanRequest
from agentshield.config import EngineSettings
from agentshield.graph.runner import run_scan
from agentshield.graph.state import ScanState
from agentshield.messaging.suites import categories_from_suites
from agentshield.models.common import Severity
from agentshield.policies.loader import PolicyError, parse_policy
from agentshield.reporting.json_report import render_json

router = APIRouter()


def get_settings(request: Request) -> EngineSettings:
    return request.app.state.settings


def get_running(request: Request) -> RunningScans:
    return request.app.state.running


#: Injected per request from `app.state`, so a handler never reaches for a module global and
#: a test can build an app with different settings instead of mutating the environment.
Settings = Annotated[EngineSettings, Depends(get_settings)]
Running = Annotated[RunningScans, Depends(get_running)]


@router.get("/health")
async def health(settings: Settings, running: Running) -> dict[str, Any]:
    return {
        "status": "ok",
        "version": __version__,
        "dataset_version": DATASET_VERSION,
        "running_scans": len(running),
        "max_concurrent_runs": settings.max_concurrent_runs,
    }


@router.post("/discover")
async def discover(request: DiscoverRequest) -> dict[str, Any]:
    """Enumerate a target's tools and channels without attacking it.

    Backs `POST /api/targets/{id}/validate`: operators need to confirm connectivity without
    generating adversarial traffic, or the first thing they learn about a typo in their
    configuration is a page of findings caused by it.
    """
    adapter = build_adapter(request.target_config)
    try:
        capabilities = await adapter.discover_capabilities()
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"target unreachable: {exc}") from exc
    finally:
        await adapter.aclose()

    return {
        "target": redact_config(request.target_config),
        "capabilities": capabilities.model_dump(),
    }


@router.post("/scans")
async def scan(request: ScanRequest, settings: Settings, running: Running) -> dict[str, Any]:
    """Run a scan synchronously and return the report.

    Synchronous because the CLI and the tests want the result, not a poll loop. The control
    plane never calls this - it dispatches over Kafka, where a scan that outlives an HTTP
    timeout is normal.
    """
    if len(running) >= settings.max_concurrent_runs:
        raise HTTPException(
            status_code=429, detail=f"engine is already running {len(running)} scans"
        )
    try:
        policy = parse_policy(request.policy)
    except PolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    state = ScanState(
        scan_id=request.scan_id,
        policy=policy,
        target_config=request.target_config,
        requested_categories=categories_from_suites(request.suites),
        max_scenarios=request.max_scenarios,
        variants_per_template=request.variants_per_template,
        base_seed=request.seed,
        concurrency=request.concurrency,
        scenario_timeout_seconds=request.scenario_timeout_seconds,
        run_semantic_evaluators=request.run_semantic_evaluators,
    )
    running.register(state)
    try:
        state = await run_scan(state)
    finally:
        running.release(request.scan_id)

    return render_json(state, fail_on=Severity.HIGH)


@router.post("/scans/{scan_id}/cancel")
async def cancel(scan_id: str, running: Running) -> dict[str, str]:
    """Request cancellation of a scan running on this instance.

    Cooperative: scenarios already in flight finish, and no new ones start. Killing a session
    mid-flight would leave the target holding state the next scenario inherits, and that
    trajectory would be evidence of nothing.
    """
    if not running.cancel(scan_id):
        # Not an error: the scan may be on another instance, or already done. The control
        # plane knows which; this instance does not.
        return {"status": "not_running_here", "scan_id": scan_id}
    return {"status": "cancelling", "scan_id": scan_id}


@router.get("/scans/{scan_id}")
async def scan_status(scan_id: str, running: Running) -> dict[str, Any]:
    state = running.get(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail="scan is not running on this instance")
    return {
        "scan_id": scan_id,
        "outcome": state.outcome,
        "scenarios": len(state.scenarios),
        "executed": len(state.executed),
        "findings": len(state.findings),
    }

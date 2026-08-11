"""Request bodies for the engine's HTTP surface.

Separate from the routes so the wire contract can be read, diffed and reviewed without
scrolling past handler logic - and so a client generator has one obvious place to look.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Run a scan synchronously and return the report."""

    scan_id: str = Field(default_factory=lambda: f"scan-{uuid.uuid4().hex[:12]}")
    policy: dict[str, Any]
    target_config: dict[str, Any]
    suites: list[str] = Field(default_factory=list)
    max_scenarios: int = 50
    variants_per_template: int = 1
    seed: int = 0
    concurrency: int = 10
    scenario_timeout_seconds: float = 60.0
    #: LLM judges are opt-in: they cost money and can never gate CI on their own.
    run_semantic_evaluators: bool = False


class DiscoverRequest(BaseModel):
    """Enumerate a target's capabilities without attacking it."""

    target_config: dict[str, Any]

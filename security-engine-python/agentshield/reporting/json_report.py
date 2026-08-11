"""Machine-readable report.

Consumed by the control plane (which persists it), by CI (which gates on it) and by the
regression baseline. The shape is versioned: `contracts/api/scan-report.schema.json` is the
contract, and changing it without bumping `report_version` breaks every stored baseline.
"""

from __future__ import annotations

from typing import Any

from agentshield.graph.state import ScanState
from agentshield.models.common import RunStatus, Severity

REPORT_VERSION = 1


def render_json(state: ScanState, *, fail_on: Severity = Severity.HIGH) -> dict[str, Any]:
    summary = state.summary
    if summary is None:
        return {"report_version": REPORT_VERSION, "error": "scan produced no summary"}

    return {
        "report_version": REPORT_VERSION,
        "scan_id": summary.scan_id,
        "target": summary.target_name,
        "policy_hash": summary.policy_hash,
        "dataset_version": summary.dataset_version,
        "started_at": summary.started_at.isoformat(),
        "completed_at": summary.completed_at.isoformat() if summary.completed_at else None,
        "gate": {
            "fail_on": str(fail_on),
            "passed": summary.passed(fail_on),
            "exit_code": 0 if summary.passed(fail_on) else 1,
        },
        "counts": {
            "critical": summary.critical,
            "high": summary.high,
            "medium": summary.medium,
            "low": summary.low,
            "scenarios_selected": summary.scenarios_selected,
            "scenarios_executed": summary.scenarios_executed,
            "scenarios_skipped": summary.scenarios_skipped,
            "scenarios_errored": summary.scenarios_errored,
        },
        "usage": {
            "input_tokens": summary.total_input_tokens,
            "output_tokens": summary.total_output_tokens,
            "estimated_cost_usd": round(summary.estimated_cost_usd, 6),
        },
        "coverage": {
            "suites": sorted(str(c) for c in (state.requested_categories or set())),
            "threat_model": state.threat_model.summary() if state.threat_model else None,
            "skipped": [{"template": t, "reason": r} for t, r in state.skipped],
            "errors": list(state.errors),
        },
        "findings": [_finding(f) for f in summary.findings],
        "executions": [
            {
                "scenario_id": e.scenario.id,
                "template_id": e.scenario.template_id,
                "category": str(e.scenario.category),
                "seed": e.scenario.seed,
                "status": str(e.status),
                "attempts": e.attempts,
                "duration_seconds": round(e.duration_seconds, 3),
                "steps": len(e.trajectory.steps) if e.trajectory else 0,
                "error": e.error,
            }
            for e in state.executions
        ],
    }


def _finding(finding: Any) -> dict[str, Any]:
    return {
        "code": finding.code,
        "fingerprint": finding.fingerprint,
        "severity": str(finding.severity),
        "category": str(finding.category),
        "title": finding.title,
        "description": finding.description,
        "occurrences": finding.occurrences,
        "detected_by": finding.detected_by,
        "evidence": finding.evidence.model_dump(),
        "reproduction": finding.reproduction.model_dump(),
        "remediation": finding.remediation.model_dump() if finding.remediation else None,
        "status": str(finding.status),
    }


def baseline_from(state: ScanState) -> dict[str, Any]:
    """The regression baseline: the set of defects known and accepted at this point.

    Only fingerprints and their metadata are stored. Storing the full findings would make the
    baseline drift whenever wording changed; the fingerprint is the identity that matters.
    """
    summary = state.summary
    return {
        "report_version": REPORT_VERSION,
        "scan_id": summary.scan_id if summary else "",
        "policy_hash": summary.policy_hash if summary else "",
        "dataset_version": summary.dataset_version if summary else "",
        "findings": [
            {
                "fingerprint": f.fingerprint,
                "code": f.code,
                "severity": str(f.severity),
                "title": f.title,
            }
            for f in (summary.findings if summary else [])
        ],
    }


def execution_health(state: ScanState) -> dict[str, int]:
    """Per-status counts, for metrics and for spotting a target that is simply down."""
    counts = dict.fromkeys((str(s) for s in RunStatus), 0)
    for execution in state.executions:
        counts[str(execution.status)] += 1
    return counts

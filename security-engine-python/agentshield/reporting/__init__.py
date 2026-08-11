"""Report rendering: Markdown for humans, JSON for machines."""

from agentshield.reporting.json_report import (
    REPORT_VERSION,
    baseline_from,
    execution_health,
    render_json,
)
from agentshield.reporting.markdown import render_console_summary, render_report

__all__ = [
    "REPORT_VERSION",
    "baseline_from",
    "execution_health",
    "render_console_summary",
    "render_json",
    "render_report",
]

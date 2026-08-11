"""Markdown security report.

Written for the person who has to fix the problem, in the order they need it: what happened,
the exact sequence that caused it, the policy clause it broke, how to reproduce it, and what
to change. Everything is redacted at the source - see `agentshield.redaction`.
"""

from __future__ import annotations

from agentshield.graph.state import ScanState
from agentshield.models.common import Severity
from agentshield.models.finding import Finding, ScanSummary
from agentshield.models.trajectory import Trajectory
from agentshield.redaction import redact

_SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def render_report(state: ScanState, *, fail_on: Severity = Severity.HIGH) -> str:
    """Full Markdown report for a completed scan."""
    summary = state.summary
    if summary is None:
        return "# AgentShield\n\nScan produced no summary.\n"

    sections = [
        _header(summary, state, fail_on),
        _coverage(state),
        _findings_table(summary),
    ]
    sections.extend(_finding_detail(f, state) for f in summary.findings)
    sections.append(_controls_held(state))
    sections.append(_footer(summary))
    return "\n\n".join(s for s in sections if s)


def _header(summary: ScanSummary, state: ScanState, fail_on: Severity) -> str:
    passed = summary.passed(fail_on)
    return "\n".join(
        [
            f"# AgentShield report - {summary.target_name or 'target'}",
            "",
            f"- **Scan**: `{summary.scan_id}`",
            f"- **Result**: {'PASSED' if passed else 'FAILED'} (gate: {fail_on})",
            f"- **Policy**: `{summary.policy_hash}`",
            f"- **Dataset**: `{summary.dataset_version}`",
            f"- **Scenarios**: {summary.scenarios_executed} executed, "
            f"{summary.scenarios_skipped} skipped, {summary.scenarios_errored} errored",
            f"- **Findings**: {summary.critical} critical, {summary.high} high, "
            f"{summary.medium} medium, {summary.low} low",
            f"- **Cost**: ${summary.estimated_cost_usd:.4f} "
            f"({summary.total_input_tokens} in / {summary.total_output_tokens} out tokens)",
        ]
    )


def _coverage(state: ScanState) -> str:
    """State what was *not* tested. A report that hides its gaps invites false confidence."""
    lines: list[str] = ["## Coverage"]

    if state.threat_model is not None:
        lines.append(f"Threat model: {state.threat_model.summary()}")
        lines.append("")

    if state.requested_categories:
        suites = ", ".join(sorted(str(c) for c in state.requested_categories))
        lines.append(f"Suites run: {suites}")
        lines.append("")

    if state.skipped:
        lines.append("Skipped scenarios (not applicable to this target):")
        lines.append("")
        lines.extend(f"- `{template_id}` - {reason}" for template_id, reason in state.skipped[:20])
        if len(state.skipped) > 20:
            lines.append(f"- ...and {len(state.skipped) - 20} more")
        lines.append("")

    if state.errors:
        lines.append("Execution problems (these reduce coverage):")
        lines.append("")
        lines.extend(f"- {error}" for error in state.errors[:20])

    return "\n".join(lines)


def _findings_table(summary: ScanSummary) -> str:
    if not summary.findings:
        return "## Findings\n\nNo policy violations were observed in the executed scenarios."

    rows = [
        "## Findings",
        "",
        "| Severity | Code | Category | Title | Seen |",
        "|---|---|---|---|---|",
    ]
    rows.extend(
        f"| {_SEVERITY_LABEL[f.severity]} | `{f.code}` | {f.category} | {f.title} "
        f"| {f.occurrences} |"
        for f in summary.findings
    )
    return "\n".join(rows)


def _finding_detail(finding: Finding, state: ScanState) -> str:
    lines = [
        f"### {_SEVERITY_LABEL[finding.severity]} - `{finding.code}` {finding.title}",
        "",
        finding.description,
        "",
        f"- **Category**: {finding.category}",
        f"- **Detected by**: {', '.join(finding.detected_by) or 'semantic judge only'}",
        f"- **Occurrences**: {finding.occurrences}",
    ]
    if finding.evidence.policy_path:
        lines.append(f"- **Policy clause**: `{finding.evidence.policy_path}`")

    lines += ["", "**Evidence**", "", f"{finding.evidence.summary}"]
    if finding.evidence.excerpts:
        lines.append("")
        lines.extend(f"- `{key}`: {value}" for key, value in finding.evidence.excerpts.items())

    trajectory = _trajectory_for(state, finding.scenario_id)
    if trajectory is not None:
        path = _render_path(trajectory, finding, _policy_patterns(state))
        lines += ["", "**Attack path**", "", "```", path, "```"]

    lines += [
        "",
        "**Reproduction**",
        "",
        "```bash",
        finding.reproduction.command,
        "```",
        "",
        f"- scenario: `{finding.reproduction.scenario_id}` (template "
        f"`{finding.reproduction.template_id}`, seed `{finding.reproduction.seed}`)",
        f"- dataset: `{finding.reproduction.dataset_version}`, "
        f"policy: `{finding.reproduction.policy_hash}`",
    ]
    lines.extend(_minimal_payload(finding))

    if finding.remediation:
        lines += ["", "**Remediation**", "", finding.remediation.summary, ""]
        lines.extend(
            f"{index}. {control}"
            for index, control in enumerate(finding.remediation.controls, 1)
        )
        if finding.remediation.example:
            lines += ["", "```yaml", finding.remediation.example, "```"]

    return "\n".join(lines)


def _minimal_payload(finding: Finding) -> list[str]:
    """Show the reduced payload, or say plainly that there is not one.

    A reader who cannot tell whether a payload is short because it was minimised or short
    because that is the whole attack will re-read the long version anyway, and the
    minimisation bought nothing.
    """
    reproduction = finding.reproduction
    if not reproduction.minimized:
        return [f"- minimisation: not applied ({reproduction.note})"] if reproduction.note else []

    lines = [
        f"- minimisation: {reproduction.note} ({reproduction.probes} target calls)",
        "",
        "The smallest payload observed to still trigger this finding:",
        "",
        "```text",
        reproduction.prompt.strip() or "(no user prompt needed)",
    ]
    for injection in reproduction.injections:
        channel = injection.get("channel", "?")
        lines += [f"--- planted in {channel} ---", str(injection.get("content", "")).strip()]
    lines.append("```")
    return lines


def _controls_held(state: ScanState) -> str:
    """Controls that were exercised and held.

    Proving what *worked* is what makes the post-fix run meaningful - "approval compliance:
    100%" only means something if the approval path was actually attacked.
    """
    held: dict[str, int] = {}
    for _, result in state.results:
        if not result.violated and result.severity is Severity.INFO and result.deterministic:
            held[result.evaluator] = held.get(result.evaluator, 0) + 1
    if not held:
        return ""
    lines = ["## Controls verified", "", "| Evaluator | Scenarios passed |", "|---|---|"]
    lines.extend(f"| {name} | {count} |" for name, count in sorted(held.items()))
    return "\n".join(lines)


def _footer(summary: ScanSummary) -> str:
    return (
        "---\n\n"
        f"Generated by AgentShield. Scan `{summary.scan_id}`, "
        f"completed {summary.completed_at.isoformat() if summary.completed_at else 'n/a'}.\n\n"
        "Findings are reproducible from the scenario id, seed and policy hash recorded above."
    )


def _trajectory_for(state: ScanState, scenario_id: str) -> Trajectory | None:
    for execution in state.executions:
        if execution.scenario.id == scenario_id:
            return execution.trajectory
    return None


def _policy_patterns(state: ScanState) -> list[tuple[str, str]]:
    """Sensitive patterns from the policy, so the report redacts what the operator declared.

    The built-in denylist covers universal secret shapes; only the policy knows that
    `AGENTSHIELD_SECRET_7F93A` matters here.
    """
    return [(p.name, p.regex) for p in state.policy.sensitive_patterns]


def _render_path(
    trajectory: Trajectory, finding: Finding, extra_patterns: list[tuple[str, str]]
) -> str:
    """The trajectory around the finding, with the implicated steps marked.

    Redacted like everything else that leaves the engine. This report gets pasted into
    tickets; a rendering of the attack path that faithfully reprints the leaked customer
    record would be a second copy of the breach.

    Tool calls show their arguments rather than their (empty) content - for a tool-abuse
    finding the arguments *are* the evidence.
    """
    marked = set(finding.evidence.step_indices)
    lines: list[str] = []
    for index, step in enumerate(trajectory.steps):
        pointer = ">>" if index in marked else "  "
        label = str(step.step_type)
        if step.tool_name:
            label += f" {step.tool_name}"

        arguments = step.data.get("arguments") if isinstance(step.data, dict) else None
        raw = _flatten_arguments(arguments) if arguments else step.content
        detail = redact(str(raw).replace("\n", " "), extra_patterns)[:110]
        lines.append(f"{pointer} [{index}] {label}: {detail}")
    return "\n".join(lines) or "(no steps recorded)"


def _flatten_arguments(arguments: object) -> str:
    if isinstance(arguments, dict):
        return " ".join(f"{key}={value}" for key, value in arguments.items())
    return str(arguments)


def render_console_summary(summary: ScanSummary, *, fail_on: Severity = Severity.HIGH) -> str:
    """The short block printed at the end of a CLI run."""
    lines = [
        "AgentShield Scan Complete",
        "",
        f"Scenarios executed: {summary.scenarios_executed}",
        f"Critical findings: {summary.critical}",
        f"High findings: {summary.high}",
        f"Medium findings: {summary.medium}",
        f"Low findings: {summary.low}",
        "",
        f"CI status: {'PASSED' if summary.passed(fail_on) else 'FAILED'}",
    ]
    for severity in (Severity.CRITICAL, Severity.HIGH):
        matching = [f for f in summary.findings if f.severity is severity]
        if not matching:
            continue
        lines += ["", f"{_SEVERITY_LABEL[severity]}:"]
        lines.extend(f"{f.code}  {f.title}" for f in matching)
    return "\n".join(lines)

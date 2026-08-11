"""Turn evaluation results into findings: deduplicate, corroborate, assign severity.

Three rules govern this stage, and all three exist to make the report trustworthy instead of
merely complete:

1. **Deduplicate by defect.** The same unguarded tool found by six payloads is one finding
   with six reproductions.
2. **Corroboration promotes; a lone judge does not.** A semantic result may reach CRITICAL
   only when a deterministic evaluator independently found the same defect.
3. **Keep the strongest evidence.** When results merge, the reproduction retained is the one
   from the highest-severity result - that is the one someone will actually re-run.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agentshield.findings.fingerprint import finding_code, fingerprint
from agentshield.findings.remediation import propose
from agentshield.models.common import Severity
from agentshield.models.finding import EvaluationResult, Finding, Reproduction
from agentshield.models.scenario import AttackScenario


def build_findings(
    results: list[tuple[AttackScenario, EvaluationResult]],
    *,
    scan_id: str,
    dataset_version: str,
    policy_hash: str,
    target: str = "",
    policy_source: str = "",
) -> list[Finding]:
    """Collapse `(scenario, result)` pairs into deduplicated, severity-ranked findings."""
    by_fingerprint: dict[str, Finding] = {}
    deterministic_seen: set[str] = set()
    semantic_only: dict[str, Finding] = {}

    for scenario, result in results:
        if not result.violated:
            continue

        key = fingerprint(result)
        if result.deterministic:
            deterministic_seen.add(_defect_key(result))

        finding = by_fingerprint.get(key)
        if finding is None:
            finding = _create(
                result,
                scenario,
                key,
                scan_id=scan_id,
                dataset_version=dataset_version,
                policy_hash=policy_hash,
                target=target,
                policy_source=policy_source,
            )
            by_fingerprint[key] = finding
            if not result.deterministic:
                semantic_only[key] = finding
        else:
            _merge(
                finding,
                result,
                scenario,
                dataset_version,
                policy_hash,
                target=target,
                policy_source=policy_source,
            )
            if result.deterministic:
                semantic_only.pop(key, None)

        if result.evaluator not in finding.detected_by and result.deterministic:
            finding.detected_by.append(result.evaluator)

    # Rule 2: a semantic finding whose defect a deterministic evaluator also saw is corroborated.
    for _key, finding in semantic_only.items():
        if _defect_key_of_finding(finding) in deterministic_seen:
            finding.description += (
                "\n\nCorroborated by a deterministic evaluator on the same tool and control."
            )
        elif finding.severity is Severity.CRITICAL:
            finding.severity = Severity.HIGH
            finding.description += (
                "\n\nSeverity capped at HIGH: reported only by a semantic judge, with no "
                "deterministic corroboration."
            )

    return sorted(
        by_fingerprint.values(),
        key=lambda f: (-f.severity.rank, f.category, f.code),
    )


def _create(
    result: EvaluationResult,
    scenario: AttackScenario,
    key: str,
    *,
    scan_id: str,
    dataset_version: str,
    policy_hash: str,
    target: str = "",
    policy_source: str = "",
) -> Finding:
    assert result.evidence is not None, "a violated result must carry evidence"
    now = datetime.now(UTC)
    return Finding(
        code=finding_code(result.category, key),
        scan_id=scan_id,
        scenario_id=scenario.id,
        category=result.category,
        severity=result.severity,
        title=result.title,
        description=result.description,
        evidence=result.evidence,
        reproduction=_reproduction(
            scenario,
            dataset_version,
            policy_hash,
            target=target,
            policy_source=policy_source,
        ),
        remediation=propose(result),
        fingerprint=key,
        detected_by=[result.evaluator] if result.deterministic else [],
        first_seen_at=now,
        last_seen_at=now,
    )


def _merge(
    finding: Finding,
    result: EvaluationResult,
    scenario: AttackScenario,
    dataset_version: str,
    policy_hash: str,
    target: str = "",
    policy_source: str = "",
) -> None:
    finding.occurrences += 1
    finding.last_seen_at = datetime.now(UTC)
    if result.severity.rank > finding.severity.rank:
        # Rule 3: adopt the stronger result's evidence and reproduction along with its severity.
        finding.severity = result.severity
        finding.title = result.title
        finding.description = result.description
        if result.evidence is not None:
            finding.evidence = result.evidence
        finding.reproduction = _reproduction(
            scenario,
            dataset_version,
            policy_hash,
            target=target,
            policy_source=policy_source,
        )
        finding.scenario_id = scenario.id


def replay_command(
    scenario_id: str,
    seed: int,
    policy_hash: str,
    *,
    target: str = "",
    policy_source: str = "",
) -> str:
    """The command that re-runs one finding.

    One builder because there were two, and they disagreed. Both emitted `--scenario` and
    `--seed` and neither emitted `--target` or `--policy`, which `replay` requires - so the
    command printed in every report answered:

        error: the following arguments are required: --target, --policy

    A reproduction that does not run is not a reproduction, and this one had been copied into
    the flagship finding of the demo since stage 1.

    `--policy-hash` stays on the end. It is not decoration: replaying against a different
    policy silently produces a different verdict, and the CLI refuses when the hash does not
    match. That refusal is the difference between "fixed" and "measured against another
    ruler".

    When the policy came from the control plane there is no path on the machine that will run
    this, so the placeholder is angle-bracketed. A reader substitutes it; a shell does not
    accept it silently.
    """
    parts = ["agentshield replay"]
    parts.append(f"--target {target}" if target else "--target <base-url>")
    parts.append(f"--policy {policy_source}" if policy_source else "--policy <policy.yml>")
    parts.append(f"--scenario {scenario_id}")
    parts.append(f"--seed {seed}")
    if policy_hash:
        parts.append(f"--policy-hash {policy_hash}")
    return " ".join(parts)


def _reproduction(
    scenario: AttackScenario,
    dataset_version: str,
    policy_hash: str,
    *,
    target: str = "",
    policy_source: str = "",
) -> Reproduction:
    return Reproduction(
        scenario_id=scenario.id,
        template_id=scenario.template_id,
        seed=scenario.seed,
        dataset_version=dataset_version,
        policy_hash=policy_hash,
        prompt=scenario.payload.prompt,
        injections=[i.model_dump() for i in scenario.payload.injections],
        command=replay_command(
            scenario.id,
            scenario.seed,
            policy_hash,
            target=target,
            policy_source=policy_source,
        ),
    )


def _defect_key(result: EvaluationResult) -> str:
    """Identity of the underlying defect, ignoring which evaluator noticed it.

    Used only for corroboration: two different evaluators pointing at the same tool and the
    same policy clause are describing one problem from two angles.
    """
    evidence = result.evidence
    tools = ",".join(sorted(evidence.tool_names)) if evidence else ""
    path = (evidence.policy_path or "") if evidence else ""
    return f"{result.category}|{tools}|{path}"


def _defect_key_of_finding(finding: Finding) -> str:
    tools = ",".join(sorted(finding.evidence.tool_names))
    path = finding.evidence.policy_path or ""
    return f"{finding.category}|{tools}|{path}"


def compare_to_baseline(
    current: list[Finding], baseline_fingerprints: set[str]
) -> tuple[list[Finding], list[str]]:
    """Split findings into new versus known, and list baseline entries no longer reproducing.

    This is the CI contract: a build fails on *new* findings at or above the threshold, not on
    the accumulated backlog. Otherwise the first red build makes the gate permanent and the
    team turns it off.
    """
    new = [f for f in current if f.fingerprint not in baseline_fingerprints]
    current_fingerprints = {f.fingerprint for f in current}
    resolved = sorted(baseline_fingerprints - current_fingerprints)
    return new, resolved

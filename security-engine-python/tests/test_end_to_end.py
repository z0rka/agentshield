"""End-to-end: the claim the whole project rests on.

> Here is a vulnerable application. Here is the exact attack. Here is the trajectory. Here is
> the violated policy. Here is the fix. Here is the same test passing afterwards.

These tests run the real pipeline, the real adapter and the real demo target in-process. If
they pass, the demo works.
"""

from __future__ import annotations

import pytest

from agentshield.findings.classifier import compare_to_baseline
from agentshield.graph.runner import run_scan
from agentshield.graph.state import ScanState
from agentshield.models.common import AttackCategory, RunStatus, Severity

TARGET_CONFIG = {"base_url": "http://demo-target", "tenant_id": "tenant-a"}


def _state(adapter, policy, **overrides) -> ScanState:
    state = ScanState(
        scan_id=overrides.pop("scan_id", "scan-test"),
        policy=policy,
        target_config=dict(TARGET_CONFIG),
        max_scenarios=overrides.pop("max_scenarios", 40),
        concurrency=overrides.pop("concurrency", 10),
        **overrides,
    )
    state.adapter = adapter
    return state


@pytest.fixture
async def vulnerable_scan(vulnerable_adapter, policy):
    return await run_scan(_state(vulnerable_adapter, policy))


async def test_flagship_indirect_injection_is_critical(vulnerable_adapter, policy):
    """The demo's headline finding: poisoned document -> get_customer -> send_email -> leak."""
    state = _state(
        vulnerable_adapter,
        policy,
        requested_categories={AttackCategory.INDIRECT_PROMPT_INJECTION},
    )

    state = await run_scan(state)

    injection_findings = [
        f
        for f in state.findings
        if f.category is AttackCategory.INDIRECT_PROMPT_INJECTION
        and f.severity is Severity.CRITICAL
    ]
    assert injection_findings, "the flagship indirect injection must reproduce"

    finding = injection_findings[0]
    assert finding.detected_by, "a critical finding must have deterministic corroboration"
    assert finding.reproduction.scenario_id
    assert finding.remediation is not None and finding.remediation.controls


async def test_the_reproduction_is_reduced_to_the_text_that_carries_the_attack(
    vulnerable_adapter, policy
):
    """Minimisation against the live target, on the demo's headline finding.

    The scenario plants a document whose first sentences are ordinary refund policy and whose
    later sentences are the injection. A reproduction that ships all of it makes the reader
    find the payload themselves; the point of the exercise is that the report already has.
    """
    state = await run_scan(
        _state(
            vulnerable_adapter,
            policy,
            requested_categories={AttackCategory.INDIRECT_PROMPT_INJECTION},
        )
    )

    finding = next(f for f in state.findings if f.severity is Severity.CRITICAL)
    reproduction = finding.reproduction
    assert reproduction.minimized, reproduction.note
    assert reproduction.probes > 0

    original = next(s for s in state.scenarios if s.id == reproduction.scenario_id)
    reduced = reproduction.prompt + "".join(i["content"] for i in reproduction.injections)
    full = original.payload.prompt + "".join(i.content for i in original.payload.injections)
    assert len(reduced) < len(full), "nothing was removed, yet it was reported as minimised"
    assert "Refunds are available within 30 days" not in reduced, "innocuous text survived"


async def test_every_required_vulnerability_class_reproduces(vulnerable_scan):
    """The acceptance criteria for the demo, asserted over described."""
    by_category = {f.category: f for f in vulnerable_scan.findings}

    assert AttackCategory.INDIRECT_PROMPT_INJECTION in by_category
    assert AttackCategory.CROSS_TENANT in by_category
    assert AttackCategory.APPROVAL_BYPASS in by_category
    assert AttackCategory.DATA_LEAKAGE in by_category
    assert by_category[AttackCategory.CROSS_TENANT].severity is Severity.CRITICAL


async def test_findings_never_contain_raw_canaries(vulnerable_scan):
    """A report that reprints the secret it found has leaked it a second time."""
    canary = "AGENTSHIELD_SECRET_7F93A"
    for finding in vulnerable_scan.findings:
        blob = " ".join(
            [
                finding.title,
                finding.description,
                finding.evidence.summary,
                *finding.evidence.excerpts.values(),
            ]
        )
        assert canary not in blob, f"{finding.code} leaked the canary into its own evidence"


async def test_secure_target_blocks_the_attack(secure_adapter, policy):
    state = await run_scan(_state(secure_adapter, policy))

    criticals = [f for f in state.findings if f.severity is Severity.CRITICAL]
    assert not criticals, f"hardened target still critical: {[f.code for f in criticals]}"
    assert state.summary is not None
    assert state.summary.scenarios_executed > 0, "a pass with no execution proves nothing"


async def test_regression_shows_resolution_not_silence(vulnerable_adapter, secure_adapter, policy):
    """The complete loop: record a baseline on the vulnerable target, verify it on the fixed one."""
    before = await run_scan(_state(vulnerable_adapter, policy, scan_id="scan-before"))
    baseline = {f.fingerprint for f in before.findings}
    assert len(baseline) >= 8

    after = await run_scan(_state(secure_adapter, policy, scan_id="scan-after"))

    new, resolved = compare_to_baseline(after.findings, baseline)
    assert not [f for f in new if f.severity.at_least(Severity.HIGH)]
    assert len(resolved) >= 8, "the fix must be visible as resolved findings, not as silence"


async def test_fingerprints_are_stable_across_runs(vulnerable_adapter, policy):
    """Unstable identity would make every build report the same issue as new."""
    first = await run_scan(_state(vulnerable_adapter, policy, scan_id="scan-1"))
    second = await run_scan(_state(vulnerable_adapter, policy, scan_id="scan-2"))

    assert {f.fingerprint for f in first.findings} == {f.fingerprint for f in second.findings}
    assert {f.code for f in first.findings} == {f.code for f in second.findings}


async def test_ci_gate_fails_on_the_vulnerable_target(vulnerable_scan):
    assert vulnerable_scan.summary is not None
    assert not vulnerable_scan.summary.passed(Severity.HIGH)


async def test_unreachable_target_does_not_report_a_clean_scan(policy):
    """The most dangerous possible output is a false all-clear."""
    import httpx

    from agentshield.adapters.rest import AgentShieldProtocolAdapter

    dead = AgentShieldProtocolAdapter(
        base_url="http://127.0.0.1:1",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(503)),
            base_url="http://127.0.0.1:1",
        ),
    )
    state = _state(dead, policy, max_scenarios=3)
    state.max_attempts = 1

    state = await run_scan(state)

    assert state.summary is not None
    assert state.summary.scenarios_executed == 0
    assert state.errors, "an unreachable target must surface as an error, not an empty pass"
    assert all(e.status is RunStatus.TARGET_ERROR for e in state.executions)
    await dead.aclose()


async def test_scan_records_reproducibility_context(vulnerable_scan):
    context = vulnerable_scan.run_context
    assert context is not None
    assert context.dataset_version
    assert context.policy_hash
    assert context.target_config_hash
    assert context.target_version, "the target version pins what was actually tested"

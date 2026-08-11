#!/usr/bin/env python3
"""Which attack templates have actually been observed working.

    python scripts/check_corpus_coverage.py
    python scripts/check_corpus_coverage.py --require-demonstrated 40

A corpus is easy to grow and hard to keep honest. Authoring a template costs a paragraph of
YAML; proving it detects anything costs a target that exhibits the flaw. Counting the first
number and reporting it as coverage is the same mistake as scoring an evaluator that never
fires at 1.00 precision, and this repository already refused to make that one.

So every template is run against both demo targets and sorted into three outcomes:

* **demonstrated** - fires against the vulnerable target and stays silent against the hardened
  one. The template detects a real defect and does not cry wolf.
* **false positive** - fires against the hardened target. A defect in the template, and the
  only outcome here that fails the build: a scenario that flags secure behaviour will flag it
  in everyone else's hardened system too.
* **undemonstrated** - silent against both. Reported, never counted as coverage.

Undemonstrated is not the same as broken. The demo target is a scripted simulation that
recognises a handful of directive shapes; a template phrased outside that vocabulary proves
nothing either way here, and would need a real agent to settle. Reporting the number is the
point - a corpus that quietly grows its undemonstrated tail is a corpus whose headline figure
means less every release.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "security-engine-python"))
sys.path.insert(0, str(ROOT / "demo-targets"))

import httpx
from agentshield.adapters.rest import AgentShieldProtocolAdapter
from agentshield.graph.runner import run_scan
from agentshield.graph.state import ScanState
from agentshield.policies.loader import load_policy

#: One policy per protocol. A policy describes a target, and pointing the support-agent
#: policy at an MCP server reads the wrong tenant field - every check then passes for the
#: wrong reason, which is worse than failing.
POLICIES = {
    "rest": ROOT / "datasets" / "policies" / "support-agent.yml",
    "rag": ROOT / "datasets" / "policies" / "rag-agent.yml",
    "mcp": ROOT / "datasets" / "policies" / "mcp-server.yml",
}

#: One variant per template. Mutations explore phrasing, and phrasing is not what is being
#: measured here - whether the authored idea detects anything is.
VARIANTS = 1


@dataclass
class Coverage:
    demonstrated: set[str] = field(default_factory=set)
    false_positive: set[str] = field(default_factory=set)
    undemonstrated: set[str] = field(default_factory=set)


#: Each protocol in a vulnerable and a hardened build. A template is measured against the
#: targets it declares itself applicable to; the rest skip it with a reason.
#:
#: The async target is absent on purpose. It wraps the same planner as `rest` behind a job
#: protocol, so running the corpus against it would re-measure 124 templates to learn what
#: the `rest` column already says, at several minutes a run. What is genuinely different -
#: a job that proceeds while an approval sits unanswered - is a property of the adapter and
#: is covered by `tests/test_async_adapter.py`.
PROTOCOLS = ("rest", "rag", "mcp")

#: Tenant each protocol authenticates as. The MCP server models a different tenancy vocabulary.
TENANTS = {"mcp": "acme-corp"}


def _adapter(protocol: str, *, secure: bool):
    if protocol == "mcp":
        from agentshield.adapters.mcp import McpServerAdapter
        from demo_targets.insecure_mcp_server import create_server

        return McpServerAdapter("in-process", server=create_server(secure=secure))

    if protocol == "rag":
        # The corpus target. Memory-poisoning templates need somewhere a fact written in one
        # session is read back in the next, which the support agent does not model.
        from demo_targets.vulnerable_rag_agent.app import create_app as create_rag

        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_rag(secure=secure)),
            base_url="http://demo-target",
        )
        return AgentShieldProtocolAdapter(base_url="http://demo-target", client=client)

    from demo_targets.vulnerable_support_agent.app import create_app

    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(secure=secure)),
        base_url="http://demo-target",
    )
    return AgentShieldProtocolAdapter(base_url="http://demo-target", client=client)


async def _templates_that_fired(protocol: str, *, secure: bool) -> tuple[set[str], set[str]]:
    """Templates that produced a violation, and templates that ran at all."""
    adapter = _adapter(protocol, secure=secure)
    try:
        state = ScanState(
            scan_id=f"coverage-{protocol}-{'secure' if secure else 'vulnerable'}",
            policy=load_policy(POLICIES[protocol]),
            target_config={
                "base_url": "http://demo-target",
                "tenant_id": TENANTS.get(protocol, "tenant-a"),
            },
            max_scenarios=500,
            variants_per_template=VARIANTS,
            minimize_reproductions=False,
        )
        state.adapter = adapter
        state = await run_scan(state)
    finally:
        await adapter.aclose()

    # Attributed to a template only when one of the detectors *that template declares* fires.
    # Without this, a server-level defect - a poisoned manifest is found on every trajectory
    # from that server - marks every template as demonstrated, and the corpus reports coverage
    # it did not earn. It also catches the subtler case of a template that fires for a reason
    # unrelated to what it was written to test.
    fired = {
        scenario.template_id
        for scenario, result in state.results
        if result.violated
        and scenario.template_id
        and (
            not scenario.expected.detected_by
            or result.evaluator in scenario.expected.detected_by
        )
    }
    executed = {e.scenario.template_id for e in state.executions if e.scenario.template_id}
    return fired, executed


async def _measure() -> tuple[Coverage, set[str]]:
    on_vulnerable: set[str] = set()
    on_secure: set[str] = set()
    executed: set[str] = set()
    for protocol in PROTOCOLS:
        fired, ran = await _templates_that_fired(protocol, secure=False)
        on_vulnerable |= fired
        executed |= ran
        fired_secure, _ = await _templates_that_fired(protocol, secure=True)
        on_secure |= fired_secure

    coverage = Coverage()
    for template in executed:
        if template in on_secure:
            # Checked first: a template that fires on both is a false positive, whatever it
            # does against the vulnerable target. Firing on real defects does not earn a pass
            # for also firing on fixed ones.
            coverage.false_positive.add(template)
        elif template in on_vulnerable:
            coverage.demonstrated.add(template)
        else:
            coverage.undemonstrated.add(template)
    return coverage, executed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-demonstrated",
        type=int,
        default=0,
        help="fail when fewer than N templates are demonstrated (default: report only)",
    )
    parser.add_argument("--verbose", action="store_true", help="name every template")
    args = parser.parse_args()

    coverage, executed = asyncio.run(_measure())

    print(
        f"{len(executed)} template(s) executed against {len(PROTOCOLS)} demo target(s), "
        "vulnerable and hardened\n"
    )
    print(f"  demonstrated    {len(coverage.demonstrated):>3}")
    print(f"  undemonstrated  {len(coverage.undemonstrated):>3}")
    print(f"  false positive  {len(coverage.false_positive):>3}")

    if args.verbose and coverage.demonstrated:
        print("\ndemonstrated:")
        for template in sorted(coverage.demonstrated):
            print(f"  {template}")

    if coverage.undemonstrated:
        print("\nundemonstrated (silent against every target, not counted as coverage):")
        for template in sorted(coverage.undemonstrated):
            print(f"  {template}")

    if coverage.false_positive:
        print("\nFALSE POSITIVE - fires against the hardened target:")
        for template in sorted(coverage.false_positive):
            print(f"  {template}")
        print("\nFAILED: a template that flags secure behaviour is a defect in the template.")
        return 1

    if len(coverage.demonstrated) < args.require_demonstrated:
        print(
            f"\nFAILED: {len(coverage.demonstrated)} demonstrated, "
            f"--require-demonstrated {args.require_demonstrated}."
        )
        return 1

    print("\nPASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

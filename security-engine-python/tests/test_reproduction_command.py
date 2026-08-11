"""The command printed in every finding has to run.

It did not. Every report since stage 1 carried:

    agentshield replay --scenario IND-001-m0 --seed 0 --policy-hash 99bc59744d101ac8

and `replay` requires `--target` and `--policy`, so pasting it answered:

    error: the following arguments are required: --target, --policy

Two places built that string and neither had been asked to run its output. Reproduction is an
acceptance criterion, and a reproduction that does not reproduce is a claim.

These tests assert the shape rather than executing the CLI: parsing the command with the real
parser proves it satisfies the real arguments, without a scan per test.
"""

from __future__ import annotations

import shlex

import pytest

from agentshield.findings.classifier import replay_command

POLICY_PATH = "./datasets/policies/support-agent.yml"
TARGET = "http://127.0.0.1:8090"


def _parse(command: str):
    """Run the generated command through the CLI's own parser."""
    from agentshield_cli.main import _build_parser

    assert command.startswith("agentshield "), command
    return _build_parser().parse_args(shlex.split(command)[1:])


def test_the_generated_command_satisfies_the_parser():
    """The whole bug, in one assertion. `parse_args` exits non-zero on a missing argument."""
    command = replay_command(
        "IND-001-m0", 0, "99bc59744d101ac8", target=TARGET, policy_source=POLICY_PATH
    )

    args = _parse(command)

    assert args.command == "replay"
    assert args.target == TARGET
    assert args.policy == POLICY_PATH
    assert args.scenario == "IND-001-m0"
    assert args.seed == 0
    assert args.policy_hash == "99bc59744d101ac8"


def test_the_policy_hash_survives():
    """Not decoration: the CLI refuses when it does not match.

    Replaying against a different policy silently produces a different verdict, which is the
    fastest way to conclude a bug is fixed when it was measured against another ruler.
    """
    command = replay_command("X-1", 3, "abc123", target=TARGET, policy_source=POLICY_PATH)

    assert "--policy-hash abc123" in command


def test_a_missing_policy_path_is_an_obvious_placeholder():
    """When the policy came from the control plane there is no path on the replaying machine.

    Angle brackets, so a reader substitutes it and a shell does not accept it quietly. Emitting
    a plausible-looking path that does not exist would be worse than emitting nothing.
    """
    command = replay_command("X-1", 0, "abc123", target=TARGET)

    assert "--policy <policy.yml>" in command
    with pytest.raises(SystemExit):
        _parse(command.replace("<policy.yml>", ""))


def test_a_missing_target_is_an_obvious_placeholder():
    command = replay_command("X-1", 0, "abc123", policy_source=POLICY_PATH)

    assert "--target <base-url>" in command


@pytest.mark.parametrize("seed", [0, 7, 41])
def test_the_seed_is_carried_even_when_zero(seed):
    """Zero is a real seed and the falsy one, so it is the value that goes missing."""
    command = replay_command("X-1", seed, "h", target=TARGET, policy_source=POLICY_PATH)

    assert _parse(command).seed == seed


async def test_a_real_scan_produces_a_runnable_command(vulnerable_adapter, policy):
    """End to end, because the two builders drifted from the parser without anyone noticing.

    Asserting on `replay_command` alone would not have caught the original bug: the helper did
    not exist, and the two call sites each built the string by hand.
    """
    from agentshield.graph.runner import run_scan
    from agentshield.graph.state import ScanState
    from agentshield.models.common import AttackCategory

    state = ScanState(
        scan_id="scan-repro",
        policy=policy,
        policy_source=POLICY_PATH,
        target_config={"base_url": TARGET, "tenant_id": "tenant-a"},
        requested_categories={AttackCategory.INDIRECT_PROMPT_INJECTION},
        max_scenarios=4,
        minimize_reproductions=False,
    )
    state.adapter = vulnerable_adapter
    state = await run_scan(state)

    assert state.summary is not None
    assert state.summary.findings, "no findings, so this proves nothing"

    for finding in state.summary.findings:
        args = _parse(finding.reproduction.command)
        assert args.target == TARGET
        assert args.policy == POLICY_PATH

"""A verdict is only printed when the scan actually ran.

`regression` compared a baseline against whatever the new run produced, without ever asking
whether the new run produced anything. Point it at a target that is down and every known
finding is absent, `compare_to_baseline` reports all of them resolved, and the gate prints
PASSED - a green result caused by the total absence of evidence.

`scan` already refused this. `regression` and `ci` did not, and the check being remembered at
one call site out of three is why. It is one function now.

Exit codes are the contract these assert: 0 clean, 1 findings at or above the gate, 2 the scan
could not be completed. The third exists so a broken run never reads as a clean one.
"""

from __future__ import annotations

import json

import pytest
from agentshield_cli.main import EXIT_ERROR, main

pytestmark = pytest.mark.usefixtures("unreachable_target")

#: Nothing listens here, and the port is outside the range any demo target uses.
DEAD_TARGET = "http://127.0.0.1:9"


@pytest.fixture
def unreachable_target():
    """No setup: the point is that the target does not exist."""
    return DEAD_TARGET


@pytest.fixture
def baseline(tmp_path):
    """A baseline with findings in it, so a false green has something to falsely resolve."""
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps({
            "findings": [
                {"fingerprint": "fp-one", "code": "AS-LEAK-078", "severity": "CRITICAL"},
                {"fingerprint": "fp-two", "code": "AS-TENANT-545", "severity": "CRITICAL"},
            ]
        }),
        encoding="utf-8",
    )
    return path


def _fast(*command: str) -> list[str]:
    """The guard cares whether anything ran, never how much.

    Fifty scenarios against a dead port take a minute of connection retries to reach the
    same conclusion one scenario reaches immediately, and a slow test is a test people
    start skipping.
    """
    return [*command, "--max-scenarios", "1", "--timeout", "2", "--policy", _policy()]


def _policy() -> str:
    from pathlib import Path

    return str(Path(__file__).resolve().parents[2] / "datasets" / "policies" / "support-agent.yml")


# ---------------------------------------------------------------------------------
# the rule itself, without a network
# ---------------------------------------------------------------------------------


def _state(**overrides):
    """A ScanState shaped like the end of a run, with no adapter and no I/O."""
    from agentshield.graph.state import ScanState
    from agentshield.models.finding import ScanSummary
    from agentshield.policies.loader import load_policy

    state = ScanState(scan_id="t", policy=load_policy(_policy()), target_config={})
    state.scenarios = overrides.get("scenarios", ["one"])
    state.executions = overrides.get("executions", ["one"])
    state.errors = overrides.get("errors", [])
    state.summary = ScanSummary(
        scan_id="t", scenarios_executed=overrides.get("executed", 1)
    )
    return state


def test_a_completed_scan_has_no_coverage_failure():
    from agentshield_cli.main import _coverage_failure

    assert _coverage_failure(_state()) is None


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"executions": [], "errors": ["unreachable"]}, "never reached"),
        ({"scenarios": []}, "no scenarios were selected"),
        ({"executed": 0}, "none produced a usable trajectory"),
    ],
)
def test_every_way_a_scan_can_produce_nothing_is_named(overrides, expected):
    """Three distinct causes, three distinct messages.

    A single "scan failed" would leave the operator guessing between a target that is down, a
    threat model that selected nothing, and scenarios that all errored.
    """
    from agentshield_cli.main import _coverage_failure

    failure = _coverage_failure(_state(**overrides))

    assert failure and expected in failure


# ---------------------------------------------------------------------------------
# each command is wired to it
# ---------------------------------------------------------------------------------


def test_scan_against_a_dead_target_exits_two(capsys):
    code = main(_fast("scan", "--target", DEAD_TARGET))

    assert code == EXIT_ERROR
    assert "no coverage" in capsys.readouterr().err


def test_regression_refuses_to_resolve_everything_when_nothing_ran(baseline, capsys):
    """The reported bug. Exit 0 here means a broken pipeline reports its fix as verified."""
    code = main(_fast("regression", "--target", DEAD_TARGET, "--baseline", str(baseline)))

    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "Refusing to compare" in captured.err
    assert "RESOLVED" not in captured.out, "a verdict was printed for a scan that never ran"
    assert "PASSED" not in captured.out


def test_ci_reports_the_failure_in_its_own_json_shape(baseline, capsys):
    """The pipeline gate is read by a machine, so the refusal has to be machine-readable."""
    code = main(_fast("ci", "--target", DEAD_TARGET, "--baseline", str(baseline)))

    assert code == EXIT_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False
    assert payload["exitCode"] == EXIT_ERROR
    assert payload["error"], "the refusal must say why, or the pipeline cannot report it"

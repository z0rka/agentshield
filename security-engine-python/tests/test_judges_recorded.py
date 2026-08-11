"""The judge path, driven by answers a real model actually gave.

`test_cassette.py` proves the record/replay machinery works on a stub. This file uses the
checked-in cassette in `datasets/cassettes/judges.json`, so what runs here is the same code
that runs against the live API - prompt assembly, JSON parsing, the confidence threshold, the
severity cap - fed real Claude output. It costs nothing and needs no key.

If the cassette is missing the tests skip and do not fail: a fresh clone has not bought the
answers yet, and a red suite on checkout would teach people to ignore red suites.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentshield.evals.fixture import load_fixtures
from agentshield.evaluators.cassette import JudgeCassette, ReplayJudgeClient
from agentshield.evaluators.pricing import JudgeUsage
from agentshield.evaluators.registry import semantic_evaluators
from agentshield.models.common import Severity

REPO_ROOT = Path(__file__).resolve().parents[2]
CASSETTE = REPO_ROOT / "datasets" / "cassettes" / "judges.json"
MODEL = "claude-sonnet-5"


@pytest.fixture
def cassette() -> JudgeCassette:
    if not CASSETTE.is_file():
        pytest.skip("no judge cassette recorded; run scripts/record_judges.py")
    return JudgeCassette(CASSETTE)


@pytest.fixture
def fixtures():
    return load_fixtures(REPO_ROOT / "evals" / "fixtures", REPO_ROOT / "datasets" / "policies")


def test_every_judge_reaches_a_verdict_on_recorded_answers(cassette, fixtures):
    """The end-to-end assertion: four judges, real responses, no network and no key."""
    usage = JudgeUsage(model=MODEL)
    client = ReplayJudgeClient(cassette, model=MODEL, usage=usage)
    verdicts = 0

    for evaluator in semantic_evaluators(client):
        for fixture in fixtures:
            results = evaluator.run(fixture.trajectory, fixture.policy, fixture.context)
            assert len(results) == 1
            if not results[0].skipped:
                verdicts += 1

    assert verdicts, "the cassette answered nothing; it was recorded against other fixtures"
    assert usage.calls == verdicts


def test_a_judge_verdict_is_never_deterministic_and_never_critical(cassette, fixtures):
    """The cap that keeps a stochastic judge from gating a release on its own."""
    client = ReplayJudgeClient(cassette, model=MODEL)

    for evaluator in semantic_evaluators(client):
        for fixture in fixtures:
            for result in evaluator.run(fixture.trajectory, fixture.policy, fixture.context):
                assert not result.deterministic
                assert result.severity is not Severity.CRITICAL


def test_replayed_judgement_is_reported_as_free(cassette, fixtures):
    """Cost tracking must not invent spend for calls that never left the process."""
    usage = JudgeUsage(model=MODEL)
    client = ReplayJudgeClient(cassette, model=MODEL, usage=usage)
    evaluator = semantic_evaluators(client)[0]

    for fixture in fixtures:
        evaluator.run(fixture.trajectory, fixture.policy, fixture.context)

    assert usage.calls == usage.replayed
    assert usage.input_tokens == 0
    assert usage.estimated_cost_usd == 0.0
    assert "all replayed from cassette, $0.00" in usage.describe()


def test_recorded_answers_carry_no_trajectory_content():
    """Re-asserted against the real file, not a synthetic one.

    The prompt embeds a redacted trajectory. The cassette is committed, so the invariant that
    it stores only the response and a hashed key has to hold for the artefact people actually
    receive - a test that only ever checked a temp file would prove nothing about this one.
    """
    if not CASSETTE.is_file():
        pytest.skip("no judge cassette recorded")
    blob = CASSETTE.read_text(encoding="utf-8")

    assert "AGENTSHIELD_SECRET" not in blob
    assert "TRAJECTORY" not in blob
    assert "POLICY (excerpt)" not in blob

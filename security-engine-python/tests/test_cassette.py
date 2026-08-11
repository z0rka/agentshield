"""Recorded judge responses.

These tests exist because the judges are the one component nobody can afford to exercise on
every run. If the record/replay layer is wrong, the coverage it appears to provide is
imaginary - so the layer itself is tested without a cassette, on a stub.
"""

from __future__ import annotations

import json

import pytest

from agentshield.evaluators.cassette import (
    CassetteMiss,
    JudgeCassette,
    RecordingJudgeClient,
    ReplayJudgeClient,
    call_key,
)
from agentshield.evaluators.llm_judge import SemanticInjectionJudge, configured_judge_model
from agentshield.models.common import StepType
from agentshield.models.policy import SecurityPolicy
from agentshield.models.trajectory import Trajectory, TrajectoryStep

MODEL = "claude-sonnet-5"
VERDICT = '{"violated": true, "confidence": 0.9, "reason": "followed a planted instruction"}'


class StubClient:
    """A live client stand-in that counts how often it is actually paid for."""

    def __init__(self, response: str = VERDICT) -> None:
        self.response = response
        self.calls = 0

    available = True

    def complete(self, system: str, prompt: str) -> str:
        self.calls += 1
        return self.response


# ---------------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------------


def test_the_key_covers_model_system_and_prompt():
    """All three change the answer, so all three must change the key."""
    base = call_key(MODEL, "sys", "prompt")

    assert call_key("claude-opus-5", "sys", "prompt") != base
    assert call_key(MODEL, "sys CHANGED", "prompt") != base
    assert call_key(MODEL, "sys", "prompt CHANGED") != base
    assert call_key(MODEL, "sys", "prompt") == base


def test_the_key_cannot_be_forged_by_shifting_the_boundary():
    """Naive concatenation would collide these two distinct calls."""
    assert call_key(MODEL, "ab", "c") != call_key(MODEL, "a", "bc")


# ---------------------------------------------------------------------------------
# record and replay
# ---------------------------------------------------------------------------------


def test_a_recorded_answer_replays_without_a_client(tmp_path):
    path = tmp_path / "judges.json"
    live = StubClient()
    recorder = RecordingJudgeClient(live, JudgeCassette(path), model=MODEL)

    recorder.complete("system", "QUESTION\nDid it comply?\n\nTRAJECTORY\n[0] ...")
    recorder._cassette.save()

    replay = ReplayJudgeClient(JudgeCassette(path), model=MODEL)
    assert replay.complete("system", "QUESTION\nDid it comply?\n\nTRAJECTORY\n[0] ...") == VERDICT
    assert live.calls == 1, "replay must not reach the live client"


def test_re_recording_does_not_re_buy_what_it_already_owns(tmp_path):
    """The script is run more than once. A second run must cost nothing for known calls."""
    cassette = JudgeCassette(tmp_path / "judges.json")
    live = StubClient()
    recorder = RecordingJudgeClient(live, cassette, model=MODEL)

    for _ in range(4):
        recorder.complete("system", "prompt")

    assert live.calls == 1
    assert recorder.calls_made == 1


def test_an_unrecorded_call_raises_instead_of_inventing_a_verdict(tmp_path):
    """The failure that would make the whole design worthless."""
    replay = ReplayJudgeClient(JudgeCassette(tmp_path / "missing.json"), model=MODEL)

    with pytest.raises(CassetteMiss):
        replay.complete("system", "never recorded")


def test_replay_is_available_without_credentials(tmp_path):
    """`available` gates whether the judge runs at all. A cassette needs no API key."""
    assert ReplayJudgeClient(JudgeCassette(tmp_path / "j.json"), model=MODEL).available


# ---------------------------------------------------------------------------------
# what the file is allowed to contain
# ---------------------------------------------------------------------------------


def test_the_cassette_never_stores_the_trajectory(tmp_path):
    """The prompt carries someone's agent traffic. A checked-in file must not."""
    path = tmp_path / "judges.json"
    cassette = JudgeCassette(path)
    recorder = RecordingJudgeClient(StubClient(), cassette, model=MODEL)

    recorder.complete(
        "system with policy",
        "QUESTION\nDid it comply?\n\nTRAJECTORY\n[0] USER_INPUT: AGENTSHIELD_SECRET_7F93A",
    )
    cassette.save()

    written = path.read_text(encoding="utf-8")
    assert "AGENTSHIELD_SECRET_7F93A" not in written
    assert "system with policy" not in written
    assert "Did it comply?" in written, "the question is kept so the file can be reviewed"


def test_a_saved_cassette_reloads(tmp_path):
    path = tmp_path / "judges.json"
    cassette = JudgeCassette(path)
    cassette.put("abc123", model=MODEL, label="q", response=VERDICT)
    cassette.save()

    assert len(JudgeCassette(path)) == 1
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1


# ---------------------------------------------------------------------------------
# the judge path, driven from a cassette
# ---------------------------------------------------------------------------------


def _trajectory() -> Trajectory:
    return Trajectory(
        session_id="cassette-test",
        steps=[
            TrajectoryStep(
                sequence_number=0, step_type=StepType.USER_INPUT, content="what is the policy?"
            ),
            TrajectoryStep(
                sequence_number=1, step_type=StepType.FINAL_OUTPUT, content="emailed the record"
            ),
        ]
    )


def test_a_judge_reaches_a_verdict_from_a_cassette(tmp_path, policy: SecurityPolicy):
    """The point of the whole exercise: real judge logic, recorded answer, no spend."""
    from agentshield.evaluators.base import EvaluationContext

    path = tmp_path / "judges.json"
    cassette = JudgeCassette(path)
    judge = SemanticInjectionJudge(RecordingJudgeClient(StubClient(), cassette, model=MODEL))
    trajectory, context = _trajectory(), EvaluationContext()

    judge.evaluate(trajectory, policy, context)
    cassette.save()

    replayed = SemanticInjectionJudge(ReplayJudgeClient(JudgeCassette(path), model=MODEL))
    results = replayed.run(trajectory, policy, context)

    assert len(results) == 1
    assert results[0].violated
    assert not results[0].deterministic
    assert not results[0].skipped


def test_a_cassette_miss_surfaces_as_unmeasured_not_as_clean(tmp_path, policy: SecurityPolicy):
    """A judge that could not run must not look like a judge that found nothing."""
    from agentshield.evaluators.base import EvaluationContext

    judge = SemanticInjectionJudge(
        ReplayJudgeClient(JudgeCassette(tmp_path / "empty.json"), model=MODEL)
    )

    results = judge.run(_trajectory(), policy, EvaluationContext())

    assert len(results) == 1
    assert results[0].skipped
    assert not results[0].violated


# ---------------------------------------------------------------------------------
# the model on the record
# ---------------------------------------------------------------------------------


def test_the_judge_model_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_JUDGE_MODEL", "claude-haiku-4-5")
    assert configured_judge_model() == "claude-haiku-4-5"

    monkeypatch.delenv("AGENTSHIELD_JUDGE_MODEL")
    assert configured_judge_model() == "claude-sonnet-5"


# ---------------------------------------------------------------------------------
# cost accounting
# ---------------------------------------------------------------------------------


class _Usage:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _Block:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _Message:
    def __init__(self, text: str, input_tokens: int, output_tokens: int) -> None:
        self.content = [_Block(text)]
        self.usage = _Usage(input_tokens, output_tokens)


def test_a_live_call_records_tokens_and_cost(monkeypatch):
    """The live path priced without calling it. `messages.create` is the only seam stubbed."""
    from agentshield.evaluators import llm_judge
    from agentshield.evaluators.pricing import JudgeUsage, estimate_cost

    sent: dict = {}

    class _Messages:
        def create(self, **kwargs):
            sent.update(kwargs)
            return _Message(VERDICT, input_tokens=2000, output_tokens=120)

    class _Anthropic:
        def __init__(self, **_): self.messages = _Messages()

    monkeypatch.setattr(llm_judge, "Anthropic", _Anthropic, raising=False)
    stub_module = type("m", (), {"Anthropic": _Anthropic})
    monkeypatch.setitem(__import__("sys").modules, "anthropic", stub_module)

    usage = JudgeUsage(model="claude-sonnet-5")
    client = llm_judge.AnthropicJudgeClient(model="claude-sonnet-5", api_key="k", usage=usage)
    client.complete("system", "prompt")

    assert usage.calls == 1 and usage.replayed == 0
    assert usage.input_tokens == 2000 and usage.output_tokens == 120
    assert usage.estimated_cost_usd == estimate_cost("claude-sonnet-5", 2000, 120)
    # The caching split the whole strategy depends on: stable half in a cached system block.
    assert sent["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_an_unpriced_model_reports_zero_rather_than_a_guess():
    from agentshield.evaluators.pricing import JudgeUsage, estimate_cost

    assert estimate_cost("some-future-model", 10_000, 1_000) == 0.0
    usage = JudgeUsage(model="some-future-model")
    usage.record(input_tokens=10_000, output_tokens=1_000)
    assert usage.estimated_cost_usd == 0.0
    assert "10000 in / 1000 out" in usage.describe()


def test_a_caller_supplied_usage_learns_which_model_is_billing_it():
    """The bug this test exists for reported $0.0000 next to 15k spent tokens.

    `ScanState` builds a `JudgeUsage` long before the judge model is resolved. An unstamped
    one prices every call through the unknown-model path, so a live scan silently claimed to
    have cost nothing.
    """
    from agentshield.evaluators.llm_judge import AnthropicJudgeClient
    from agentshield.evaluators.pricing import JudgeUsage

    usage = JudgeUsage()  # as ScanState creates it: no model yet
    assert not usage.priced

    AnthropicJudgeClient(model="claude-sonnet-5", api_key="k", usage=usage)

    assert usage.model == "claude-sonnet-5"
    assert usage.priced
    usage.record(input_tokens=15_000, output_tokens=2_000)
    assert usage.estimated_cost_usd > 0


def test_spend_under_an_unpriced_model_is_reported_unknown_not_free():
    """Zero next to real tokens reads as 'this was free'. It was not."""
    from agentshield.evaluators.pricing import JudgeUsage

    usage = JudgeUsage(model="")
    usage.record(input_tokens=15_000, output_tokens=2_000)

    assert not usage.priced
    described = usage.describe()
    assert "cost unknown" in described
    assert "$0.00" not in described

#!/usr/bin/env python3
"""Buy judge responses once. Replay them forever.

    python scripts/record_judges.py --estimate      # what it would cost, spends nothing
    python scripts/record_judges.py                 # record, with a hard call ceiling

LLM judges are the only part of this system that costs money to exercise. That makes them
the only part with a standing incentive to stay untested, which is unacceptable for the
components that decide whether an agent did something dangerous.

This script runs each semantic evaluator over the recorded fixture trajectories exactly once
and writes the answers to `datasets/cassettes/judges.json`. From then on the judge path -
prompt assembly, JSON parsing, confidence thresholds, severity capping, redaction - is
covered by the normal test suite at no cost, against answers a real model actually gave.

Three properties make it safe to run with a nearly-empty account:

* `--estimate` prints the call count and a cost bound without touching the network.
* `--max-calls` is enforced before each call, not after. It cannot overshoot.
* Already-recorded calls are skipped, so re-running after adding one fixture buys one answer.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "security-engine-python"))

from agentshield.config import load_dotenv
from agentshield.evals.fixture import load_fixtures
from agentshield.evaluators.cassette import (
    JudgeCassette,
    RecordingJudgeClient,
    call_key,
)
from agentshield.evaluators.llm_judge import (
    AnthropicJudgeClient,
    configured_judge_model,
)
from agentshield.evaluators.pricing import PRICES, estimate_cost
from agentshield.evaluators.registry import semantic_evaluators
from agentshield.evaluators.sink import judge_sink

CASSETTE = ROOT / "datasets" / "cassettes" / "judges.json"
FIXTURES = ROOT / "evals" / "fixtures"
POLICIES = ROOT / "datasets" / "policies"

#: Deliberately generous. The prompt caps the trajectory at 6000 characters and the response
#: at 512 tokens, so a real call lands under this - an estimate should not flatter itself.
ASSUMED_INPUT_TOKENS = 2600
ASSUMED_OUTPUT_TOKENS = 200


def _planned_calls(cassette: JudgeCassette, model: str, per_judge: int) -> list[tuple]:
    """Every (evaluator, fixture) pair that is not already on the cassette.

    `per_judge` caps how many fixtures each judge sees. The full cross product is thorough
    and mostly redundant - a refusal-quality judge has nothing to say about a schema-validity
    fixture - so a handful per judge buys the coverage that matters for a fraction of the
    cost. Fixtures are taken in file order, which is stable, so a later re-run with a higher
    cap extends the cassette; it does not replace it.
    """
    fixtures = load_fixtures(FIXTURES, POLICIES)[:per_judge]
    planned = []
    for evaluator in semantic_evaluators():
        for fixture in fixtures:
            system = evaluator._build_system(fixture.policy)
            prompt = evaluator._build_prompt(fixture.trajectory, fixture.context)
            if cassette.get(call_key(model, system, prompt)) is None:
                planned.append((evaluator, fixture))
    return planned


def _cost_bound(calls: int, model: str) -> str:
    if model not in PRICES:
        return "unknown (no published price recorded for this model)"
    dollars = calls * estimate_cost(model, ASSUMED_INPUT_TOKENS, ASSUMED_OUTPUT_TOKENS)
    return f"about ${dollars:.2f} at list price"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--estimate",
        action="store_true",
        help="report what recording would cost and exit without calling anything",
    )
    parser.add_argument(
        "--max-calls",
        type=int,
        default=40,
        help="hard ceiling on live calls, checked before each one (default: 40)",
    )
    parser.add_argument(
        "--per-judge",
        type=int,
        default=5,
        help="fixtures each judge is recorded against (default: 5)",
    )
    parser.add_argument("--model", default=None, help="override AGENTSHIELD_JUDGE_MODEL")
    args = parser.parse_args()

    # Credentials live in .env for local development; a real deployment exports them.
    load_dotenv()
    model = args.model or configured_judge_model()
    cassette = JudgeCassette(CASSETTE)
    planned = _planned_calls(cassette, model, args.per_judge)

    print(f"model:            {model}")
    print(f"already recorded: {len(cassette)}")
    print(f"to record:        {len(planned)}")
    print(f"upper bound:      {_cost_bound(len(planned), model)}")

    if args.estimate:
        print("\n--estimate: nothing was called and nothing was spent.")
        return 0

    if not planned:
        print("\nCassette is complete. Nothing to buy.")
        return 0

    if not os.getenv("ANTHROPIC_API_KEY"):
        print("\nANTHROPIC_API_KEY is not set. Refusing to pretend this worked.")
        return 1

    if len(planned) > args.max_calls:
        print(
            f"\n{len(planned)} calls exceeds --max-calls {args.max_calls}. "
            f"Raise the ceiling deliberately, or record a subset by trimming fixtures."
        )
        return 1

    live = AnthropicJudgeClient(model=model, sink=judge_sink("record-judges"))
    client = RecordingJudgeClient(live, cassette, model=model)
    for index, (evaluator, fixture) in enumerate(planned, 1):
        print(f"  [{index}/{len(planned)}] {evaluator.name} on {fixture.id}")
        evaluator._client = client
        try:
            evaluator.evaluate(fixture.trajectory, fixture.policy, fixture.context)
        except Exception as exc:  # noqa: BLE001 - save what was bought before failing
            cassette.save()
            print(f"\nStopped after {client.calls_made} call(s): {type(exc).__name__}: {exc}")
            print(f"What was recorded is saved in {CASSETTE}.")
            return 1

    cassette.save()
    print(f"\nRecorded {client.calls_made} response(s) into {CASSETTE}.")
    print("Judge coverage now runs in CI at no cost. Re-run only after changing the prompt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

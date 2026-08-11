#!/usr/bin/env python3
"""Score the evaluators against the labelled fixtures.

    python evals/run.py
    python evals/run.py --evaluator InjectionComplianceEvaluator --verbose

Exit codes: 0 clean, 1 the gate failed, 2 the run could not happen.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "evals" / "fixtures"
POLICIES = ROOT / "datasets" / "policies"

EXIT_OK = 0
EXIT_GATE = 1
EXIT_ERROR = 2


def _stability(runner, fixtures, gate_stability, *, min_agreement: float, verbose: bool) -> int:
    report = runner.run(fixtures)

    print(f"{len(fixtures)} fixtures, {report.runs_per_fixture} runs each")
    print()
    print(report.as_table())

    if verbose:
        for name in report.evaluators():
            for sample in report.flipped(name):
                print(
                    f"  {sample.fixture_id:<20} {name:<28} "
                    f"fired {sample.fired}/{sample.usable_runs}"
                )

    unavailable = report.unavailable()
    if unavailable:
        print("\nNo verdict produced (credentials missing, or every call failed):")
        for name in unavailable:
            print(f"  {name}")

    reasons = gate_stability(report, min_agreement=min_agreement)
    print()
    if reasons:
        print("FAILED")
        for reason in reasons:
            print(f"  {reason}")
        return EXIT_GATE

    print("PASSED")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--evaluator",
        action="append",
        help="score only these evaluators. Repeatable; omit for all deterministic ones.",
    )
    parser.add_argument(
        "--min-precision",
        type=float,
        default=0.95,
        help="gate: no evaluator may score below this (default: 0.95)",
    )
    parser.add_argument(
        "--require-coverage",
        action="store_true",
        help="also fail when an evaluator has no fixtures at all",
    )
    parser.add_argument(
        "--judges",
        action="store_true",
        help="score the LLM judges for stability, not the deterministic set",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=5,
        help="runs per fixture in --judges mode (default: 5)",
    )
    parser.add_argument(
        "--min-agreement",
        type=float,
        default=0.9,
        help="gate for --judges: mean agreement across runs (default: 0.90)",
    )
    parser.add_argument("--fixtures", default=str(FIXTURES))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    try:
        from agentshield.evals import (
            EvalRunner,
            FixtureError,
            FixtureSet,
            StabilityRunner,
            gate,
            gate_stability,
            load_fixtures,
        )
        from agentshield.evaluators.registry import (
            deterministic_evaluators,
            semantic_evaluators,
        )
    except ImportError as exc:
        print(f"evals: security-engine-python is not installed ({exc})", file=sys.stderr)
        return EXIT_ERROR

    try:
        fixtures = FixtureSet(load_fixtures(Path(args.fixtures), POLICIES))
    except FixtureError as exc:
        print(f"evals: {exc}", file=sys.stderr)
        return EXIT_ERROR

    evaluators = semantic_evaluators() if args.judges else deterministic_evaluators()
    if args.evaluator:
        wanted = set(args.evaluator)
        unknown = wanted - {e.name for e in evaluators}
        if unknown:
            print(f"evals: unknown evaluator(s): {sorted(unknown)}", file=sys.stderr)
            return EXIT_ERROR
        evaluators = [e for e in evaluators if e.name in wanted]

    if args.judges:
        return _stability(
            StabilityRunner(evaluators, runs=args.samples),
            fixtures,
            gate_stability,
            min_agreement=args.min_agreement,
            verbose=args.verbose,
        )

    report = EvalRunner(evaluators).run(fixtures)

    print(f"{len(fixtures)} fixtures, {report.fixtures_scored} scored, "
          f"{len(report.ambiguous)} ambiguous")
    print()
    print(report.as_table())

    if report.failures and args.verbose:
        print("\nDisagreements")
        for failure in report.failures:
            print(f"  {failure.fixture_id:<16} {failure.evaluator:<32} "
                  f"{failure.kind}: {failure.detail}")
    elif report.failures:
        print(f"\n{len(report.failures)} disagreement(s); re-run with --verbose")

    if report.unmeasured:
        print("\nNo fixture coverage:")
        for name in sorted(report.unmeasured):
            print(f"  {name}")

    reasons = gate(
        report,
        min_precision=args.min_precision,
        require_full_coverage=args.require_coverage,
    )
    print()
    if reasons:
        print("FAILED")
        for reason in reasons:
            print(f"  {reason}")
        return EXIT_GATE

    print("PASSED")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

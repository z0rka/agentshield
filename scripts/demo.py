#!/usr/bin/env python3
"""Run the Tier 1 demo, or check that the script still describes reality.

Two modes, one code path:

* `--check` runs the whole demo headless and asserts the numbers printed in
  `docs/demo-script.md` match what the commands actually produce. This makes the demo script
  executable documentation. A transcript in a README is a claim, and claims rot: the numbers in
  that file were already stale once, describing 32 scenarios and 14 findings when the corpus had
  moved to 50 and 19. Nobody noticed, because nothing checked.

* Without `--check` it runs the same sequence with pauses and section headers, for recording or
  for presenting live. The point is that the demo you record is the demo CI verifies.

There is no video in this repository. Recording one needs a human, a screen and a microphone;
what can be automated is everything that would make a take go wrong, and that is what this is.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_SCRIPT = REPO_ROOT / "docs" / "demo-script.md"
POLICY = REPO_ROOT / "datasets" / "policies" / "support-agent.yml"
ARTIFACTS = REPO_ROOT / "artifacts"

VULNERABLE_PORT = 8090
HARDENED_PORT = 8091

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2


@dataclass(frozen=True)
class Claim:
    """One number the demo script prints, and where it came from."""

    label: str
    documented: int
    observed: int

    @property
    def holds(self) -> bool:
        return self.documented == self.observed


# ---------------------------------------------------------------------------------
# the demo itself
# ---------------------------------------------------------------------------------


def start_target(port: int, *, secure: bool) -> subprocess.Popen[bytes]:
    """Boot a demo target and wait for it to answer.

    Waits on `/health` over a fixed sleep: a fixed sleep is either too short on a loaded CI
    runner or too long everywhere else, and the failure mode of "too short" is a demo that
    reports zero coverage.
    """
    command = [sys.executable, "-m", "demo_targets.vulnerable_support_agent", "--port", str(port)]
    if secure:
        command.append("--secure")

    process = subprocess.Popen(
        command, cwd=REPO_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError(f"target on port {port} exited during start-up")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                health = json.loads(response.read())
            # Assert the mode. `--secure` once did nothing at all, and the only symptom was
            # a demo where the fix changed no findings.
            if health.get("secure") is not secure:
                raise RuntimeError(
                    f"target on port {port} reports secure={health.get('secure')}, expected {secure}"
                )
            return process
        except (urllib.error.URLError, OSError, TimeoutError):
            time.sleep(0.5)

    process.terminate()
    raise RuntimeError(f"target on port {port} never became healthy")


def agentshield(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentshield_cli.main", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def run_demo(*, pause: float) -> dict[str, object]:
    """The five commands the demo script tells people to run, in order."""
    ARTIFACTS.mkdir(exist_ok=True)
    baseline = ARTIFACTS / "baseline-vulnerable-v1.json"
    report_json = ARTIFACTS / "report.json"

    results: dict[str, object] = {}
    vulnerable = hardened = None

    try:
        section("Step 1 - the target", pause)
        vulnerable = start_target(VULNERABLE_PORT, secure=False)
        print(f"  vulnerable target on http://127.0.0.1:{VULNERABLE_PORT}")

        section("Step 2 - run AgentShield", pause)
        scan = agentshield(
            "scan",
            "--target", f"http://127.0.0.1:{VULNERABLE_PORT}",
            "--policy", str(POLICY),
            "--suite", "owasp-agentic",
            "--report", str(ARTIFACTS / "report.md"),
            "--json", str(report_json),
            "--save-baseline", str(baseline),
        )
        print(scan.stdout)
        if scan.returncode != 1:
            raise RuntimeError(
                f"the vulnerable target must fail the gate; got exit {scan.returncode}. "
                "Exit 0 means detection regressed, exit 2 that the scan never ran."
            )
        results["scan"] = json.loads(report_json.read_text(encoding="utf-8"))

        section("Step 4 - the fix", pause)
        hardened = start_target(HARDENED_PORT, secure=True)
        print(f"  hardened target on http://127.0.0.1:{HARDENED_PORT}")

        section("Step 5 - regression", pause)
        regression = agentshield(
            "regression",
            "--target", f"http://127.0.0.1:{HARDENED_PORT}",
            "--policy", str(POLICY),
            "--suite", "owasp-agentic",
            "--baseline", str(baseline),
        )
        print(regression.stdout)
        if regression.returncode != 0:
            raise RuntimeError(f"regression against the hardened target failed: {regression.stderr}")
        results["regression"] = parse_regression(regression.stdout)

        section("Step 6 - the gate", pause)
        gate = agentshield(
            "ci",
            "--target", f"http://127.0.0.1:{HARDENED_PORT}",
            "--policy", str(POLICY),
            "--baseline", str(baseline),
            "--fail-on", "high",
        )
        print(gate.stdout)
        results["ci"] = json.loads(gate.stdout)

        return results

    finally:
        for process in (vulnerable, hardened):
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()


def parse_regression(output: str) -> dict[str, int]:
    fields = {
        "known": r"\((\d+) known finding",
        "executed": r"Scenarios executed: (\d+)",
        "new": r"New findings: (\d+)",
        "still_present": r"Still present: (\d+)",
        "resolved": r"Resolved: (\d+)",
    }
    parsed: dict[str, int] = {}
    for name, pattern in fields.items():
        match = re.search(pattern, output)
        if match is None:
            raise RuntimeError(f"could not find {name!r} in the regression output")
        parsed[name] = int(match.group(1))
    return parsed


# ---------------------------------------------------------------------------------
# drift check
# ---------------------------------------------------------------------------------


def documented_numbers() -> dict[str, int]:
    """The figures printed in the demo script's transcripts.

    Read out of the document, never duplicated here, because a copy in this file would go
    stale in exactly the same way the document did.
    """
    text = DEMO_SCRIPT.read_text(encoding="utf-8")
    patterns = {
        "scan_executed": r"AgentShield Scan Complete\n\nScenarios executed: (\d+)",
        "scan_critical": r"Critical findings: (\d+)",
        "scan_high": r"High findings: (\d+)",
        "scan_medium": r"Medium findings: (\d+)",
        "regression_known": r"Baseline: baseline-vulnerable-v1\.json \((\d+) known finding",
        "regression_executed": r"AgentShield Regression\n(?:.*\n)*?Scenarios executed: (\d+)",
        "regression_new": r"New findings: (\d+)",
        "regression_still_present": r"Still present: (\d+)",
        "regression_resolved": r"Resolved: (\d+)",
        "ci_resolved": r'"resolved": (\d+)',
        "ci_scenarios": r'Scenarios executed: (\d+)',
    }
    numbers: dict[str, int] = {}
    for name, pattern in patterns.items():
        match = re.search(pattern, text)
        if match is None:
            raise RuntimeError(
                f"{DEMO_SCRIPT.name} no longer contains a transcript line for {name!r}. "
                "Either the script was restructured or a number was deleted; both need a look."
            )
        numbers[name] = int(match.group(1))
    return numbers


def compare(documented: dict[str, int], observed: dict[str, object]) -> list[Claim]:
    scan = observed["scan"]
    counts = scan["counts"]  # type: ignore[index]
    regression = observed["regression"]  # type: ignore[assignment]
    ci = observed["ci"]  # type: ignore[assignment]

    return [
        Claim("scan: scenarios executed", documented["scan_executed"], counts["scenarios_executed"]),
        Claim("scan: critical", documented["scan_critical"], counts["critical"]),
        Claim("scan: high", documented["scan_high"], counts["high"]),
        Claim("scan: medium", documented["scan_medium"], counts["medium"]),
        Claim("regression: baseline size", documented["regression_known"], regression["known"]),
        Claim("regression: executed", documented["regression_executed"], regression["executed"]),
        Claim("regression: new", documented["regression_new"], regression["new"]),
        Claim("regression: still present", documented["regression_still_present"], regression["still_present"]),
        Claim("regression: resolved", documented["regression_resolved"], regression["resolved"]),
        Claim("ci: resolved", documented["ci_resolved"], ci["resolved"]),
    ]


# ---------------------------------------------------------------------------------


def section(title: str, pause: float) -> None:
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)
    if pause:
        time.sleep(pause)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="assert docs/demo-script.md still matches what the commands produce",
    )
    parser.add_argument(
        "--pause",
        type=float,
        default=0.0,
        help="seconds between sections, for recording or presenting",
    )
    args = parser.parse_args(argv)

    try:
        observed = run_demo(pause=args.pause)
    except RuntimeError as exc:
        print(f"demo: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.check:
        print()
        print("Demo complete. Reports in artifacts/.")
        print("Open the dashboard with: agentshield ui --report artifacts/report.json")
        return EXIT_OK

    claims = compare(documented_numbers(), observed)
    drifted = [claim for claim in claims if not claim.holds]

    print()
    print("docs/demo-script.md vs. a real run")
    print()
    for claim in claims:
        mark = "ok  " if claim.holds else "DIFF"
        print(f"  {mark} {claim.label:<32} documented {claim.documented:>3}  actual {claim.observed:>3}")

    if drifted:
        print()
        print(f"{len(drifted)} number(s) in the demo script no longer describe a real run.", file=sys.stderr)
        print("Update the transcripts, or find out why the numbers moved.", file=sys.stderr)
        return EXIT_DRIFT

    print()
    print("PASSED: the demo script describes what the commands do.")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

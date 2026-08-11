"""The `agentshield` command.

Standard-library argparse rather than a CLI framework: this binary runs inside CI containers,
and every dependency it carries is a dependency someone's build has to resolve. The exit code
is the contract - 0 clean, 1 findings at or above the gate, 2 the scan could not be completed.

That third code matters. A scan that never reached the target must not exit 0; "no findings"
and "no coverage" look identical from the outside and only one of them is safe.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from agentshield.attacks.catalog import load_catalog
from agentshield.config import load_dotenv
from agentshield.findings.classifier import compare_to_baseline
from agentshield.graph.runner import run_scan
from agentshield.graph.state import ScanState
from agentshield.models.common import SUITE_ALIASES, AttackCategory, Severity
from agentshield.policies.loader import PolicyError, load_policy
from agentshield.reporting.json_report import baseline_from, render_json
from agentshield.reporting.markdown import render_console_summary, render_report
from agentshield.telemetry import configure_tracing

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_ERROR

    # Local development keeps credentials in .env; a deployment exports them and this is a
    # no-op. Loaded before anything reads the environment, and never overrides a real var.
    load_dotenv()
    # Off unless OTEL_EXPORTER_OTLP_ENDPOINT is set, so a plain CLI run stays dependency-free.
    configure_tracing(service_name="agentshield-cli")

    try:
        return int(args.handler(args))
    except PolicyError as exc:
        print(f"agentshield: policy error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"agentshield: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("agentshield: interrupted", file=sys.stderr)
        return EXIT_ERROR


# -- commands ----------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    state = _run(args)
    summary = state.summary
    if summary is None:
        print("agentshield: scan produced no summary", file=sys.stderr)
        return EXIT_ERROR

    fail_on = Severity(args.fail_on.upper())
    print(render_console_summary(summary, fail_on=fail_on))

    if args.report:
        _write(args.report, render_report(state, fail_on=fail_on))
        print(f"\nMarkdown report: {args.report}")
    if args.json:
        _write(args.json, json.dumps(render_json(state, fail_on=fail_on), indent=2))
        print(f"JSON report: {args.json}")
    if args.save_baseline:
        _write(args.save_baseline, json.dumps(baseline_from(state), indent=2))
        print(f"Baseline: {args.save_baseline}")

    failure = _coverage_failure(state)
    if failure:
        _print_errors(state, failure)
        return EXIT_ERROR
    return EXIT_OK if summary.passed(fail_on) else EXIT_FINDINGS


def cmd_regression(args: argparse.Namespace) -> int:
    """Re-run against a recorded baseline and report what changed.

    The output people actually care about after a fix: what is new, what is gone, what is
    still open.
    """
    baseline_path = Path(args.baseline)
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    known = {entry["fingerprint"] for entry in baseline.get("findings", [])}

    state = _run(args)
    summary = state.summary
    if summary is None:
        return EXIT_ERROR

    # Before the diff, never after. A regression run with no coverage would otherwise report
    # every known finding as resolved and print PASSED.
    failure = _coverage_failure(state)
    if failure:
        _print_errors(state, failure)
        print(
            f"Refusing to compare against {baseline_path.name}: "
            f"{len(known)} known finding(s) would all be reported resolved.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    fail_on = Severity(args.fail_on.upper())
    new, resolved = compare_to_baseline(summary.findings, known)
    still_open = [f for f in summary.findings if f.fingerprint in known]

    print("AgentShield Regression")
    print()
    print(f"Baseline: {baseline_path.name} ({len(known)} known finding(s))")
    print(f"Scenarios executed: {summary.scenarios_executed}")
    print(f"New findings: {len(new)}")
    print(f"Still present: {len(still_open)}")
    print(f"Resolved: {len(resolved)}")
    print()

    for finding in new:
        print(f"NEW       {finding.severity:<8} {finding.code}  {finding.title}")
    for finding in still_open:
        print(f"OPEN      {finding.severity:<8} {finding.code}  {finding.title}")
    for fingerprint in resolved:
        entry = next(
            (e for e in baseline.get("findings", []) if e["fingerprint"] == fingerprint), {}
        )
        print(f"RESOLVED  {entry.get('severity', ''):<8} {entry.get('code', fingerprint)}")

    blocking = [f for f in new if f.severity.at_least(fail_on)]
    print()
    print(f"CI status: {'FAILED' if blocking else 'PASSED'}")
    return EXIT_FINDINGS if blocking else EXIT_OK


def cmd_ci(args: argparse.Namespace) -> int:
    """Machine-readable gate output, matching the control plane's `/api/ci/...` contract."""
    known: set[str] = set()
    if args.baseline and Path(args.baseline).is_file():
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        known = {entry["fingerprint"] for entry in baseline.get("findings", [])}

    state = _run(args)
    summary = state.summary
    if summary is None:
        print(json.dumps({"passed": False, "error": "scan produced no summary"}))
        return EXIT_ERROR

    fail_on_severity = Severity(args.fail_on.upper())
    # Written before the gate is decided, and to a file, never stdout, because stdout here
    # belongs to the machine. Someone debugging a red build needs the evidence, and re-running
    # the scan to get it is both slow and a second, different scan.
    if getattr(args, "report", None):
        _write(args.report, render_report(state, fail_on=fail_on_severity))
    if getattr(args, "json", None):
        _write(args.json, json.dumps(render_json(state, fail_on=fail_on_severity), indent=2))

    failure = _coverage_failure(state)
    if failure:
        print(json.dumps({
            "passed": False,
            "error": failure,
            "exitCode": EXIT_ERROR,
            "scanId": summary.scan_id,
            "scenariosExecuted": summary.scenarios_executed,
        }, indent=2))
        return EXIT_ERROR

    new, resolved = compare_to_baseline(summary.findings, known)
    blocking = [f for f in new if f.severity.at_least(fail_on_severity)]

    print(
        json.dumps(
            {
                "passed": not blocking,
                "newCritical": sum(1 for f in new if f.severity is Severity.CRITICAL),
                "newHigh": sum(1 for f in new if f.severity is Severity.HIGH),
                "resolved": len(resolved),
                "exitCode": EXIT_FINDINGS if blocking else EXIT_OK,
                "scanId": summary.scan_id,
                "scenariosExecuted": summary.scenarios_executed,
            },
            indent=2,
        )
    )
    return EXIT_FINDINGS if blocking else EXIT_OK


def cmd_replay(args: argparse.Namespace) -> int:
    """Re-run one scenario, exactly as a finding recorded it.

    This is the command printed in every finding's reproduction block, so it has to work
    without any of the surrounding scan configuration: scenario id and seed are enough.
    """
    catalog = load_catalog(args.datasets)
    template_id = args.scenario.split("-m")[0] if "-m" in args.scenario else args.scenario
    try:
        template = catalog.by_id(template_id)
    except KeyError:
        print(f"agentshield: unknown scenario {args.scenario!r}", file=sys.stderr)
        return EXIT_ERROR

    policy = load_policy(args.policy)
    if args.policy_hash and policy.content_hash != args.policy_hash:
        # Replaying against a different policy silently produces a different verdict, which
        # is the fastest way to conclude a bug is fixed when it is not.
        print(
            f"agentshield: policy hash mismatch (finding recorded {args.policy_hash}, "
            f"this policy is {policy.content_hash}); results are not comparable",
            file=sys.stderr,
        )
        return EXIT_ERROR

    from agentshield.attacks.mutator import mutate_scenario

    scenario = mutate_scenario(template.instantiate(seed=args.seed), args.seed)
    target_config = _target_config(args)
    state = ScanState(
        scan_id=f"replay-{uuid.uuid4().hex[:8]}",
        policy=policy,
        policy_source=args.policy,
        target_config=target_config,
        requested_categories={scenario.category},
        max_scenarios=1,
        base_seed=args.seed,
        scenario_timeout_seconds=float(target_config["timeout_seconds"]),
    )
    # Pin the exact scenario over re-selecting: replay must not depend on whatever the
    # threat model happens to choose today.
    state.scenarios = [scenario]
    state = asyncio.run(_replay_pipeline(state))

    summary = state.summary
    if summary is None:
        return EXIT_ERROR

    fail_on = Severity(args.fail_on.upper())
    print(f"Replayed {scenario.id} (template {template.id}, seed {args.seed})")
    print()
    if not summary.findings:
        print("No violation reproduced. The control now holds for this scenario.")
        return EXIT_OK
    for finding in summary.findings:
        print(f"{finding.severity:<9} {finding.code}  {finding.title}")
    print()
    print(f"CI status: {'PASSED' if summary.passed(fail_on) else 'FAILED'}")
    return EXIT_OK if summary.passed(fail_on) else EXIT_FINDINGS


async def _replay_pipeline(state: ScanState) -> ScanState:
    """The scan pipeline with scenario generation skipped, since replay supplies it."""
    from agentshield.graph import nodes

    for node in (
        nodes.load_target,
        nodes.discover_capabilities,
        nodes.build_target_threat_model,
        nodes.execute_attack,
        nodes.collect_trajectory,
        nodes.evaluate_deterministically,
        nodes.classify_finding,
        nodes.generate_remediation,
        nodes.minimize_reproduction,
        nodes.finalize_report,
    ):
        state = await node(state)
    return state


def cmd_ui(args: argparse.Namespace) -> int:
    """Serve the dashboard over a report on disk.

    Static files would need no server at all, except that a browser refuses to `fetch` a
    sibling file over `file://`. See `ui.py`.
    """
    from agentshield_cli.ui import locate_web_ui, serve

    try:
        serve(
            Path(args.report),
            web_ui=locate_web_ui(args.web_ui),
            host=args.host,
            port=args.port,
            open_browser=not args.no_open,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"agentshield: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def cmd_list_attacks(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.datasets)
    print(f"AgentShield attack corpus (dataset {catalog.version})")
    print()
    for category, count in sorted(catalog.counts().items(), key=lambda kv: str(kv[0])):
        print(f"  {category!s:<30} {count:>3} template(s)")
    print()
    print(f"  {'TOTAL':<30} {len(catalog):>3} template(s)")
    print()
    # Derived from the catalogue. The count was hardcoded and went stale the first time
    # anyone added a template, which quietly overstated coverage in the one command whose
    # entire job is reporting how much coverage there is.
    print(
        f"Each template expands into `--variants` mutated scenarios, so {len(catalog)} "
        f"templates at --variants 4 is {len(catalog) * 4} executed scenarios - "
        f"{len(catalog)} distinct ideas, not {len(catalog) * 4}."
    )
    if args.verbose:
        print()
        for template in catalog.templates:
            print(f"  {template.id:<12} {template.category!s:<28} {template.name}")
    return EXIT_OK


# -- shared plumbing ---------------------------------------------------------------


def _run(args: argparse.Namespace) -> ScanState:
    policy = load_policy(args.policy)
    target_config = _target_config(args)
    state = ScanState(
        scan_id=args.scan_id or f"scan-{uuid.uuid4().hex[:12]}",
        policy=policy,
        # The path, not only the parsed policy: every finding's reproduction command has to
        # name something a reader can pass back to `--policy`.
        policy_source=args.policy,
        target_config=target_config,
        requested_categories=_categories(args),
        max_scenarios=args.max_scenarios,
        variants_per_template=args.variants,
        base_seed=args.seed,
        concurrency=args.concurrency,
        scenario_timeout_seconds=float(target_config["timeout_seconds"]),
        run_semantic_evaluators=args.judges,
        minimize_reproductions=args.minimize,
    )
    state.judge_client = _judge_client(args)
    return asyncio.run(run_scan(state))


def _judge_client(args: argparse.Namespace):
    """A cassette when one is named, otherwise the live API client the evaluators build."""
    if not args.judge_cassette:
        return None

    from agentshield.evaluators.cassette import JudgeCassette, ReplayJudgeClient
    from agentshield.evaluators.llm_judge import configured_judge_model

    path = Path(args.judge_cassette)
    if not path.is_file():
        raise SystemExit(f"judge cassette not found: {path}")
    return ReplayJudgeClient(JudgeCassette(path), model=configured_judge_model())


#: Keys `--target-config` may set. Everything the adapters read, and nothing else: an unknown
#: key is a typo, and a typo that is silently ignored produces a scan against the wrong
#: endpoint that looks like a scan against the right one.
TARGET_CONFIG_KEYS = frozenset({
    "type",
    "adapter_type",
    "base_url",
    "tenant_id",
    "timeout_seconds",
    "poll_seconds",
    "headers",
    "invoke_path",
    "method",
    "request_template",
    "response_path",
    "session_field",
    "correlation_id_field",
    "declared_tools",
    "transport",
})


def _target_config(args: argparse.Namespace) -> dict[str, Any]:
    """Assemble the target configuration from the file, then the flags.

    Flags win. `--target-config target.yml --target http://staging.test` is how one file
    describes an agent and the environment picks which deployment of it to scan, and it would
    be useless the other way round.

    The generic REST adapter has always accepted a request template, a response path, a
    session field and a correlation id field - the specification asks for exactly that - but
    the CLI could pass none of them. An operator could describe an arbitrary agent through the
    Java API and not through the tool the quickstart tells them to use.
    """
    config: dict[str, Any] = {}

    if getattr(args, "target_config", None):
        config.update(_load_target_config(args.target_config))

    # Flags override the file. `None` means "not given"; an explicit empty string does not
    # occur for any of these, so a plain truthiness test would be wrong for `timeout` alone.
    overrides = {
        "base_url": args.target,
        "adapter_type": args.adapter,
        "tenant_id": args.tenant,
        "timeout_seconds": args.timeout,
    }
    for key, value in overrides.items():
        if value is not None:
            config[key] = value

    if args.header:
        headers = dict(config.get("headers") or {})
        headers.update(h.split("=", 1) for h in args.header if "=" in h)
        config["headers"] = headers

    config.setdefault("adapter_type", "rest_agentshield")
    config.setdefault("timeout_seconds", 60.0)

    if not config.get("base_url"):
        raise SystemExit(
            "agentshield: no target. Pass --target, or set base_url in --target-config."
        )
    return config


def _load_target_config(path: str) -> dict[str, Any]:
    """Read and check a target configuration file.

    Rejecting unknown keys rather than ignoring them is the whole value of the check. A
    misspelled `response_path` that is silently dropped produces a scan that reads the wrong
    field, finds nothing, and reports a clean result - which is the one output a security tool
    must never produce by accident.
    """
    import yaml

    source = Path(path)
    if not source.is_file():
        raise SystemExit(f"agentshield: target config not found: {source}")

    try:
        loaded = yaml.safe_load(source.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SystemExit(f"agentshield: {source} is not valid YAML: {exc}") from exc

    if not isinstance(loaded, dict):
        raise SystemExit(f"agentshield: {source} must contain a mapping")

    unknown = sorted(set(loaded) - TARGET_CONFIG_KEYS)
    if unknown:
        raise SystemExit(
            f"agentshield: {source} has unknown key(s): {', '.join(unknown)}. "
            f"Known: {', '.join(sorted(TARGET_CONFIG_KEYS))}"
        )
    return loaded


def _categories(args: argparse.Namespace) -> set[AttackCategory] | None:
    """Resolve `--suite`. Omitted means "let the threat model decide"."""
    if not args.suite:
        return None
    selected: set[AttackCategory] = set()
    for name in args.suite:
        key = name.strip()
        if key.lower() in SUITE_ALIASES:
            selected.update(SUITE_ALIASES[key.lower()])
            continue
        try:
            selected.add(AttackCategory(key.upper()))
        except ValueError:
            known = ", ".join([*SUITE_ALIASES, *(str(c) for c in AttackCategory)])
            raise SystemExit(f"agentshield: unknown suite {name!r}. Known: {known}") from None
    return selected


def _write(path: str, content: str) -> None:
    """Write an output file, creating parent directories.

    `--report ./artifacts/report.md` should not fail because `artifacts/` does not exist yet;
    in CI that directory is usually created by the job, and locally it is created by nobody.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")


def _coverage_failure(state: ScanState) -> str | None:
    """Why this scan's results cannot be trusted, or None when they can.

    Every command that prints a verdict has to ask this, which is why it is one function and
    not a check remembered at three call sites. A scan that reached nothing produces an empty
    finding list, and an empty finding list is indistinguishable from a clean system unless
    something looks.

    In `regression` the mistake is worse than in `scan`. With no scenarios executed, every
    baseline finding is absent from the new run, `compare_to_baseline` reports all of them
    RESOLVED, and the gate goes green at precisely the moment the evidence is missing. That is
    the false all-clear this tool exists to prevent, produced by the tool itself.
    """
    if not state.executions and state.errors:
        return "the target was never reached"
    if not state.scenarios:
        return "no scenarios were selected for this target"
    if state.summary and state.summary.scenarios_executed == 0:
        return "scenarios were selected but none produced a usable trajectory"
    return None


def _print_errors(state: ScanState, reason: str | None = None) -> None:
    print(file=sys.stderr)
    print(f"Scan did not complete with usable coverage: {reason}", file=sys.stderr)
    for error in state.errors[:10]:
        print(f" - {error}", file=sys.stderr)
    print(
        "\nExit 2, not 0: no findings and no coverage are different results.",
        file=sys.stderr,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="Security testing for AI agents, RAG applications and MCP servers.",
        epilog="Only scan systems you own or are authorised to test.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="run a security scan against a target")
    _add_target_arguments(scan)
    scan.add_argument("--report", help="write a Markdown report to this path")
    scan.add_argument("--json", help="write the machine-readable report to this path")
    scan.add_argument("--save-baseline", help="write a regression baseline to this path")
    scan.set_defaults(handler=cmd_scan)

    regression = subparsers.add_parser(
        "regression", help="re-run against a baseline and report what changed"
    )
    _add_target_arguments(regression)
    regression.add_argument("--baseline", required=True, help="baseline JSON from a prior scan")
    regression.set_defaults(handler=cmd_regression)

    ci = subparsers.add_parser("ci", help="run a scan and emit the CI gate result as JSON")
    _add_target_arguments(ci)
    ci.add_argument("--baseline", help="baseline JSON; findings in it do not fail the build")
    ci.add_argument("--report", help="also write the Markdown report here (stdout stays JSON)")
    ci.add_argument("--json", help="also write the full JSON report here")
    ci.set_defaults(handler=cmd_ci)

    replay = subparsers.add_parser(
        "replay", help="re-run a single scenario exactly as a finding recorded it"
    )
    _add_target_arguments(replay)
    replay.add_argument("--scenario", required=True, help="scenario or template id")
    replay.add_argument("--policy-hash", help="policy hash recorded with the finding")
    replay.add_argument("--datasets", help="dataset directory (defaults to ./datasets)")
    replay.set_defaults(handler=cmd_replay)

    ui = subparsers.add_parser("ui", help="serve the dashboard over a JSON report")
    ui.add_argument("--report", required=True, help="JSON report from `agentshield scan --json`")
    ui.add_argument("--port", type=int, default=8099)
    ui.add_argument("--host", default="127.0.0.1", help="bind address; loopback by default")
    ui.add_argument("--no-open", action="store_true", help="do not open a browser")
    ui.add_argument("--web-ui", help="dashboard directory (defaults to the one in the checkout)")
    ui.set_defaults(handler=cmd_ui)

    listing = subparsers.add_parser("list-attacks", help="show the attack corpus")
    listing.add_argument("--datasets", help="dataset directory (defaults to ./datasets)")
    listing.add_argument("-v", "--verbose", action="store_true")
    listing.set_defaults(handler=cmd_list_attacks)

    return parser


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--target",
        help="target base URL. Optional when --target-config supplies base_url",
    )
    parser.add_argument(
        "--target-config",
        help=(
            "YAML describing an arbitrary agent: invoke_path, request_template, "
            "response_path, headers, correlation_id_field. Flags override it"
        ),
    )
    parser.add_argument("--policy", required=True, help="security policy YAML")
    parser.add_argument(
        "--suite",
        action="append",
        help="attack suite or alias (owasp-agentic, injection, data, agency, smoke). "
        "Repeatable. Omit to select suites from the target's threat model.",
    )
    parser.add_argument(
        "--adapter",
        # No argparse default. A default here is indistinguishable from a value the user
        # typed, so it would override `adapter_type` in --target-config and the file would
        # silently do nothing. The default is applied after merging instead.
        default=None,
        choices=["rest_agentshield", "rest_generic", "async_agent", "mcp"],
        help="target adapter (default: the AgentShield inspection protocol)",
    )
    parser.add_argument("--tenant", default=None, help="tenant to authenticate as")
    parser.add_argument("--max-scenarios", type=int, default=50)
    parser.add_argument(
        "--variants", type=int, default=1, help="mutated variants generated per template"
    )
    parser.add_argument("--seed", type=int, default=0, help="mutation seed; fixes reproducibility")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument(
        "--timeout", type=float, default=None, help="per-scenario timeout (default: 60)"
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=["critical", "high", "medium", "low"],
        help="lowest severity that fails the build (default: high)",
    )
    parser.add_argument(
        "--judges",
        action="store_true",
        help="also run LLM judges (needs ANTHROPIC_API_KEY; never gates CI on its own)",
    )
    parser.add_argument(
        "--judge-cassette",
        default=None,
        help=(
            "answer judges from recorded responses. Costs nothing, needs no key, and "
            "needs no key; a case that was never recorded is reported unmeasured, not clean"
        ),
    )
    parser.add_argument(
        "--no-minimize",
        dest="minimize",
        action="store_false",
        help=(
            "skip reproduction minimisation. It delta-debugs each severe finding's payload "
            "down to the text that still triggers it, which costs extra target calls"
        ),
    )
    parser.add_argument("--header", action="append", help="extra request header, NAME=VALUE")
    parser.add_argument("--scan-id", default=None)


if __name__ == "__main__":
    sys.exit(main())

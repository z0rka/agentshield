#!/usr/bin/env python3
"""Validate that both sides of the system still agree on the shared contracts.

Run in CI. Catches the class of bug where the Java enum gains a value the Python enum does
not have, or a dataset references a category nobody implements - mismatches that otherwise
surface as a scan silently skipping a whole suite.

    python contracts/validate.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "contracts"


def _fail(message: str) -> str:
    return f"FAIL {message}"


def _source(name: str, root: Path) -> Path:
    """Locate a source file by name, wherever its package currently sits.

    Searching for the file, not hard-coding its path, matters more than it looks: when the control
    plane was reorganised into layered packages, a hard-coded path turned this check into a
    silent SKIP. A contract check that stops running without failing is worse than no check,
    because the build stays green while the two sides drift.
    """
    matches = sorted(root.rglob(name))
    if not matches:
        raise FileNotFoundError(f"{name} not found under {root.relative_to(ROOT)}")
    if len(matches) > 1:
        raise FileNotFoundError(
            f"{name} is ambiguous: {[str(m.relative_to(ROOT)) for m in matches]}"
        )
    return matches[0]


def check_event_types() -> list[str]:
    """The Java EventTypes constants and the envelope schema's enum must match exactly."""
    schema = json.loads((CONTRACTS / "events" / "envelope.schema.json").read_text("utf-8"))
    declared = set(schema["properties"]["eventType"]["enum"])

    java = _source("EventTypes.java", ROOT / "control-plane-java" / "src" / "main").read_text("utf-8")
    # Only the event-type constants: the nested Topics class holds topic names, and the
    # routing helper matches on prefixes like "security.attack." that are not event types.
    event_type_section = java.split("class Topics")[0]
    in_java = {
        value
        for value in re.findall(
            r'String\s+[A-Z_]+\s*=\s*"(security\.[a-z.]+)"', event_type_section
        )
        if not value.endswith(".")
    }

    errors = []
    for missing in sorted(in_java - declared):
        errors.append(_fail(f"EventTypes.java declares {missing}, absent from envelope.schema.json"))
    for missing in sorted(declared - in_java):
        errors.append(_fail(f"envelope.schema.json declares {missing}, absent from EventTypes.java"))
    return errors


def check_attack_categories() -> list[str]:
    """Python AttackCategory, the finding schema and the Java migration must agree."""
    python = _source(
        "common.py", ROOT / "security-engine-python" / "agentshield" / "models"
    ).read_text("utf-8")
    section = python.split("class AttackCategory")[1].split("class ")[0]
    in_python = set(re.findall(r'^\s+([A-Z_]+) = "\1"', section, flags=re.MULTILINE))

    schema = json.loads((CONTRACTS / "events" / "finding-created.schema.json").read_text("utf-8"))
    in_schema = set(schema["properties"]["category"]["enum"])

    errors = []
    for missing in sorted(in_python - in_schema):
        errors.append(_fail(f"AttackCategory.{missing} is missing from finding-created.schema.json"))
    for missing in sorted(in_schema - in_python):
        errors.append(_fail(f"finding-created.schema.json declares {missing}, absent from AttackCategory"))
    return errors


def check_policy_examples() -> list[str]:
    """Every shipped policy must parse under the engine's own loader.

    A policy the schema accepts but the loader rejects is worse than either failing alone:
    it looks valid right up to the moment someone tries to scan with it.
    """
    sys.path.insert(0, str(ROOT / "security-engine-python"))
    try:
        from agentshield.policies.loader import load_policy
    except ImportError:
        return ["SKIP policy examples (security-engine-python is not installed)"]

    errors = []
    for policy_file in sorted((ROOT / "datasets" / "policies").glob("*.y*ml")):
        try:
            load_policy(policy_file)
        except Exception as exc:  # noqa: BLE001
            errors.append(_fail(f"{policy_file.name} does not load: {exc}"))
    return errors


def check_dataset_categories() -> list[str]:
    """Dataset files must declare a category the engine knows about."""
    sys.path.insert(0, str(ROOT / "security-engine-python"))
    try:
        from agentshield.models.common import AttackCategory
    except ImportError:
        return ["SKIP dataset categories (security-engine-python is not installed)"]

    import yaml

    known = {str(c) for c in AttackCategory}
    errors = []
    for dataset in sorted((ROOT / "datasets").rglob("*.y*ml")):
        if "policies" in dataset.parts:
            continue
        raw = yaml.safe_load(dataset.read_text("utf-8")) or {}
        category = raw.get("category")
        if category not in known:
            errors.append(_fail(f"{dataset.name} declares unknown category {category!r}"))
    return errors


def check_openapi_routes() -> list[str]:
    """Every path in the OpenAPI document must exist in a controller, and the reverse.

    A hand-written spec is only a contract while something compares it to the code. Generated
    specs always agree with the application and therefore catch nothing; this one fails the
    build when a route is renamed, added without documenting, or documented without existing.
    """
    import re

    import yaml

    spec_file = CONTRACTS / "api" / "control-plane.openapi.yaml"
    spec = yaml.safe_load(spec_file.read_text("utf-8"))
    documented = {path for path in (spec.get("paths") or {})}

    controllers = sorted((ROOT / "control-plane-java" / "src" / "main").rglob("*Controller.java"))
    if not controllers:
        return [_fail("no controllers found; the OpenAPI document cannot be checked")]

    implemented: set[str] = set()
    for controller in controllers:
        source = controller.read_text("utf-8")
        base = re.search(r'@RequestMapping\("([^"]+)"\)', source)
        prefix = base.group(1) if base else ""
        # The path argument is optional: a bare `@PostMapping` maps the class-level prefix
        # itself. Requiring a quoted argument silently skips those, which is how a checker
        # reports a route as undocumented when it is really unseen.
        for mapping in re.finditer(
            r'@(?:Get|Post|Put|Patch|Delete)Mapping(?:\((?:value\s*=\s*)?"([^"]*)")?', source
        ):
            route = f"{prefix}{mapping.group(1) or ''}".replace("//", "/")
            implemented.add(route.rstrip("/") or "/")

    # Internal engine dispatch is undocumented on purpose: a shared-token endpoint that
    # nobody outside the system should build against is not part of the public contract.
    implemented = {r for r in implemented if not r.startswith("/internal")}

    errors = []
    for route in sorted(documented - implemented):
        errors.append(_fail(f"OpenAPI documents {route}, which no controller implements"))
    for route in sorted(implemented - documented):
        errors.append(_fail(f"controller exposes {route}, which the OpenAPI document omits"))
    return errors


def check_target_adapters() -> list[str]:
    """Every Java `TargetType` must name an adapter the engine actually registers.

    The string on the right of `ASYNC_AGENT("async_agent")` is a contract between two languages
    and no compiler sees it. It pointed at `rest_generic` for a whole stage: the async adapter
    existed, its tests passed, and every async target registered through the API was driven by
    the generic one - output only, so the approval window that adapter exists to observe could
    not be seen. Nothing failed, because a target that answers looks fine to a scanner that
    only reads answers.

    Two directions, because they catch different mistakes. A Java type naming an adapter that
    does not exist fails at scan time with a stack trace; a Java type naming the *wrong*
    existing adapter fails silently, forever, which is the one that happened.
    """
    java = _source("TargetType.java", ROOT / "control-plane-java" / "src" / "main").read_text("utf-8")
    java_map = dict(re.findall(r'\b([A-Z_]+)\("([a-z_]+)"\)', java))

    registry = _source(
        "registry.py", ROOT / "security-engine-python" / "agentshield" / "adapters"
    ).read_text("utf-8")
    known_adapters = set(re.findall(r'^\s*"([a-z_]+)":\s*_build_\w+,', registry, re.MULTILINE))
    python_map = dict(
        re.findall(r'^\s*"([A-Z_]+)":\s*"([a-z_]+)",', registry, re.MULTILINE)
    )

    errors: list[str] = []
    if not java_map:
        return [_fail("TargetType.java declares no target types; the pattern must have changed")]
    if not known_adapters:
        return [_fail("registry.py registers no adapters; the pattern must have changed")]

    for target_type, adapter in sorted(java_map.items()):
        if adapter not in known_adapters:
            errors.append(_fail(
                f"TargetType.{target_type} names adapter {adapter!r}, "
                f"which the engine does not register (known: {sorted(known_adapters)})"
            ))
            continue
        expected = python_map.get(target_type)
        if expected is not None and expected != adapter:
            errors.append(_fail(
                f"TargetType.{target_type} maps to {adapter!r} in Java "
                f"and {expected!r} in the engine"
            ))

    for target_type, adapter in sorted(python_map.items()):
        if target_type not in java_map:
            errors.append(_fail(
                f"the engine maps {target_type} to {adapter!r}, "
                "and TargetType.java has no such constant"
            ))

    return errors


CHECKS = (
    ("event types", check_event_types),
    ("attack categories", check_attack_categories),
    ("policy examples", check_policy_examples),
    ("dataset categories", check_dataset_categories),
    ("openapi routes", check_openapi_routes),
    ("target adapters", check_target_adapters),
)


def main() -> int:
    failures = 0
    for name, check in CHECKS:
        try:
            messages = check()
        except FileNotFoundError as exc:
            # A check that cannot find what it inspects has not passed. Reporting this as a
            # skip is how a renamed file quietly disables a contract check for months.
            print(_fail(f"{name}: {exc}"))
            failures += 1
            continue

        problems = [m for m in messages if m.startswith("FAIL")]
        for message in messages:
            print(message)
        if problems:
            failures += len(problems)
        else:
            print(f"OK   {name}")

    print()
    print(f"{'FAILED' if failures else 'PASSED'}: {failures} contract mismatch(es)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

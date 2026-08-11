"""Labelled trajectories: the ground truth the evaluators are scored against."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentshield.evaluators.base import EvaluationContext
from agentshield.models.common import AttackCategory, Severity, StepType
from agentshield.models.policy import SecurityPolicy
from agentshield.models.scenario import AttackPayload, AttackScenario, ExpectedOutcome
from agentshield.models.trajectory import Trajectory, TrajectoryStep
from agentshield.policies.loader import load_policy


class FixtureError(ValueError):
    """A fixture is malformed. Always fatal: a case nobody can parse scores nothing."""


@dataclass(frozen=True, slots=True)
class Expectation:
    """What a correct evaluator set does with this trajectory."""

    must_fire: frozenset[str] = frozenset()
    must_not_fire: frozenset[str] = frozenset()
    severity_at_least: Severity | None = None

    def scored_evaluators(self) -> frozenset[str]:
        return self.must_fire | self.must_not_fire


@dataclass(frozen=True, slots=True)
class Fixture:
    """One labelled case."""

    id: str
    label: str
    description: str
    policy: SecurityPolicy
    trajectory: Trajectory
    context: EvaluationContext
    expect: Expectation
    source: Path

    @property
    def scored(self) -> bool:
        """`ambiguous` cases are recorded and reported, never counted.

        Scoring a case the team disagrees about would bake one person's reading into the
        metric and hide the disagreement.
        """
        return self.label != "ambiguous"


# Step shorthand -> (StepType, which key carries the body).
_STEP_KINDS: dict[str, StepType] = {
    "user": StepType.USER_INPUT,
    "model": StepType.MODEL_OUTPUT,
    "retrieval": StepType.RETRIEVAL,
    "call": StepType.TOOL_CALL,
    "result": StepType.TOOL_RESULT,
    "approval_request": StepType.APPROVAL_REQUEST,
    "approval_result": StepType.APPROVAL_RESULT,
    "final": StepType.FINAL_OUTPUT,
    "error": StepType.ERROR,
}

_VALID_LABELS = {"true_positive", "true_negative", "ambiguous"}


def load_fixtures(root: Path, policies_root: Path) -> list[Fixture]:
    """Load every fixture under `root`, newest schema only."""
    if not root.is_dir():
        raise FixtureError(f"fixture directory not found: {root}")

    fixtures = [
        _parse(path, _read(path), policies_root) for path in sorted(root.rglob("*.y*ml"))
    ]
    if not fixtures:
        raise FixtureError(f"no fixtures found under {root}")

    _assert_unique_ids(fixtures)
    return fixtures


def _read(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        # Fixtures are hand-written, and the commonest mistake is an unquoted colon. A
        # traceback from the YAML scanner names a column and not a file, which is the wrong
        # end of the problem.
        raise FixtureError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise FixtureError(f"{path.name}: expected a mapping at the top level")
    return raw


def _parse(path: Path, raw: dict[str, Any], policies_root: Path) -> Fixture:
    try:
        identifier = str(raw["id"])
        label = str(raw["label"])
        policy_name = str(raw["policy"])
        steps = raw["trajectory"]
    except KeyError as exc:
        raise FixtureError(f"{path.name}: missing required field {exc}") from exc

    if label not in _VALID_LABELS:
        raise FixtureError(f"{path.name}: unknown label {label!r}, expected one of {_VALID_LABELS}")

    policy_file = policies_root / f"{policy_name}.yml"
    if not policy_file.is_file():
        raise FixtureError(f"{path.name}: policy {policy_name!r} not found at {policy_file}")

    context_raw = raw.get("context") or {}
    expect_raw = raw.get("expect") or {}

    return Fixture(
        id=identifier,
        label=label,
        description=str(raw.get("description", "")).strip(),
        policy=load_policy(policy_file),
        trajectory=_trajectory(path, steps, context_raw),
        context=EvaluationContext(
            authenticated_tenant=context_raw.get("authenticated_tenant"),
            canaries=list(context_raw.get("canaries", [])),
            declared_tools=list(context_raw.get("declared_tools", [])),
            system_prompt=context_raw.get("system_prompt"),
            scenario=_scenario(identifier, context_raw),
            # The manifest. Two evaluators judge what a target *offers*, not what it did, so
            # a fixture for them carries no trajectory worth speaking of.
            tool_descriptions=dict(context_raw.get("tool_descriptions", {})),
            tool_scopes={
                name: list(scopes)
                for name, scopes in (context_raw.get("tool_scopes") or {}).items()
            },
            harness_initiated_calls=bool(context_raw.get("harness_initiated_calls", False)),
        ),
        expect=Expectation(
            must_fire=frozenset(expect_raw.get("must_fire", [])),
            must_not_fire=frozenset(expect_raw.get("must_not_fire", [])),
            severity_at_least=(
                Severity(expect_raw["severity_at_least"])
                if "severity_at_least" in expect_raw
                else None
            ),
        ),
        source=path,
    )


def _scenario(identifier: str, context: dict[str, Any]) -> AttackScenario | None:
    """Build the minimal scenario some evaluators need to have an opinion.

    `ExternalSideEffectEvaluator` asks whether the scenario forbade a tool, so without one it
    can never fire and would sit permanently unmeasured. A fixture supplies the same three
    fields the real corpus does.
    """
    forbidden_tools = list(context.get("forbidden_tools", []))
    forbidden_values = list(context.get("forbidden_values", []))
    forbidden_recipients = list(context.get("forbidden_recipients", []))
    if not (forbidden_tools or forbidden_values or forbidden_recipients):
        return None

    return AttackScenario(
        id=identifier,
        category=AttackCategory.TOOL_ABUSE,
        name=identifier,
        payload=AttackPayload(prompt=""),
        expected=ExpectedOutcome(
            forbidden_tools=forbidden_tools,
            forbidden_values=forbidden_values,
            forbidden_recipients=forbidden_recipients,
        ),
    )


def _trajectory(path: Path, steps: Any, context: dict[str, Any]) -> Trajectory:
    if not isinstance(steps, list) or not steps:
        raise FixtureError(f"{path.name}: `trajectory` must be a non-empty list")

    built: list[TrajectoryStep] = []
    for index, entry in enumerate(steps):
        if not isinstance(entry, dict):
            raise FixtureError(f"{path.name}: step {index} must be a mapping")
        built.append(_step(path, index, entry))

    return Trajectory(
        session_id=f"fixture-{path.stem}",
        steps=built,
        tenant_id=context.get("authenticated_tenant"),
        duration_seconds=float(context.get("duration_seconds", 0.0)),
        input_tokens=int(context.get("input_tokens", 0)),
        output_tokens=int(context.get("output_tokens", 0)),
        estimated_cost_usd=float(context.get("estimated_cost_usd", 0.0)),
    )


def _step(path: Path, index: int, entry: dict[str, Any]) -> TrajectoryStep:
    kinds = _STEP_KINDS.keys() & entry.keys()
    if len(kinds) != 1:
        raise FixtureError(
            f"{path.name}: step {index} must name exactly one of {sorted(_STEP_KINDS)}, "
            f"found {sorted(kinds) or 'none'}"
        )

    kind = kinds.pop()
    step_type = _STEP_KINDS[kind]
    body = entry[kind]

    data: dict[str, Any] = {}
    tool_name: str | None = None
    content = ""

    if step_type in {StepType.TOOL_CALL, StepType.TOOL_RESULT}:
        tool_name = str(body)
        content = str(entry.get("content", ""))
        if "args" in entry:
            data["arguments"] = entry["args"]
        data.update(entry.get("data", {}))
    elif step_type in {StepType.APPROVAL_REQUEST, StepType.APPROVAL_RESULT}:
        tool_name = str(body)
        data["tool_name"] = tool_name
        if "args" in entry:
            data["arguments"] = entry["args"]
        if "approved" in entry:
            data["approved"] = bool(entry["approved"])
        if "approval_id" in entry:
            data["approval_id"] = str(entry["approval_id"])
    else:
        content = str(body)
        # Retrieval steps carry the metadata that decides whether the content should have been
        # trusted - document id, trust level, tenant, memory provenance. Dropping it here made
        # those fields unreachable from a fixture, so an evaluator that reads them could not be
        # given a test case at all.
        data.update(entry.get("data", {}))

    return TrajectoryStep(
        sequence_number=index,
        step_type=step_type,
        tool_name=tool_name,
        content=content,
        data=data,
        source=entry.get("source"),
    )


def _assert_unique_ids(fixtures: list[Fixture]) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for fixture in fixtures:
        if fixture.id in seen:
            duplicates.add(fixture.id)
        seen.add(fixture.id)
    if duplicates:
        raise FixtureError(f"duplicate fixture ids: {sorted(duplicates)}")


@dataclass(slots=True)
class FixtureSet:
    """Fixtures plus the questions a report needs to ask of them."""

    fixtures: list[Fixture] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.fixtures)

    def scored(self) -> list[Fixture]:
        return [f for f in self.fixtures if f.scored]

    def ambiguous(self) -> list[Fixture]:
        return [f for f in self.fixtures if not f.scored]

    def evaluators_covered(self) -> set[str]:
        covered: set[str] = set()
        for fixture in self.scored():
            covered |= fixture.expect.scored_evaluators()
        return covered

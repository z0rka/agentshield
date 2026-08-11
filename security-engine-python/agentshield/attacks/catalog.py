"""The attack dataset: versioned templates on disk, loaded into scenarios.

Attacks are data files, not Python. The corpus can therefore be reviewed by someone who
is not a Python developer, versioned independently of the engine, and extended without a
release. Every template carries its own expected outcome, so a scenario documents what a
*secure* system does rather than encoding the failure it happens to catch today.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentshield.models.common import AttackCategory, Severity
from agentshield.models.scenario import (
    AttackPayload,
    AttackScenario,
    ExpectedOutcome,
    InjectedArtifact,
)

#: Repository-relative default. Override with AGENTSHIELD_DATASETS or an explicit path.
DEFAULT_DATASET_DIRS = ("datasets",)


class DatasetError(ValueError):
    """A dataset file is malformed."""


@dataclass(slots=True)
class AttackTemplate:
    """One authored attack, before mutation."""

    id: str
    category: AttackCategory
    name: str
    prompt: str
    description: str = ""
    version: str = "1"
    injections: list[dict[str, Any]] = field(default_factory=list)
    requires_tools: list[str] = field(default_factory=list)
    requires_channels: list[str] = field(default_factory=list)
    requires_adapter: list[str] = field(default_factory=list)
    #: Extra request fields carried into the payload: a tenant override, a replayed
    #: approval token, an MCP call plan. Adapter-specific by design - the corpus stays
    #: data and the adapter is the only thing that knows what any of it means.
    metadata: dict[str, Any] = field(default_factory=dict)
    expected: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    #: Placeholder values substituted into the prompt and injections, chosen by seed.
    variables: dict[str, list[str]] = field(default_factory=dict)

    def instantiate(self, *, seed: int = 0, suffix: str = "") -> AttackScenario:
        """Render this template into a concrete scenario.

        Variable choices are a pure function of the seed, so `--seed 42` reproduces the exact
        same scenario on any machine.
        """
        bindings = {
            name: values[seed % len(values)]
            for name, values in self.variables.items()
            if values
        }
        return AttackScenario(
            id=f"{self.id}{suffix}",
            category=self.category,
            name=self.name,
            description=self.description,
            template_id=self.id,
            template_version=self.version,
            seed=seed,
            tags=list(self.tags),
            requires_tools=list(self.requires_tools),
            requires_channels=list(self.requires_channels),
            requires_adapter=list(self.requires_adapter),
            expected=_parse_expected(self.expected),
            payload=AttackPayload(
                prompt=_substitute(self.prompt, bindings),
                seed=seed,
                metadata=_substitute_deep(self.metadata, bindings),
                injections=[
                    InjectedArtifact(
                        channel=str(raw.get("channel", "knowledge_base")),
                        artifact_id=str(raw.get("id", f"{self.id}-doc-{index}")),
                        title=_substitute(str(raw.get("title", "")), bindings),
                        content=_substitute(str(raw.get("content", "")), bindings),
                        tool_name=raw.get("tool_name"),
                    )
                    for index, raw in enumerate(self.injections)
                ],
            ),
        )


class AttackCatalog:
    """All templates available to a scan."""

    def __init__(self, templates: list[AttackTemplate], *, version: str = "unknown") -> None:
        self.templates = templates
        self.version = version

    def __len__(self) -> int:
        return len(self.templates)

    def by_category(self, categories: set[AttackCategory]) -> list[AttackTemplate]:
        return [t for t in self.templates if t.category in categories]

    def by_id(self, template_id: str) -> AttackTemplate:
        for template in self.templates:
            if template.id == template_id:
                return template
        raise KeyError(f"unknown attack template: {template_id}")

    def counts(self) -> dict[AttackCategory, int]:
        counts: dict[AttackCategory, int] = {}
        for template in self.templates:
            counts[template.category] = counts.get(template.category, 0) + 1
        return counts


def load_catalog(root: str | Path | None = None) -> AttackCatalog:
    """Load every `*.yml` under the dataset root."""
    directory = Path(root) if root else _discover_root()
    if not directory.is_dir():
        raise DatasetError(f"dataset directory not found: {directory}")

    templates: list[AttackTemplate] = []
    version = "unknown"
    for file in sorted(directory.rglob("*.y*ml")):
        # policies/ holds example security policies, not attacks.
        if "policies" in file.parts:
            continue
        loaded, file_version = _load_file(file)
        templates.extend(loaded)
        version = file_version or version

    if not templates:
        raise DatasetError(f"no attack templates found under {directory}")
    _assert_unique(templates)
    return AttackCatalog(templates, version=version)


def _load_file(path: Path) -> tuple[list[AttackTemplate], str | None]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise DatasetError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise DatasetError(f"{path}: expected a mapping at the top level")

    try:
        default_category = AttackCategory(raw["category"])
    except (KeyError, ValueError) as exc:
        raise DatasetError(f"{path}: missing or unknown `category`") from exc

    templates: list[AttackTemplate] = []
    for entry in raw.get("templates", []):
        if not isinstance(entry, dict):
            raise DatasetError(f"{path}: each template must be a mapping")
        try:
            templates.append(
                AttackTemplate(
                    id=str(entry["id"]),
                    category=AttackCategory(entry.get("category", default_category)),
                    name=str(entry.get("name", entry["id"])),
                    prompt=str(entry["prompt"]),
                    description=str(entry.get("description", "")),
                    version=str(entry.get("version", raw.get("version", "1"))),
                    injections=list(entry.get("injections", [])),
                    requires_tools=list(entry.get("requires_tools", [])),
                    requires_channels=list(entry.get("requires_channels", [])),
                    requires_adapter=list(entry.get("requires_adapter", [])),
                    metadata=dict(entry.get("metadata", {})),
                    expected=dict(entry.get("expected", {})),
                    tags=list(entry.get("tags", [])),
                    variables={k: list(v) for k, v in (entry.get("variables") or {}).items()},
                )
            )
        except KeyError as exc:
            raise DatasetError(f"{path}: template missing required field {exc}") from exc

    return templates, raw.get("dataset_version")


def _parse_expected(raw: dict[str, Any]) -> ExpectedOutcome:
    return ExpectedOutcome(
        forbidden_tools=list(raw.get("forbidden_tools", [])),
        forbidden_values=list(raw.get("forbidden_values", [])),
        forbidden_recipients=list(raw.get("forbidden_recipients", [])),
        detected_by=list(raw.get("detected_by", [])),
        severity_on_violation=Severity(raw.get("severity_on_violation", Severity.HIGH)),
        expect_refusal=bool(raw.get("expect_refusal", False)),
    )


def _substitute(text: str, bindings: dict[str, str]) -> str:
    result = text
    for name, value in bindings.items():
        result = result.replace(f"{{{{{name}}}}}", value)
    return result


def _assert_unique(templates: list[AttackTemplate]) -> None:
    """Duplicate ids would make findings ambiguous and baselines meaningless."""
    seen: set[str] = set()
    duplicates: set[str] = set()
    for template in templates:
        if template.id in seen:
            duplicates.add(template.id)
        seen.add(template.id)
    if duplicates:
        raise DatasetError(f"duplicate attack template ids: {sorted(duplicates)}")


def _discover_root() -> Path:
    override = os.getenv("AGENTSHIELD_DATASETS")
    if override:
        return Path(override)
    # Walk up from this file to the repository root, which holds `datasets/`.
    here = Path(__file__).resolve()
    for parent in here.parents:
        for candidate in DEFAULT_DATASET_DIRS:
            path = parent / candidate
            if path.is_dir():
                return path
    return Path("datasets")


def _substitute_deep(value: Any, bindings: dict[str, str]) -> Any:
    """Apply variable substitution through nested metadata.

    Metadata is structured, so the flat `_substitute` used for prompts would leave a
    `{{customer_id}}` sitting inside a call plan untouched - and the scenario would call the
    server with a literal placeholder and report whatever came back.
    """
    if isinstance(value, str):
        return _substitute(value, bindings)
    if isinstance(value, dict):
        return {key: _substitute_deep(item, bindings) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute_deep(item, bindings) for item in value]
    return value

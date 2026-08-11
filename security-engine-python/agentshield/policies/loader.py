"""Load and validate security policies."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agentshield.models.policy import SecurityPolicy


class PolicyError(ValueError):
    """The policy document is malformed. Always fatal: a scan run against a policy we do not
    fully understand would produce findings nobody can trust."""


def load_policy(path: str | Path) -> SecurityPolicy:
    file = Path(path)
    if not file.is_file():
        raise PolicyError(f"policy file not found: {file}")
    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy {file} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"policy {file} must be a mapping at the top level")
    return parse_policy(raw)


def parse_policy(raw: dict[str, Any]) -> SecurityPolicy:
    try:
        return SecurityPolicy.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError
        raise PolicyError(f"policy is invalid: {exc}") from exc


def canaries_from(policy: SecurityPolicy) -> list[str]:
    """Literal canary values a policy declares, for seeding into the target.

    Only patterns with no regex metacharacters can be used as literal seed values; the rest
    are detection-only.
    """
    literals: list[str] = []
    for pattern in policy.canary_patterns():
        if not any(ch in pattern.regex for ch in ".*+?[]()|\\^$"):
            literals.append(pattern.regex)
    return literals

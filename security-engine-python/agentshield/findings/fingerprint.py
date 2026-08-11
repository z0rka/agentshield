"""Stable identity for a finding.

A fingerprint answers one question: *is this the same problem we already know about?* It has
to survive re-runs, mutated payloads and reordered steps, or the CI gate cries wolf on every
build. It must also not collapse genuinely different problems into one, or a real regression
hides behind a known issue.

The identity is therefore **the defect, not the exploit**: which control failed, on which
tool, in which category. The specific prompt that triggered it is a property of the
reproduction, not of the identity - five payloads reaching the same unguarded `send_email`
are one finding with five reproductions, and fixing the tool fixes all five.
"""

from __future__ import annotations

import hashlib
import re

from agentshield.models.common import AttackCategory
from agentshield.models.finding import EvaluationResult

#: Category -> short code used in the human-facing finding id (AS-INJECTION-004).
CATEGORY_CODES: dict[AttackCategory, str] = {
    AttackCategory.DIRECT_PROMPT_INJECTION: "INJECTION",
    AttackCategory.INDIRECT_PROMPT_INJECTION: "INJECTION",
    AttackCategory.TOOL_RESULT_POISONING: "INJECTION",
    AttackCategory.TOOL_ABUSE: "AGENCY",
    AttackCategory.APPROVAL_BYPASS: "APPROVAL",
    AttackCategory.DATA_LEAKAGE: "LEAK",
    AttackCategory.CROSS_TENANT: "TENANT",
    AttackCategory.UNBOUNDED_CONSUMPTION: "BUDGET",
    AttackCategory.IMPROPER_OUTPUT_HANDLING: "OUTPUT",
    AttackCategory.MEMORY_POISONING: "MEMORY",
}


def fingerprint(result: EvaluationResult) -> str:
    """Content hash identifying the defect this result describes."""
    evidence = result.evidence
    tools = ",".join(sorted(evidence.tool_names)) if evidence else ""
    policy_path = (evidence.policy_path or "") if evidence else ""
    material = "|".join(
        [
            str(result.category),
            result.evaluator,
            tools,
            policy_path,
            _normalise_title(result.title),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def finding_code(category: AttackCategory, fingerprint_value: str) -> str:
    """Human-facing identifier, e.g. `AS-INJECTION-004`.

    Derived from the fingerprint so the same defect keeps the same code across scans and
    across machines - a code that shifts between runs is useless in a ticket title.
    """
    prefix = CATEGORY_CODES.get(category, "GENERIC")
    number = int(fingerprint_value[:4], 16) % 1000
    return f"AS-{prefix}-{number:03d}"


def _normalise_title(title: str) -> str:
    """Strip the parts of a title that vary between runs.

    Step indices, counts and quoted values change with every mutation of the same attack;
    keeping them in the identity would produce a new "finding" on every run.
    """
    normalised = title.lower()
    normalised = re.sub(r"\bstep\s+\d+\b", "step N", normalised)
    normalised = re.sub(r"\b\d+(\.\d+)?\b", "N", normalised)
    normalised = re.sub(r"\s+", " ", normalised)
    return normalised.strip()

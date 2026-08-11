"""Dataset integrity.

The corpus is data, so nothing type-checks it. These tests are the review gate: a template
with a typo in an evaluator name would otherwise sit in the dataset for months, quietly
documenting an expectation nobody ever checks.
"""

from __future__ import annotations

import pytest

from agentshield.attacks.catalog import load_catalog
from agentshield.attacks.mutator import expand, mutate_scenario
from agentshield.evaluators.registry import DETERMINISTIC_EVALUATORS, SEMANTIC_EVALUATORS
from agentshield.models.common import AttackCategory

KNOWN_EVALUATORS = {c.name for c in (*DETERMINISTIC_EVALUATORS, *SEMANTIC_EVALUATORS)}


@pytest.fixture(scope="module")
def catalog(request):
    return load_catalog(request.config.rootpath.parent / "datasets")


def test_corpus_loads(catalog):
    assert len(catalog) >= 25


def test_every_category_is_represented(catalog):
    covered = set(catalog.counts())
    # MEMORY_POISONING and IMPROPER_OUTPUT_HANDLING are exercised through templates filed
    # under their parent suites until they get dedicated corpora in stage 3.
    expected = set(AttackCategory) - {
        AttackCategory.MEMORY_POISONING,
        AttackCategory.IMPROPER_OUTPUT_HANDLING,
    }
    assert expected.issubset(covered), f"missing suites: {sorted(expected - covered)}"


def test_template_ids_are_unique(catalog):
    ids = [t.id for t in catalog.templates]
    assert len(ids) == len(set(ids))


def test_expected_detectors_reference_real_evaluators(catalog):
    """A scenario claiming `SensitveDataLeakEvaluator` documents nothing."""
    for template in catalog.templates:
        for name in template.expected.get("detected_by", []):
            assert name in KNOWN_EVALUATORS, f"{template.id} references unknown evaluator {name}"


def test_every_template_instantiates(catalog):
    for template in catalog.templates:
        scenario = template.instantiate(seed=7)
        assert scenario.payload.prompt.strip()
        assert "{{" not in scenario.payload.prompt, f"{template.id} left a variable unbound"
        for injection in scenario.payload.injections:
            assert "{{" not in injection.content


def test_no_real_secrets_in_the_corpus(catalog):
    """Every credential-shaped value must be a synthetic canary or a `.test` address."""
    forbidden_markers = ("AKIA", "-----BEGIN", "sk-ant-", "ghp_")
    for template in catalog.templates:
        blob = template.prompt + "".join(str(i.get("content", "")) for i in template.injections)
        for marker in forbidden_markers:
            assert marker not in blob, f"{template.id} contains what looks like a real secret"
        for address in _emails(blob):
            assert address.endswith((".test", ".example", ".invalid")), (
                f"{template.id} uses {address}, which is not a reserved test domain"
            )


def test_mutation_is_deterministic(catalog):
    template = catalog.by_id("IND-001")
    base = template.instantiate(seed=0)

    first = mutate_scenario(base, 3)
    second = mutate_scenario(base, 3)

    assert first.payload.prompt == second.payload.prompt
    assert [i.content for i in first.payload.injections] == [
        i.content for i in second.payload.injections
    ]
    assert first.id == second.id


def test_mutation_varies_by_seed(catalog):
    base = catalog.by_id("IND-001").instantiate(seed=0)

    variants = expand(base, 6)

    contents = {v.payload.injections[0].content for v in variants}
    assert len(contents) >= 4, "mutation should produce materially different payloads"


def test_variant_zero_is_the_authored_payload(catalog):
    """Seed 0 must exercise the payload exactly as a human wrote it."""
    base = catalog.by_id("IND-001").instantiate(seed=0)

    variant = mutate_scenario(base, 0)

    assert variant.payload.injections[0].content == base.payload.injections[0].content


def _emails(text: str) -> list[str]:
    import re

    # Trailing punctuation is sentence structure, not part of the address.
    return [m.rstrip(".,;:") for m in re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", text)]

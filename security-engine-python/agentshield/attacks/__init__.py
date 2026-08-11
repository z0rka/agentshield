"""Attack corpus: templates, mutation and target-aware selection."""

from agentshield.attacks.catalog import (
    AttackCatalog,
    AttackTemplate,
    DatasetError,
    load_catalog,
)
from agentshield.attacks.mutator import MUTATIONS, expand, mutate_scenario
from agentshield.attacks.selection import (
    SelectionResult,
    ThreatModel,
    build_threat_model,
    infer_classification,
    select_categories,
    select_scenarios,
)

__all__ = [
    "MUTATIONS",
    "AttackCatalog",
    "AttackTemplate",
    "DatasetError",
    "SelectionResult",
    "ThreatModel",
    "build_threat_model",
    "expand",
    "infer_classification",
    "load_catalog",
    "mutate_scenario",
    "select_categories",
    "select_scenarios",
]

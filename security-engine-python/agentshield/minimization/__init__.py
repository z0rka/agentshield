"""Reproduction minimisation: the shortest payload that still triggers the same finding."""

from agentshield.minimization.ddmin import DEFAULT_PROBE_BUDGET, Oracle, Reduction, ddmin
from agentshield.minimization.minimizer import (
    MinimizationBudget,
    Probe,
    ReproductionMinimizer,
)
from agentshield.minimization.segments import (
    INJECTION,
    PROMPT,
    Segment,
    assemble,
    describe,
    segment_payload,
)

__all__ = [
    "DEFAULT_PROBE_BUDGET",
    "INJECTION",
    "MinimizationBudget",
    "Oracle",
    "PROMPT",
    "Probe",
    "Reduction",
    "ReproductionMinimizer",
    "Segment",
    "assemble",
    "ddmin",
    "describe",
    "segment_payload",
]

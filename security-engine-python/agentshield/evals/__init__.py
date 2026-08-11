"""Measuring the evaluators.

AgentShield judges agents; this package judges AgentShield. The question it answers is whether
a change to detection made things better or merely different, which is not arguable without
numbers.
"""

from agentshield.evals.fixture import Fixture, FixtureError, FixtureSet, load_fixtures
from agentshield.evals.runner import EvalRunner, StabilityRunner, gate
from agentshield.evals.scoring import Confusion, Failure, Report
from agentshield.evals.stability import Sample, StabilityReport, gate_stability

__all__ = [
    "Confusion",
    "EvalRunner",
    "Failure",
    "Fixture",
    "FixtureError",
    "FixtureSet",
    "Report",
    "Sample",
    "StabilityReport",
    "StabilityRunner",
    "gate",
    "gate_stability",
    "load_fixtures",
]

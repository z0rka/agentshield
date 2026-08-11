"""AgentShield security engine.

Executes adversarial scenarios against AI agents, records their trajectories and
judges those trajectories against a declarative security policy.
"""

__version__ = "0.1.0"

# The dataset corpus, attack templates and evaluator set are versioned independently of
# the package so that a finding can be reproduced exactly. Every AttackRun records these.
DATASET_VERSION = "2026.08.1"
EVALUATOR_SET_VERSION = "1"
PROMPT_VERSION = "1"

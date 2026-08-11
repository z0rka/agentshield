"""A support agent with the failure modes AgentShield exists to find.

Deliberate defects:

* retrieved documents are concatenated into the instruction space, so any imperative in the
  knowledge base becomes a command (indirect prompt injection);
* `send_email` accepts any recipient;
* `get_customer` returns the full record, canary secret included, with no redaction;
* approval is a sentence in the system prompt over a gate in the execution path;
* `issue_refund` self-approves one amount and executes another;
* no tenant check anywhere - isolation exists only in the prompt.

Run with `--secure` to get the hardened variant used for the post-fix regression run.
"""

from demo_targets.vulnerable_support_agent.agent import SupportAgent
from demo_targets.vulnerable_support_agent.app import create_app

__all__ = ["SupportAgent", "create_app"]

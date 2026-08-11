"""Vulnerable RAG agent.

A RAG application is compromised through its *corpus*, and the damage often lands in a later
session than the one that caused it. That is why this is a separate target from the support
agent, which is compromised through its tools.

Intentional defects, each mapping to a scenario family:

* no source trust level - every passage carries one and the vulnerable build never reads it;
* malicious citations - the answer cites the clean document that matched by keyword while the
  content came from the planted one, so a human spot-check passes;
* context poisoning across turns - the working set is never cleared;
* system prompt leakage through retrieval, never through the chat surface;
* poisoned facts written to durable memory with no provenance, tenant scope or confidence.

Nothing here is deployable. All content is synthetic, all secrets are canaries, and the agent
has no tool that reaches outside the process.
"""

__all__: list[str] = []

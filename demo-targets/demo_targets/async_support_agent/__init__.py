"""Asynchronous support agent - the job-based protocol.

Wraps the same vulnerable planner as `vulnerable_support_agent` behind:

    POST /jobs               create work, return immediately
    GET  /jobs/{id}          status, output and steps
    GET  /jobs/{id}/events   newline-delimited progress
    POST /jobs/{id}/approval resolve a pending gate
    POST /jobs/{id}/cancel   stop it

The agent logic is identical on purpose. Nothing here is a new vulnerability; the point is
that the *same* defect is harder to observe when the answer arrives later, and a scanner that
only knows how to await a response cannot see it at all.

One defect is genuinely new, and it only exists in this shape: the vulnerable build **keeps
working while a job sits in `AWAITING_APPROVAL`**. A synchronous agent that asks and proceeds
has both events in one trajectory, in order, where anyone can see them. Here the approval
request is emitted, the job parks, and the side effect happens anyway - in a different
request, minutes later, to nobody watching.

Not deployable. All side effects are mocked and every secret is a canary.
"""

__all__: list[str] = []

# ruff: noqa: E501
"""Remediation proposals.

A finding without a fix is a complaint. The catalogue below is deterministic and opinionated:
each entry names controls that move enforcement *out of the prompt and into the system*,
because "add a line to the system prompt telling it not to" is the fix people reach for first
and the one that keeps failing.

An optional LLM pass can tailor wording to the specific target, but the controls themselves
are fixed - a model-generated remediation that varies between runs is not something a team
can track to completion.
"""

from __future__ import annotations

from agentshield.models.common import AttackCategory
from agentshield.models.finding import EvaluationResult, Remediation

_GENERIC = Remediation(
    summary="Enforce the violated control outside the model.",
    controls=[
        "Move the check into the tool implementation or the backend, where it cannot be talked out of.",
        "Fail closed when the check cannot be evaluated.",
        "Add a regression test from this finding so the fix is verified on every build.",
    ],
)

#: Keyed by evaluator name - the evaluator knows exactly which control failed, which makes it
#: a better key than the broad category.
BY_EVALUATOR: dict[str, Remediation] = {
    "ForbiddenToolEvaluator": Remediation(
        summary="Authorise tools at the backend, and give the agent the smallest tool set that does the job.",
        controls=[
            "Enforce an explicit tool allowlist per agent role; deny by default.",
            "Check authorisation inside the tool handler, not in the prompt or the orchestration layer.",
            "Split broad tools (`execute_sql`, `update_any_customer`) into narrow, purpose-built ones.",
            "Separate read tools from write tools so a read-only task cannot reach a write path.",
        ],
        example=(
            "tools:\n"
            "  execute_sql:\n"
            "    allowed: false\n"
            "  get_customer:\n"
            "    classification: SENSITIVE_READ\n"
            "    required_scope: customer.read\n"
            "    tenant_bound: true"
        ),
    ),
    "ApprovalComplianceEvaluator": Remediation(
        summary="Make approval a gate in the execution path, not an instruction in the prompt.",
        controls=[
            "Block the tool handler until a valid approval token for that exact action is presented.",
            "Bind each approval to a hash of the arguments, a single use and a short expiry.",
            "Reject any approval that arrives after execution - ordering must be enforced server-side.",
            "Record approval identity, timestamp and arguments in the audit log.",
        ],
    ),
    "ToolArgumentMutationEvaluator": Remediation(
        summary="Bind the approval to the exact arguments that will execute.",
        controls=[
            "Hash the arguments at approval time; re-verify the hash inside the tool handler.",
            "Show the human the same rendered payload the tool will receive.",
            "Treat any post-approval mutation as a denied action, not a retry.",
        ],
    ),
    "SensitiveDataLeakEvaluator": Remediation(
        summary="Redact on the way out and keep sensitive reads away from outbound tools.",
        controls=[
            "Apply PII and secret redaction at the tool boundary, before data enters the model context.",
            "Return opaque references (`customer_ref`) instead of raw records where possible.",
            "Forbid the same session from combining a SENSITIVE_READ with an EXTERNAL_COMMUNICATION tool.",
            "Scan outbound tool arguments for canaries and sensitive patterns; fail closed on a match.",
        ],
    ),
    "RecipientAllowlistEvaluator": Remediation(
        summary="Constrain destinations in the tool, not in the instructions.",
        controls=[
            "Enforce a recipient allowlist inside `send_email`; reject anything else with an error.",
            "Require human approval for any recipient outside the organisation's domains.",
            "Log every rejected destination - repeated rejections are an attack signal.",
        ],
        example=(
            "tools:\n"
            "  send_email:\n"
            "    classification: EXTERNAL_COMMUNICATION\n"
            "    requires_approval: true\n"
            "    recipient_allowlist:\n"
            '     - "@company.test"'
        ),
    ),
    "TenantIsolationEvaluator": Remediation(
        summary="Scope every query by the authenticated tenant at the data layer.",
        controls=[
            "Derive tenant from the authenticated session; never from a model-supplied argument.",
            "Enforce tenant scoping in the repository or via row-level security, not in the agent.",
            "Return 404 rather than 403 for other tenants' objects so existence does not leak.",
            "Stamp the owning tenant on every response so isolation is observable in traces.",
        ],
    ),
    "InjectionComplianceEvaluator": Remediation(
        summary="Keep retrieved content as data: it must never be able to choose an action.",
        controls=[
            "Wrap retrieved content in a clearly delimited, untrusted region and never concatenate it into the instruction block.",
            "Attach a trust level to every source and require a higher level before any write tool becomes available.",
            "Require human approval for side-effecting tools when untrusted content is in context.",
            "Validate tool arguments against the *user's* request, rejecting values that only appear in retrieved documents.",
            "Sanitise the corpus on ingestion: strip instruction-shaped text from documents.",
        ],
    ),
    "ExternalSideEffectEvaluator": Remediation(
        summary="Gate irreversible effects behind authorisation the model cannot influence.",
        controls=[
            "Require a signed capability for each side-effecting call, issued by the backend.",
            "Make side-effecting tools idempotent and rate-limited per session.",
            "Run dangerous operations in a sandbox with a dry-run mode used by default in non-production.",
        ],
    ),
    "UnsafeOutputSinkEvaluator": Remediation(
        summary="Validate and parameterise everything the model produces before it reaches an interpreter.",
        controls=[
            "Use parameterised queries; never interpolate model output into SQL.",
            "Pass arguments as a list to the OS; never build a shell string.",
            "Validate URLs, file paths and header values against strict allowlists.",
            "Escape by context (HTML, URL, shell) at the point of use, not once at the source.",
        ],
    ),
    "SchemaValidityEvaluator": Remediation(
        summary="Validate the agent's output against the schema before anything consumes it.",
        controls=[
            "Enforce the response schema at the API boundary and reject non-conforming answers.",
            "Retry with a repair prompt at most once, then fail explicitly over passing malformed data on.",
        ],
    ),
    "BudgetEvaluator": Remediation(
        summary="Give every run a hard ceiling enforced by the runtime.",
        controls=[
            "Enforce max steps, tool calls, tokens, cost and wall-clock per session in the orchestrator.",
            "Make cancellation propagate to in-flight tool calls.",
            "Emit a metric per dimension so the ceiling is observable before it is hit.",
        ],
    ),
    "LoopEvaluator": Remediation(
        summary="Detect and break repetition in the orchestrator.",
        controls=[
            "Track a signature of each tool call; abort after N identical repeats.",
            "Use bounded retries with backoff, and treat a repeated failure as terminal.",
            "Require observable progress between iterations to continue.",
        ],
    ),
}

#: Fallback per category when no evaluator-specific entry exists.
BY_CATEGORY: dict[AttackCategory, Remediation] = {
    AttackCategory.MEMORY_POISONING: Remediation(
        summary="Give memory a provenance and a trust model.",
        controls=[
            "Record source, tenant and confidence with every stored fact; reject writes that lack them.",
            "Never write to long-term memory from untrusted content without human confirmation.",
            "Scope memory reads to the writing tenant, and support deletion.",
        ],
    ),
}


def propose(result: EvaluationResult) -> Remediation:
    """Deterministic remediation for one evaluation result."""
    return BY_EVALUATOR.get(result.evaluator) or BY_CATEGORY.get(result.category) or _GENERIC

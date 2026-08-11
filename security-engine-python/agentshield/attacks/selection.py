"""Threat modelling and attack selection.

Running every scenario against every target wastes budget and buries the result that matters.
Selection is driven by what the target can actually do: an agent with no outbound tool cannot
exfiltrate through one, so the exfiltration suite would only ever produce passes that look
like coverage.

The threat model is derived from the *intersection* of what the target advertises and what the
policy declares. Disagreement between the two is itself worth reporting - a tool present on the
target but missing from the policy is unreviewed capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentshield.adapters.base import TargetCapabilities
from agentshield.attacks.catalog import AttackCatalog, AttackTemplate
from agentshield.models.common import AttackCategory, ToolClassification
from agentshield.models.policy import SecurityPolicy
from agentshield.models.scenario import AttackScenario


@dataclass(slots=True)
class ThreatModel:
    """What this specific target is exposed to."""

    tools: dict[str, ToolClassification] = field(default_factory=dict)
    channels: set[str] = field(default_factory=set)
    #: Tools the target exposes but the policy never mentions.
    undeclared_tools: set[str] = field(default_factory=set)
    #: Tools the policy describes but the target does not expose.
    missing_tools: set[str] = field(default_factory=set)
    approval_gated_tools: set[str] = field(default_factory=set)
    tenant_bound_tools: set[str] = field(default_factory=set)
    supports_trajectory: bool = False
    #: The adapter that produced this model. A scenario written for one protocol is
    #: meaningless against another - an MCP call plan sent to a REST agent is just an
    #: unread metadata key, and the scenario would score as a pass having tested nothing.
    adapter_type: str = ""

    @property
    def has_retrieval(self) -> bool:
        return bool(self.channels) or any(
            "search" in name or "retriev" in name or "knowledge" in name for name in self.tools
        )

    @property
    def has_outbound(self) -> bool:
        return ToolClassification.EXTERNAL_COMMUNICATION in self.tools.values()

    @property
    def has_sensitive_read(self) -> bool:
        return ToolClassification.SENSITIVE_READ in self.tools.values()

    @property
    def has_code_execution(self) -> bool:
        return ToolClassification.CODE_EXECUTION in self.tools.values()

    @property
    def has_financial(self) -> bool:
        return ToolClassification.FINANCIAL_WRITE in self.tools.values()

    @property
    def has_write(self) -> bool:
        return any(c.is_side_effecting for c in self.tools.values())

    @property
    def exfiltration_path(self) -> bool:
        """The combination that turns a leak into an incident."""
        return self.has_sensitive_read and self.has_outbound

    def summary(self) -> str:
        lines = [
            f"tools: {len(self.tools)}",
            f"channels: {sorted(self.channels) or 'none'}",
            f"exfiltration path: {'yes' if self.exfiltration_path else 'no'}",
            f"approval-gated: {sorted(self.approval_gated_tools) or 'none'}",
        ]
        if self.undeclared_tools:
            lines.append(f"undeclared on target: {sorted(self.undeclared_tools)}")
        if self.missing_tools:
            lines.append(f"declared but absent: {sorted(self.missing_tools)}")
        return "; ".join(lines)


def build_threat_model(
    capabilities: TargetCapabilities, policy: SecurityPolicy, *, adapter_type: str = ""
) -> ThreatModel:
    """Derive the threat model from discovered capabilities and the declared policy."""
    target_tools = capabilities.tool_names
    policy_tools = set(policy.tools)

    classifications = {
        name: policy.effective_tool(name).classification
        for name in target_tools | policy_tools
    }
    # Fall back to naming heuristics for tools the policy did not classify, so an
    # unreviewed `execute_sql` is still recognised as dangerous over UNKNOWN.
    for name, classification in list(classifications.items()):
        if classification is ToolClassification.UNKNOWN:
            classifications[name] = infer_classification(name)

    return ThreatModel(
        tools=classifications,
        channels=capabilities.channel_names,
        undeclared_tools=target_tools - policy_tools,
        missing_tools=policy_tools - target_tools if target_tools else set(),
        approval_gated_tools={n for n, t in policy.tools.items() if t.requires_approval},
        tenant_bound_tools={n for n, t in policy.tools.items() if t.tenant_bound},
        supports_trajectory=capabilities.supports_trajectory,
        adapter_type=adapter_type,
    )


def infer_classification(tool_name: str) -> ToolClassification:
    """Best-effort classification for an unreviewed tool, from its name.

    A heuristic, and it is used only to *raise* suspicion - never to grant a permission.
    """
    name = tool_name.lower()
    if any(k in name for k in ("execute", "shell", "eval", "query", "sql", "command")):
        return ToolClassification.CODE_EXECUTION
    if any(k in name for k in ("refund", "payment", "charge", "transfer", "invoice")):
        return ToolClassification.FINANCIAL_WRITE
    if any(k in name for k in ("send", "email", "message", "notify", "post", "webhook", "http")):
        return ToolClassification.EXTERNAL_COMMUNICATION
    if any(k in name for k in ("update", "delete", "create", "write", "set_", "modify")):
        return ToolClassification.WRITE
    if any(k in name for k in ("customer", "user", "account", "profile", "record", "pii")):
        return ToolClassification.SENSITIVE_READ
    if any(k in name for k in ("search", "get", "list", "read", "lookup", "fetch")):
        return ToolClassification.READ
    return ToolClassification.UNKNOWN


def select_categories(model: ThreatModel) -> set[AttackCategory]:
    """Suites worth running against this target."""
    selected = {AttackCategory.DIRECT_PROMPT_INJECTION, AttackCategory.UNBOUNDED_CONSUMPTION}

    if model.has_retrieval:
        selected.add(AttackCategory.INDIRECT_PROMPT_INJECTION)
    if model.supports_trajectory:
        # Tool-level suites need visible tool calls; without them a pass proves nothing.
        selected.add(AttackCategory.TOOL_RESULT_POISONING)
        selected.add(AttackCategory.TOOL_ABUSE)
    if model.has_sensitive_read or model.has_outbound:
        selected.add(AttackCategory.DATA_LEAKAGE)
    if model.tenant_bound_tools:
        selected.add(AttackCategory.CROSS_TENANT)
    if model.approval_gated_tools:
        selected.add(AttackCategory.APPROVAL_BYPASS)
    if model.has_write or model.has_code_execution:
        selected.add(AttackCategory.IMPROPER_OUTPUT_HANDLING)
    if "memory" in model.channels:
        selected.add(AttackCategory.MEMORY_POISONING)

    return selected


@dataclass(slots=True)
class SelectionResult:
    scenarios: list[AttackScenario]
    skipped: list[tuple[str, str]] = field(default_factory=list)
    categories: set[AttackCategory] = field(default_factory=set)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)


def select_scenarios(
    catalog: AttackCatalog,
    model: ThreatModel,
    *,
    categories: set[AttackCategory] | None = None,
    max_scenarios: int = 50,
    variants_per_template: int = 1,
    base_seed: int = 0,
) -> SelectionResult:
    """Choose and instantiate the scenarios to run.

    Scenarios the target cannot exercise are *skipped with a reason*, never silently dropped
    and never failed. A report that says "12 scenarios skipped: target exposes no outbound
    tool" is honest; one that shows them as passes is not.

    The budget is spent round-robin across categories, not in catalog order. Taking templates
    in order until the cap means whichever category sorts last gets nothing, so adding
    templates to one suite silently removes coverage of another - a scan that reports "no
    cross-tenant findings" because it never ran a cross-tenant scenario is the worst output
    this tool can produce.
    """
    from agentshield.attacks.mutator import expand

    chosen = categories if categories is not None else select_categories(model)
    available_tools = set(model.tools)
    available_channels = model.channels

    skipped: list[tuple[str, str]] = []
    applicable: dict[AttackCategory, list[AttackScenario]] = {}

    for template in catalog.by_category(chosen):
        base = template.instantiate(seed=base_seed)
        reason = _inapplicable_reason(base, template, available_tools, available_channels, model)
        if reason:
            skipped.append((template.id, reason))
            continue
        applicable.setdefault(base.category, []).append(base)

    scenarios = _round_robin(applicable, max_scenarios, variants_per_template, base_seed, expand)
    return SelectionResult(scenarios, skipped, chosen)


def _round_robin(
    by_category: dict[AttackCategory, list[AttackScenario]],
    max_scenarios: int,
    variants_per_template: int,
    base_seed: int,
    expand,
) -> list[AttackScenario]:
    """Take one template from each category in turn until the budget is gone.

    Categories are visited in name order so a given catalog and cap always produce the same
    scan; a selection that shifted between runs would make two reports incomparable for a
    reason that has nothing to do with the target.
    """
    # Sorted by template id within each category as well as across them. Catalog order is the
    # order files happen to be read, so without this, splitting one suite into two files
    # changes which scenarios a capped scan runs - the corpus would be reorganised for
    # readability and the scan would quietly start testing something else.
    queues = [
        sorted(by_category[category], key=lambda scenario: scenario.template_id or scenario.id)
        for category in sorted(by_category, key=str)
    ]
    scenarios: list[AttackScenario] = []

    while queues and len(scenarios) < max_scenarios:
        for queue in queues:
            if not queue:
                continue
            for variant in expand(queue.pop(0), variants_per_template, base_seed=base_seed):
                scenarios.append(variant)
                if len(scenarios) >= max_scenarios:
                    return scenarios
        queues = [queue for queue in queues if queue]

    return scenarios


def _inapplicable_reason(
    scenario: AttackScenario,
    template: AttackTemplate,
    tools: set[str],
    channels: set[str],
    model: ThreatModel,
) -> str | None:
    missing_tools = set(template.requires_tools) - tools
    if missing_tools:
        return f"target does not expose {sorted(missing_tools)}"
    missing_channels = set(template.requires_channels) - channels
    if missing_channels:
        return f"target has no {sorted(missing_channels)} channel to poison"
    if template.requires_tools and not model.supports_trajectory:
        return "target does not expose a trajectory, so tool-level assertions cannot be checked"
    required = set(template.requires_adapter)
    if required and model.adapter_type and model.adapter_type not in required:
        return f"scenario targets {sorted(required)}, this target speaks {model.adapter_type}"
    return None

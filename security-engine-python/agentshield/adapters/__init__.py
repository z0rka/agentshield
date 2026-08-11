"""Target adapters: the only AgentShield code that knows what a target looks like."""

from agentshield.adapters.base import (
    BaseTargetAdapter,
    TargetAdapter,
    TargetCapabilities,
    TargetError,
    ToolDescriptor,
)
from agentshield.adapters.mcp import McpServerAdapter
from agentshield.adapters.registry import build_adapter, redact_config, target_config_hash
from agentshield.adapters.rest import AgentShieldProtocolAdapter, RestAgentAdapter

__all__ = [
    "AgentShieldProtocolAdapter",
    "BaseTargetAdapter",
    "McpServerAdapter",
    "RestAgentAdapter",
    "TargetAdapter",
    "TargetCapabilities",
    "TargetError",
    "ToolDescriptor",
    "build_adapter",
    "redact_config",
    "target_config_hash",
]

"""Engine configuration, from the environment.

Deliberately flat and dependency-free. The engine is a worker: everything durable lives in
the control plane, so there is no engine-side config store to keep in sync.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def load_dotenv(path: Path | None = None) -> int:
    """Load `.env` into the process environment for local development.

    Hand-rolled over a dependency: this reads six lines of `KEY=value` and the alternative is
    a package every consumer of this library has to resolve for a convenience none of them
    need in production, where configuration comes from the orchestrator.

    **A value already in the environment always wins.** A `.env` that silently overrode a
    deliberately exported variable would make the same command behave differently depending on
    a file the operator may not know exists, and in CI that means a run configured by whatever
    happens to be checked out.

    Returns the number of variables set, so a caller can say nothing was found.
    """
    env_file = path or Path.cwd() / ".env"
    if not env_file.is_file():
        return 0

    loaded = 0
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip().strip("'\"")
        if not name or name in os.environ:
            continue
        os.environ[name] = value
        loaded += 1
    return loaded


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True, frozen=True)
class EngineSettings:
    control_plane_url: str = ""
    control_plane_internal_token: str = "local-engine-token"
    kafka_bootstrap_servers: str = ""
    kafka_group_id: str = "agentshield-security-engine"
    port: int = 8081
    #: Concurrent attack runs. The NFR floor for the local demo is 10.
    max_concurrent_runs: int = 10
    scenario_timeout_seconds: float = 60.0
    max_attempts: int = 2
    dataset_path: str | None = None
    #: LLM judges are opt-in: they cost money and cannot gate CI on their own.
    enable_semantic_evaluators: bool = False
    judge_model: str = "claude-sonnet-5"
    otel_endpoint: str | None = None
    service_name: str = "agentshield-security-engine"
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> EngineSettings:
        return cls(
            control_plane_url=os.getenv("AGENTSHIELD_CONTROL_PLANE_URL", ""),
            control_plane_internal_token=os.getenv(
                "AGENTSHIELD_INTERNAL_TOKEN", "local-engine-token"
            ),
            kafka_bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", ""),
            kafka_group_id=os.getenv(
                "AGENTSHIELD_KAFKA_GROUP_ID", "agentshield-security-engine"
            ),
            port=_int("AGENTSHIELD_ENGINE_PORT", 8081),
            max_concurrent_runs=_int("AGENTSHIELD_MAX_CONCURRENT_RUNS", 10),
            scenario_timeout_seconds=_float("AGENTSHIELD_SCENARIO_TIMEOUT", 60.0),
            max_attempts=_int("AGENTSHIELD_MAX_ATTEMPTS", 2),
            dataset_path=os.getenv("AGENTSHIELD_DATASETS"),
            enable_semantic_evaluators=_bool("AGENTSHIELD_ENABLE_JUDGES", False),
            judge_model=os.getenv("AGENTSHIELD_JUDGE_MODEL", "claude-sonnet-5"),
            otel_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
            service_name=os.getenv("OTEL_SERVICE_NAME", "agentshield-security-engine"),
            log_level=os.getenv("AGENTSHIELD_LOG_LEVEL", "INFO"),
        )

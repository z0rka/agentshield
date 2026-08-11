"""Where judge calls are recorded for later inspection.

A judged finding is an opinion produced by a specific model reading a specific prompt version.
Six months later, defending or disputing it means answering "which model, which prompt, what
did it actually say" - and none of that is in the finding, which keeps one sentence of
reasoning and a confidence number.

Langfuse is that record. It is deliberately a *sink*, not a source: the prompt lives in this
repository and is versioned by `JUDGE_PROMPT_VERSION`, so a scan reproduces from a checkout
with no network call to anybody. Fetching prompts from a hosted service would move the
definition of what the judges ask out of version control, and a scan nobody can reproduce
offline is not evidence.

**Never configured is the normal case.** No credentials means `NullJudgeSink`, which does
nothing and costs nothing. Observability that can fail a scan is worse than no observability,
so every error here is swallowed and logged.
"""

from __future__ import annotations

import logging
import os
from typing import Protocol

from agentshield.evaluators.pricing import estimate_cost
from agentshield.redaction import redact

log = logging.getLogger(__name__)


class JudgeSink(Protocol):
    """Receives one record per judge call. Must never raise."""

    def record(
        self,
        *,
        model: str,
        prompt_version: str,
        prompt: str,
        answer: str,
        input_tokens: int,
        output_tokens: int,
        latency_seconds: float,
    ) -> None: ...

    def flush(self) -> None: ...


class NullJudgeSink:
    """The default. Does nothing, so nothing can go wrong."""

    def record(self, **_: object) -> None:
        return

    def flush(self) -> None:
        return


class LangfuseJudgeSink:
    """Records each judge call as a Langfuse generation.

    Constructed only through `judge_sink()`, which checks credentials first - so reaching this
    class means the SDK is installed and keys are present.
    """

    def __init__(self, client: object, *, scan_id: str) -> None:
        self._client = client
        self._scan_id = scan_id

    def record(
        self,
        *,
        model: str,
        prompt_version: str,
        prompt: str,
        answer: str,
        input_tokens: int,
        output_tokens: int,
        latency_seconds: float,
    ) -> None:
        try:
            generation = self._client.start_observation(
                name="judge",
                as_type="generation",
                model=model,
                # Redacted before it leaves the process. The prompt embeds a trajectory, and a
                # security tool that ships its customers' agent traffic to a third-party
                # dashboard has recreated the problem it was bought to find.
                input=redact(prompt),
                output=redact(answer),
                # The prompt version rides as `version`, which is what makes "show every
                # verdict produced by prompt v1 on this model" a filter and not an archaeology
                # exercise. It is the whole reason this sink exists.
                version=prompt_version,
                metadata={
                    "scan_id": self._scan_id,
                    "latency_seconds": round(latency_seconds, 3),
                },
                usage_details={"input": input_tokens, "output": output_tokens},
                cost_details={"total": estimate_cost(model, input_tokens, output_tokens)},
            )
            generation.end()
        except Exception as exc:  # noqa: BLE001 - telemetry must not fail a scan
            log.warning("langfuse record failed: %s", exc)

    def flush(self) -> None:
        try:
            self._client.flush()
        except Exception as exc:  # noqa: BLE001
            log.warning("langfuse flush failed: %s", exc)


def judge_sink(scan_id: str) -> JudgeSink:
    """A Langfuse sink when it is configured and importable, otherwise the null sink.

    Three ways to get the null sink, all of them normal: no keys, SDK not installed, or the
    client refused to construct. None of them is an error worth stopping a scan for.
    """
    if not (os.getenv("LANGFUSE_PUBLIC_KEY") and os.getenv("LANGFUSE_SECRET_KEY")):
        return NullJudgeSink()

    try:
        from langfuse import Langfuse  # imported lazily: optional dependency

        client = Langfuse(
            public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
            secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
            host=os.getenv("LANGFUSE_HOST") or "https://cloud.langfuse.com",
        )
        # Checked here, not on first write. A sink that swallows every record because
        # the keys are wrong looks identical to one that is working, and the discovery would
        # be an empty dashboard days later.
        if not client.auth_check():
            log.warning("langfuse credentials rejected; judge calls will not be recorded")
            return NullJudgeSink()
    except Exception as exc:  # noqa: BLE001 - absence is a supported configuration
        log.info("langfuse not enabled (%s); judge calls will not be recorded", exc)
        return NullJudgeSink()

    log.info("langfuse enabled for scan %s", scan_id)
    return LangfuseJudgeSink(client, scan_id=scan_id)

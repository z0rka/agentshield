"""Recorded judge responses, so a real model is paid for once and replayed forever.

LLM judges are the only part of this system that costs money to exercise, which makes them
the only part with a standing incentive to go untested. A judge nobody can afford to run is a
judge whose parsing, severity capping and redaction are unverified - and those are exactly the
places a security tool fails quietly.

The fix is the oldest one available: capture the real responses once, check them in, and
replay them from then on. Every later test run, CI included, exercises the full judge path
against answers a real model actually gave, at no cost.

**A cassette stores the response, never the prompt.** The prompt carries the trajectory, and
a trajectory is the thing this repository is most careful not to publish. The key is a hash,
so a recorded file is reviewable without becoming a corpus of somebody's agent traffic.

**A miss is not a pass.** `ReplayJudgeClient` raises, `Evaluator` turns that into a skipped
result, and the report says the judge did not run. A cassette that silently answered "no
violation" for an unrecorded case would be the exact failure this whole design exists to
prevent.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from agentshield.evaluators.llm_judge import JudgeClient
from agentshield.evaluators.pricing import JudgeUsage


class CassetteMiss(LookupError):
    """No recorded response for this call.

    Raised, never defaulted. The caller decides what an unmeasured judge means; guessing
    here would put an invented verdict into a security report.
    """


def call_key(model: str, system: str, prompt: str) -> str:
    """Stable identity for one judge call.

    All three inputs matter. The model because different models answer differently; the
    system text because it carries the prompt version and the policy; the prompt because it
    carries the question and the trajectory. Change any of them and the recording no longer
    describes the call being made - which is a miss, and should be.
    """
    material = "\x00".join([model, system, prompt])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


class JudgeCassette:
    """A file of recorded judge responses, keyed by call."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._entries: dict[str, dict[str, str]] = {}
        if path.is_file():
            self._entries = json.loads(path.read_text(encoding="utf-8")).get("calls", {})

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: str) -> str | None:
        entry = self._entries.get(key)
        return entry["response"] if entry else None

    def put(self, key: str, *, model: str, label: str, response: str) -> None:
        self._entries[key] = {
            "model": model,
            # A human-readable hint at what was asked. Enough to review the file, not enough
            # to reconstruct the trajectory.
            "label": label,
            "response": response,
            "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "note": "Recorded judge responses. Keys are hashes; prompts are deliberately absent.",
            "calls": dict(sorted(self._entries.items())),
        }
        self.path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class ReplayJudgeClient:
    """Answers from a cassette. Never reaches the network, never costs anything."""

    def __init__(
        self, cassette: JudgeCassette, *, model: str, usage: JudgeUsage | None = None
    ) -> None:
        self._cassette = cassette
        self.model = model
        self.usage = usage if usage is not None else JudgeUsage()
        self.usage.model = self.usage.model or model

    @property
    def available(self) -> bool:
        """True even with no credentials - that is the entire point."""
        return True

    def complete(self, system: str, prompt: str) -> str:
        key = call_key(self.model, system, prompt)
        recorded = self._cassette.get(key)
        if recorded is not None:
            # Counted, and free. A report claiming spend for a replayed call would be as wrong
            # as one hiding spend for a live one.
            self.usage.record_replay()
        if recorded is None:
            raise CassetteMiss(
                f"no recorded response for {key} on {self.model}; "
                f"re-record with scripts/record_judges.py"
            )
        return recorded


class RecordingJudgeClient:
    """Wraps a live client and writes every answer to a cassette.

    Used once, deliberately, by the recording script - never by tests or by a scan. Recording
    from inside a normal run would spend money on a schedule nobody chose.
    """

    def __init__(self, inner: JudgeClient, cassette: JudgeCassette, *, model: str) -> None:
        self._inner = inner
        self._cassette = cassette
        self.model = model
        self.calls_made = 0

    @property
    def available(self) -> bool:
        return bool(getattr(self._inner, "available", True))

    def complete(self, system: str, prompt: str) -> str:
        key = call_key(self.model, system, prompt)
        cached = self._cassette.get(key)
        if cached is not None:
            # Already recorded. Re-running the script must not re-buy answers it owns.
            return cached
        response = self._inner.complete(system, prompt)
        self.calls_made += 1
        self._cassette.put(key, model=self.model, label=_label(prompt), response=response)
        return response


def _label(prompt: str) -> str:
    """First line of the question, for a reviewable file. Never trajectory content."""
    for line in prompt.splitlines():
        stripped = line.strip()
        if stripped and stripped != "QUESTION":
            return stripped[:120]
    return "(no question)"

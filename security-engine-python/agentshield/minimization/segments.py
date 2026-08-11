"""Splitting an attack payload into removable units, and putting it back together.

Delta debugging needs parts it is allowed to drop, and the choice of part is what decides
whether the answer is any use to a person. Characters produce a technically smaller result that
nobody can read; whole artifacts produce a result that almost never shrinks. Sentences and
lines are the unit a reader already reasons in - "it was this instruction in the document" -
so that is the unit here.

Reassembly keeps the original separators, which buys the property the minimiser depends on:
**keeping every segment rebuilds the payload byte for byte.** Without it, the first probe would
be testing a reformatted lookalike of the attack, not the attack itself, and every conclusion
drawn afterwards would be about the wrong input.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Sequence
from dataclasses import dataclass

from agentshield.models.scenario import AttackPayload

#: Segment origins.
PROMPT = "prompt"
INJECTION = "injection"

#: Sentence ends and line breaks, captured so the separator can be restored on reassembly.
#: Deliberately conservative: it does not try to be a sentence tokeniser, because splitting an
#: adversarial payload slightly coarsely costs a little minimality, while splitting it wrongly
#: produces reproductions that do not parse as language.
_BOUNDARY = re.compile(r"((?<=[.!?])[ \t]+|\r?\n+)")


@dataclass(frozen=True, slots=True)
class Segment:
    """One droppable piece of a payload, and where it came from."""

    #: PROMPT or INJECTION.
    origin: str
    #: Index into `payload.injections`, or -1 for the prompt.
    artifact: int
    text: str
    #: Whitespace that followed this segment in the original. Carried so reassembly is exact.
    separator: str = ""


def segment_payload(payload: AttackPayload) -> list[Segment]:
    """Break the prompt and every injected document into sentence-level segments."""
    segments = [Segment(PROMPT, -1, text, sep) for text, sep in _split(payload.prompt)]
    for index, artifact in enumerate(payload.injections):
        segments.extend(
            Segment(INJECTION, index, text, sep) for text, sep in _split(artifact.content)
        )
    return segments


def assemble(
    payload: AttackPayload, segments: Sequence[Segment], kept: Collection[int]
) -> AttackPayload:
    """Rebuild the payload from the kept segment indices.

    `model_copy` over constructing a new `AttackPayload`: metadata and seed are carried through
    untouched, and they stay carried through when someone adds a field to the model. Enumerating
    the fields here would silently start dropping the new one.
    """
    keep = set(kept)
    prompt_parts: list[str] = []
    artifact_parts: dict[int, list[str]] = {}

    for index, segment in enumerate(segments):
        if index not in keep:
            continue
        piece = segment.text + segment.separator
        if segment.origin == PROMPT:
            prompt_parts.append(piece)
        else:
            artifact_parts.setdefault(segment.artifact, []).append(piece)

    segmented = {s.artifact for s in segments if s.origin == INJECTION}
    injections = []
    for index, artifact in enumerate(payload.injections):
        if index not in segmented:
            # Nothing to remove from it, so ddmin never had a say. Carrying it through is the
            # only honest option: dropping it would be a reduction nobody tested.
            injections.append(artifact)
            continue
        content = "".join(artifact_parts.get(index, []))
        if not content.strip():
            # Every sentence gone means the document is not load-bearing, so the whole planted
            # artifact goes with it. A poisoned document reduced to whitespace is noise.
            continue
        injections.append(artifact.model_copy(update={"content": content}))

    return payload.model_copy(
        update={"prompt": "".join(prompt_parts), "injections": injections}
    )


def describe(segments: Sequence[Segment], kept: Collection[int]) -> str:
    """One line for the report: what was dropped, and from where."""
    keep = set(kept)
    dropped_prompt = sum(
        1 for i, s in enumerate(segments) if i not in keep and s.origin == PROMPT
    )
    dropped_injection = sum(
        1 for i, s in enumerate(segments) if i not in keep and s.origin == INJECTION
    )
    parts = []
    if dropped_prompt:
        parts.append(f"{dropped_prompt} prompt")
    if dropped_injection:
        parts.append(f"{dropped_injection} injected")
    if not parts:
        return "no segment could be removed"
    return f"removed {' and '.join(parts)} segment(s) of {len(segments)}"


def _split(text: str) -> list[tuple[str, str]]:
    """Split into (body, separator) pairs whose concatenation is the original string."""
    if not text:
        return []
    parts = _BOUNDARY.split(text)
    pieces: list[tuple[str, str]] = []
    for index in range(0, len(parts), 2):
        body = parts[index]
        separator = parts[index + 1] if index + 1 < len(parts) else ""
        if body or separator:
            pieces.append((body, separator))
    return pieces

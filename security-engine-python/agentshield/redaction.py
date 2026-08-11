"""Redaction applied to everything that leaves the engine.

A security report gets pasted into tickets, chat and CI logs. If proving a leak requires
reprinting the leaked value, the tool has created a second leak. So evidence names the
pattern that matched and shows a masked excerpt - enough for a human to verify, not enough
to be useful to anyone reading over their shoulder.

The same rule covers traces and structured logs: see docs/architecture.md §observability for
the attribute denylist.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

#: Always redacted regardless of policy, because they are secrets in every context.
BUILTIN_PATTERNS: tuple[tuple[str, str], ...] = (
    ("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("bearer-token", r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}"),
    ("authorization-header", r"(?i)authorization:\s*\S+"),
    ("aws-access-key", r"AKIA[0-9A-Z]{16}"),
    ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("api-key-assignment", r"(?i)\b(api[_-]?key|secret|password)\s*[:=]\s*\S{8,}"),
)

_MASK = "***"


def mask(value: str, *, keep: int = 4) -> str:
    """Mask a value, leaving a short prefix so a human can still correlate it.

    `AGENTSHIELD_SECRET_7F93A` -> `AGEN***[len=24]`. The length is retained because
    "a 24-character secret reached send_email" is itself useful evidence.
    """
    if not value:
        return _MASK
    prefix = value[: min(keep, max(0, len(value) - 1))]
    return f"{prefix}{_MASK}[len={len(value)}]"


def redact(text: str, extra_patterns: Iterable[tuple[str, str]] = ()) -> str:
    """Replace every known secret shape in `text` with a labelled placeholder."""
    if not text:
        return text
    result = text
    for name, pattern in (*BUILTIN_PATTERNS, *extra_patterns):
        result = re.sub(pattern, f"[REDACTED:{name}]", result)
    return result


def redact_value(value: str, secrets: Iterable[str]) -> str:
    """Redact specific literal values (canaries, tenant identifiers) out of `value`."""
    result = value
    for secret in secrets:
        if secret and secret in result:
            result = result.replace(secret, f"[REDACTED:{mask(secret)}]")
    return result


def excerpt(text: str, needle: str, *, width: int = 60) -> str:
    """A short, redacted window around `needle` - the proof, without the payload.

    Returns the leading `width` characters when the needle is absent, so callers never have
    to branch on "did we find it".
    """
    if not text:
        return ""
    index = text.find(needle) if needle else -1
    if index < 0:
        return redact(text[:width].strip())
    start = max(0, index - width // 2)
    end = min(len(text), index + len(needle) + width // 2)
    window = text[start:end]
    if needle:
        window = window.replace(needle, mask(needle))
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{redact(window.strip())}{suffix}"


def redact_arguments(arguments: dict[str, object], sensitive_keys: Iterable[str]) -> dict[str, str]:
    """Render tool arguments for evidence, masking the keys a policy marked sensitive."""
    sensitive = {k.lower() for k in sensitive_keys}
    rendered: dict[str, str] = {}
    for key, value in arguments.items():
        text = value if isinstance(value, str) else str(value)
        rendered[key] = mask(text) if key.lower() in sensitive else redact(text)
    return rendered

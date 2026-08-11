"""What the engine refuses to point itself at.

The control plane has its own SSRF guard, and it is the stricter one: there, a user registers a
URL and the *server* makes the request, so anything reachable from the control plane's network
is a target the user should not have been able to reach. That is the classic forgery shape and
it is denied by default.

This guard is not a copy of it, and the difference is intentional: the engine runs in two
situations with
different threat models:

* **As a CLI on an operator's laptop**, pointed at a target they typed themselves. There is no
  privilege boundary to cross - they could `curl` it directly - and refusing loopback would
  break the demo while preventing nothing.
* **As a worker in a cluster**, driven by whatever the control plane sends. Here internal
  addresses matter, and `block_private` turns that on.

**One rule holds everywhere: cloud metadata endpoints are always refused.** No configuration
re-enables them. They serve instance credentials to anything that connects, and a scan report
containing them cannot be unpublished. Everything else is deployment policy; this is not.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

#: Instance-metadata addresses. They sit inside link-local and would be caught by the range
#: check when it is on, but they are refused unconditionally and named separately so the error
#: says what the caller just tried to do.
METADATA_ADDRESSES: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS, Azure, DigitalOcean, Oracle
    "169.254.170.2",    # AWS ECS task metadata
    "100.100.100.200",  # Alibaba Cloud
    "192.0.0.192",      # Oracle Cloud legacy
})


class TargetNotAllowed(ValueError):
    """The target URL is one the engine will not send traffic to."""


def ensure_target_allowed(url: str, *, block_private: bool = False) -> None:
    """Raise `TargetNotAllowed` when this URL must not be scanned.

    The host is resolved, never pattern-matched: blocking the literal `169.254.169.254`
    stops nobody, because a name an attacker controls can point at it. Resolution here and
    connection later remain two lookups, so this does not close DNS rebinding - see the control
    plane's `SsrfGuard` for the same caveat, stated in the same terms.
    """
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise TargetNotAllowed(f"target URL must be http or https, got {parts.scheme or 'none'!r}")
    host = parts.hostname
    if not host:
        raise TargetNotAllowed("target URL must include a host")

    for address in _resolve(host):
        if str(address) in METADATA_ADDRESSES:
            raise TargetNotAllowed(
                f"{host} resolves to the cloud metadata endpoint {address}, which serves "
                "instance credentials and is never a valid scan target"
            )
        if not block_private:
            continue
        reason = _classify(address)
        if reason:
            raise TargetNotAllowed(
                f"{host} resolves to {address} ({reason}); the engine is configured to refuse "
                "internal addresses. Unset AGENTSHIELD_BLOCK_PRIVATE_TARGETS to scan locally."
            )


def _classify(address: ipaddress._BaseAddress) -> str | None:
    """Why this address is internal, or None when it is publicly routable."""
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_private:
        # Checked after the more specific cases: `is_private` is true for loopback and
        # link-local too, and the precise word is what makes the error actionable.
        return "private range"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved"
    return None


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        # Refused, not waved through. Treating "could not check" as "safe" turns a DNS outage
        # into a bypass of the only control standing between this tool and a metadata endpoint.
        raise TargetNotAllowed(
            f"target host {host} does not resolve, so it cannot be checked"
        ) from exc
    return [ipaddress.ip_address(info[4][0]) for info in infos]

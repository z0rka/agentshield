"""What the engine refuses to point itself at.

The negative cases carry the weight here. A guard that lets one metadata request through has
failed completely, and a guard that refuses loopback by default breaks the demo without
preventing anything - the operator running the CLI could reach that address by other means.
Both halves are asserted.

Every address is a literal. A test that needs DNS to resolve an attacker-shaped name fails in
an offline CI runner for reasons that have nothing to do with the code under test.
"""

from __future__ import annotations

import pytest

from agentshield.adapters.registry import build_adapter
from agentshield.adapters.urlguard import (
    METADATA_ADDRESSES,
    TargetNotAllowed,
    ensure_target_allowed,
)

# ---------------------------------------------------------------------------------
# always refused, whatever the configuration says
# ---------------------------------------------------------------------------------


@pytest.mark.parametrize("address", sorted(METADATA_ADDRESSES))
def test_metadata_endpoints_are_refused_even_with_private_targets_allowed(address):
    """The one rule no configuration re-enables.

    These serve instance credentials to anything that connects. A scan report containing them
    cannot be unpublished, so this is not a deployment policy.
    """
    with pytest.raises(TargetNotAllowed, match="metadata"):
        ensure_target_allowed(f"http://{address}/latest/meta-data/", block_private=False)


def test_the_metadata_refusal_names_what_was_attempted():
    with pytest.raises(TargetNotAllowed, match="credentials"):
        ensure_target_allowed("http://169.254.169.254/")


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "gopher://x/", "ftp://x/", "//x/", "not-a-url"]
)
def test_non_http_schemes_are_refused(url):
    with pytest.raises(TargetNotAllowed):
        ensure_target_allowed(url)


def test_a_url_without_a_host_is_refused():
    with pytest.raises(TargetNotAllowed, match="host"):
        ensure_target_allowed("http:///path")


def test_a_host_that_does_not_resolve_is_refused_not_assumed_safe():
    """"Could not check" must never read as "checked and fine"."""
    with pytest.raises(TargetNotAllowed, match="does not resolve"):
        ensure_target_allowed("http://no-such-host.invalid")


# ---------------------------------------------------------------------------------
# deployment policy: internal addresses
# ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("127.0.0.1", "loopback"),
        ("10.0.0.5", "private range"),
        ("192.168.1.20", "private range"),
        ("169.254.1.1", "link-local"),
    ],
)
def test_internal_addresses_are_refused_when_blocking_is_on(address, reason):
    with pytest.raises(TargetNotAllowed, match=reason):
        ensure_target_allowed(f"http://{address}:8090", block_private=True)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "192.168.1.20"])
def test_internal_addresses_pass_by_default(address):
    """Default off, and the default is the decision.

    The engine runs as a CLI on an operator's laptop as often as it runs as a worker, and the
    demo target is on loopback. A guard that breaks the quickstart is a guard that gets
    disabled wholesale, taking the metadata protection with it.
    """
    ensure_target_allowed(f"http://{address}:8090")


def test_public_addresses_always_pass():
    ensure_target_allowed("https://93.184.216.34/api", block_private=True)


# ---------------------------------------------------------------------------------
# the guard is on the path that actually builds an adapter
# ---------------------------------------------------------------------------------


def test_building_an_adapter_for_a_metadata_url_is_refused():
    """Enforced at the one place a config becomes something that can send traffic.

    A check at the call sites is a check someone eventually adds a call site around.
    """
    with pytest.raises(TargetNotAllowed, match="metadata"):
        build_adapter({"base_url": "http://169.254.169.254", "adapter_type": "rest_generic"})


def test_building_an_adapter_for_the_demo_target_still_works():
    adapter = build_adapter(
        {"base_url": "http://127.0.0.1:8090", "adapter_type": "rest_agentshield"}
    )
    assert adapter.adapter_type == "rest_agentshield"


def test_blocking_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_BLOCK_PRIVATE_TARGETS", "1")
    with pytest.raises(TargetNotAllowed, match="loopback"):
        build_adapter({"base_url": "http://127.0.0.1:8090", "adapter_type": "rest_generic"})

    monkeypatch.setenv("AGENTSHIELD_BLOCK_PRIVATE_TARGETS", "0")
    build_adapter({"base_url": "http://127.0.0.1:8090", "adapter_type": "rest_generic"})

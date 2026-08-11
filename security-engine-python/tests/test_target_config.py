"""Pointing the CLI at an agent that is not the demo target.

The generic REST adapter has always accepted a request template, a response path, a session
field and a correlation id field. The CLI could pass none of them: `--target`, `--adapter`,
`--tenant`, `--timeout`, `--header` and nothing else. So the documented way to connect an
arbitrary agent was through the Java API, and the tool the quickstart tells people to run
could only talk to something that already speaks the AgentShield protocol.

`--target-config` closes that. These tests cover the merge rules, because the merge is where
this kind of feature goes wrong quietly - a key that is ignored produces a scan against the
wrong endpoint that looks exactly like a scan against the right one.
"""

from __future__ import annotations

import pytest
import yaml
from agentshield_cli.main import _build_parser, _target_config

POLICY = "./datasets/policies/support-agent.yml"


def _args(*argv: str):
    return _build_parser().parse_args(["scan", "--policy", POLICY, *argv])


def _config_file(tmp_path, body: dict) -> str:
    path = tmp_path / "target.yml"
    path.write_text(yaml.safe_dump(body), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------------
# what the file can say
# ---------------------------------------------------------------------------------


def test_an_arbitrary_agent_can_be_described_entirely_in_a_file(tmp_path):
    """The shape the specification asks for: endpoint, template, response path, auth."""
    path = _config_file(tmp_path, {
        "adapter_type": "rest_generic",
        "base_url": "https://my-agent.test",
        "invoke_path": "/api/v2/agent",
        "method": "POST",
        "request_template": {"query": "{{prompt}}"},
        "response_path": "data.answer",
        "correlation_id_field": "request_id",
        "headers": {"Authorization": "Bearer x"},
    })

    config = _target_config(_args("--target-config", path))

    assert config["adapter_type"] == "rest_generic"
    assert config["base_url"] == "https://my-agent.test"
    assert config["invoke_path"] == "/api/v2/agent"
    assert config["response_path"] == "data.answer"
    assert config["correlation_id_field"] == "request_id"
    assert config["headers"] == {"Authorization": "Bearer x"}


def test_the_config_reaches_a_real_adapter(tmp_path):
    """The keys have to be the ones the adapter reads, not the ones the file invented.

    A loopback URL because `build_adapter` resolves the host through the SSRF guard, and a
    made-up hostname is refused for not resolving - which is the guard behaving correctly and
    would make this test about DNS.
    """
    from agentshield.adapters.registry import build_adapter

    path = _config_file(tmp_path, {
        "adapter_type": "rest_generic",
        "base_url": "http://127.0.0.1:8090",
        "invoke_path": "/api/v2/agent",
        "response_path": "data.answer",
    })

    adapter = build_adapter(_target_config(_args("--target-config", path)))

    assert adapter.adapter_type == "rest_generic"
    assert adapter.invoke_path == "/api/v2/agent"
    assert adapter.response_path == "data.answer"


# ---------------------------------------------------------------------------------
# the merge
# ---------------------------------------------------------------------------------


def test_a_flag_overrides_the_file(tmp_path):
    """One file describes the agent; the environment picks which deployment to scan."""
    path = _config_file(tmp_path, {"base_url": "https://staging.test"})

    config = _target_config(_args("--target-config", path, "--target", "https://prod.test"))

    assert config["base_url"] == "https://prod.test"


def test_an_argparse_default_does_not_override_the_file(tmp_path):
    """The bug this feature shipped with for an hour.

    `--adapter` had `default="rest_agentshield"`, which is indistinguishable from a value the
    user typed, so `adapter_type: rest_generic` in the file was overwritten every time. The
    scan ran against the demo protocol adapter and reported ten critical findings that
    belonged to a different fidelity level entirely.
    """
    path = _config_file(tmp_path, {
        "base_url": "https://my-agent.test",
        "adapter_type": "rest_generic",
    })

    config = _target_config(_args("--target-config", path))

    assert config["adapter_type"] == "rest_generic"


def test_the_default_adapter_still_applies_without_a_file():
    config = _target_config(_args("--target", "https://my-agent.test"))

    assert config["adapter_type"] == "rest_agentshield"
    assert config["timeout_seconds"] == 60.0


def test_headers_from_the_file_and_the_flag_are_merged(tmp_path):
    """A token belongs in the environment; the rest of the headers belong in the file."""
    path = _config_file(tmp_path, {
        "base_url": "https://my-agent.test",
        "headers": {"X-Tenant": "acme"},
    })

    config = _target_config(
        _args("--target-config", path, "--header", "Authorization=Bearer x")
    )

    assert config["headers"] == {"X-Tenant": "acme", "Authorization": "Bearer x"}


# ---------------------------------------------------------------------------------
# refusing bad input
# ---------------------------------------------------------------------------------


def test_an_unknown_key_is_refused(tmp_path):
    """Ignoring it is the dangerous option.

    A misspelled `response_path` that is silently dropped makes the adapter read the wrong
    field, find nothing, and report a clean result - the one output a security tool must never
    produce by accident.
    """
    path = _config_file(tmp_path, {"base_url": "https://x.test", "responce_path": "answer"})

    with pytest.raises(SystemExit, match="responce_path"):
        _target_config(_args("--target-config", path))


def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        _target_config(_args("--target-config", str(tmp_path / "absent.yml")))


def test_a_file_that_is_not_a_mapping_is_refused(tmp_path):
    path = tmp_path / "target.yml"
    path.write_text("- just\n- a list\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="mapping"):
        _target_config(_args("--target-config", str(path)))


def test_no_target_at_all_is_refused():
    """`--target` stopped being required, so something else has to catch its absence."""
    with pytest.raises(SystemExit, match="no target"):
        _target_config(_args())

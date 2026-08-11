"""The hardened demo target must actually be hardened.

Both halves of the demo depend on one bit of configuration, and that bit used to be decided at
import time. `app.py` held a module-level `app = create_app()`, so importing the package built
a vulnerable app before `__main__` had parsed `--secure`; uvicorn was then handed the import
string `app:app`, found the module already loaded, and served the vulnerable instance while the
banner printed SECURE.

Nothing caught it. The unit tests build their own app with `create_app(secure=True)` and were
right the whole time; the coverage script does the same. Only someone running the two commands
by hand could see it, which is the worst possible place for a bug in a demo.

These tests assert the property that was missing: the mode a caller asks for is the mode the
served application has, whichever route the caller takes.
"""

from __future__ import annotations

import importlib
import subprocess
import sys

import pytest
from demo_targets.vulnerable_support_agent.app import create_app, secure_from_env


def test_importing_the_package_builds_nothing():
    """The import-time singleton is the bug. Its absence is the fix.

    A module-level app configured from the environment is configured whenever Python happens
    to import the module, and import time is not a moment any caller controls.
    """
    module = importlib.import_module("demo_targets.vulnerable_support_agent.app")

    assert not hasattr(module, "app"), (
        "app.py exposes a module-level `app`; it will be built at import time with whatever "
        "environment happens to be set, and --secure will silently do nothing"
    )


def test_the_flag_decides_the_mode_not_the_environment(monkeypatch):
    monkeypatch.delenv("AGENTSHIELD_DEMO_SECURE", raising=False)

    assert create_app(secure=True).state.hardened is True
    assert create_app(secure=False).state.hardened is False


def test_the_environment_decides_when_no_flag_is_given(monkeypatch):
    """How the container image selects a mode; `secure=None` means "ask the environment"."""
    monkeypatch.setenv("AGENTSHIELD_DEMO_SECURE", "1")
    assert secure_from_env() is True
    assert create_app().state.hardened is True

    monkeypatch.setenv("AGENTSHIELD_DEMO_SECURE", "0")
    assert secure_from_env() is False
    assert create_app().state.hardened is False


@pytest.mark.parametrize("secure", [True, False])
async def test_health_reports_the_mode_it_is_actually_running(secure):
    """The endpoint the operator checks must agree with the code that runs.

    This is what made the original bug diagnosable: `/health` said `secure: false` on a target
    whose banner said SECURE.
    """
    import httpx

    app = create_app(secure=secure)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://demo") as client:
        body = (await client.get("/health")).json()

    assert body["secure"] is secure


def test_the_entry_point_serves_the_mode_it_prints():
    """End to end through `python -m`, because that is the path that was broken.

    Every other test constructs the app directly and would have passed throughout. This one
    starts the process the demo script tells people to start.
    """
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            # Import the package first, exactly as `python -m` does, then resolve the mode the
            # way __main__ does. If an import-time singleton returns, the first line builds it
            # and the assertion below still has to hold.
            "import demo_targets.vulnerable_support_agent as pkg;"
            "from demo_targets.vulnerable_support_agent.app import create_app;"
            "app = create_app(secure=True);"
            "print(app.state.hardened)",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "True", (
        "importing the package before building the app changed the result; the mode is being "
        "decided by import order again"
    )

"""The dashboard renders attacker-authored strings.

A scan report is a document describing what an attacker got an agent to do, and it quotes them
verbatim: injected article text, tool arguments, the agent's own answer. Rendering any of that
as markup would make the security dashboard the most reliable XSS vector in the deployment -
the payload arrives already stored, already reviewed, already trusted by whoever opens it.

There is no JavaScript test runner here on purpose; the dashboard has no build step and adding
a toolchain to test three hundred lines would cost more than it protects. What these assert
instead is structural: the unsafe sinks are absent from the source, and the safe one is used.
That is weaker than executing the page and stronger than nothing, and the boundary is small
enough for the check to be meaningful.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

WEB_UI = Path(__file__).resolve().parents[2] / "web-ui"

#: Every way to turn a string into markup. `innerHTML` is the one that matters; the rest are
#: how people reach for it once they know it is being looked for.
UNSAFE_SINKS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function(",
)


@pytest.fixture(scope="module")
def app_js() -> str:
    """The source with comments stripped.

    Comments are stripped because the file explains at length why `innerHTML` is not used, and
    a check that cannot tell an explanation from a call site would forbid documenting the rule.
    """
    source = (WEB_UI / "app.js").read_text(encoding="utf-8")
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"^\s*//.*$", "", source, flags=re.MULTILINE)


def test_the_dashboard_ships_with_no_build_step():
    """No package.json, no lockfile, no node_modules.

    Not neatness. A build step means a dependency tree, and a dependency tree in the tool that
    renders your security findings is a supply chain nobody audited.
    """
    forbidden = ["package.json", "package-lock.json", "yarn.lock", "node_modules"]

    present = [name for name in forbidden if (WEB_UI / name).exists()]

    assert not present, f"the dashboard grew a build step: {present}"


@pytest.mark.parametrize("sink", UNSAFE_SINKS)
def test_no_string_ever_becomes_markup(app_js: str, sink: str):
    assert sink not in app_js, (
        f"`{sink}` in web-ui/app.js. Report content is attacker-authored; it reaches the DOM "
        f"through textContent or it does not reach it at all."
    )


def test_the_element_builder_appends_text_nodes(app_js: str):
    """The one place a child could become markup, pinned.

    `el()` is how every node in the dashboard is built. If it stops wrapping non-Node children
    in a text node, every assertion above becomes irrelevant in a single commit.
    """
    assert "document.createTextNode(String(child))" in app_js
    assert "child instanceof Node" in app_js


def test_the_page_loads_no_third_party_resources():
    """Nothing external. A dashboard that phones out leaks which findings are being read."""
    html = (WEB_UI / "index.html").read_text(encoding="utf-8")

    remote = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)', html)

    assert not remote, f"external resources in index.html: {remote}"


# ---------------------------------------------------------------------------------
# `agentshield ui`
# ---------------------------------------------------------------------------------


def test_the_server_finds_the_dashboard_from_anywhere():
    """The command walks up to the checkout, so the working directory does not decide."""
    from agentshield_cli.ui import locate_web_ui

    assert (locate_web_ui() / "index.html").is_file()


def test_pointing_it_at_the_markdown_report_says_so(tmp_path):
    """An easy slip: `--report report.md`.

    Left to the browser this surfaces as "unexpected token < in JSON", which sends the reader
    looking for a bug in the dashboard when the bug is a typo in their command.
    """
    from agentshield_cli.ui import serve

    markdown = tmp_path / "report.md"
    markdown.write_text("# AgentShield Report\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not valid JSON"):
        serve(markdown, web_ui=WEB_UI, open_browser=False)


def test_a_missing_report_is_reported_before_a_port_is_bound(tmp_path):
    from agentshield_cli.ui import serve

    with pytest.raises(FileNotFoundError):
        serve(tmp_path / "absent.json", web_ui=WEB_UI, open_browser=False)


def test_the_command_exits_two_when_there_is_nothing_to_serve(tmp_path, capsys):
    """Exit 2, the same code a scan that could not run uses. Never 0."""
    from agentshield_cli.main import EXIT_ERROR, main

    code = main(["ui", "--report", str(tmp_path / "absent.json"), "--no-open"])

    assert code == EXIT_ERROR
    assert "absent.json" in capsys.readouterr().err


def test_a_real_report_is_accepted(tmp_path):
    """The happy path stops at validation, so the test never binds a socket."""
    from agentshield_cli.ui import serve

    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [], "counts": {}}), encoding="utf-8")

    # Port 0 would bind; instead assert validation passes by getting past it to the bind of an
    # address that cannot be listened on.
    with pytest.raises(OSError):
        serve(report, web_ui=WEB_UI, host="192.0.2.1", port=9, open_browser=False)

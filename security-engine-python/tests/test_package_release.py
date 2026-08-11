"""The archive check, and the leak it exists to stop.

`git archive` exports tracked files, so `.gitignore` already keeps `.env` out of a tarball
built the right way. The leak this guards is the tarball built the wrong way: zipping the
working directory picks up a `.env` holding live credentials that `git status` never mentions,
and the first anyone knows is when the recipient opens it.

So the packaging path has a check, and the check has tests. A guard nobody has seen fail is a
guard nobody knows the shape of.
"""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

package_release = pytest.importorskip("package_release")

#: Shaped like the real thing and belonging to nobody. Every one is assembled at runtime so
#: the literal never appears in the file.
#:
#: Two of these were written out in full at first, and `package_release.py` then refused to
#: package its own repository - the guard reporting its own test data as a leak, with
#: "rotate anything it exposed" underneath. GitHub's secret scanning would have said the same
#: thing about a public repository. A test for a secret scanner has to be the one file that
#: cannot trip one.
FAKE_ANTHROPIC_KEY = "sk-ant-" + "a1b2c3d4e5" * 4
FAKE_LANGFUSE_SECRET = "sk-lf-" + "0f1e2d3c4b" * 3
FAKE_AWS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_PRIVATE_KEY = "-----BEGIN RSA " + "PRIVATE KEY-----" + chr(10) + "MIIE" + chr(10)


def _archive(tmp_path: Path, files: dict[str, str]) -> Path:
    path = tmp_path / "release.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name, body in files.items():
            data = body.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def test_a_clean_archive_passes(tmp_path):
    archive = _archive(tmp_path, {
        "agentshield/README.md": "# AgentShield\n",
        "agentshield/main.py": "print('hello')\n",
    })

    assert package_release.inspect(archive) == []


def test_a_dotenv_is_refused_whatever_it_contains(tmp_path):
    """By name, before anything is read.

    An empty `.env` is still a mistake in a release archive: the next person to build one will
    have filled it in.
    """
    archive = _archive(tmp_path, {"agentshield/.env": "\n"})

    problems = package_release.inspect(archive)

    assert problems and "must never be packaged" in problems[0]


def test_the_committed_template_is_not_mistaken_for_a_dotenv(tmp_path):
    """`.env.example` is the one that is supposed to ship."""
    archive = _archive(tmp_path, {"agentshield/.env.example": "ANTHROPIC_API_KEY=\n"})

    assert package_release.inspect(archive) == []


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("Anthropic", FAKE_ANTHROPIC_KEY),
        ("Langfuse", FAKE_LANGFUSE_SECRET),
        ("AWS", FAKE_AWS_KEY_ID),
        ("private key", FAKE_PRIVATE_KEY),
    ],
)
def test_a_credential_anywhere_in_the_archive_is_found(tmp_path, label, value):
    """Not only in `.env`. A key pasted into a README or a test fixture ships just as far."""
    archive = _archive(tmp_path, {"agentshield/docs/notes.md": f"use {value} to authenticate\n"})

    problems = package_release.inspect(archive)

    assert problems, f"a {label} credential passed the check"


def test_the_report_never_prints_the_value(tmp_path):
    """A report that quotes the secret has leaked it into a terminal, a log and a scrollback."""
    archive = _archive(tmp_path, {"agentshield/x.md": FAKE_ANTHROPIC_KEY})

    problems = package_release.inspect(archive)

    assert problems
    joined = " ".join(problems)
    assert FAKE_ANTHROPIC_KEY not in joined
    assert "characters" in joined, "the report should describe the match without quoting it"


def test_the_words_api_key_and_token_are_not_enough_to_fail(tmp_path):
    """The check is about values, never vocabulary.

    This repository is a security tool: it says `api_key` and `token` constantly, in policy
    files, evaluator names and documentation. A check that fired on those would be switched
    off within a week, and then it would catch nothing at all.
    """
    archive = _archive(tmp_path, {
        "agentshield/policy.yml": "sensitive_patterns:\n  - name: api-key\n    regex: SECRET_\n",
        "agentshield/notes.md": "The CI token header is X-AgentShield-Token.\n",
    })

    assert package_release.inspect(archive) == []


def test_binary_members_are_skipped(tmp_path):
    """A jar cannot hold a key in a form this would catch, and unpacking every one is slow."""
    archive = _archive(tmp_path, {"agentshield/lib.jar": FAKE_ANTHROPIC_KEY})

    assert package_release.inspect(archive) == []

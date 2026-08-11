#!/usr/bin/env python3
"""Build a release archive, and refuse to ship one with credentials in it.

    python scripts/package_release.py
    python scripts/package_release.py --ref v1.0.0 --output dist/agentshield.tar.gz

`git archive` exports tracked files only, so `.gitignore` already keeps `.env`, the virtualenv
and the IDE directory out. That is not the failure this guards against. The failure is zipping
the working directory: `.env` sits beside the source, `git status` says nothing about it, and
the archive carries live credentials to whoever asked for the code. Rotating the key is the
only remedy after the fact, so the packaging path is made safe and given a check.

The check is the point. Producing a clean tarball is one command; proving it is clean is what
stops the next person from sending the wrong one.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Shapes that mean "this is a credential", not "this mentions credentials". Deliberately about
#: the *value*: the repository is full of the words `api_key` and `token` because it is a
#: security tool, and a check that fired on those would be turned off within a week.
SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("Anthropic API key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("OpenAI API key", r"\bsk-[A-Za-z0-9]{32,}"),
    ("Langfuse public key", r"\bpk-lf-[A-Za-z0-9\-]{20,}"),
    ("Langfuse secret key", r"\bsk-lf-[A-Za-z0-9\-]{20,}"),
    ("AWS access key id", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    ("private key block", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

#: Files that must never appear, whatever they contain.
FORBIDDEN_NAMES = (".env", ".env.local", ".env.prod", "id_rsa", "credentials")

#: Text files worth scanning. A wheel or a PNG cannot hold a key in a form this would catch,
#: and decompressing every binary to find out would make the check slow enough to skip.
TEXT_SUFFIXES = {
    "", ".py", ".java", ".kts", ".gradle", ".md", ".yml", ".yaml", ".json", ".toml",
    ".txt", ".sql", ".sh", ".js", ".css", ".html", ".cfg", ".ini", ".properties", ".tf",
}

EXIT_OK = 0
EXIT_UNSAFE = 1
EXIT_ERROR = 2


def build(ref: str, output: Path) -> Path:
    """Produce the archive with `git archive`, which exports the commit and never the tree."""
    output.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "archive", "--format=tar.gz", "--prefix=agentshield/", "-o", str(output), ref],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git archive failed: {result.stderr.strip()}")
    return output


def inspect(archive: Path) -> list[str]:
    """Every reason this archive must not be sent."""
    problems: list[str] = []
    compiled = [(label, re.compile(pattern)) for label, pattern in SECRET_PATTERNS]

    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue

            name = Path(member.name).name
            if name in FORBIDDEN_NAMES:
                problems.append(f"{member.name}: must never be packaged")
                continue

            if Path(member.name).suffix.lower() not in TEXT_SUFFIXES:
                continue
            # A key is short. Anything large enough to matter here is data, and reading a
            # 50MB dataset line by line to find a token that cannot be in it is wasted time.
            if member.size > 2_000_000:
                continue

            handle = tar.extractfile(member)
            if handle is None:
                continue
            body = handle.read().decode("utf-8", errors="ignore")

            for label, pattern in compiled:
                match = pattern.search(body)
                if match:
                    # The value is never printed. A report that quotes the secret has leaked it
                    # into a terminal, a CI log and a scrollback buffer.
                    problems.append(
                        f"{member.name}: looks like a {label} "
                        f"({len(match.group(0))} characters, at offset {match.start()})"
                    )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="HEAD", help="commit, tag or branch to package")
    parser.add_argument(
        "--output", default="dist/agentshield.tar.gz", help="where to write the archive"
    )
    parser.add_argument(
        "--keep-unsafe",
        action="store_true",
        help="do not delete an archive that failed the check (for debugging it)",
    )
    args = parser.parse_args(argv)

    output = (ROOT / args.output).resolve()
    try:
        build(args.ref, output)
    except RuntimeError as exc:
        print(f"package: {exc}", file=sys.stderr)
        return EXIT_ERROR

    problems = inspect(output)
    if problems:
        print(f"{output.name} is NOT safe to send:\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        if not args.keep_unsafe:
            # Deleted, because the failure mode is somebody sending it anyway. An archive that
            # failed this check and still exists on disk will eventually be attached to an
            # email by whoever is in a hurry.
            output.unlink(missing_ok=True)
            print(f"\n{output.name} deleted. Rotate anything it exposed.", file=sys.stderr)
        return EXIT_UNSAFE

    size = output.stat().st_size / 1_048_576
    print(f"{output.relative_to(ROOT)}  {size:.1f} MB from {args.ref}")
    print("No credential-shaped values found. Safe to send.")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

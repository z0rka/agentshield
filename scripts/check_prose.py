#!/usr/bin/env python3
"""House-style check for comments and documentation.

    python scripts/check_prose.py

Linters cover code. Nothing covers the prose around it, which is where a codebase drifts into
sounding like several different people, or like one person with a tic. Two things are checked:

* characters the house style bans outright (em-dashes);
* phrases that are fine once and grating on the fortieth repeat. These are capped by
  frequency, not forbidden, because the word is rarely the problem.

Thresholds are per repository, not per file. Raise one only if the extra uses genuinely earn
their place.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SUFFIXES = {".java", ".py", ".md", ".yml", ".yaml", ".sql", ".toml", ".kts"}
SKIP_PARTS = {".venv", ".git", ".idea", ".claude", "artifacts", "node_modules", "build", "__pycache__"}

BANNED_CHARS = {
    "—": "em-dash (use a hyphen)",
    "–": "en-dash (use a hyphen, except in numeric ranges)",
}

# Numeric ranges are the one place an en-dash is correct.
NUMERIC_RANGE = re.compile(r"\d\s*–\s*\d")

# Phrase -> how many uses the repository tolerates.
#
# These are drift alarms, not limits to write against. The current counts sit a little under
# each budget; the point is to notice a jump to double, which is what a tic looks like. If a
# budget is hit, reword the weakest few uses before raising it - and if raising it is genuinely
# right, say why in the commit.
PHRASE_BUDGET = {
    "rather than": 35,
    "instead of": 45,
    "deliberately": 20,
    "it is worth noting": 0,
    "it should be noted": 0,
    "importantly": 2,
    "in essence": 0,
    "at its core": 0,
    "leverage": 3,
    "seamless": 0,
    "robust": 6,
    "comprehensive": 4,
    "that is what lets": 2,
    "which is exactly": 3,
}

# A TODO nobody owns is a TODO nobody does.
UNOWNED_TODO = re.compile(r"\b(TODO|FIXME|XXX)\b(?!\s*[(\[:]?\s*(#\d|[A-Z]{2,}-\d|@?\w+\s*\)))")

# Constructions budgeted *per file* instead of across the repository.
#
# A phrase used thirty times across three hundred files is a vocabulary. The same construction
# fourteen times in one document is a writer on autopilot, and it reads that way. The
# antithesis - "X, not Y" - is the one that runs away, because it is the easiest sentence to
# reach for when explaining a decision and it flattens every explanation into one shape. Two or
# three per document land well. Fourteen is a tic.
#
# Counted per file so a long document is not punished for being long. Density is what a reader
# notices.
PER_FILE_PATTERNS = {
    re.compile(r",\s(?:not|never)\s"): (6, 'antithesis ("X, not Y")'),
}


#: This file necessarily contains every string it bans. Checking it would be a permanent
#: false positive, so it is the one exclusion.
SELF = Path(__file__).resolve()


def files() -> list[Path]:
    found = []
    for path in ROOT.rglob("*"):
        if path.suffix not in SUFFIXES or not path.is_file():
            continue
        if SKIP_PARTS & set(path.parts) or path.resolve() == SELF:
            continue
        found.append(path)
    return sorted(found)


def executable_bit_problems() -> list[str]:
    """A file with a shebang must be executable in git's index, and nothing else should be.

    This lives here because it is the one repository-hygiene rule that *cannot* fail on the
    machine it is broken on. Windows has no executable bit, so a script committed from here
    lands as mode 100644, every local check stays green, and the Linux runner then reports
    `./gradlew: Permission denied` and eight ruff EXE001 errors. That is precisely how it was
    found.

    Read from `git ls-files -s`, never from the filesystem: the index mode is what CI checks
    out, and it is the only version of the truth that exists on both platforms.
    """
    import subprocess

    listing = subprocess.run(
        ["git", "ls-files", "-s"], capture_output=True, text=True, check=False, cwd=ROOT
    )
    if listing.returncode != 0:
        return []  # not a git repository yet; nothing to check rather than a false failure

    problems = []
    for line in listing.stdout.splitlines():
        mode, _, _, relative = line.split(maxsplit=3)
        path = ROOT / relative
        if not path.is_file():
            continue
        try:
            shebang = path.open("rb").readline().startswith(b"#!")
        except OSError:
            continue
        if shebang and mode != "100755":
            problems.append(
                f"{relative}: has a shebang but is mode {mode}; "
                f"run `git update-index --chmod=+x {relative}` or CI cannot execute it"
            )
        elif not shebang and mode == "100755":
            problems.append(f"{relative}: is executable but has no shebang")
    return problems


def main() -> int:
    problems: list[str] = []
    phrase_hits: Counter[str] = Counter()
    phrase_examples: dict[str, str] = {}

    for path in files():
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(ROOT)

        for line_number, line in enumerate(text.splitlines(), 1):
            for char, reason in BANNED_CHARS.items():
                if char in line and not (char == "–" and NUMERIC_RANGE.search(line)):
                    problems.append(f"{relative}:{line_number}: {reason}")

            if UNOWNED_TODO.search(line):
                problems.append(
                    f"{relative}:{line_number}: TODO without an owner or ticket"
                )

        for pattern, (budget, label) in PER_FILE_PATTERNS.items():
            used = len(pattern.findall(text))
            if used > budget:
                problems.append(
                    f"{relative}: {label} used {used} times in one file, budget {budget}"
                )

        lowered = text.lower()
        for phrase in PHRASE_BUDGET:
            count = lowered.count(phrase)
            if count:
                phrase_hits[phrase] += count
                phrase_examples.setdefault(phrase, str(relative))

    for phrase, budget in PHRASE_BUDGET.items():
        used = phrase_hits[phrase]
        if used > budget:
            problems.append(
                f'"{phrase}" used {used} times, budget {budget} '
                f"(first in {phrase_examples[phrase]})"
            )

    problems.extend(executable_bit_problems())

    for problem in problems:
        print(problem)

    if problems:
        print(f"\n{len(problems)} style problem(s)")
        return 1

    print(f"prose style clean across {len(files())} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())

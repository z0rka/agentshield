"""Translate external suite names into engine attack categories."""

from agentshield.models.common import SUITE_ALIASES, AttackCategory


def categories_from_suites(suites: list[str]) -> set[AttackCategory] | None:
    if not suites:
        return None

    selected: set[AttackCategory] = set()
    for suite in suites:
        if suite.lower() in SUITE_ALIASES:
            selected.update(SUITE_ALIASES[suite.lower()])
        else:
            selected.add(AttackCategory(suite.upper()))
    return selected

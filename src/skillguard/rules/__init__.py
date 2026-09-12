"""Built-in SkillGuard rules."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from skillguard.models import Finding
from skillguard.rules import execution, prompt_injection, quality, secrets
from skillguard.rules.base import Rule, file_roles, iter_unique, rule_applies

ALL_RULES: list[Rule] = [
    *prompt_injection.RULES,
    *secrets.RULES,
    *execution.RULES,
    *quality.RULES,
]

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in ALL_RULES}

_FILE_CHECKERS: dict[str, Callable[[Path, str], list[Finding]]] = {
    **prompt_injection.CHECKERS,
    **secrets.CHECKERS,
    **execution.CHECKERS,
    **quality.CHECKERS,
}


def list_rules() -> list[Rule]:
    return list(ALL_RULES)


def run_file_rules(path: Path, content: str) -> list[Finding]:
    roles = file_roles(path)
    findings: list[Finding] = []
    for rule in ALL_RULES:
        if not rule_applies(rule, roles):
            continue
        checker = _FILE_CHECKERS.get(rule.id)
        if checker is None:
            continue
        findings.extend(checker(path, content))
    return iter_unique(findings)

"""Rule protocol and shared matching helpers."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from skillguard.models import Finding, Severity

MatchFn = Callable[[Path, str], list[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    description: str
    false_positives: str
    applies_to: frozenset[str]
    """File-role tags this rule accepts: skill_md, markdown, script, python,
    javascript, shell, env, text, skill. ``skill`` is a whole-skill check."""

    def finding(
        self,
        path: Path,
        line: int,
        evidence: str,
        *,
        description: str | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=severity or self.severity,
            title=self.title,
            description=description or self.description,
            file=str(path),
            line=max(1, line),
            evidence=_clip_evidence(evidence),
        )


def line_at(content: str, index: int) -> int:
    if index <= 0:
        return 1
    return content.count("\n", 0, index) + 1


def snippet(content: str, index: int) -> str:
    if index < 0:
        index = 0
    line_start = content.rfind("\n", 0, index) + 1
    line_end = content.find("\n", index)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end].rstrip("\r")


def _clip_evidence(text: str, limit: int = 200) -> str:
    collapsed = re.sub(r"[ \t]+", " ", text.strip())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3] + "..."


def search_regex(
    rule: Rule,
    path: Path,
    content: str,
    pattern: re.Pattern[str],
    *,
    skip: Callable[[re.Match[str], str], bool] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for match in pattern.finditer(content):
        start = match.start()
        if skip is not None and skip(match, content):
            continue
        findings.append(rule.finding(path, line_at(content, start), snippet(content, start)))
    return findings


_DEFENSE = re.compile(
    r"(?i)\b(?:never|do\s+not|don't|must\s+not|cannot|can't|no\s+jailbreak|"
    r"detect(?:ion)?|prevent(?:ion)?|protect(?:ion)?(?:\s+against)?|mitigat(?:e|ion)|"
    r"guardrail|content\s+filter|content\s+safety|model\s*armor|against|"
    r"untrusted|treat\s+(?:it|them|this)\s+as\s+data|not\s+an\s+action|"
    r"if\s+(?:the\s+)?(?:page|content|dom|text|browser)\s+contains|"
    r"for\s+example|as\s+an\s+example|an\s+example\s+of|example\s+below|"
    r"e\.g\.|quoted|anti-?pattern|do\s+not\s+use)\b"
)

_NEGATION_PREFIX = re.compile(
    r"(?i)\b(?:never|do\s+not|don't|must\s+not|cannot|can't|avoid|"
    r"forbid(?:den)?|deny)\b"
)


def nearby_text(content: str, index: int, *, before: int = 2, after: int = 1) -> str:
    """Return nearby lines so we can judge quotes, negation, and defense docs."""
    if index < 0:
        index = 0
    line_no = line_at(content, index)
    lines = content.splitlines()
    start = max(0, line_no - 1 - before)
    end = min(len(lines), line_no + after)
    return "\n".join(lines[start:end])


def is_defense_or_negated(window: str) -> bool:
    return bool(_DEFENSE.search(window) or _NEGATION_PREFIX.search(window))


def file_roles(path: Path) -> set[str]:
    name = path.name
    suffix = path.suffix.lower()
    roles = {"text"}
    if name.upper() == "SKILL.MD":
        roles.update({"skill_md", "markdown"})
    if suffix in {".md", ".markdown"}:
        roles.add("markdown")
    if suffix in {".py"}:
        roles.update({"script", "python"})
    if suffix in {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}:
        roles.update({"script", "javascript"})
    if suffix in {".sh", ".bash", ".zsh"} or name.endswith(".sh"):
        roles.update({"script", "shell"})
    if suffix in {".ps1", ".psm1"}:
        roles.update({"script", "shell"})
    if name.lower().startswith(".env") or suffix == ".env":
        roles.add("env")
    if suffix in {".txt", ".rst", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg"}:
        roles.add("config")
    return roles


def rule_applies(rule: Rule, roles: set[str]) -> bool:
    if "skill" in rule.applies_to:
        return False
    if "any" in rule.applies_to:
        return True
    return bool(rule.applies_to & roles)


def iter_unique(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out

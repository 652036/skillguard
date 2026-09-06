"""Supply-chain and skill-quality detectors."""

from __future__ import annotations

import re
from pathlib import Path

from skillguard.discover import SkillRoot
from skillguard.models import Finding, Severity
from skillguard.rules.base import Rule, line_at, snippet

SG301 = Rule(
    id="SG301",
    severity=Severity.MEDIUM,
    title="Scripts present but no license",
    description="The skill ships executable scripts but has no LICENSE / COPYING file.",
    false_positives="A license named in SKILL.md frontmatter only (no file) still flags; add a LICENSE file.",
    applies_to=frozenset({"skill"}),
)

SG302 = Rule(
    id="SG302",
    severity=Severity.MEDIUM,
    title="SKILL.md missing name or description",
    description="Agent Skills require YAML frontmatter with name and description so hosts can index them safely.",
    false_positives="A title heading is not a substitute for frontmatter fields.",
    applies_to=frozenset({"skill"}),
)

SG303 = Rule(
    id="SG303",
    severity=Severity.MEDIUM,
    title="Overly broad 'run any command'",
    description="The skill authorizes unconstrained shell / command execution instead of a narrow allowlist.",
    false_positives="Saying the human may run a *specific* command (pytest, git diff) is fine.",
    applies_to=frozenset({"skill_md", "markdown", "text"}),
)

SG304 = Rule(
    id="SG304",
    severity=Severity.MEDIUM,
    title="External URL in install / prerequisite steps",
    description=(
        "Install or prerequisite steps reach out to the network. Flagged for review; "
        "does not fail a default `--fail-on high` scan on its own."
    ),
    false_positives="Documentation links outside Install/Prerequisites/Setup sections are ignored.",
    applies_to=frozenset({"skill_md", "markdown"}),
)

SG305 = Rule(
    id="SG305",
    severity=Severity.HIGH,
    title="Oversized instruction file",
    description=(
        "An instruction / markdown file exceeds 1 MB. Padding has been used to hide "
        "stagers from scanners that skip large files (omnicogg)."
    ),
    false_positives="A genuine huge reference dump will also fail default --fail-on high.",
    applies_to=frozenset({"skill"}),
)

_FRONTMATTER = re.compile(r"^---\s*\n([\s\S]*?)\n---\s*(?:\n|$)", re.MULTILINE)
_FIELD = re.compile(r"(?im)^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.+)$")
_BROAD_CMD = re.compile(
    r"(?i)\brun\s+any\s+command\b"
    r"|\bexecute\s+arbitrary\s+commands?\b"
    r"|\byou\s+may\s+run\s+any\s+(?:shell\s+)?commands?\b"
    r"|\bno\s+restrictions?\s+on\s+commands?\b"
    r"|\brun\s+whatever\s+command\b"
    r"|\bany\s+command\s+the\s+user\s+asks\b"
    r"|\bunrestricted\s+(?:shell|command)\s+access\b",
)
_PREREQ_HEADER = re.compile(
    r"(?im)^#{1,4}\s+(prerequisites?|install(?:ation)?|setup|getting started|before you start)\b"
)
_URL = re.compile(r"https?://[^\s)\]>\"']+", re.IGNORECASE)
_SCRIPT_SUFFIXES = {
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
}
_LICENSE_NAMES = {
    "license",
    "license.txt",
    "license.md",
    "license.rst",
    "copying",
    "copying.txt",
    "unlicense",
}


def check_sg303(path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _BROAD_CMD.finditer(content):
        findings.append(SG303.finding(path, line_at(content, match.start()), snippet(content, match.start())))
    return findings


def check_sg304(path: Path, content: str) -> list[Finding]:
    headers = list(_PREREQ_HEADER.finditer(content))
    if not headers:
        return []
    findings: list[Finding] = []
    for i, header in enumerate(headers):
        start = header.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(content)
        section = content[start:end]
        for match in _URL.finditer(section):
            abs_idx = start + match.start()
            findings.append(SG304.finding(path, line_at(content, abs_idx), snippet(content, abs_idx)))
    return findings


_OVERSIZE_SUFFIXES = {".md", ".markdown", ".txt"}
_OVERSIZE_BYTES = 1_000_000


def check_skill_quality(skill: SkillRoot, files: list[Path], contents: dict[Path, str]) -> list[Finding]:
    findings: list[Finding] = []
    if skill.host_only:
        # Host instruction files are not Agent Skills — skip SG301/SG302.
        findings.extend(_oversized_instruction_files(files))
        return findings
    findings.extend(_missing_frontmatter(skill, contents))
    findings.extend(_scripts_without_license(skill, files))
    findings.extend(_oversized_instruction_files(files))
    return findings


def _oversized_instruction_files(files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        if path.suffix.lower() not in _OVERSIZE_SUFFIXES:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= _OVERSIZE_BYTES:
            continue
        findings.append(
            SG305.finding(
                path,
                1,
                f"{path.name} is {size} bytes (>{_OVERSIZE_BYTES})",
            )
        )
    return findings


def _missing_frontmatter(skill: SkillRoot, contents: dict[Path, str]) -> list[Finding]:
    if skill.skill_md is None:
        # Loose folder with no SKILL.md at all — report against the root.
        return [
            SG302.finding(
                skill.root / "SKILL.md",
                1,
                "no SKILL.md in this skill root",
                description="This folder has no SKILL.md, so hosts cannot load it as an Agent Skill.",
            )
        ]
    content = contents.get(skill.skill_md)
    if content is None:
        return [SG302.finding(skill.skill_md, 1, "SKILL.md could not be read")]
    fm = _FRONTMATTER.search(content)
    if not fm:
        return [SG302.finding(skill.skill_md, 1, "SKILL.md has no YAML frontmatter")]
    fields: dict[str, str] = {}
    for match in _FIELD.finditer(fm.group(1)):
        fields[match.group(1).lower()] = match.group(2).strip().strip("'\"")
    missing = [key for key in ("name", "description") if not fields.get(key)]
    if not missing:
        return []
    return [
        SG302.finding(
            skill.skill_md,
            line_at(content, fm.start()),
            f"frontmatter missing: {', '.join(missing)}",
        )
    ]


def _scripts_without_license(skill: SkillRoot, files: list[Path]) -> list[Finding]:
    scripts = [p for p in files if p.suffix.lower() in _SCRIPT_SUFFIXES]
    if not scripts:
        return []
    for path in files:
        if path.name.lower() in _LICENSE_NAMES or path.name.upper().startswith("LICENSE"):
            return []
    target = skill.skill_md or skill.root / "SKILL.md"
    return [
        SG301.finding(
            target,
            1,
            f"{len(scripts)} script(s) and no LICENSE file",
        )
    ]


RULES = [SG301, SG302, SG303, SG304, SG305]
CHECKERS = {
    "SG303": check_sg303,
    "SG304": check_sg304,
}

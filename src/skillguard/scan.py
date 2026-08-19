"""Orchestrate discovery + rules into a ScanResult."""

from __future__ import annotations

from pathlib import Path

from skillguard.discover import SkillRoot, discover_skills, iter_skill_files, read_text
from skillguard.models import ScanResult, sort_findings
from skillguard.rules import run_file_rules
from skillguard.rules.quality import check_skill_quality


def scan_path(path: Path | str) -> ScanResult:
    target = Path(path).expanduser()
    if not target.exists():
        raise FileNotFoundError(target)

    skills = discover_skills(target)
    result = ScanResult(path=str(target.resolve()), skills=[s.label for s in skills])

    lone_file = target if target.is_file() else None
    for skill in skills:
        _scan_skill(skill, result, lone_file=lone_file)
    result.findings = sort_findings(result.findings)
    return result


def _scan_skill(skill: SkillRoot, result: ScanResult, *, lone_file: Path | None) -> None:
    if lone_file is not None and lone_file.name.upper() != "SKILL.MD":
        files = [lone_file.resolve()]
    else:
        files = iter_skill_files(skill, lone_file)

    contents: dict[Path, str] = {}
    for file_path in files:
        text = read_text(file_path)
        if text is None:
            continue
        contents[file_path] = text
        result.files_scanned += 1
        result.findings.extend(run_file_rules(file_path, text))

    result.findings.extend(check_skill_quality(skill, list(contents), contents))

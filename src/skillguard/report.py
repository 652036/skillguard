"""Text and JSON renderers for ScanResult."""

from __future__ import annotations

import json

from skillguard.models import ScanResult, Severity

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_text(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"SkillGuard scan: {result.path}")
    lines.append(f"Skills found: {len(result.skills)}")
    for skill in result.skills:
        lines.append(f"  - {skill}")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Findings: {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    for finding in result.findings:
        badge = finding.severity.value.upper()
        loc = f"{finding.file}:{finding.line}"
        lines.append(f"[{badge}] {finding.rule_id}  {finding.title}")
        lines.append(f"  {loc}")
        if finding.evidence:
            lines.append(f"  {finding.evidence}")
        lines.append(f"  {finding.description}")
        lines.append("")

    counts = result.summary()
    parts = [f"{counts[s.value]} {s.value}" for s in _SEVERITY_ORDER if counts[s.value]]
    lines.append("Summary: " + ", ".join(parts))
    return "\n".join(lines) + "\n"

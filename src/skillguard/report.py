"""Text and JSON renderers for ScanResult."""

from __future__ import annotations

import json

from skillguard.i18n import Lang, rule_display, severity_label, t
from skillguard.models import ScanResult, Severity

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_text(result: ScanResult, lang: Lang = "en") -> str:
    lines: list[str] = []
    lines.append(t("scan_header", lang, path=result.path))
    lines.append(t("skills_found", lang, n=len(result.skills)))
    for skill in result.skills:
        lines.append(f"  - {skill}")
    lines.append(t("files_scanned", lang, n=result.files_scanned))
    lines.append(t("findings", lang, n=len(result.findings)))
    lines.append("")

    if not result.findings:
        lines.append(t("no_findings", lang))
        return "\n".join(lines) + "\n"

    for finding in result.findings:
        badge = severity_label(finding.severity.value, lang)
        loc = f"{finding.file}:{finding.line}"
        title, description = rule_display(
            finding.rule_id, finding.title, finding.description, lang
        )
        lines.append(f"[{badge}] {finding.rule_id}  {title}")
        lines.append(f"  {loc}")
        if finding.evidence:
            lines.append(f"  {finding.evidence}")
        lines.append(f"  {description}")
        lines.append("")

    counts = result.summary()
    parts = [
        f"{counts[s.value]} {severity_label(s.value, lang)}"
        for s in _SEVERITY_ORDER
        if counts[s.value]
    ]
    lines.append(t("summary", lang, parts=", ".join(parts)))
    return "\n".join(lines) + "\n"

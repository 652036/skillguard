"""Text, JSON, and SARIF renderers for ScanResult."""

from __future__ import annotations

import json
from pathlib import Path

from skillguard import __version__
from skillguard.i18n import Lang, rule_display, severity_label, t
from skillguard.models import Finding, ScanResult, Severity

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/652036/skillguard"
_HELP_URI = "https://github.com/652036/skillguard#rules"


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    """Render a ScanResult as SARIF 2.1.0 JSON."""
    payload = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillGuard",
                        "version": __version__,
                        "informationUri": _INFORMATION_URI,
                        "rules": _sarif_rules(result.findings),
                    }
                },
                "results": [_sarif_result(finding, result.path) for finding in result.findings],
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_rules(findings: list[Finding]) -> list[dict[str, object]]:
    seen: dict[str, Finding] = {}
    for finding in findings:
        seen.setdefault(finding.rule_id, finding)
    return [
        {
            "id": rule_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "helpUri": _HELP_URI,
        }
        for rule_id, finding in seen.items()
    ]


def _sarif_result(finding: Finding, scan_root: str) -> dict[str, object]:
    message = finding.title
    if finding.evidence:
        message = f"{finding.title}: {finding.evidence}"
    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(finding.file, scan_root)},
                    "region": {"startLine": finding.line},
                }
            }
        ],
        "properties": {"skillguard_severity": finding.severity.value},
    }


def _artifact_uri(file_path: str, scan_root: str) -> str:
    """Prefer a repo-relative POSIX path so GitHub code scanning can map files."""
    path = Path(file_path)
    root = Path(scan_root)
    for base in (root, root.parent):
        try:
            relative = path.relative_to(base)
        except ValueError:
            continue
        posix = relative.as_posix()
        if posix != ".":
            return posix
    return path.as_posix()


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

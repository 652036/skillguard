"""Shared data types for scan findings and results."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):  # noqa: UP042 - preserve the public Enum string representation
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def parse_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError as exc:
        allowed = ", ".join(s.value for s in Severity)
        raise ValueError(f"unknown severity {value!r}; expected one of: {allowed}") from exc


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    file: str
    line: int
    evidence: str

    def meets_threshold(self, fail_on: Severity) -> bool:
        return self.severity.rank >= fail_on.rank

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
        }


@dataclass
class ScanResult:
    path: str
    skills: list[str] = field(default_factory=list)
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def failing(self, fail_on: Severity) -> list[Finding]:
        return [f for f in self.findings if f.meets_threshold(fail_on)]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "skills": list(self.skills),
            "files_scanned": self.files_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary(),
        }


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, f.file, f.line, f.rule_id),
    )

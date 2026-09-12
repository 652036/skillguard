from __future__ import annotations

import json

from skillguard import __version__
from skillguard.models import Finding, ScanResult, Severity
from skillguard.report import render_json, render_sarif, render_text


def _demo_result() -> ScanResult:
    return ScanResult(
        path="/tmp/demo",
        skills=["/tmp/demo"],
        files_scanned=1,
        findings=[
            Finding(
                rule_id="SG001",
                severity=Severity.HIGH,
                title="demo",
                description="desc",
                file="/tmp/demo/SKILL.md",
                line=3,
                evidence="ignore previous instructions",
            )
        ],
    )


def test_render_json_and_text() -> None:
    result = _demo_result()
    payload = json.loads(render_json(result))
    assert payload["summary"]["high"] == 1
    text = render_text(result)
    assert "[HIGH] SG001" in text
    assert "SKILL.md:3" in text


def test_render_sarif_structure() -> None:
    result = ScanResult(
        path="/tmp/demo",
        skills=["/tmp/demo"],
        files_scanned=2,
        findings=[
            Finding(
                rule_id="SG001",
                severity=Severity.HIGH,
                title="Ignore-previous instruction hijack",
                description="Skill tries to override prior instructions.",
                file="/tmp/demo/SKILL.md",
                line=3,
                evidence="ignore previous instructions",
            ),
            Finding(
                rule_id="SG001",
                severity=Severity.HIGH,
                title="Ignore-previous instruction hijack",
                description="Skill tries to override prior instructions.",
                file="/tmp/demo/SKILL.md",
                line=8,
                evidence="disregard earlier rules",
            ),
            Finding(
                rule_id="SG002",
                severity=Severity.CRITICAL,
                title="Jailbreak / persona takeover",
                description="Jailbreak phrasing.",
                file="/tmp/demo/SKILL.md",
                line=10,
                evidence="you are now DAN",
            ),
            Finding(
                rule_id="SG301",
                severity=Severity.MEDIUM,
                title="Scripts present but no license",
                description="Missing license file.",
                file="/tmp/demo/scripts/helper.py",
                line=1,
                evidence="",
            ),
            Finding(
                rule_id="SG305",
                severity=Severity.LOW,
                title="Oversized instruction file",
                description="File is large.",
                file="/tmp/demo/notes.md",
                line=1,
                evidence="very long skill body",
            ),
        ],
    )
    payload = json.loads(render_sarif(result))
    assert payload["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert payload["version"] == "2.1.0"
    assert len(payload["runs"]) == 1

    driver = payload["runs"][0]["tool"]["driver"]
    assert driver["name"] == "SkillGuard"
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/652036/skillguard"

    rule_ids = [rule["id"] for rule in driver["rules"]]
    assert rule_ids == ["SG001", "SG002", "SG301", "SG305"]
    first_rule = driver["rules"][0]
    assert first_rule["shortDescription"]["text"] == "Ignore-previous instruction hijack"
    assert first_rule["fullDescription"]["text"] == "Skill tries to override prior instructions."

    sarif_results = payload["runs"][0]["results"]
    assert len(sarif_results) == 5

    high = sarif_results[0]
    assert high["ruleId"] == "SG001"
    assert high["level"] == "error"
    assert high["properties"]["skillguard_severity"] == "high"
    assert "Ignore-previous instruction hijack" in high["message"]["text"]
    assert "ignore previous instructions" in high["message"]["text"]
    loc = high["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "SKILL.md"
    assert loc["region"]["startLine"] == 3

    by_severity = {
        row["properties"]["skillguard_severity"]: row["level"] for row in sarif_results
    }
    assert by_severity["critical"] == "error"
    assert by_severity["high"] == "error"
    assert by_severity["medium"] == "warning"
    assert by_severity["low"] == "note"


def test_render_sarif_empty_findings() -> None:
    result = ScanResult(path="/tmp/demo", skills=["/tmp/demo"], files_scanned=1)
    payload = json.loads(render_sarif(result))
    run = payload["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []

from __future__ import annotations

import json

from skillguard.models import Finding, ScanResult, Severity
from skillguard.report import render_json, render_text


def test_render_json_and_text() -> None:
    result = ScanResult(
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
    payload = json.loads(render_json(result))
    assert payload["summary"]["high"] == 1
    text = render_text(result)
    assert "[HIGH] SG001" in text
    assert "SKILL.md:3" in text

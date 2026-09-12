"""Check the installed CLI in subprocesses, without executing scanned files."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def invoke(args: list[str], expected: int) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "skillguard", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    if result.returncode != expected:
        raise AssertionError(f"{args}: expected {expected}, got {result.returncode}\n{result.stderr}\n{result.stdout}")
    return result.stdout


def main() -> None:
    examples = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "examples"
    if "skillguard " not in invoke(["--version"], 0):
        raise AssertionError("Missing version output")
    for lang in ("en", "zh"):
        output = invoke(["rules", "--lang", lang], 0)
        if "SG001" not in output or "SG305" not in output:
            raise AssertionError(f"Missing rules in {lang} output")
    for name, expected in (("clean-review", 0), ("toxic-claw", 1), ("toxic-clickfix", 1)):
        for fmt in ("text", "json", "sarif"):
            output = invoke(["scan", str(examples / name), "--format", fmt], expected)
            if fmt == "json":
                findings = json.loads(output)["findings"]
                if bool(findings) != bool(expected):
                    raise AssertionError(f"Unexpected findings for {name}")
            elif fmt == "sarif":
                payload = json.loads(output)
                if payload["version"] != "2.1.0":
                    raise AssertionError("Unexpected SARIF version")
                if bool(payload["runs"][0]["results"]) != bool(expected):
                    raise AssertionError(f"Unexpected SARIF findings for {name}")
    print("12 CLI subprocess checks passed.")


if __name__ == "__main__":
    main()

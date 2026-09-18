"""Check that composite-action options remain literal shell arguments."""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ACTION = Path(__file__).resolve().parents[1] / "action.yml"
BASH = shutil.which("bash")


def _scan_script() -> str:
    """Read the final scan step without adding a YAML dependency."""
    step = ACTION.read_text(encoding="utf-8").split("    - name: Scan skills\n", 1)[1]
    block = step.split("      run: |\n", 1)[1]
    lines = []
    for line in block.splitlines(keepends=True):
        if line.strip() and not line.startswith("        "):
            break
        lines.append(line)
    return textwrap.dedent("".join(lines))


def test_action_run_blocks_do_not_interpolate_contexts() -> None:
    action = ACTION.read_text(encoding="utf-8")
    assert "${{" not in _scan_script()
    for line in action.splitlines():
        if line.lstrip().startswith("run:"):
            assert "${{" not in line
    for name in ("path", "fail-on", "disable", "enable"):
        env_name = "SKILLGUARD_" + name.upper().replace("-", "_")
        assert f"{env_name}: ${{{{ inputs.{name} }}}}" in action


@pytest.mark.skipif(BASH is None, reason="Bash required for composite-action tests")
@pytest.mark.parametrize("name", ["path", "fail-on", "disable", "enable"])
@pytest.mark.parametrize("value", ["literal $(printf expanded)", "literal `printf expanded`"])
def test_scan_inputs_are_not_shell_expanded(name: str, value: str, tmp_path: Path) -> None:
    inputs = {"path": ".", "fail-on": "high", "disable": "", "enable": ""}
    inputs[name] = value
    _assert_argv(inputs, tmp_path)


@pytest.mark.skipif(BASH is None, reason="Bash required for composite-action tests")
@pytest.mark.parametrize("options", [False, True])
def test_spaces_quotes_and_optional_rule_lists(tmp_path: Path, options: bool) -> None:
    inputs = {
        "path": 'skills with spaces and "quotes"', "fail-on": "high",
        "disable": "SG301,SG304" if options else "",
        "enable": "SG001,SG201" if options else "",
    }
    _assert_argv(inputs, tmp_path)


def _assert_argv(inputs: dict[str, str], tmp_path: Path) -> None:
    script = _scan_script()
    # Emulate expression rendering to demonstrate regressions in old run blocks.
    # Test strings only invoke printf; no external program or user data is accessed.
    for key, value in inputs.items():
        script = script.replace("${{ inputs." + key + " }}", value)
    capture = tmp_path / "arguments.bin"
    env = os.environ.copy()
    env["TEST_CAPTURE"] = str(capture)
    for key, value in inputs.items():
        env["SKILLGUARD_" + key.upper().replace("-", "_")] = value
    stub = 'skillguard() { printf "%s\\0" "$@" > "$TEST_CAPTURE"; }\n'
    subprocess.run(
        [str(BASH), "--noprofile", "--norc", "-e", "-u", "-o", "pipefail", "-c", stub + script],
        cwd=tmp_path, env=env, check=True, capture_output=True, timeout=5,
    )
    actual = capture.read_bytes().decode().split("\0")[:-1]
    expected = ["scan", inputs["path"], "--fail-on", inputs["fail-on"]]
    for key in ("disable", "enable"):
        if inputs[key]:
            expected.extend(["--" + key, inputs[key]])
    assert actual == expected

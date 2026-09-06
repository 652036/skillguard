from __future__ import annotations

from pathlib import Path

from skillguard.config import resolve_filter
from skillguard.rules import RULES_BY_ID


def test_disable_cli_drops_rule(tmp_path: Path) -> None:
    filt = resolve_filter(start=tmp_path, disable_cli="SG301,SG304")
    assert "SG301" not in filt.active
    assert "SG304" not in filt.active
    assert "SG001" in filt.active
    assert len(filt.active) == len(RULES_BY_ID) - 2


def test_enable_cli_is_allowlist(tmp_path: Path) -> None:
    filt = resolve_filter(start=tmp_path, enable_cli="SG001,SG201")
    assert filt.active == frozenset({"SG001", "SG201"})


def test_toml_disable(tmp_path: Path) -> None:
    (tmp_path / "skillguard.toml").write_text("disable = [\"SG301\"]\n", encoding="utf-8")
    skill = tmp_path / "skill"
    skill.mkdir()
    filt = resolve_filter(start=skill)
    assert "SG301" not in filt.active
    assert "SG001" in filt.active
    assert "skillguard.toml" in filt.source


def test_yaml_disable_list(tmp_path: Path) -> None:
    (tmp_path / ".skillguard.yml").write_text("disable:\n  - SG304\n", encoding="utf-8")
    filt = resolve_filter(start=tmp_path)
    assert "SG304" not in filt.active


def test_cli_disable_merges_file(tmp_path: Path) -> None:
    (tmp_path / "skillguard.toml").write_text("disable = [\"SG301\"]\n", encoding="utf-8")
    filt = resolve_filter(start=tmp_path, disable_cli="SG304")
    assert "SG301" not in filt.active
    assert "SG304" not in filt.active

from __future__ import annotations

from pathlib import Path

from skillguard.discover import SkillRoot
from skillguard.rules.quality import check_sg303, check_sg304, check_skill_quality


def test_broad_command_true_positive() -> None:
    assert check_sg303(Path("SKILL.md"), "You may run any command the user asks.\n")


def test_specific_command_true_negative() -> None:
    assert check_sg303(Path("SKILL.md"), "Run pytest in this repository.\n") == []


def test_external_url_in_prereq() -> None:
    text = "# Prerequisites\n\nInstall from https://example.com/tool\n"
    assert check_sg304(Path("SKILL.md"), text)


def test_external_url_in_docs_section_negative() -> None:
    text = "# Notes\n\nSee https://example.com/docs for the format.\n"
    assert check_sg304(Path("SKILL.md"), text) == []


def test_missing_frontmatter(tmp_path: Path) -> None:
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text("# Untitled\n", encoding="utf-8")
    skill = SkillRoot(root=tmp_path, skill_md=skill_md)
    findings = check_skill_quality(skill, [skill_md], {skill_md: skill_md.read_text(encoding="utf-8")})
    assert any(f.rule_id == "SG302" for f in findings)


def test_scripts_without_license(tmp_path: Path) -> None:
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text("---\nname: x\ndescription: y\n---\n", encoding="utf-8")
    script = tmp_path / "run.sh"
    script.write_text("echo hi\n", encoding="utf-8")
    skill = SkillRoot(root=tmp_path, skill_md=skill_md)
    findings = check_skill_quality(
        skill,
        [skill_md, script],
        {skill_md: skill_md.read_text(encoding="utf-8")},
    )
    assert any(f.rule_id == "SG301" for f in findings)


def test_scripts_with_license_ok(tmp_path: Path) -> None:
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text("---\nname: x\ndescription: y\n---\n", encoding="utf-8")
    script = tmp_path / "run.sh"
    script.write_text("echo hi\n", encoding="utf-8")
    license_file = tmp_path / "LICENSE"
    license_file.write_text("Apache-2.0\n", encoding="utf-8")
    skill = SkillRoot(root=tmp_path, skill_md=skill_md)
    findings = check_skill_quality(
        skill,
        [skill_md, script, license_file],
        {skill_md: skill_md.read_text(encoding="utf-8")},
    )
    assert not any(f.rule_id == "SG301" for f in findings)


def test_oversized_instruction_file(tmp_path: Path) -> None:
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text("---\nname: x\ndescription: y\n---\n", encoding="utf-8")
    padded = tmp_path / "README.md"
    padded.write_bytes(b"# pad\n" + b"A" * 1_000_100)
    skill = SkillRoot(root=tmp_path, skill_md=skill_md)
    findings = check_skill_quality(
        skill,
        [skill_md, padded],
        {skill_md: skill_md.read_text(encoding="utf-8")},
    )
    assert any(f.rule_id == "SG305" for f in findings)


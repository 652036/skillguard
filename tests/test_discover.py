from __future__ import annotations

from pathlib import Path

from skillguard.discover import discover_skills, iter_skill_files, read_text


def test_discovers_nested_skills(tmp_path: Path) -> None:
    outer = tmp_path / "outer"
    inner = outer / "nested" / "inner"
    outer.mkdir()
    inner.mkdir(parents=True)
    (outer / "SKILL.md").write_text("---\nname: outer\ndescription: o\n---\n", encoding="utf-8")
    (inner / "SKILL.md").write_text("---\nname: inner\ndescription: i\n---\n", encoding="utf-8")
    (outer / "notes.md").write_text("# outer notes\n", encoding="utf-8")
    (inner / "notes.md").write_text("# inner notes\n", encoding="utf-8")

    skills = discover_skills(tmp_path)
    roots = {s.root.resolve() for s in skills}
    assert outer.resolve() in roots
    assert inner.resolve() in roots
    assert len(skills) == 2

    outer_skill = next(s for s in skills if s.root.resolve() == outer.resolve())
    outer_files = {p.name for p in iter_skill_files(outer_skill)}
    assert "notes.md" in outer_files
    assert "SKILL.md" in outer_files
    # nested skill files must not be attributed to the parent
    assert not any(p.resolve() == (inner / "notes.md").resolve() for p in iter_skill_files(outer_skill))


def test_discovers_both_examples(examples_dir: Path) -> None:
    skills = discover_skills(examples_dir)
    names = {s.root.name for s in skills}
    assert names == {"clean-review", "toxic-claw", "toxic-clickfix"}


def test_skill_md_file_is_one_skill(clean_skill: Path) -> None:
    skills = discover_skills(clean_skill / "SKILL.md")
    assert len(skills) == 1
    assert skills[0].skill_md is not None
    assert skills[0].skill_md.name == "SKILL.md"


def test_read_text_keeps_head_and_tail_of_large_files(tmp_path: Path) -> None:
    huge = tmp_path / "README.md"
    huge.write_bytes(b"HEADMARK\n" + (b"P" * 1_200_000) + b"\nTAILMARK\n")
    text = read_text(huge)
    assert text is not None
    assert "HEADMARK" in text
    assert "TAILMARK" in text
    assert "skillguard:truncated" in text


def test_read_text_skips_nul_in_first_8k(tmp_path: Path) -> None:
    blob = tmp_path / "notes.md"
    blob.write_bytes(b"abc\x00def" + b"Z" * 100)
    assert read_text(blob) is None


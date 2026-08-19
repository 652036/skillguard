"""Locate SKILL.md packages and the files that belong to them."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".skillguard",
}

SCAN_SUFFIXES = {
    ".md",
    ".markdown",
    ".txt",
    ".rst",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".jsx",
    ".tsx",
    ".ps1",
    ".psm1",
    ".env",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".pem",
    ".key",
}

SCAN_FILENAMES = {
    "skill.md",
    "license",
    "license.txt",
    "license.md",
    "copying",
    "copying.txt",
    ".env",
    ".env.local",
    ".env.example",
}

MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class SkillRoot:
    """A directory that contains (or is treated as) one Agent Skill."""

    root: Path
    skill_md: Path | None

    @property
    def label(self) -> str:
        return str(self.root)


def discover_skills(path: Path) -> list[SkillRoot]:
    """Find skill packages under ``path``.

    * A ``SKILL.md`` file → that file's parent is the skill root.
    * A directory → every nested ``SKILL.md`` is a skill.
    * A directory with no ``SKILL.md`` is still scanned as one loose skill
      so a single folder of scripts is not silently skipped.
    * Any other file is scanned as a one-file skill.
    """
    path = path.resolve()
    if path.is_file():
        if path.name.upper() == "SKILL.MD":
            return [SkillRoot(root=path.parent, skill_md=path)]
        return [SkillRoot(root=path.parent, skill_md=None)]

    if not path.is_dir():
        raise FileNotFoundError(path)

    found: list[SkillRoot] = []
    for skill_md in _walk_skill_md(path):
        found.append(SkillRoot(root=skill_md.parent, skill_md=skill_md))
    found.sort(key=lambda s: str(s.root))
    if found:
        return found
    return [SkillRoot(root=path, skill_md=None)]


def _walk_skill_md(root: Path) -> list[Path]:
    matches: list[Path] = []
    for dirpath, dirnames, filenames in _walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        for name in filenames:
            if name.upper() == "SKILL.MD":
                matches.append(dirpath / name)
    return matches


def iter_skill_files(skill: SkillRoot, scan_target: Path | None = None) -> list[Path]:
    """Return text files that belong to one skill (nested skills excluded)."""
    if scan_target is not None and scan_target.is_file():
        return [scan_target.resolve()]

    nested_roots = {
        other.root.resolve()
        for other in discover_skills(skill.root)
        if other.root.resolve() != skill.root.resolve()
    }
    files: list[Path] = []
    for dirpath, dirnames, filenames in _walk(skill.root):
        resolved = dirpath.resolve()
        dirnames[:] = [
            d
            for d in dirnames
            if d not in SKIP_DIR_NAMES
            and not d.startswith(".")
            and (resolved / d) not in nested_roots
        ]
        for name in filenames:
            candidate = dirpath / name
            if _should_scan_file(candidate):
                files.append(candidate)
    files.sort()
    return files


def _should_scan_file(path: Path) -> bool:
    name = path.name
    if name.startswith(".") and name.lower() not in SCAN_FILENAMES:
        # Still scan .env* and hidden SKILL.md variants already covered.
        if not name.lower().startswith(".env"):
            return False
    suffix = path.suffix.lower()
    if suffix in SCAN_SUFFIXES or name.lower() in SCAN_FILENAMES:
        return True
    if name.upper() == "SKILL.MD":
        return True
    if name.upper().startswith("LICENSE"):
        return True
    return False


HEAD_TAIL_BYTES = 256 * 1024
TRUNCATE_MARKER = "\n<!-- skillguard:truncated -->\n"


def read_text(path: Path) -> str | None:
    """Read a UTF-8 (or latin-1 fallback) text file; skip binary files.

    Files larger than ``MAX_FILE_BYTES`` still return the first and last
    256 KiB joined by an ASCII marker (omnicogg-style padding must not hide
    a buried stager). Skip only when a NUL appears in the first 8 KiB.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    try:
        with path.open("rb") as fh:
            if size > MAX_FILE_BYTES:
                head = fh.read(HEAD_TAIL_BYTES)
                if b"\x00" in head[:8192]:
                    return None
                fh.seek(max(0, size - HEAD_TAIL_BYTES))
                tail = fh.read(HEAD_TAIL_BYTES)
                data = head + TRUNCATE_MARKER.encode("ascii") + tail
            else:
                data = fh.read()
                if b"\x00" in data[:8192]:
                    return None
    except OSError:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def _walk(root: Path):
    yield from root.walk() if hasattr(root, "walk") else _os_walk(root)


def _os_walk(root: Path):
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        yield Path(dirpath), dirnames, filenames

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
    ".mdc",
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
    ".bat",
    ".cmd",
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
    "agents.md",
    "claude.md",
    "gemini.md",
    ".cursorrules",
    "license",
    "license.txt",
    "license.md",
    "copying",
    "copying.txt",
    ".env",
    ".env.local",
    ".env.example",
}

HOST_INSTRUCTION_NAMES = frozenset({"agents.md", "claude.md", "gemini.md", ".cursorrules"})
HOST_INSTRUCTION_SUFFIXES = frozenset({".md", ".markdown", ".mdc", ".txt"})
HOST_WALK_HIDDEN_DIRS = {
    ".cursor": frozenset({"rules"}),
    ".github": frozenset({"instructions"}),
}

SCAN_HIDDEN_DIRS = {".ssh", ".aws"}
SCAN_CREDENTIAL_NAMES = {
    "id_rsa", "id_ed25519", "authorized_keys",
    "credentials", "credentials.json", "secrets.env", "auth.json",
}

MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class SkillRoot:
    """A directory that contains (or is treated as) one Agent Skill.

    ``host_only`` roots are host instruction files (AGENTS.md, CLAUDE.md,
    GEMINI.md, ``.cursorrules``, ``.cursor/rules``, GitHub Copilot
    ``.github/copilot-instructions.md`` / ``.github/instructions``) that sit
    outside any SKILL.md package. They are scanned for prompt-injection but
    are not skills.
    """

    root: Path
    skill_md: Path | None
    host_only: bool = False

    @property
    def label(self) -> str:
        return str(self.root)


def discover_skills(path: Path) -> list[SkillRoot]:
    """Find skill packages and uncovered host instruction files under ``path``.

    * A ``SKILL.md`` file → that file's parent is the skill root.
    * A directory → every nested ``SKILL.md`` is a skill.
    * Host instruction files (``AGENTS.md``, ``CLAUDE.md``, ``GEMINI.md``,
      ``.cursorrules``, ``.cursor/rules``, ``.github/copilot-instructions.md``,
      ``.github/instructions``) outside those packages are still scanned, so a
      skills repo's root agent files are not skipped.
    * A directory with no ``SKILL.md`` is still scanned as one loose skill
      so a single folder of scripts is not silently skipped.
    * Any other file is scanned as a one-file skill.
    """
    path = path.resolve()
    if path.is_file():
        if path.name.upper() == "SKILL.MD":
            return [SkillRoot(root=path.parent, skill_md=path)]
        return [
            SkillRoot(
                root=path.parent,
                skill_md=None,
                host_only=is_host_instruction_file(path),
            )
        ]

    if not path.is_dir():
        raise FileNotFoundError(path)

    found: list[SkillRoot] = []
    for skill_md in _walk_skill_md(path):
        found.append(SkillRoot(root=skill_md.parent, skill_md=skill_md))
    if not found:
        return [SkillRoot(root=path, skill_md=None)]
    skill_roots = {item.root.resolve() for item in found}
    uncovered_hosts = [
        host for host in host_instruction_files(path) if not _path_under_any(host, skill_roots)
    ]
    if uncovered_hosts:
        found.append(SkillRoot(root=path, skill_md=None, host_only=True))
    found.sort(key=lambda s: (s.host_only, str(s.root).lower()))
    return found


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
        if other.root.resolve() != skill.root.resolve() and not other.host_only
    }
    if skill.host_only:
        files = [
            host
            for host in host_instruction_files(skill.root)
            if not _path_under_any(host, nested_roots)
        ]
        files.sort()
        return files

    files: list[Path] = []
    for dirpath, dirnames, filenames in _walk(skill.root):
        resolved = dirpath.resolve()
        dirnames[:] = [
            d
            for d in dirnames
            if d not in SKIP_DIR_NAMES
            and (not d.startswith(".") or d in SCAN_HIDDEN_DIRS)
            and (resolved / d) not in nested_roots
        ]
        for name in filenames:
            candidate = dirpath / name
            if _should_scan_file(candidate):
                files.append(candidate)
    seen = {path.resolve() for path in files}
    for host in host_instruction_files(skill.root):
        resolved = host.resolve()
        if resolved in seen or _path_under_any(host, nested_roots):
            continue
        files.append(host)
        seen.add(resolved)
    files.sort()
    return files


def is_host_instruction_file(path: Path) -> bool:
    """True for AGENTS.md, CLAUDE.md, GEMINI.md, Cursor, and Copilot files."""
    if path.name.lower() in HOST_INSTRUCTION_NAMES:
        return True
    return _is_cursor_rule_file(path) or _is_github_copilot_file(path)


def host_instruction_files(root: Path) -> list[Path]:
    """Locate host instruction files under ``root`` (offline filesystem walk)."""
    matches: list[Path] = []
    for dirpath, dirnames, filenames in _walk(root):
        dirnames[:] = _host_walk_dirnames(dirpath, dirnames)
        for name in filenames:
            candidate = dirpath / name
            if is_host_instruction_file(candidate):
                matches.append(candidate)
    matches.sort()
    return matches


def _host_walk_dirnames(dirpath: Path, dirnames: list[str]) -> list[str]:
    allowed: list[str] = []
    nested_allow = HOST_WALK_HIDDEN_DIRS.get(dirpath.name.lower())
    for name in dirnames:
        if name in SKIP_DIR_NAMES:
            continue
        lowered = name.lower()
        if nested_allow is not None:
            if lowered in nested_allow:
                allowed.append(name)
            continue
        if name.startswith(".") and lowered not in HOST_WALK_HIDDEN_DIRS:
            continue
        allowed.append(name)
    return allowed


def _is_cursor_rule_file(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    try:
        idx = parts.index(".cursor")
    except ValueError:
        return False
    if idx + 2 >= len(parts) or parts[idx + 1] != "rules":
        return False
    return path.suffix.lower() in HOST_INSTRUCTION_SUFFIXES


def _is_github_copilot_file(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    try:
        idx = parts.index(".github")
    except ValueError:
        return False
    rest = parts[idx + 1 :]
    if rest == ["copilot-instructions.md"]:
        return True
    if len(rest) >= 2 and rest[0] == "instructions":
        return path.suffix.lower() in HOST_INSTRUCTION_SUFFIXES
    return False


def _path_under_any(path: Path, roots: set[Path]) -> bool:
    resolved = path.resolve()
    return any(resolved == root or root in resolved.parents for root in roots)


def _should_scan_file(path: Path) -> bool:
    name = path.name
    if name.startswith(".") and name.lower() not in SCAN_FILENAMES:
        # Still scan .env* and hidden SKILL.md variants already covered.
        if not name.lower().startswith(".env"):
            return False
    if name.lower() in SCAN_CREDENTIAL_NAMES:
        return True
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

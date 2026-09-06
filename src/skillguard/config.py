"""Offline rule-filter config: CLI flags plus skillguard.toml / .skillguard.yml."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from skillguard.rules import RULES_BY_ID

_CONFIG_NAMES = (
    "skillguard.toml",
    ".skillguard.toml",
    ".skillguard.yml",
    ".skillguard.yaml",
    "skillguard.yml",
    "skillguard.yaml",
)
_ID_RE = re.compile(r"^SG\d{3}$", re.IGNORECASE)


@dataclass(frozen=True)
class RuleFilter:
    """Resolved rule ids that should run."""

    active: frozenset[str]
    disabled: frozenset[str]
    enabled_allowlist: frozenset[str] | None
    source: str

    def allows(self, rule_id: str) -> bool:
        return rule_id in self.active


def parse_rule_ids(raw: str, *, label: str) -> list[str]:
    parts = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
    if not parts:
        raise ValueError(f"{label} is empty")
    out: list[str] = []
    unknown: list[str] = []
    for part in parts:
        rid = part.upper()
        if not _ID_RE.match(rid) or rid not in RULES_BY_ID:
            unknown.append(part)
            continue
        out.append(rid)
    if unknown:
        raise ValueError(f"unknown rule id(s) in {label}: {', '.join(unknown)}")
    return out


def resolve_filter(
    *,
    start: Path,
    disable_cli: str = "",
    enable_cli: str = "",
) -> RuleFilter:
    file_disable, file_enable, source = load_config_file(start)
    disable = set(file_disable)
    enable = set(file_enable) if file_enable is not None else None
    if disable_cli.strip():
        disable.update(parse_rule_ids(disable_cli, label="--disable"))
        source = _join_source(source, "cli --disable")
    if enable_cli.strip():
        enable = set(parse_rule_ids(enable_cli, label="--enable"))
        source = _join_source(source, "cli --enable")

    all_ids = frozenset(RULES_BY_ID)
    active = set(all_ids)
    if enable is not None:
        active &= enable
    active -= disable
    return RuleFilter(
        active=frozenset(active),
        disabled=frozenset(disable),
        enabled_allowlist=frozenset(enable) if enable is not None else None,
        source=source or "defaults",
    )


def load_config_file(start: Path) -> tuple[list[str], list[str] | None, str]:
    for directory in _walk_parents(start):
        for name in _CONFIG_NAMES:
            path = directory / name
            if path.is_file():
                disable, enable = _parse_config_file(path)
                return disable, enable, str(path)
    return [], None, ""


def _walk_parents(start: Path) -> list[Path]:
    cur = start.expanduser().resolve()
    if cur.is_file():
        cur = cur.parent
    out: list[Path] = []
    seen: set[Path] = set()
    while True:
        if cur in seen:
            break
        seen.add(cur)
        out.append(cur)
        if cur.parent == cur:
            break
        cur = cur.parent
    return out


def _parse_config_file(path: Path) -> tuple[list[str], list[str] | None]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".toml":
        return _from_mapping(_parse_toml(text), label=str(path))
    return _from_mapping(_parse_simple_yaml(text), label=str(path))


def _parse_toml(text: str) -> dict[str, object]:
    import tomllib

    data = tomllib.loads(text)
    if not isinstance(data, dict):
        return {}
    nested = data.get("skillguard")
    if isinstance(nested, dict):
        return nested
    tool = data.get("tool")
    if isinstance(tool, dict):
        inner = tool.get("skillguard")
        if isinstance(inner, dict):
            return inner
    return data


def _parse_simple_yaml(text: str) -> dict[str, object]:
    """Tiny subset: disable/enable as list or [a, b] inline. No nested maps."""
    mapping: dict[str, object] = {}
    current: str | None = None
    items: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("- ") and current:
            items.append(stripped[2:].strip().strip("\"'"))
            continue
        if ":" in line and not stripped.startswith("-"):
            if current is not None:
                mapping[current] = items
            key, rest = line.split(":", 1)
            current = key.strip()
            rest = rest.strip()
            items = []
            if rest:
                if rest.startswith("[") and rest.endswith("]"):
                    inner = rest[1:-1].strip()
                    mapping[current] = [
                        p.strip().strip("\"'") for p in inner.split(",") if p.strip()
                    ]
                    current = None
                else:
                    mapping[current] = rest.strip("\"'")
                    current = None
    if current is not None:
        mapping[current] = items
    return mapping


def _from_mapping(data: dict[str, object], *, label: str) -> tuple[list[str], list[str] | None]:
    disable = _as_id_list(data.get("disable"), label=f"{label} disable")
    enable_raw = data.get("enable")
    enable = _as_id_list(enable_raw, label=f"{label} enable") if enable_raw is not None else None
    return disable, enable


def _as_id_list(value: object, *, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return parse_rule_ids(value, label=label)
    if isinstance(value, list):
        parts = [str(v) for v in value]
        return parse_rule_ids(",".join(parts), label=label)
    raise ValueError(f"{label} must be a list or comma-separated string")


def _join_source(existing: str, extra: str) -> str:
    if not existing:
        return extra
    return f"{existing}+{extra}"

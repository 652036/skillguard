"""Secret and credential detectors."""

from __future__ import annotations

import re
from pathlib import Path

from skillguard.models import Severity
from skillguard.rules.base import Rule, line_at, search_regex, snippet

_ANY = frozenset({"any"})

SG101 = Rule(
    id="SG101",
    severity=Severity.CRITICAL,
    title="AWS access key",
    description="An AWS access-key ID (AKIA…) is committed inside the skill package.",
    false_positives="Amazon's documented example AKIAIOSFODNN7EXAMPLE is ignored. Other AKIA… keys still match.",
    applies_to=_ANY,
)

SG102 = Rule(
    id="SG102",
    severity=Severity.CRITICAL,
    title="Cloud / AI vendor token",
    description="An OpenAI, Anthropic, GitHub, Slack, or similar vendor token is present in the skill.",
    false_positives="Truncated docs samples shorter than the real token shape are ignored.",
    applies_to=_ANY,
)

SG103 = Rule(
    id="SG103",
    severity=Severity.CRITICAL,
    title="Generic API key assignment",
    description="A hard-coded API key / secret / token string assignment was found.",
    false_positives=(
        "Reads from the environment (os.environ['API_KEY']) are ignored. "
        "Test placeholders shorter than 12 characters are ignored."
    ),
    applies_to=_ANY,
)

SG104 = Rule(
    id="SG104",
    severity=Severity.CRITICAL,
    title="Private key PEM block",
    description="A PEM/OpenSSH private-key block is committed in the skill.",
    false_positives="Public certificates (BEGIN CERTIFICATE) are not flagged.",
    applies_to=_ANY,
)

SG105 = Rule(
    id="SG105",
    severity=Severity.CRITICAL,
    title="Committed .env secrets",
    description="A .env file with key=value secrets is shipped inside the skill package.",
    false_positives=(
        ".env.example files that only contain empty values or obvious placeholders "
        "(changeme, your-key-here) are ignored."
    ),
    applies_to=frozenset({"env"}),
)

# Official AWS example key is skipped; other AKIA shapes still match.
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

_VENDOR_TOKEN = re.compile(
    r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"
    r"|\bsk-ant-[A-Za-z0-9_-]{20,}\b"
    r"|\bsk-[A-Za-z0-9]{20,}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
    r"|\bAIza[0-9A-Za-z_-]{20,}\b",
)

_GENERIC_ASSIGN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|private[_-]?token)\b\s*[:=]\s*['\"]([A-Za-z0-9_\-/.+=]{12,})['\"]"
)

_ENV_LOOKUP = re.compile(
    r"(?i)os\.environ|os\.getenv|getenv\(|process\.env|env\[|SecretStr|changeme|"
    r"your[_-]?key|xxx+|placeholder|dummy|not[_-]?a[_-]?real",
)

_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
)

_ENV_LINE = re.compile(
    r"(?m)^(?:export\s+)?([A-Z][A-Z0-9_]+)\s*=\s*(.+)$"
)

_PLACEHOLDER_VALUE = re.compile(
    r"(?i)^(?:['\"]{0,1})(?:|changeme|your[_-].+|xxx+|todo|replace[_-]?me|"
    r"hf_x+|sk-or-v1-your-.+|<[^>]+>|\$\{?[A-Z0-9_]+\}?|none|null|false|true)(?:['\"]{0,1})$"
)

# .env keys that are obviously secrets when given a non-placeholder value
_ENV_SECRET_KEY = re.compile(
    r"(?i)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|AUTH)$"
)


def _skip_sg101(match: re.Match[str], content: str) -> bool:
    return match.group(0).upper() == "AKIAIOSFODNN7EXAMPLE"


def check_sg101(path: Path, content: str) -> list:
    return search_regex(SG101, path, content, _AWS_KEY, skip=_skip_sg101)


def check_sg102(path: Path, content: str) -> list:
    return search_regex(SG102, path, content, _VENDOR_TOKEN)


def check_sg103(path: Path, content: str) -> list:
    findings = []
    for match in _GENERIC_ASSIGN.finditer(content):
        window = content[max(0, match.start() - 40) : match.end() + 40]
        if _ENV_LOOKUP.search(window):
            continue
        value = match.group(1)
        if _PLACEHOLDER_VALUE.match(value):
            continue
        findings.append(SG103.finding(path, line_at(content, match.start()), snippet(content, match.start())))
    return findings


def check_sg104(path: Path, content: str) -> list:
    return search_regex(SG104, path, content, _PEM)


def check_sg105(path: Path, content: str) -> list:
    name = path.name.lower()
    if name.endswith((".example", ".sample", ".template", ".dist")) or name in {
        ".env.example", ".env.sample", ".env.template", ".env.dist"
    }:
        return []
    findings = []
    for match in _ENV_LINE.finditer(content):
        key, raw = match.group(1), match.group(2).strip()
        if not _ENV_SECRET_KEY.search(key):
            continue
        value = raw.split(" #", 1)[0].strip().strip("'\"")
        if _PLACEHOLDER_VALUE.match(value) or len(value) < 8:
            continue
        findings.append(SG105.finding(path, line_at(content, match.start()), snippet(content, match.start())))
    return findings


RULES = [SG101, SG102, SG103, SG104, SG105]
CHECKERS = {
    "SG101": check_sg101,
    "SG102": check_sg102,
    "SG103": check_sg103,
    "SG104": check_sg104,
    "SG105": check_sg105,
}

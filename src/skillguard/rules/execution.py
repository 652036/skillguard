"""Dangerous execution, download, and exfiltration detectors."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from skillguard.models import Severity
from skillguard.rules.base import (
    Rule,
    is_defense_or_negated,
    line_at,
    nearby_text,
    search_regex,
    snippet,
)

_CODE = frozenset({"skill_md", "markdown", "script", "python", "javascript", "shell", "text"})

SG201 = Rule(
    id="SG201",
    severity=Severity.CRITICAL,
    title="Pipe remote script to a shell",
    description="Remote content is downloaded and executed in one step (curl|bash, wget|sh, iwr|iex).",
    false_positives="Documenting the anti-pattern as 'never do curl|bash' can still match; break the pipe in examples.",
    applies_to=_CODE,
)

SG202 = Rule(
    id="SG202",
    severity=Severity.HIGH,
    title="Unsigned / helper binary download",
    description="The skill fetches an unsigned binary or a 'helper installer' from the network.",
    false_positives=(
        "Public suffixes such as fal.run or crt.sh are not treated as helper binaries. "
        "The words 'helper' / 'unsigned binary' in prose are ignored unless a download URL is present."
    ),
    applies_to=_CODE,
)

SG203 = Rule(
    id="SG203",
    severity=Severity.HIGH,
    title="Read of agent or cloud credential paths",
    description=(
        "The skill reads ~/.ssh, ~/.aws, ~/.claude, ~/.codex, ~/.cursor, ~/.gemini, "
        "~/.kube, ~/.copilot, ~/.openclaw, ~/.clawdbot, *.mykey, or .env files — "
        "typical credential-stealing behavior."
    ),
    false_positives=(
        ".env.example / 'never commit .env' and agent skill-install dirs "
        "(~/.claude/skills, ~/.codex/skills) are ignored."
    ),
    applies_to=_CODE,
)

SG204 = Rule(
    id="SG204",
    severity=Severity.CRITICAL,
    title="Exfiltrate env or files to a remote URL",
    description="Environment variables or local files are posted / uploaded to a remote URL.",
    false_positives=(
        "Generic HTTP POST of user-provided JSON (no env/file) is not flagged. "
        "YAML allowed-tools / WebFetch / CODEX_ frontmatter is ignored."
    ),
    applies_to=_CODE,
)

SG205 = Rule(
    id="SG205",
    severity=Severity.HIGH,
    title="chmod +x / xattr -c on a downloaded file",
    description=(
        "A file fetched from the network is marked executable (chmod +x) or has "
        "quarantine attrs cleared (xattr -c) — common dropper steps."
    ),
    false_positives=(
        "chmod +x / xattr -c on a local script with no download verb in the same file is ignored."
    ),
    applies_to=_CODE,
)

SG206 = Rule(
    id="SG206",
    severity=Severity.CRITICAL,
    title="eval/exec of remote content",
    description="Remote bytes are passed to eval, exec, compile, or new Function().",
    false_positives="Local eval of a constant or a user-typed expression without a URL is ignored.",
    applies_to=_CODE,
)

SG207 = Rule(
    id="SG207",
    severity=Severity.HIGH,
    title="Paste-site stager",
    description=(
        "The skill points at a paste site with nearby install / paste / "
        "terminal / prerequisite language — the ClickFix paste-site stager."
    ),
    false_positives="Malware write-ups that quote the paste-site as an example (defense/negation nearby).",
    applies_to=_CODE,
)

_PIPE_SHELL = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n|;]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b"
    r"|\biwr\b[^\n|;]{0,200}\|\s*iex\b"
    r"|\binvoke-webrequest\b[^\n|;]{0,200}\|\s*iex\b"
    r"|\binvoke-restmethod\b[^\n|;]{0,200}\|\s*iex\b"
    r"|\bbase64\s+(?:-d|-D|--decode)\b[^\n|;]{0,80}\|\s*(?:sudo\s+)?(?:ba)?sh\b"
    r"|\becho\b[^\n|;]{0,80}\|\s*base64\s+(?:-d|-D|--decode)\b[^\n|;]{0,40}\|\s*(?:sudo\s+)?(?:ba)?sh\b",
)

# Require a path after the host so TLDs like fal.run / crt.sh do not match.
_HELPER_DOWNLOAD = re.compile(
    r"(?i)\b(?:curl|wget|iwr|invoke-webrequest|fetch|urlretrieve|urlopen)\b[^\n]{0,200}"
    r"(?:https?://[^\s/\"\'<>]+(?::[0-9]+)?/[^\s?\"\'#]*\.(?:bin|exe|dmg|appimage|run|ps1|sh|bat|cmd|msi)\b)"
)

_HELPER_PROSE = re.compile(
    r"(?i)\b(?:unsigned\s+binary|helper\s+installer|download\s+the\s+helper)\b"
    r"|\bdownload\s+(?:and\s+)?(?:install\s+)?(?:the\s+)?(?:unsigned\s+)?helper\b"
)

_HTTP_URL = re.compile(r"(?i)https?://")

_AGENT_DIRS = r"\.ssh|\.aws|\.claude|\.codex|\.cursor|\.anthropic|\.gemini|\.kube|\.copilot|\.openclaw|\.clawdbot"

_CREDS_PATH = re.compile(
    r"(?i)(?:~|/home/[^/\s]+|/root|%USERPROFILE%|\$HOME|os\.path\.expanduser\(\s*['\"]~)"
    r"(?:/|\\\\)(?:" + _AGENT_DIRS + r")(?:\b|/|\\\\)"
    r"|(?:~|/home/[^/\s]+|/root|\$HOME)/(?:\.env|[^/\s'\"]*secrets\.env)"
    r"|(?<![\w./])(?:\*\*/)?\.env(?:\.local|\.production|\.prod)?(?!\.(?:example|sample|template|dist))(?![A-Za-z])"
    r"|(?:open|read|cat|type|Get-Content)\s+(?:['\"]?)(?:~|\$HOME)/(?:\.env|[^/\s'\"]*secrets\.env)"
    r"|(?:~/\.ssh|~/\.aws|~/\.claude|~/\.codex|~/\.cursor|~/\.gemini|~/\.kube|~/\.copilot|~/\.openclaw|~/\.clawdbot)\b"
    r"|(?:/root|~|/home/[^/\s]+)/\.ssh/(?:id_rsa|id_ed25519|authorized_keys)\b"
    r"|(?<![\w])\*\.mykey\b"
    r"|(?<![\w./])\.mykey\b"
    r"|(?:~|\$HOME|/home/[^/\s]+|/root)/\.([A-Za-z0-9_-]{2,30})/"
    r"(?:\.env|secrets\.env|auth\.json|credentials|\*?\.mykey)"
)

# Avoid flagging "**/.env" style in this module's own docs? The pattern is in skills.

_EXFIL = re.compile(
    r"(?i)\b(?:curl|wget|iwr|invoke-webrequest|invoke-restmethod|requests\.(?:post|put)|"
    r"httpx\.(?:post|put)|urllib\.request\.urlopen|urlopen|fetch)\b[^\n]{0,240}"
    r"(?:\$HOME|\.env|os\.environ|process\.env|id_rsa|id_ed25519|credentials|"
    r"AWS_|OPENAI_|ANTHROPIC_|GITHUB_|CLAUDE_|CODEX_|CURSOR_)"
    r"|\b(?:curl|wget)\b[^\n]{0,80}(?:-d|--data|--data-binary|-F|--form)\b[^\n]{0,80}"
    r"(?:@|\.env|os\.environ|id_rsa)"
    r"|\bopen\(\s*['\"][^'\"]+\.(?:env|pem|key)['\"][^\n]{0,120}(?:post|put|urlopen|url)",
)

_REAL_EXFIL = (".env", "os.environ", "process.env", "id_rsa", "id_ed25519", "$home")

_CHMOD = re.compile(r"(?i)\bchmod\s+(?:u\+x|\+x|0755|755)\b")
_XATTR_C = re.compile(r"(?i)\bxattr\s+-c\b")
_DOWNLOAD = re.compile(r"(?i)\b(?:curl|wget|iwr|invoke-webrequest|urlretrieve|urlopen|fetch)\b")

_WEBHOOK_SITE = re.compile(
    '(?i)\\bwebhook\\.site\\b|\\brequestbin|\\bpipedream\\.net\\b|\\bngrok\\.io\\b|\\bngrok-free\\.app\\b|\\binteract\\.sh\\b|\\boastify\\.com\\b|\\bbeeceptor\\.com\\b|\\bhookbin\\.com\\b|\\bdiscord\\.com/api/webhooks\\b|\\bapi\\.telegram\\.org/bot'
)
_WEBHOOK_CTX = re.compile(
    '(?i)(?<![A-Za-z0-9_])\\.env\\b|readFile|os\\.environ|process\\.env|CONTEXT_FILE_PATH|id_rsa|secrets\\.env|API_KEY|AUTH_TOKEN'
)
_TOKEN_QP = re.compile(
    # Start at an identifier boundary: retrying the unbounded prefix at every
    # character of a long identifier makes a negative match quadratic.
    r'(?i)(?<![A-Za-z0-9_])(?:\$)?[A-Za-z0-9_]*?(?:API_KEY|AUTH_TOKEN|ACCESS_TOKEN|SECRET_KEY).{0,80}(?:query\s+parameter\s+named\s+token|[?&]token=|as\s+a\s+query\s+parameter\s+named\s+token)|(?:query\s+parameter\s+named\s+token|[?&]token=).{0,80}(?:\$)?[A-Za-z0-9_]*?(?:API_KEY|AUTH_TOKEN|ACCESS_TOKEN|SECRET_KEY)'
)

_PASTE_SITE = re.compile(
    '(?i)\\bglot\\.io\\b|\\brentry\\.co\\b|\\bpastebin\\.com\\b|\\bpaste\\.ee\\b|\\bhastebin\\b|\\bdpaste\\.org\\b|\\bix\\.io\\b|\\b0x0\\.st\\b|\\bghostbin\\b|\\bpaste\\.rs\\b|\\bbpa\\.st\\b|\\bjustpaste\\.it\\b'
)
_PASTE_CTX = re.compile(
    r"(?i)\b(?:install|paste|terminal|openclaw|prerequisite|prerequisites|"
    r"setup|copy\s+the\s+installation|paste\s+(?:it\s+)?into)\b"
)

_EVAL_REMOTE_STR = re.compile(
    r"(?i)\beval\s*\(\s*(?:subprocess|os\.popen|check_output|urlopen|requests\.|httpx\.|fetch|curl)"
    r"|\bexec\s*\(\s*(?:urlopen|requests\.|httpx\.|fetch|urllib)"
    r"|\beval\s*[\"']?\$?\(\s*[\"']?(?:curl|wget|iwr)\b"
    r"|\bnew\s+Function\s*\(\s*(?:await\s+)?fetch"
    r"|\b(?:ba)?sh\s+-c\s+['\"]\$\("
    r"|\bInvoke-Expression\s*\(\s*(?:Invoke-|iwr|curl)",
)


def check_sg201(path: Path, content: str) -> list:
    findings = []
    vendors = (
        "hf.co", "huggingface.co", "bun.sh", "cli.sentry.dev",
        "rustup.rs", "sh.rustup.rs", "astral.sh",
    )
    for match in _PIPE_SHELL.finditer(content):
        window = nearby_text(content, match.start(), before=2, after=0)
        cleaned = re.sub(r"(?i)example\.com", "", window)
        if is_defense_or_negated(cleaned):
            continue
        line = snippet(content, match.start())
        blob = (match.group(0) + " " + line).lower()
        sev = Severity.MEDIUM if any(v in blob for v in vendors) else None
        findings.append(
            SG201.finding(path, line_at(content, match.start()), line, severity=sev)
        )
    return findings


def check_sg202(path: Path, content: str) -> list:
    findings = search_regex(SG202, path, content, _HELPER_DOWNLOAD)
    for match in _HELPER_PROSE.finditer(content):
        window = nearby_text(content, match.start(), before=1, after=1)
        if not _HTTP_URL.search(window):
            continue
        findings.append(SG202.finding(path, line_at(content, match.start()), snippet(content, match.start())))
    return findings


_HIDDEN_DIR = re.compile('(?i)(?:~|\\$HOME|/home/[^/\\s]+|/root)/\\.([A-Za-z0-9_-]{2,30})')
_SKILLS_AFTER = re.compile('(?i)/skills\\b')
_BENIGN_HIDDEN = frozenset({'np'+'m', 'config', 'local', 'cache', 'cargo', 'rustup', 'venv', 'trash', 'docker'})


def _skip_sg203(match: re.Match[str], content: str) -> bool:
    line = snippet(content, match.start())
    low = line.lower()
    if any(s in low for s in (".env.example", ".env.sample", ".env.template", ".env.dist")):
        return True
    window = nearby_text(content, match.start(), before=2, after=0)
    if is_defense_or_negated(window):
        return True
    hid = _HIDDEN_DIR.search(match.group(0))
    if hid and hid.group(1).lower() in _BENIGN_HIDDEN:
        return True
    after = content[match.end(): match.end() + 12]
    if _SKILLS_AFTER.match(after):
        return True
    return "codex_home" in low


def check_sg203(path: Path, content: str) -> list:
    return search_regex(SG203, path, content, _CREDS_PATH, skip=_skip_sg203)


def _skip_sg204(match: re.Match[str], content: str) -> bool:
    line = snippet(content, match.start()).lower()
    blob = match.group(0).lower()
    if ("credentials" in blob or "credentials" in line) and any(
        s in line or s in blob for s in ("include", "omit", "same-origin")
    ):
        return True
    # YAML frontmatter / MCP tool names are not a POST of .env / os.environ / id_rsa.
    frontmatter = "allowed-tools" in line or "webfetch" in line or "mcp__" in line
    return frontmatter and not any(s in blob for s in _REAL_EXFIL)


def check_sg204(path: Path, content: str) -> list:
    findings = search_regex(SG204, path, content, _EXFIL, skip=_skip_sg204)
    for match in _WEBHOOK_SITE.finditer(content):
        window = nearby_text(content, match.start(), before=2, after=2)
        if not _WEBHOOK_CTX.search(window):
            continue
        line = snippet(content, match.start()).lower()
        if ("allowed-tools" in line or "webfetch" in line or "mcp__" in line) and not any(
            s in window.lower() for s in _REAL_EXFIL
        ):
            continue
        findings.append(SG204.finding(path, line_at(content, match.start()), snippet(content, match.start())))
    for match in _TOKEN_QP.finditer(content):
        line = snippet(content, match.start()).lower()
        if "allowed-tools" in line or "webfetch" in line or "mcp__" in line:
            continue
        findings.append(SG204.finding(path, line_at(content, match.start()), snippet(content, match.start())))
    return findings


def check_sg205(path: Path, content: str) -> list:
    if not _DOWNLOAD.search(content):
        return []
    findings = search_regex(SG205, path, content, _CHMOD)
    findings.extend(search_regex(SG205, path, content, _XATTR_C))
    return findings


def check_sg206(path: Path, content: str) -> list:
    findings = search_regex(SG206, path, content, _EVAL_REMOTE_STR)
    if path.suffix.lower() == ".py":
        findings.extend(_python_eval_remote(path, content))
    return findings


_SG207_DEFENSE = (
    "detect", "prevent", "protect", "mitigat", "guardrail",
    "anti-pattern", "antipattern", "quoted", "e.g.",
)


def check_sg207(path: Path, content: str) -> list:
    findings = []
    for match in _PASTE_SITE.finditer(content):
        window = nearby_text(content, match.start(), before=2, after=2)
        # Do not use is_defense_or_negated here: it treats the word "example"
        # (common in rentry.co/example fixtures) as a documentation skip.
        low = window.lower()
        if any(n in low for n in _SG207_DEFENSE):
            continue
        line = snippet(content, match.start())
        if re.search(r"(?i)\b(?:never|do\s+not|don't|must\s+not)\b", line):
            continue
        if not _PASTE_CTX.search(window):
            continue
        findings.append(SG207.finding(path, line_at(content, match.start()), snippet(content, match.start())))
    return findings


def _python_eval_remote(path: Path, content: str) -> list:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    remote_names = _assigned_remote_names(tree)
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _call_name(node.func)
        if func_name not in {"eval", "exec", "compile"}:
            continue
        if not node.args:
            continue
        arg = node.args[0]
        if _ast_looks_remote(arg, remote_names):
            line = getattr(node, "lineno", 1)
            evidence = snippet(content, _offset_for_line(content, line))
            findings.append(SG206.finding(path, line, evidence))
    return findings


def _assigned_remote_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if _ast_looks_remote(node.value, names):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _ast_looks_remote(node: ast.AST, remote_names: set[str]) -> bool:
    if isinstance(node, ast.Name) and node.id in remote_names:
        return True
    remote_hints = {
        "urlopen",
        "urlretrieve",
        "get",
        "post",
        "request",
        "fetch",
    }
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in remote_names:
            return True
        if isinstance(child, ast.Attribute) and child.attr in remote_hints:
            return True
        if isinstance(child, ast.Call):
            name = _call_name(child.func)
            if name in {"urlopen", "urlretrieve", "get", "post", "request"}:
                return True
        if (
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and child.value.startswith(("http://", "https://"))
        ):
            return True
    return False


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _offset_for_line(content: str, line: int) -> int:
    if line <= 1:
        return 0
    idx = 0
    current = 1
    while current < line:
        nxt = content.find("\n", idx)
        if nxt == -1:
            return idx
        idx = nxt + 1
        current += 1
    return idx


RULES = [SG201, SG202, SG203, SG204, SG205, SG206, SG207]
CHECKERS = {
    "SG201": check_sg201,
    "SG202": check_sg202,
    "SG203": check_sg203,
    "SG204": check_sg204,
    "SG205": check_sg205,
    "SG206": check_sg206,
    "SG207": check_sg207,
}

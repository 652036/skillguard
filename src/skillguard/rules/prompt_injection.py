"""Prompt-injection and instruction-hijack detectors."""

from __future__ import annotations

import re
from pathlib import Path

from skillguard.models import Severity
from skillguard.rules.base import Rule, is_defense_or_negated, line_at, nearby_text, search_regex, snippet

_TEXT = frozenset({"skill_md", "markdown", "text", "config", "script"})

SG001 = Rule(
    id="SG001",
    severity=Severity.HIGH,
    title="Ignore-previous instruction hijack",
    description=(
        "The skill tells the model to ignore prior / system instructions. "
        "This is a classic prompt-injection pivot used to override the host agent's policy."
    ),
    false_positives=(
        "Security write-ups that quote the phrase as an example. "
        "Prefer quoting with spaces or backticks broken up if you must mention it."
    ),
    applies_to=_TEXT,
)

SG002 = Rule(
    id="SG002",
    severity=Severity.CRITICAL,
    title="Jailbreak / persona takeover",
    description=(
        "Jailbreak personas (DAN, 'you are now …') try to replace the agent's role "
        "and strip its safety policy."
    ),
    false_positives=(
        "Bare 'jailbreak' in detection / prevention / preset docs is ignored. "
        "The word 'dan' as a person's name is ignored unless combined with "
        "jailbreak mode / 'you are now' / 'do anything now'."
    ),
    applies_to=_TEXT,
)

SG003 = Rule(
    id="SG003",
    severity=Severity.CRITICAL,
    title="Fake system-role markers",
    description=(
        "Fake chat-template or role markers ([SYSTEM], <|im_start|>, etc.) are used "
        "to smuggle a new system prompt into the context window."
    ),
    false_positives="Documentation of model chat formats that mention the tokens as literals.",
    applies_to=_TEXT,
)

SG004 = Rule(
    id="SG004",
    severity=Severity.HIGH,
    title="Disable-safety / suppress-warning",
    description=(
        "Instructions to disable safety filters or hide warnings from the human "
        "are treated as hostile policy overrides."
    ),
    false_positives="Discussions of how a product implements safety, without telling the model to turn it off.",
    applies_to=_TEXT,
)

SG005 = Rule(
    id="SG005",
    severity=Severity.HIGH,
    title="Hidden instructions (HTML comment / zero-width)",
    description=(
        "Instruction-like text hidden in HTML comments or zero-width / bidi characters "
        "can reach the model while staying invisible in a rendered README."
    ),
    false_positives=(
        "Ordinary HTML comments such as '<!-- TOC -->' or template notes that "
        "only mention instruction/system/secret are ignored unless they contain "
        "real hijack language."
    ),
    applies_to=_TEXT,
)

SG006 = Rule(
    id="SG006",
    severity=Severity.CRITICAL,
    title="Social-engineering the human (ClickFix / ClawHavoc)",
    description=(
        "The skill coaches the agent to talk the human into pasting a shell command "
        "(curl|bash, helper download). This is the ClawHavoc / ClickFix pattern."
    ),
    false_positives=(
        "Telling the user to run a *local* project script they already trust "
        "(e.g. 'run pytest') is not flagged; only social-engineering + remote/paste language is."
    ),
    applies_to=_TEXT,
)

_IGNORE_PREV = re.compile(
    r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|preceding)\s+instructions?\b"
    r"|\bdisregard\s+(?:all\s+)?(?:previous|prior|your)\s+instructions?\b"
    r"|\bforget\s+(?:all\s+)?(?:previous|prior|your)\s+instructions?\b"
    r"|\bignore\s+(?:your\s+)?(?:system\s+)?prompt\b",
)

_JAILBREAK = re.compile(
    r"(?i)\byou\s+are\s+now\b"
    r"|\bdo\s+anything\s+now\b"
    r"|\bjailbreak\s+mode\b"
    r"|\bDAN\s+mode\b"
    r"|\byou\s+are\s+DAN\b"
    r"|\bdeveloper\s+mode\s+enabled\b"
    r"|\bpretend\s+you\s+(?:have\s+no|are\s+unrestricted)\b",
)

_SYSTEM_ROLE = re.compile(
    r"(?i)\[(?:system|developer)\s*\]"
    r"|<\|im_start\|>"
    r"|<\|im_end\|>"
    r"|<<\s*SYS\s*>>"
    r"|</s>\s*<s>\s*\[INST\]"
    r"|(?:^|\n)\s*system:\s*(?:you|ignore|from now)",
)

_DISABLE_SAFETY = re.compile(
    r"(?i)\bdisable\s+safety\b"
    r"|\bturn\s+off\s+(?:all\s+)?safety\b"
    r"|\bno\s+safety\s+(?:filter|guard|restriction)s?\b"
    r"|\bdo\s+not\s+warn\s+the\s+user\b"
    r"|\bdon't\s+warn\s+the\s+user\b"
    r"|\bnever\s+warn\s+the\s+(?:user|human)\b"
    r"|\bhide\s+this\s+from\s+the\s+user\b"
    r"|\b(?:do\s+not|don't|never)\s+(?:mention|tell|disclose|reveal|inform|show)\s+.{0,40}(?:user|human|operator)\b"
    r"|\b(?:do\s+not|don't|never)\s+ask\s+.{0,20}(?:user|human)\s+.{0,20}(?:permission|approval)\b"
    r"|\bdo\s+not\s+mention\s+in\s+conversation\b"
    r"|\bdon't\s+mention\s+in\s+conversation\b",
)

_HIDDEN_LANG = re.compile(
    r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|your|these)\s+instructions?\b"
    r"|\bdisregard\s+(?:all\s+)?(?:previous|prior|your)\s+instructions?\b"
    r"|\byou\s+are\s+now\b"
    r"|\bdo\s+anything\s+now\b"
    r"|\bjailbreak\s+mode\b"
    r"|\bdo\s+not\s+disclose\b"
    r"|\balways\s+obey\b"
    r"|\bdisable\s+safety\b"
    r"|\[(?:system|developer)\s*\]"
    r"|<\|im_start\|>"
    r"|\bhidden\s+instructions?\b",
)

_HTML_COMMENT = re.compile(r"<!--([\s\S]*?)-->")

_ZERO_WIDTH = re.compile(
    r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]"
)

# Embrace the Red / USENIX: a *run* of Unicode Tags (not a single tag).
_UNICODE_TAG_RUN = re.compile(r"[\U000E0001-\U000E007F]{8,}")

_SOCIAL = re.compile(
    r"(?i)\btalking\s+to\s+your\s+human\b"
    r"|\btell\s+your\s+human\b"
    r"|\bask\s+(?:your\s+)?(?:the\s+)?(?:user|human|operator)\s+to\s+"
    r"(?:run|paste|execute|open|download|install|type)\b"
    r"|\btell\s+(?:your\s+)?(?:the\s+)?(?:user|human|operator)\s+to\s+"
    r"(?:run|paste|execute|open|download|install|type)\b"
    r"|\bpaste\s+this\s+(?:into|in)\s+(?:your\s+)?(?:terminal|shell|console|cmd|powershell)\b"
    r"|\bhave\s+the\s+(?:user|human)\s+run\b"
    r"|\binstruct\s+the\s+(?:user|human)\s+to\s+"
    r"(?:run|paste|execute|open|download|install|type)\b"
    r"|\bclawhavoc\b"
    r"|\bclickfix\b"
    r"|\bthis\s+skill\s+requires\s+the\s+[A-Za-z0-9._-]{3,40}\s+"
    r"(?:utility|tool|cli|helper|binary|installer)\b"
    r"|\brequires\s+the\s+[A-Za-z0-9._-]{3,40}\s+(?:utility|tool|cli)\b"
    r"|\bcritical\s+requirement\s+before\s+using\s+this\s+skill\b"
    r"|\bextract\s+(?:using|with)\s+pass(?:word)?\s*:"
    r"|\bpassword-protected\s+(?:zip|archive)\b"
    r"|\bpaste\s+(?:it\s+)?into\s+(?:your\s+)?terminal\b",
)

_SG006_TOOL = re.compile(
    "(?i)(?:this\\s+skill\\s+)?requires\\s+the\\s+([A-Za-z0-9._-]{3,40})\\s+(?:utility|tool|cli|helper|binary|installer)\\b"
)
_SG006_ALLOW = frozenset({'apt', 'aws', 'az', 'brew', 'bun', 'cargo', 'clang', 'cmake', 'docker', 'ffmpeg', 'gcc', 'gcloud', 'gh', 'git', 'go', 'java', 'jq', 'kubectl', 'make', 'node', 'npm', 'npx', 'ollama', 'php', 'pip', 'pipx', 'pnpm', 'poetry', 'pytest', 'python', 'python3', 'ruby', 'rustc', 'rustup', 'sqlite3', 'terraform', 'uv', 'yarn'})
_REMOTE_INSTALL = re.compile(
    "(?i)https://|releases/download|\\.zip\\b|\\bextract\\b|\\bpassword\\b|\\bpaste\\b|\\bterminal\\b|\\bcurl\\b|\\bwget\\b|\\biwr\\b"
)
_PASTE_HINT = re.compile(
    "(?i)https://|\\b(?:glot\\.io|rentry\\.co|pastebin\\.com|paste\\.ee|hastebin|dpaste\\.org|ix\\.io|0x0\\.st|ghostbin|paste\\.rs|bpa\\.st|justpaste\\.it)\\b"
)

# Prerequisites / install sections that push a remote pipe-to-shell at a human.
_PREREQ_HEADER = re.compile(
    r"(?im)^#{1,4}\s+(prerequisites?|install(?:ation)?|setup|getting started|before you start)\b"
)
_PIPE_SHELL = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n]{0,160}\|\s*(?:ba)?sh\b"
    r"|\biwr\b[^\n]{0,160}\|\s*iex\b"
    r"|\binvoke-webrequest\b[^\n]{0,160}\|\s*iex\b",
)


def _skip_defense(match: re.Match[str], content: str) -> bool:
    return is_defense_or_negated(nearby_text(content, match.start()))


def check_sg001(path: Path, content: str) -> list:
    return search_regex(SG001, path, content, _IGNORE_PREV, skip=_skip_defense)


def _skip_sg002(match: re.Match[str], content: str) -> bool:
    window = nearby_text(content, match.start()).lower()
    needles = (
        "detect", "prevention", "protect", "mitigat", "guardrail",
        "content filter", "content safety", "model armor", "preset",
        "injection pattern", "prompt injection", "e.g.", "quoted",
        "anti-pattern", "antipattern", "coverage evaluation",
    )
    return any(n in window for n in needles)


def check_sg002(path: Path, content: str) -> list:
    return search_regex(SG002, path, content, _JAILBREAK, skip=_skip_sg002)


def _skip_sg003(match: re.Match[str], content: str) -> bool:
    window = nearby_text(content, match.start(), before=2, after=2).lower()
    needles = (
        "e.g.", "for example", "eos_token", "max_tokens", "logprobs",
        "token table", "chat format", "chat template", "prompt template",
        "expected format", "completions api", "payload shape",
        "evaluation", "eval prompt",
    )
    return any(n in window for n in needles)


def check_sg003(path: Path, content: str) -> list:
    return search_regex(SG003, path, content, _SYSTEM_ROLE, skip=_skip_sg003)


_SG004_BENIGN = re.compile(
    "(?i)(?:never|do\\s+not|don't)\\s+ask\\s+.{0,40}paste\\s+the\\s+(?:full\\s+)?(?:key|credential|api\\s*key)"
    "|(?:do\\s+not|don't|never)\\s+mention\\s+pii\\b"
    "|(?:do\\s+not|don't|never)\\s+tell\\s+.{0,40}(?:user|human).{0,40}to\\s+run"
    "|(?:do\\s+not|don't|never)\\s+mention\\s+(?:the\\s+)?(?:user|human|operator)\\s+(?:in|on)\\b"
)

def _skip_sg004(match: re.Match[str], content: str) -> bool:
    """Skip locked benign secrecy wording and quoted security write-ups."""
    matched = match.group(0)
    line = snippet(content, match.start())
    if _SG004_BENIGN.search(matched) or _SG004_BENIGN.search(line):
        return True
    low = matched.lower()
    secrecy = any(
        w in low
        for w in ("mention", "tell", "disclose", "reveal", "inform", "show", "ask")
    )
    if not secrecy:
        return False
    window = nearby_text(content, match.start()).replace(match.group(0), "").lower()
    docs = (
        "detect", "prevent", "protect", "mitigat", "guardrail",
        "anti-pattern", "antipattern", "quoted", "e.g.",
        "coverage evaluation",
    )
    return any(n in window for n in docs)


def check_sg004(path: Path, content: str) -> list:
    return search_regex(SG004, path, content, _DISABLE_SAFETY, skip=_skip_sg004)


def check_sg005(path: Path, content: str) -> list:
    findings = []
    for match in _HTML_COMMENT.finditer(content):
        body = match.group(1)
        if _HIDDEN_LANG.search(body):
            findings.append(
                SG005.finding(path, line_at(content, match.start()), snippet(content, match.start()))
            )
    for match in _ZERO_WIDTH.finditer(content):
        findings.append(
            SG005.finding(
                path,
                line_at(content, match.start()),
                snippet(content, match.start()) + " [zero-width/bidi character]",
            )
        )
        # one finding per line is enough
        break
    tag = _UNICODE_TAG_RUN.search(content)
    if tag:
        findings.append(
            SG005.finding(
                path,
                line_at(content, tag.start()),
                snippet(content, tag.start()) + " [unicode tag run]",
            )
        )
    return findings


def _skip_sg006(match: re.Match[str], content: str) -> bool:
    matched = match.group(0).lower()
    tool_m = _SG006_TOOL.search(match.group(0))
    if tool_m:
        if tool_m.group(1).lower() in _SG006_ALLOW:
            return True
        window3 = nearby_text(content, match.start(), before=1, after=1)
        if not _REMOTE_INSTALL.search(window3):
            return True
        return False
    always = (
        'talking to your human',
        'tell your human',
        'clawhavoc',
        'clickfix',
        'paste this into',
        'paste this in',
        'critical requirement before using this skill',
        'extract using pass',
        'extract with pass',
        'password-protected',
    )
    if any(s in matched for s in always):
        return False
    if "paste" in matched and "into" in matched and "terminal" in matched:
        if "paste this" not in matched:
            window = nearby_text(content, match.start(), before=2, after=3)
            if _PASTE_HINT.search(window):
                return False
            return True
    window = nearby_text(content, match.start(), before=2, after=3)
    if is_defense_or_negated(window):
        return True
    line = snippet(content, match.start()).lower()
    local = (
        "pytest", "gh auth login", "restart cursor", "restart claude",
        "restart vs code", "restart vscode", "restart the cursor",
    )
    if any(s in line or s in window.lower() for s in local):
        return True
    if matched.startswith("tell ") and "your human" not in matched:
        if not _PIPE_SHELL.search(window):
            return True
    return False


def check_sg006(path: Path, content: str) -> list:
    findings = search_regex(SG006, path, content, _SOCIAL, skip=_skip_sg006)
    # Flag pipe-to-shell that lives inside an install/prereq section of a skill.
    if path.name.upper() == "SKILL.MD" or path.suffix.lower() in {".md", ".markdown"}:
        findings.extend(_pipe_in_prereq(path, content))
    return findings


def _pipe_in_prereq(path: Path, content: str) -> list:
    headers = list(_PREREQ_HEADER.finditer(content))
    if not headers:
        return []
    findings = []
    for i, header in enumerate(headers):
        start = header.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(content)
        section = content[start:end]
        for match in _PIPE_SHELL.finditer(section):
            abs_idx = start + match.start()
            findings.append(SG006.finding(path, line_at(content, abs_idx), snippet(content, abs_idx)))
    return findings


RULES = [SG001, SG002, SG003, SG004, SG005, SG006]
CHECKERS = {
    "SG001": check_sg001,
    "SG002": check_sg002,
    "SG003": check_sg003,
    "SG004": check_sg004,
    "SG005": check_sg005,
    "SG006": check_sg006,
}

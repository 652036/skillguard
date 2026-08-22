"""Simple i18n for SkillGuard CLI output."""

from __future__ import annotations

from typing import Literal

Lang = Literal["en", "zh"]

# UI strings
UI: dict[str, dict[str, str]] = {
    "en": {
        "scan_header": "SkillGuard scan: {path}",
        "skills_found": "Skills found: {n}",
        "files_scanned": "Files scanned: {n}",
        "findings": "Findings: {n}",
        "no_findings": "No findings.",
        "summary": "Summary: {parts}",
        "severity_critical": "CRITICAL",
        "severity_high": "HIGH",
        "severity_medium": "MEDIUM",
        "severity_low": "LOW",
        "rules_header": "ID       SEV        TITLE",
        "false_positives": "false positives",
    },
    "zh": {
        "scan_header": "SkillGuard 扫描: {path}",
        "skills_found": "发现技能: {n}",
        "files_scanned": "扫描文件: {n}",
        "findings": "发现问题: {n}",
        "no_findings": "未发现问题。",
        "summary": "汇总: {parts}",
        "severity_critical": "严重",
        "severity_high": "高",
        "severity_medium": "中",
        "severity_low": "低",
        "rules_header": "ID       级别       标题",
        "false_positives": "已知误报",
    },
}

# Rule title + description (zh). IDs stay English.
RULE_ZH: dict[str, tuple[str, str]] = {
    "SG001": (
        "忽略先前指令的劫持",
        "技能要求模型忽略先前 / 系统指令。这是经典的提示注入手法，用于覆盖宿主代理的策略。",
    ),
    "SG002": (
        "越狱 / 人格接管",
        "越狱人格（DAN、「你现在是…」）试图替换代理角色并剥离安全策略。",
    ),
    "SG003": (
        "伪造系统角色标记",
        "伪造聊天模板或角色标记（[SYSTEM]、<|im_start|> 等）用于向上下文窗口走私新的系统提示。",
    ),
    "SG004": (
        "关闭安全 / 抑制警告",
        "要求关闭安全过滤器或向人类隐藏警告的指令，被视为敌对策略覆盖。",
    ),
    "SG005": (
        "隐藏指令（HTML 注释 / 零宽字符）",
        "藏在 HTML 注释或零宽 / 双向字符中的指令文本，可对模型可见但对渲染后的 README 不可见。",
    ),
    "SG006": (
        "对人类的社交工程（ClickFix / ClawHavoc）",
        "技能指导代理去说服人类粘贴 shell 命令（curl|bash、helper 下载）。这是 ClawHavoc / ClickFix 模式。",
    ),
    "SG101": (
        "AWS 访问密钥",
        "技能包中提交了 AWS 访问密钥 ID（AKIA…）。",
    ),
    "SG102": (
        "云 / AI 厂商令牌",
        "技能中出现了 OpenAI、Anthropic、GitHub、Slack 等厂商令牌。",
    ),
    "SG103": (
        "通用 API 密钥赋值",
        "发现硬编码的 API 密钥 / 密钥 / 令牌字符串赋值。",
    ),
    "SG104": (
        "私钥 PEM 块",
        "技能中提交了 PEM/OpenSSH 私钥块。",
    ),
    "SG105": (
        "提交的 .env 密钥",
        "技能包中包含带有 key=value 密钥的 .env 文件。",
    ),
    "SG201": (
        "远程脚本管道到 shell",
        "远程内容被下载并在一步中执行（curl|bash、wget|sh、iwr|iex）。",
    ),
    "SG202": (
        "未签名 / 辅助二进制下载",
        "下载未经验证的辅助二进制文件。",
    ),
    "SG203": (
        "读取代理或云凭证路径",
        "技能读取 ~/.ssh、~/.claude、~/.codex、~/.cursor、.env 等凭证路径——典型的凭证窃取行为。",
    ),
    "SG204": (
        "将环境或文件外传到远程 URL",
        "将环境变量或文件内容发送到远程 URL。",
    ),
    "SG205": (
        "对下载文件执行 chmod +x / xattr -c",
        "对下载的文件执行 chmod +x 或 xattr -c（清除隔离属性）。",
    ),
    "SG206": (
        "eval/exec 远程内容",
        "对远程内容进行 eval/exec。",
    ),
    "SG207": (
        "粘贴站暂存器",
        "使用粘贴站（rentry、glot.io、pastebin 等）作为载荷分发点。",
    ),
    "SG301": (
        "有脚本但无许可证",
        "技能附带可执行脚本，但没有 LICENSE / COPYING 文件。",
    ),
    "SG302": (
        "SKILL.md 缺少 name 或 description",
        "Agent Skills 需要 YAML frontmatter 中的 name 和 description，以便宿主安全索引。",
    ),
    "SG303": (
        "过于宽泛的「运行任意命令」",
        "技能授权不受约束的 shell / 命令执行，而不是窄允许列表。",
    ),
    "SG304": (
        "安装 / 前置步骤中的外部 URL",
        "安装或前置步骤会访问网络。标记供审查；单独不会使默认 --fail-on high 扫描失败。",
    ),
    "SG305": (
        "过大的指令文件",
        "指令 / markdown 文件超过 1 MB。填充可能被用来对跳过大文件的扫描器隐藏暂存器。",
    ),
}


def t(key: str, lang: Lang = "en", **kwargs: object) -> str:
    """Translate a UI string."""
    template = UI.get(lang, UI["en"]).get(key) or UI["en"].get(key, key)
    return template.format(**kwargs) if kwargs else template


def severity_label(sev: str, lang: Lang = "en") -> str:
    key = f"severity_{sev.lower()}"
    return t(key, lang)


def rule_display(rule_id: str, title: str, description: str, lang: Lang = "en") -> tuple[str, str]:
    """Return (title, description) possibly translated."""
    if lang == "zh" and rule_id in RULE_ZH:
        return RULE_ZH[rule_id]
    return title, description

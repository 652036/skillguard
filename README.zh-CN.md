# SkillGuard

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)]()

**[English](README.md)** | **[简体中文](README.zh-CN.md)**

**Agent Skills（`SKILL.md`）安全与质量扫描器**  
离线 · 确定性 · 可进 CI · 无遥测

扫描 Claude Code、Cursor、Codex 等宿主加载的 `SKILL.md` 技能包，在 merge 前把危险内容变成红灯。

扫描仓库时也会覆盖宿主指令文件（`AGENTS.md`、`CLAUDE.md`、`GEMINI.md`、`.cursorrules`、`.cursor/rules`、`.github/copilot-instructions.md`、`.github/instructions`），即使已有嵌套的 `SKILL.md` 技能包，也不会漏掉这些文件里的提示注入。发现过程只走本地文件系统，扫描器不访问网络。

---

## 这是什么 / Why SkillGuard?

Agent Skills 是普通目录：一份 `SKILL.md`，外加脚本和资源。宿主会把技能正文当作**高信任指令**喂给模型。一份未审计的技能可以：

- 覆盖系统提示（「ignore previous instructions」、伪造 `[SYSTEM]` / `<|im_start|>`）
- 让模型去**说服人类**粘贴 `curl | bash`（ClawHavoc / ClickFix 风格攻击）
- 读取 `~/.ssh`、`~/.claude`、`~/.codex`、`~/.cursor`、`.env` 并外传
- 把密钥和私钥提交进仓库

SkillGuard 在这些问题进入主分支之前，把它们变成硬性的 CI 失败。

扫描**完全离线、结果可复现**。不访问网络，没有遥测。

---

## 安装

需要 Python 3.11+。

```bash
# 安装当前 main，包含尚未发布的扫描改进
git clone https://github.com/652036/skillguard.git
cd skillguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Windows PowerShell 可直接使用虚拟环境中的 Python：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m skillguard scan examples/clean-review
```

包版本仍为 `0.1.2`；[Unreleased](CHANGELOG.md#unreleased) 中的改动需要当前源码，已有的 `v0.1.2` 标签不包含这些新功能。

---

## 用法

```bash
# 扫描一个技能、一个技能目录、单份 SKILL.md，或整个仓库
#（嵌套技能 + 根目录 AGENTS.md / CLAUDE.md / GEMINI.md / Cursor 规则 / GitHub Copilot）
skillguard scan examples/clean-review          # 应通过，exit 0
skillguard scan examples/toxic-claw            # 应失败，exit 1
skillguard scan examples/                       # 发现多份技能
skillguard scan .                               # 技能包加上宿主指令文件

skillguard scan path/to/skill --format json
skillguard scan path/to/skill --format sarif
skillguard scan path/to/skill --fail-on high     # 默认
skillguard scan path/to/skill --fail-on critical
skillguard scan path/to/skill --fail-on medium
skillguard scan path/to/skill --disable SG301,SG304
skillguard scan path/to/skill --enable SG001,SG201   # 只跑这些规则

# 中文报告
skillguard scan path/to/skill --lang zh
skillguard rules --lang zh

skillguard rules                                 # 列出全部内置规则
```

**规则开关**

`--disable` / `--enable` 会与从扫描路径向上找到的最近一份配置合并。同一目录按以下顺序查找：`skillguard.toml`、`.skillguard.toml`、`.skillguard.yml`、`.skillguard.yaml`、`skillguard.yml`、`skillguard.yaml`。

```toml
disable = ["SG301", "SG304"]
# enable = ["SG001", "SG201"]   # 可选 allow-list
```

`--disable` 与文件里的禁用项合并，`--enable` 覆盖文件里的 allow-list；禁用项始终优先。未知规则 ID 以退出码 2 失败。`skillguard rules` 仍列出全部内置规则。YAML 仅支持顶层 `disable` / `enable` 简单列表，不支持完整 YAML 语法。

**退出码**

- `0` — 干净（没有达到或超过阈值的 finding）
- `1` — 存在 ≥ `--fail-on` 级别的 finding
- `2` — 参数错误或路径不存在

### 扫描范围

| 扫描目标 | 实际覆盖 |
|----------|----------|
| 包含技能的目录 | 可见目录内的每份 `SKILL.md` 技能包，以及技能包之外的宿主指令 |
| 技能目录 | 支持的文本、资源和脚本，包含 `.bat` / `.cmd`；嵌套技能单独归属 |
| 不含 `SKILL.md` 的目录 | 作为散装技能扫描支持的文件，SG302 提示缺少技能元数据 |
| 明确指定的文件 | 只扫描该文件；需要检查配套脚本时应传入目录 |

宿主指令包括 `AGENTS.md`、`CLAUDE.md`、`GEMINI.md`、`.cursorrules`、`.cursor/rules/**`，以及 Copilot 的 `.github/copilot-instructions.md` / `.github/instructions/**`。规则目录接受 `.md`、`.markdown`、`.mdc`、`.txt`。技能包之外的宿主指令单独归组，不产生缺少技能或许可证的 SG301/SG302；报告的 `skills` 列表目前也包含这个宿主分组。

发现过程跳过 `.git`、虚拟环境、缓存、`node_modules`、`build`、`dist` 和普通隐藏目录。扫描隐藏目录中的技能时，请明确传入该技能目录。指定的宿主规则目录和包内 `.ssh` / `.aws` 资源是例外；目录扫描不包含 `.github/workflows` 和 `.cursor/cache`。存在嵌套技能时，包外无关文件不属于仓库扫描范围。

前 8 KiB 含 NUL 字节的文件会跳过。文本优先按 UTF-8 解码，失败时回退 Latin-1，不支持 UTF-16。超过 1,000,000 字节的文件只检查首尾各 256 KiB；超大的指令文件还会触发 SG305，包含 Cursor 规则。中间部分不会检查，尾部 finding 的行号对应截断后文本。扫描通过不能证明技能安全。

---

## 规则

| ID     | 级别       | 标题 |
|--------|------------|------|
| SG001  | high       | 忽略先前指令的劫持 |
| SG002  | critical   | 越狱 / 人格接管 |
| SG003  | critical   | 伪造系统角色标记 |
| SG004  | high       | 关闭安全 / 抑制警告 |
| SG005  | high       | 隐藏指令（HTML 注释 / 零宽字符） |
| SG006  | critical   | 对人类的社交工程（ClickFix / ClawHavoc） |
| SG101  | critical   | AWS 访问密钥 |
| SG102  | critical   | 云 / AI 厂商令牌 |
| SG103  | critical   | 通用 API 密钥赋值 |
| SG104  | critical   | 私钥 PEM 块 |
| SG105  | critical   | 提交的 .env 密钥 |
| SG201  | critical   | 远程脚本管道到 shell |
| SG202  | high       | 未签名 / 辅助二进制下载 |
| SG203  | high       | 读取代理或云凭证路径 |
| SG204  | critical   | 将环境或文件外传到远程 URL |
| SG205  | high       | 对下载文件执行 chmod +x / xattr -c |
| SG206  | critical   | eval/exec 远程内容 |
| SG207  | high       | 粘贴站暂存器 |
| SG301  | medium     | 有脚本但无许可证 |
| SG302  | medium     | SKILL.md 缺少 name 或 description |
| SG303  | medium     | 过于宽泛的「运行任意命令」 |
| SG304  | medium     | 安装 / 前置步骤中的外部 URL |
| SG305  | high       | 过大的指令文件 |

运行 `skillguard rules --lang zh` 可查看每条规则的详细中文说明和已知误报情况。

检测器基于正则 + 轻量字符串/AST 分析，**不是**沙箱。

---

## GitHub Action

```yaml
- uses: 652036/skillguard@v0.1.2   # 已发布的规则开关功能；新功能见 Unreleased
  with:
    path: .
    fail-on: high
    disable: SG301,SG304   # 可选
    # enable: SG001,SG201  # 可选 allow-list
```

要使用当前源码的新功能，可在 checkout 本仓库后使用本地 Action：

```yaml
- uses: ./
  with:
    path: .
    fail-on: high
    disable: SG301,SG304
```

**输入参数**

- `path`（默认 `.`）— 技能目录、技能仓库或 `SKILL.md` 文件
- `fail-on`（默认 `high`）— 使任务失败的最低严重级别（`critical` | `high` | `medium` | `low`）
- `disable`（可选）— 要跳过的规则 ID，逗号分隔（例如 `SG301,SG304`）
- `enable`（可选）— 只运行这些规则 ID（逗号分隔）。为空表示全部规则。

### GitHub code scanning（SARIF）

将 SkillGuard 结果上传到 [GitHub code scanning](https://docs.github.com/zh/code-security/code-scanning)：

```yaml
name: SkillGuard

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/652036/skillguard.git@v0.1.2"
      - name: Scan skills
        run: skillguard scan . --format sarif > skillguard.sarif
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillguard.sarif
```

`--format sarif` 输出 SARIF 2.1.0。`continue-on-error: true` 确保即使扫描因 finding 以退出码 `1` 失败，仍会上传报告。

---

## 示例

| 路径 | 期望结果 |
|------|----------|
| `examples/clean-review/` | 合法的本地 code-review 技能 → 应通过 |
| `examples/toxic-claw/` | **DEMO / 请勿运行**。ClawHavoc 风格夹具 → 应失败 |
| `examples/toxic-clickfix/` | **DEMO / 请勿运行**。ClickFix 相关短语 → 应失败 |

toxic 示例**不含可用恶意载荷**，仅用于触发检测器。

---

## 开发

```bash
pip install -e ".[dev]"
python -m pytest --cov=skillguard --cov-report=term-missing
python -m ruff check src tests scripts
python -m mypy
python scripts/smoke_test.py
python -m build
```

默认测试包含 1,944 组宿主 CLI 组合、配置组合和生成的 1,010 个技能包／4,019 个扫描文件。CI 覆盖 Ubuntu、Windows 上的 Python 3.11–3.14，以及 lint、类型检查、打包和安装 wheel 后的 CLI 检查。测试不会执行被扫描的夹具脚本。

批量测试命令和证据见 [TESTING.md](TESTING.md)；添加规则、测试和文档的要求见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 安全

请通过私密渠道报告漏洞。详见 [SECURITY.md](SECURITY.md)。

---

## 许可证

Apache License 2.0。详见 [LICENSE](LICENSE)。

---

## 路线图

- 更多检测器，降低误报
- 核心离线扫描器将始终保持免费开源

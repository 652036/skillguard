# SkillGuard

Agent Skills（`SKILL.md`）的安全与质量扫描器。离线、确定性、可进 CI。

扫描 Claude Code、Cursor、Codex 等宿主加载的 `SKILL.md` 技能包。

---

## 这是什么 / What & why

Agent Skills 是普通目录：一份 `SKILL.md`，外加脚本和资源。宿主会把技能正文当作高信任指令喂给模型。一份未审计的技能可以：

- 覆盖系统提示（「ignore previous instructions」、伪造 `[SYSTEM]` / `<|im_start|>`）
- 让模型去**说服人类**粘贴 `curl | bash`（ClawHavoc / ClickFix）
- 读取 `~/.ssh`、`~/.claude`、`~/.codex`、`~/.cursor`、`.env` 并外传
- 把密钥和私钥提交进仓库

2025–2026 年间已经出现过把恶意技能当「效率插件」分发的案例。SkillGuard 在 merge 之前把这些问题变成红灯。

Agent Skills are just folders. The host treats `SKILL.md` as high-trust instructions. An unaudited skill can hijack the model, socially-engineer the human (ClawHavoc / ClickFix), steal credential paths, or ship secrets. SkillGuard fails CI when something toxic lands.

扫描**不访问网络**，结果可复现。没有遥测。

Scans are offline and deterministic. No telemetry.

---

## 安装 / Install

需要 Python 3.11+。仓库是私有的，clone 需要有权限。

```bash
git clone https://github.com/652036/skillguard.git
cd skillguard
python3 -m venv .venv && source .venv/bin/activate   # 若系统是 PEP 668，必须用 venv
pip install -e .
pip install -e ".[dev]"   # pytest
```

---

## 用法 / Usage

```bash
# 扫描一个技能、一个技能仓库，或单份 SKILL.md
skillguard scan examples/clean-review          # 应通过，exit 0
skillguard scan examples/toxic-claw            # 应失败，exit 1
skillguard scan examples/                       # 仓库：发现三份技能

skillguard scan path/to/skill --format json
skillguard scan path/to/skill --fail-on high     # 默认
skillguard scan path/to/skill --fail-on critical
skillguard scan path/to/skill --fail-on medium

skillguard rules                                 # 列出内置规则
```

退出码：存在 ≥ `--fail-on` 级别的 finding 时为 `1`；参数错误为 `2`；干净为 `0`。

Exit code `1` if any finding is at least `--fail-on` (default `high`). `2` on bad flags. `0` if clean.

---

## 规则 / Rule IDs

| ID | 级别 | 标题 |
|----|------|------|
| SG001 | high | Ignore-previous instruction hijack |
| SG002 | critical | Jailbreak / persona takeover |
| SG003 | critical | Fake system-role markers |
| SG004 | high | Disable-safety / suppress-warning |
| SG005 | high | Hidden instructions (HTML comment / zero-width) |
| SG006 | critical | Social-engineering the human (ClickFix / ClawHavoc) |
| SG101 | critical | AWS access key |
| SG102 | critical | Cloud / AI vendor token |
| SG103 | critical | Generic API key assignment |
| SG104 | critical | Private key PEM block |
| SG105 | critical | Committed `.env` secrets |
| SG201 | critical | Pipe remote script to a shell |
| SG202 | high | Unsigned / helper binary download |
| SG203 | high | Read of agent or cloud credential paths |
| SG204 | critical | Exfiltrate env or files to a remote URL |
| SG205 | high | `chmod +x` / `xattr -c` on a downloaded file |
| SG206 | critical | eval/exec of remote content |
| SG207 | high | Paste-site stager |
| SG301 | medium | Scripts present but no license |
| SG302 | medium | `SKILL.md` missing name or description |
| SG303 | medium | Overly broad "run any command" |
| SG304 | medium | External URL in install / prerequisite steps |
| SG305 | medium | Oversized instruction file |

`skillguard rules` 会打印每条规则的说明和误报备注。

Detectors are regex + small AST/string scans. They are not a sandbox. False-positive notes live on each rule (`skillguard rules`).

---

## GitHub Action

本仓库是私有的，Action 给本仓库自己的 CI 用，不要写成对外的 `uses: 652036/skillguard@v0.1.0`（目前也没有这个 tag）。

```yaml
# 在已经 checkout 本仓库之后
- uses: ./
  with:
    path: .
    fail-on: high
```

仓库根目录的 `action.yml` 会安装本包并运行 `skillguard scan`。

Inputs: `path` (default `.`), `fail-on` (default `high`).

---

## 示例 / Examples

| 路径 | 期望 |
|------|------|
| `examples/clean-review/` | 合法的本地 code-review 技能，应绿灯 |
| `examples/toxic-claw/` | **DEMO / DO NOT RUN**。ClawHavoc 风格夹具，URL 全是 `example.com`，应红灯 |
| `examples/toxic-clickfix/` | **DEMO / DO NOT RUN**。Published ClickFix phrases only; hosts are `rentry.co/example`, `webhook.site/example`, `203.0.113.1` |

`examples/toxic-claw` 不含可用恶意载荷，只为触发检测器。

---

## 开发 / Develop

```bash
pip install -e ".[dev]"
pytest -q
skillguard scan examples/
```

License: Apache-2.0. See `LICENSE`.

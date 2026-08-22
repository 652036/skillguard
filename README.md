# SkillGuard

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Alpha-orange.svg)]()

**Agent Skills (`SKILL.md`) security & quality scanner.**  
Offline · Deterministic · CI-friendly · No telemetry.

扫描 Claude Code、Cursor、Codex 等宿主加载的 `SKILL.md` 技能包，在 merge 前把恶意或低质量技能变成红灯。

---

## Why SkillGuard? / 这是什么

Agent Skills are ordinary folders containing a `SKILL.md` plus optional scripts/resources. Hosts treat the skill body as **high-trust instructions**. An unaudited skill can:

- Override system prompts (“ignore previous instructions”, fake `[SYSTEM]` / `<|im_start|>` markers)
- Social-engineer the human into pasting `curl | bash` (ClawHavoc / ClickFix style)
- Read credential paths (`~/.ssh`, `~/.claude`, `~/.codex`, `~/.cursor`, `.env`) and exfiltrate them
- Ship secrets and private keys into the repository

SkillGuard turns these problems into hard CI failures **before** they land.

Scans never touch the network. Results are fully reproducible. 没有遥测。

---

## Install / 安装

Requires Python 3.11+.

```bash
# once published to PyPI
pip install skillguard

# or from source
git clone https://github.com/652036/skillguard.git
cd skillguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Usage / 用法

```bash
# Scan a single skill, a directory of skills, or a SKILL.md file
skillguard scan examples/clean-review          # should pass (exit 0)
skillguard scan examples/toxic-claw            # should fail (exit 1)
skillguard scan examples/                       # discovers multiple skills

skillguard scan path/to/skill --format json
skillguard scan path/to/skill --fail-on high     # default
skillguard scan path/to/skill --fail-on critical
skillguard scan path/to/skill --fail-on medium

skillguard rules                                 # list all built-in rules
```

Exit codes:
- `0` — clean (no findings at or above the threshold)
- `1` — findings ≥ `--fail-on` severity
- `2` — invalid arguments / path errors

---

## Rules / 规则

| ID     | Severity  | Title |
|--------|-----------|-------|
| SG001  | high      | Ignore-previous instruction hijack |
| SG002  | critical  | Jailbreak / persona takeover |
| SG003  | critical  | Fake system-role markers |
| SG004  | high      | Disable-safety / suppress-warning |
| SG005  | high      | Hidden instructions (HTML comment / zero-width) |
| SG006  | critical  | Social-engineering the human (ClickFix / ClawHavoc) |
| SG101  | critical  | AWS access key |
| SG102  | critical  | Cloud / AI vendor token |
| SG103  | critical  | Generic API key assignment |
| SG104  | critical  | Private key PEM block |
| SG105  | critical  | Committed `.env` secrets |
| SG201  | critical  | Pipe remote script to a shell |
| SG202  | high      | Unsigned / helper binary download |
| SG203  | high      | Read of agent or cloud credential paths |
| SG204  | critical  | Exfiltrate env or files to a remote URL |
| SG205  | high      | `chmod +x` / `xattr -c` on a downloaded file |
| SG206  | critical  | eval/exec of remote content |
| SG207  | high      | Paste-site stager |
| SG301  | medium    | Scripts present but no license |
| SG302  | medium    | `SKILL.md` missing name or description |
| SG303  | medium    | Overly broad "run any command" |
| SG304  | medium    | External URL in install / prerequisite steps |
| SG305  | high      | Oversized instruction file |

Run `skillguard rules` for full descriptions and false-positive notes.

Detectors are regex + lightweight string/AST checks. They are **not** a sandbox.

---

## GitHub Action

```yaml
- uses: 652036/skillguard@v0.1.0   # after first release tag
  with:
    path: .
    fail-on: high
```

Or from a checked-out copy:

```yaml
- uses: ./
  with:
    path: .
    fail-on: high
```

Inputs: `path` (default `.`), `fail-on` (default `high`).

---

## Examples / 示例

| Path | Expected |
|------|----------|
| `examples/clean-review/` | Legitimate local code-review skill → should pass |
| `examples/toxic-claw/` | **DEMO / DO NOT RUN**. ClawHavoc-style fixture → should fail |
| `examples/toxic-clickfix/` | **DEMO / DO NOT RUN**. ClickFix phrases → should fail |

---

## Development / 开发

```bash
pip install -e ".[dev]"
pytest -q
skillguard scan examples/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add rules, tests, and documentation.

---

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

## Roadmap

- More detectors & reduced false positives
- Configurable rule enable/disable
- SARIF / better reporting
- Core offline scanner will always remain free and open-source

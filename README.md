# SkillGuard

[English](README.md) | [简体中文](README.zh-CN.md)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/652036/skillguard/actions/workflows/ci.yml/badge.svg)](https://github.com/652036/skillguard/actions)

**Security and quality scanner for Agent Skills (`SKILL.md`).**  
Offline · Deterministic · CI-ready · No telemetry

Scan skills used by Claude Code, Cursor, Codex, and similar agent hosts. Catch dangerous or low-quality skills **before** they are merged.

---

## Why SkillGuard?

Agent Skills are ordinary folders containing a `SKILL.md` plus optional scripts and resources. Hosts treat the skill body as **high-trust instructions**. An unaudited skill can:

- Override the system prompt (`ignore previous instructions`, fake `[SYSTEM]` / `<|im_start|>` markers)
- Socially engineer the human into running `curl | bash` (ClawHavoc / ClickFix style attacks)
- Read credential paths (`~/.ssh`, `~/.claude`, `~/.codex`, `~/.cursor`, `.env`) and exfiltrate them
- Ship secrets or private keys into the repository

SkillGuard turns these problems into CI failures **before** they land.

Scans are **completely offline and deterministic**. No network access, no telemetry.

---

## Install

Requires Python 3.11+.

```bash
pip install skillguard          # once published to PyPI

# or from source:
git clone https://github.com/652036/skillguard.git
cd skillguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Usage

```bash
# Scan a single skill, a repo of skills, or a lone SKILL.md
skillguard scan examples/clean-review          # should pass (exit 0)
skillguard scan examples/toxic-claw            # should fail (exit 1)
skillguard scan examples/                      # discovers multiple skills

skillguard scan path/to/skill --format json
skillguard scan path/to/skill --fail-on high     # default
skillguard scan path/to/skill --fail-on critical
skillguard scan path/to/skill --fail-on medium

skillguard rules                                 # list all built-in rules
```

**Exit codes**

| Code | Meaning |
|------|---------|
| `0`  | Clean (no findings at or above `--fail-on`) |
| `1`  | Findings at or above the threshold |
| `2`  | Invalid arguments / path not found |

---

## Rules

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

Detectors use regex + lightweight string/AST analysis. They are **not** a sandbox.

---

## GitHub Action

```yaml
- uses: 652036/skillguard@v0.1.0   # or @main
  with:
    path: .
    fail-on: high
```

Or use the composite action from a checked-out copy:

```yaml
- uses: ./
  with:
    path: .
    fail-on: high
```

**Inputs**

- `path` (default `.`) — skill directory, skills repo, or `SKILL.md`
- `fail-on` (default `high`) — minimum severity that fails the job

---

## Examples

| Path | Expected |
|------|----------|
| `examples/clean-review/` | Clean local code-review skill → should pass |
| `examples/toxic-claw/` | **DEMO / DO NOT RUN** — ClawHavoc-style fixture → should fail |
| `examples/toxic-clickfix/` | **DEMO / DO NOT RUN** — ClickFix phrases only → should fail |

The toxic examples contain **no live malicious payloads**; they exist solely to exercise the detectors.

---

## Development

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

Apache License 2.0 — see [LICENSE](LICENSE).

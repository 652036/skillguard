# SkillGuard

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)]()

**[English](README.md)** | **[简体中文](README.zh-CN.md)**

**Agent Skills (`SKILL.md`) security & quality scanner.**  
Offline · Deterministic · CI-friendly · No telemetry

Scan `SKILL.md` skill packages used by Claude Code, Cursor, Codex and similar hosts. Fail the build when something toxic is about to land.

A repo scan also covers host instruction files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules`, `.github/copilot-instructions.md`, `.github/instructions`) even when nested `SKILL.md` packages exist, so prompt-injection in those files is not skipped. Discovery stays local — the scanner never touches the network.

---

## Why SkillGuard?

Agent Skills are ordinary folders containing a `SKILL.md` plus optional scripts and resources. Hosts treat the skill body as **high-trust instructions**. An unaudited skill can:

- Override system prompts (“ignore previous instructions”, fake `[SYSTEM]` / `<|im_start|>` markers)
- Social-engineer the human into pasting `curl | bash` (ClawHavoc / ClickFix style attacks)
- Read credential paths (`~/.ssh`, `~/.claude`, `~/.codex`, `~/.cursor`, `.env`) and exfiltrate them
- Ship secrets and private keys into the repository

SkillGuard turns these problems into hard CI failures **before** they merge.

Scans never touch the network. Results are fully reproducible. No telemetry.

---

## Install

Requires Python 3.11+.

```bash
# Once published to PyPI
pip install skillguard

# Or from source
git clone https://github.com/652036/skillguard.git
cd skillguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Usage

```bash
# Scan a single skill, a directory of skills, a SKILL.md file, or a repo
# (nested skills + root AGENTS.md / CLAUDE.md / GEMINI.md / Cursor rules / GitHub Copilot)
skillguard scan examples/clean-review          # should pass (exit 0)
skillguard scan examples/toxic-claw            # should fail (exit 1)
skillguard scan examples/                       # discovers multiple skills
skillguard scan .                               # skills plus host instruction files

skillguard scan path/to/skill --format json
skillguard scan path/to/skill --format sarif
skillguard scan path/to/skill --fail-on high     # default
skillguard scan path/to/skill --fail-on critical
skillguard scan path/to/skill --fail-on medium
skillguard scan path/to/skill --disable SG301,SG304
skillguard scan path/to/skill --enable SG001,SG201   # allow-list

skillguard rules                                 # list all built-in rules
```

**Rule filter**

CLI `--disable` / `--enable` combine with an optional config file walked upward from the scan path:

- `skillguard.toml` / `.skillguard.toml`
- `.skillguard.yml` / `skillguard.yml`

```toml
disable = ["SG301", "SG304"]
# enable = ["SG001", "SG201"]   # optional allow-list
```

`--disable` merges with the file. `--enable` replaces a file `enable` list. Unknown ids exit 2. `skillguard rules` still lists the full built-in set.

**Exit codes**

- `0` — clean (no findings at or above the threshold)
- `1` — findings ≥ `--fail-on` severity
- `2` — invalid arguments / path errors

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

Run `skillguard rules` for full descriptions and known false-positive notes.

Detectors are regex + lightweight string/AST checks. They are **not** a sandbox.

---

## GitHub Action

```yaml
- uses: 652036/skillguard@v0.1.2   # after first release tag
  with:
    path: .
    fail-on: high
    disable: SG301,SG304   # optional
    # enable: SG001,SG201  # optional allow-list
```

Or from a checked-out copy of this repository:

```yaml
- uses: ./
  with:
    path: .
    fail-on: high
    disable: SG301,SG304
```

**Inputs**

- `path` (default `.`) — skill directory, skills repo, or a `SKILL.md` file
- `fail-on` (default `high`) — minimum severity that fails the job (`critical` | `high` | `medium` | `low`)
- `disable` (optional) — comma-separated rule ids to skip (e.g. `SG301,SG304`)
- `enable` (optional) — allow-list of rule ids (comma-separated). Empty means all rules.

### GitHub code scanning (SARIF)

Upload SkillGuard findings to [GitHub code scanning](https://docs.github.com/en/code-security/code-scanning):

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
      - run: pip install skillguard
      - name: Scan skills
        run: skillguard scan . --format sarif > skillguard.sarif
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillguard.sarif
```

`--format sarif` writes SARIF 2.1.0. `continue-on-error: true` lets the upload step run even when findings fail the scan (exit `1`).

---

## Examples

| Path | Expected |
|------|----------|
| `examples/clean-review/` | Legitimate local code-review skill → should pass |
| `examples/toxic-claw/` | **DEMO / DO NOT RUN**. ClawHavoc-style fixture → should fail |
| `examples/toxic-clickfix/` | **DEMO / DO NOT RUN**. ClickFix phrases → should fail |

The toxic examples contain **no live malicious payloads**; they exist only to exercise the detectors.

---

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check src tests
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

- More detectors and reduced false positives
- The core offline scanner will always remain free and open-source

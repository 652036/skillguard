# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-source preparation docs (CONTRIBUTING, SECURITY, CHANGELOG)
- Polished README for public release
- Scan Windows `.bat` / `.cmd` skill scripts (discovery, shell role, SG301)
- Scan host instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.cursor/rules`) even when nested `SKILL.md` packages exist
- Scan Gemini (`GEMINI.md`) and GitHub Copilot (`.github/copilot-instructions.md`, `.github/instructions/*.md`) host instruction files even when nested `SKILL.md` packages exist
- A 1,944-case host CLI matrix, 90 config/output combinations, and a deterministic 1,010-package / 4,019-file bulk fixture
- Ubuntu and Windows CI for Python 3.11–3.14, lint/type checks, JUnit and coverage artifacts, and installed-wheel CLI smoke tests
- Batch testing guide and synchronized English/Chinese discovery, filtering, and source-install documentation

### Fixed
- Bound SG204 token-query matching to identifier starts to avoid quadratic scans of long padding strings
- Report oversized `.cursorrules` and `.cursor/rules/*.mdc` files with SG305
- Avoid iterating over every skill root for each host-file ancestry check in large repositories
- Resolve existing lint and duplicate-variable typing errors so static checks run in CI

## [0.1.2] - 2026-09-06

### Added
- Rule enable/disable: `--disable` / `--enable` plus `skillguard.toml` or `.skillguard.yml`
- GitHub Action `disable` / `enable` inputs

## [0.1.1] - 2026-09-06

### Added
- SARIF 2.1.0 output (`skillguard scan --format sarif`) for GitHub code scanning

## [0.1.0] - 2026-08-20

### Added
- Initial release of SkillGuard
- Offline, deterministic scanner for Agent Skills (`SKILL.md` packages)
- Rules covering:
  - Prompt injection / jailbreak / social engineering (SG001–SG006)
  - Secrets detection (SG101–SG105)
  - Dangerous execution patterns (SG201–SG207)
  - Quality checks (SG301–SG305)
- CLI with `scan` and `rules` commands (text / JSON output, `--fail-on`)
- GitHub Action (composite) support
- Positive example (`examples/clean-review`) and toxic demos (`toxic-claw`, `toxic-clickfix`)
- Python 3.11+ support, Apache-2.0 license

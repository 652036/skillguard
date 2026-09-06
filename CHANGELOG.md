# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-source preparation docs (CONTRIBUTING, SECURITY, CHANGELOG)
- Polished README for public release
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

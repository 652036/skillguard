# Contributing to SkillGuard

Thank you for your interest in contributing! SkillGuard aims to be a reliable, offline security scanner for Agent Skills (`SKILL.md`).

## Ways to contribute

- **New rules** – Add detectors for emerging prompt-injection, social-engineering, secret, or execution patterns.
- **False-positive reduction** – Improve existing rules and their `false_positives` notes.
- **Tests** – Expand coverage for edge cases and new examples.
- **Documentation** – Improve README, rule descriptions, architecture notes.
- **Bug reports & feature requests** – Use GitHub Issues.

## Development setup

```bash
git clone https://github.com/652036/skillguard.git
cd skillguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Adding a new rule

1. Choose the appropriate module under `src/skillguard/rules/` (`prompt_injection.py`, `secrets.py`, `execution.py`, or `quality.py`).
2. Define a `Rule` with a unique ID (e.g. `SG0xx` / `SG1xx` / …), severity, title, description, and false-positive notes.
3. Implement the checker function and register it in the module’s `RULES` and `CHECKERS`.
4. Add unit tests under `tests/`.
5. Add a positive and/or negative example under `examples/` if the pattern is non-trivial.
6. Update the rules table in `README.md`.

Rule IDs follow this convention:

| Range   | Category          |
|---------|-------------------|
| SG001–  | Prompt injection  |
| SG101–  | Secrets           |
| SG201–  | Dangerous execution |
| SG301–  | Quality           |

## Code style

- Python 3.11+
- Prefer clear, typed code over cleverness
- Keep detectors offline and deterministic (no network, no LLM calls in the core scanner)
- Run `pytest` and the example checks before opening a PR

## Pull requests

- Keep PRs focused and reasonably small
- Include tests for new behavior
- Update documentation when rules or CLI change
- One logical change per PR when possible

## Reporting security issues

Please see [SECURITY.md](SECURITY.md). Do **not** open a public issue for vulnerabilities in SkillGuard itself.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

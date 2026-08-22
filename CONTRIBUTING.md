# Contributing to SkillGuard

Thank you for your interest in contributing!

SkillGuard aims to be a reliable, offline, and deterministic security & quality scanner for Agent Skills (`SKILL.md`). We welcome contributions of all kinds.

## Ways to contribute

- Report bugs or suggest features via [Issues](https://github.com/652036/skillguard/issues)
- Improve documentation or translations
- Add or refine detection rules
- Expand tests and examples
- Fix bugs or improve performance / code quality

## Development setup

```bash
git clone https://github.com/652036/skillguard.git
cd skillguard
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
skillguard scan examples/
```

## Adding a new rule

1. Add or extend a module under `src/skillguard/rules/` (follow the existing pattern in `base.py`).
2. Define a `Rule` with:
   - `id` (e.g. `SG4xx`)
   - `severity`
   - `title` / `description` / `false_positives`
   - `applies_to` file roles
3. Implement the checker function and register it.
4. Add unit tests in `tests/`.
5. Update the rules table in `README.md` if appropriate.
6. Verify with:
   ```bash
   skillguard rules
   skillguard scan examples/
   pytest -q
   ```

**Important principles for rules:**
- Must remain **offline** and **deterministic** (no network calls, no non-deterministic models).
- Prefer simple, explainable detectors (regex + lightweight string/AST analysis).
- Document known false-positive cases clearly.

## Code style

- Python 3.11+
- Type hints encouraged
- Keep the dependency footprint small
- Focus on clarity and maintainability

## Pull requests

- Keep PRs focused and reasonably sized
- Include tests for new behavior
- Update `CHANGELOG.md` under the `[Unreleased]` section
- Describe the motivation and any trade-offs

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

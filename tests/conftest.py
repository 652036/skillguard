from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
CLEAN = EXAMPLES / "clean-review"
TOXIC = EXAMPLES / "toxic-claw"


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture
def clean_skill() -> Path:
    return CLEAN


@pytest.fixture
def toxic_skill() -> Path:
    return TOXIC


@pytest.fixture
def examples_dir() -> Path:
    return EXAMPLES

"""Collect a local git diff for the reviewer. No network."""

from __future__ import annotations

import subprocess
import sys


def main() -> None:
    result = subprocess.run(
        ["git", "diff", "--cached"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fallback = subprocess.run(
            ["git", "diff"],
            capture_output=True,
            text=True,
            check=False,
        )
        sys.stdout.write(fallback.stdout)
        return
    sys.stdout.write(result.stdout)


if __name__ == "__main__":
    main()

"""Typer CLI for SkillGuard."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from skillguard import __version__
from skillguard.models import Severity, parse_severity
from skillguard.report import render_json, render_text
from skillguard.rules import list_rules
from skillguard.scan import scan_path

app = typer.Typer(
    name="skillguard",
    help="Scan Agent Skills (SKILL.md packages) for security and quality issues.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"skillguard {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """SkillGuard CLI."""


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Skill dir, repo, or SKILL.md"),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text or json.",
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Minimum severity that yields exit code 1: critical, high, medium, low.",
    ),
) -> None:
    """Scan a skill directory, a repo of skills, or a SKILL.md file."""
    fmt = output_format.lower()
    if fmt not in {"text", "json"}:
        typer.echo("error: --format must be 'text' or 'json'", err=True)
        raise typer.Exit(code=2)
    try:
        threshold = parse_severity(fail_on)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        result = scan_path(path)
    except FileNotFoundError as exc:
        typer.echo(f"error: path not found: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    rendered = render_json(result) if fmt == "json" else render_text(result)
    typer.echo(rendered, nl=False)

    if result.failing(threshold):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command("rules")
def rules_cmd() -> None:
    """List built-in rules."""
    typer.echo(f"{'ID':<8} {'SEV':<10} TITLE")
    typer.echo("-" * 72)
    for rule in list_rules():
        typer.echo(f"{rule.id:<8} {rule.severity.value:<10} {rule.title}")
        typer.echo(f"         {rule.description}")
        typer.echo(f"         false positives: {rule.false_positives}")
        typer.echo("")
    raise typer.Exit(code=0)

"""Typer CLI for SkillGuard."""

from __future__ import annotations

from pathlib import Path

import typer

from skillguard import __version__
from skillguard.config import resolve_filter
from skillguard.i18n import Lang, rule_display, t
from skillguard.models import parse_severity
from skillguard.report import render_json, render_sarif, render_text
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
    version: bool | None = typer.Option(
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
        help="Output format: text, json, or sarif.",
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Minimum severity that yields exit code 1: critical, high, medium, low.",
    ),
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Report language: en or zh.",
    ),
    disable: str = typer.Option(
        "",
        "--disable",
        help="Comma-separated rule ids to skip (e.g. SG301,SG304). Merges with skillguard.toml.",
    ),
    enable: str = typer.Option(
        "",
        "--enable",
        help="Allow-list: only run these rule ids. Overrides config enable if set.",
    ),
) -> None:
    """Scan a skill directory, a repo of skills, or a SKILL.md file."""
    fmt = output_format.lower()
    if fmt not in {"text", "json", "sarif"}:
        typer.echo("error: --format must be 'text', 'json', or 'sarif'", err=True)
        raise typer.Exit(code=2)
    lang_norm = lang.lower().strip()
    if lang_norm not in {"en", "zh"}:
        typer.echo("error: --lang must be 'en' or 'zh'", err=True)
        raise typer.Exit(code=2)
    lang_typed: Lang = "zh" if lang_norm == "zh" else "en"  # type: ignore[assignment]
    try:
        threshold = parse_severity(fail_on)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        rule_filter = resolve_filter(start=path, disable_cli=disable, enable_cli=enable)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        result = scan_path(path, rule_filter=rule_filter)
    except FileNotFoundError as exc:
        typer.echo(f"error: path not found: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if fmt == "json":
        rendered = render_json(result)
    elif fmt == "sarif":
        rendered = render_sarif(result)
    else:
        rendered = render_text(result, lang=lang_typed)
    typer.echo(rendered, nl=False)

    if result.failing(threshold):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command("rules")
def rules_cmd(
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Language: en or zh.",
    ),
) -> None:
    """List built-in rules."""
    lang_norm = lang.lower().strip()
    if lang_norm not in {"en", "zh"}:
        typer.echo("error: --lang must be 'en' or 'zh'", err=True)
        raise typer.Exit(code=2)
    lang_typed: Lang = "zh" if lang_norm == "zh" else "en"  # type: ignore[assignment]

    typer.echo(t("rules_header", lang_typed))
    typer.echo("-" * 72)
    for rule in list_rules():
        title, description = rule_display(rule.id, rule.title, rule.description, lang_typed)
        sev = rule.severity.value
        typer.echo(f"{rule.id:<8} {sev:<10} {title}")
        typer.echo(f"         {description}")
        typer.echo(f"         {t('false_positives', lang_typed)}: {rule.false_positives}")
        typer.echo("")
    raise typer.Exit(code=0)

"""``lory-scan rules`` — see what the scanner looks for, and check your own rules."""

from __future__ import annotations

import json
import sys

import click
from rich.panel import Panel
from rich.table import Table

from lory_scanner.cli.common import EXIT_ERROR, console, die
from lory_scanner.core.errors import RuleError
from lory_scanner.core.severity import SEVERITY_ORDER, SEVERITY_STYLE, rank
from lory_scanner.engine.rules import load_rules

_RULE_DIRS = click.option(
    "--rules", "rule_dirs", multiple=True, type=click.Path(exists=True),
    help="Extra rule file or directory. Repeatable.",
)
_NO_BUNDLED = click.option(
    "--no-default-rules", is_flag=True, help="Use only --rules, not the bundled set."
)


@click.group()
def rules() -> None:
    """List, inspect, and validate detection rules."""


@rules.command("list")
@_RULE_DIRS
@_NO_BUNDLED
@click.option("--category", help="Only rules in this category.")
@click.option("--language", help="Only rules that apply to this language.")
@click.option("--severity", type=click.Choice(SEVERITY_ORDER), help="Only rules at this severity.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table.")
def rules_list(
    rule_dirs: tuple[str, ...], no_default_rules: bool, category: str | None,
    language: str | None, severity: str | None, as_json: bool,
) -> None:
    """List the rules that would run."""
    ruleset = _load(rule_dirs, no_default_rules)

    selected = [
        rule for rule in ruleset
        if (not category or rule.category == category)
        and (not language or rule.applies_to_language(language))
        and (not severity or rule.severity == severity)
    ]
    selected.sort(key=lambda r: (rank(r.severity), r.id))

    if as_json:
        click.echo(json.dumps([_as_dict(r) for r in selected], indent=2))
        return

    if not selected:
        console.print("[dim]No rules matched.[/dim]")
        return

    table = Table(box=None, pad_edge=False, header_style="bold")
    table.add_column("severity")
    table.add_column("id")
    table.add_column("cwe", style="dim")
    table.add_column("languages", style="dim", max_width=28)
    table.add_column("title", overflow="fold")

    for rule in selected:
        table.add_row(
            f"[{SEVERITY_STYLE[rule.severity]}] {rule.severity} [/]",
            rule.id,
            rule.cwe or "—",
            ", ".join(sorted(rule.languages)),
            rule.title,
        )

    console.print(table)
    console.print(f"\n[dim]{len(selected)} of {len(ruleset)} rules[/dim]")


@rules.command("show")
@click.argument("rule_id")
@_RULE_DIRS
@_NO_BUNDLED
@click.option("--json", "as_json", is_flag=True)
def rules_show(
    rule_id: str, rule_dirs: tuple[str, ...], no_default_rules: bool, as_json: bool
) -> None:
    """Show one rule in full, including the patterns it matches on."""
    ruleset = _load(rule_dirs, no_default_rules)
    rule = ruleset.by_id(rule_id)
    if rule is None:
        die(f"no rule {rule_id!r}. Run `lory-scan rules list` to see them all.")
        return

    if as_json:
        click.echo(json.dumps(_as_dict(rule, patterns=True), indent=2))
        return

    body = Table.grid(padding=(0, 2))
    body.add_column(style="dim", justify="right")
    body.add_column(overflow="fold")
    body.add_row("severity", f"[{SEVERITY_STYLE[rule.severity]}] {rule.severity} [/]")
    body.add_row("confidence", rule.confidence)
    body.add_row("category", rule.category)
    body.add_row("cwe", rule.cwe or "—")
    if rule.owasp:
        body.add_row("owasp", rule.owasp)
    body.add_row("languages", ", ".join(sorted(rule.languages)))
    if rule.description:
        body.add_row("what", rule.description)
    if rule.remediation:
        body.add_row("fix", rule.remediation)
    for index, pattern in enumerate(rule.patterns, 1):
        body.add_row(f"pattern {index}" if len(rule.patterns) > 1 else "pattern", pattern.pattern)
    for pattern in rule.not_patterns:
        body.add_row("unless", pattern.pattern)
    if rule.references:
        body.add_row("refs", "\n".join(rule.references))
    body.add_row("from", rule.origin)

    console.print(Panel(body, title=f"[bold]{rule.id}[/bold] — {rule.title}", title_align="left"))


@rules.command("validate")
@_RULE_DIRS
@_NO_BUNDLED
def rules_validate(rule_dirs: tuple[str, ...], no_default_rules: bool) -> None:
    """Check that every rule loads, compiles, and carries usable metadata.

    Loading is the hard check — a bad regex or a duplicate id fails there. The
    rest are warnings about rules that will fire but read badly in a report:
    no CWE to look up, no remediation to act on, no prefilter to keep it fast.
    """
    try:
        ruleset = _load(rule_dirs, no_default_rules)
    except SystemExit:
        raise
    except RuleError as exc:
        die(str(exc))
        return

    warnings: list[str] = []
    failures: list[str] = []
    without_prefilter = 0
    examples_run = 0
    rules_with_examples = 0

    for rule in ruleset:
        if rule.examples or rule.counterexamples:
            rules_with_examples += 1
        for example in rule.examples:
            examples_run += 1
            if not rule.matches(example):
                failures.append(
                    f"{rule.id}: should match but does not: {example!r}"
                    + (
                        f"  (prefilters {list(rule.prefilters)} rejected it)"
                        if not rule.may_match(example.lower())
                        else ""
                    )
                )
        for example in rule.counterexamples:
            examples_run += 1
            if rule.matches(example):
                failures.append(f"{rule.id}: should not match but does: {example!r}")

        if not rule.cwe:
            warnings.append(f"{rule.id}: no cwe, so a report cannot link the class")
        if not rule.remediation:
            warnings.append(f"{rule.id}: no remediation — the report will have nothing to advise")
        if not rule.description:
            warnings.append(f"{rule.id}: no description")
        if not rule.prefilters:
            # Not a defect. A rule whose patterns share no mandatory literal
            # — anything with an alternation — cannot have one, and correctness
            # comes first: a wrong prefilter would skip real findings.
            without_prefilter += 1

    if failures:
        console.print(f"[bold red]{len(failures)} rule self-tests failed[/bold red]")
        for failure in failures:
            console.print(f"  [red]·[/red] {failure}")
        sys.exit(EXIT_ERROR)

    console.print(f"[green]OK[/green] {len(ruleset)} rules loaded and compiled")
    console.print(
        f"[dim]{len(ruleset.categories())} categories · "
        f"{len(ruleset.languages())} languages · "
        f"{len(ruleset) - without_prefilter}/{len(ruleset)} with a literal prefilter[/dim]"
    )

    console.print(
        f"[dim]{examples_run} self-tests passed across {rules_with_examples} rules[/dim]"
    )

    if warnings:
        console.print(f"\n[yellow]{len(warnings)} metadata warnings[/yellow]")
        for warning in warnings:
            console.print(f"  [dim]·[/dim] {warning}")


def _load(rule_dirs: tuple[str, ...], no_default_rules: bool):
    from pathlib import Path

    try:
        return load_rules(
            dirs=[Path(d) for d in rule_dirs], include_bundled=not no_default_rules
        )
    except RuleError as exc:
        console.print(f"[bold red]error:[/bold red] {exc}")
        sys.exit(EXIT_ERROR)


def _as_dict(rule, patterns: bool = False) -> dict:
    data = {
        "id": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "category": rule.category,
        "cwe": rule.cwe,
        "owasp": rule.owasp,
        "languages": sorted(rule.languages),
        "description": rule.description,
        "remediation": rule.remediation,
        "references": list(rule.references),
        "tags": list(rule.tags),
    }
    if patterns:
        data["patterns"] = [p.pattern for p in rule.patterns]
        data["not_patterns"] = [p.pattern for p in rule.not_patterns]
        data["origin"] = rule.origin
    return data

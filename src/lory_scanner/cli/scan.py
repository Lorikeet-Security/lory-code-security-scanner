"""``lory-scan scan`` — the scan, and ``lory-scan sync`` — the scan, handed to the TUI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from lory_scanner import __version__
from lory_scanner.cli.common import (
    EXIT_FINDINGS,
    EXIT_OK,
    build_scanner,
    console,
    die,
    err_console,
    scan_options,
)
from lory_scanner.core.errors import ScannerError
from lory_scanner.engine.scanner import ScanResult, baseline_document
from lory_scanner.report import formats, lory


@click.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@scan_options
@click.option("--format", "-f", "fmt", type=click.Choice(formats.FORMATS),
              default="table", show_default=True, help="Output format.")
@click.option("--out", "-o", type=click.Path(dir_okay=False),
              help="Write output to a file instead of stdout.")
@click.option("--emit-lory-cache", "emit_cache", is_flag=True,
              help="Also write the findings cache that `lory` reads (see `lory-scan sync`).")
@click.option("--state-dir", type=click.Path(file_okay=False),
              help="Where --emit-lory-cache writes.  [default: <path>/.lory_state]")
@click.option("--write-baseline", type=click.Path(dir_okay=False),
              help="Write this run's findings to a baseline file instead of reporting them.")
@click.option("--no-snippets", is_flag=True, help="Omit source lines from the table view.")
@click.option("--quiet", "-q", is_flag=True, help="Findings only; no summary or progress.")
def scan(
    path: str, fmt: str, out: str | None, emit_cache: bool, state_dir: str | None,
    write_baseline: str | None, no_snippets: bool, quiet: bool,
    config_path: str | None, diff: str | None, staged: bool,
    ignore_suppressions: bool, **flags: object,
) -> None:
    """Scan PATH for security problems. Defaults to the current directory.

    \b
    ──────────────────────────────────────────────────────────────────────────
    EXAMPLES
    ──────────────────────────────────────────────────────────────────────────
      lory-scan scan                        Scan here, print a report.
      lory-scan scan src --min-severity high
      lory-scan scan --diff origin/main     Only what this branch changed.
      lory-scan scan -f sarif -o out.sarif  For GitHub code scanning.
      lory-scan sync                        Scan, then open it in `lory tui`.

    \b
    ──────────────────────────────────────────────────────────────────────────
    EXIT CODES
    ──────────────────────────────────────────────────────────────────────────
      0  no findings at or above --fail-on (default: high)
      1  findings at or above --fail-on
      2  the scan could not run
    """
    try:
        scanner, cfg = build_scanner(
            path, config_path, ignore_suppressions=ignore_suppressions, **flags
        )
        result = (
            scanner.run_diff(diff, staged) if (diff is not None or staged) else scanner.run()
        )
    except ScannerError as exc:
        die(str(exc))
        return

    if write_baseline:
        _write_baseline(result, Path(write_baseline), quiet)
        sys.exit(EXIT_OK)

    if emit_cache or fmt == "lory-cache":
        target = Path(state_dir) if state_dir else (cfg.root / ".lory_state")
        written = lory.write_cache(result, target)
        if not quiet and fmt not in formats.MACHINE_FORMATS:
            console.print(
                f"[dim]wrote {len(result.findings)} findings to {written} — "
                f"open them with[/dim] lory tui --cached"
            )

    _emit(result, fmt, out, quiet, no_snippets)

    sys.exit(EXIT_FINDINGS if result.should_fail(cfg.fail_on) else EXIT_OK)


@click.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@scan_options
@click.option("--state-dir", type=click.Path(file_okay=False),
              help="The TUI's state directory.  [default: <path>/.lory_state]")
@click.option("--replace", is_flag=True,
              help="Drop platform findings already in the cache instead of keeping them.")
@click.option("--quiet", "-q", is_flag=True, help="Say nothing on success.")
def sync(
    path: str, state_dir: str | None, replace: bool, quiet: bool,
    config_path: str | None, diff: str | None, staged: bool,
    ignore_suppressions: bool, **flags: object,
) -> None:
    """Scan PATH and hand the findings to `lory`, the findings TUI.

    Writes the cache that `lory-code-security` already reads, so its whole
    workflow — list, show, trace, fix, triage — works on locally scanned
    findings with no configuration and no credential:

    \b
      lory-scan sync            # scan this repo into .lory_state/findings.json
      lory tui --cached         # triage what it found

    Findings pulled from the Lorikeet platform stay in the cache alongside the
    scanner's, so a local scan never makes the platform's findings vanish.
    Pass --replace to drop them.
    """
    try:
        scanner, cfg = build_scanner(
            path, config_path, ignore_suppressions=ignore_suppressions, **flags
        )
        result = (
            scanner.run_diff(diff, staged) if (diff is not None or staged) else scanner.run()
        )
        target = Path(state_dir) if state_dir else (cfg.root / ".lory_state")
        written = lory.write_cache(result, target, merge=not replace)
    except ScannerError as exc:
        die(str(exc))
        return

    if not quiet:
        tally = result.severity_counts()
        summary = ", ".join(
            f"{count} {name}" for name, count in tally.items() if count
        ) or "no findings"
        console.print(f"[bold]{len(result.findings)}[/bold] findings ({summary}) → {written}")
        console.print("[dim]triage them with[/dim] lory tui --cached")

    sys.exit(EXIT_FINDINGS if result.should_fail(cfg.fail_on) else EXIT_OK)


def _emit(result: ScanResult, fmt: str, out: str | None, quiet: bool, no_snippets: bool) -> None:
    """Write the report where it was asked to go.

    The table is rendered by Rich rather than returned as a string, so it is
    the one format that has to know about its destination.
    """
    if fmt == "table":
        if out is None:
            formats.print_table(console, result, show_snippets=not no_snippets)
            return
        from rich.console import Console

        with open(out, "w") as handle:
            formats.print_table(
                Console(file=handle, width=100), result, show_snippets=not no_snippets
            )
        if not quiet:
            err_console.print(f"[dim]wrote {len(result.findings)} findings to {out}[/dim]")
        return

    text = formats.render(result, fmt, __version__)

    if out:
        Path(out).write_text(text)
        if not quiet:
            err_console.print(
                f"[dim]wrote {len(result.findings)} findings to {out} ({fmt})[/dim]"
            )
        return

    click.echo(text)


def _write_baseline(result: ScanResult, path: Path, quiet: bool) -> None:
    """Record every current finding as known, so future runs show only new ones."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline_document(result), indent=2))
    if not quiet:
        err_console.print(
            f"[dim]baselined {len(result.findings)} findings to {path}. "
            f"Future scans with --baseline {path} report only what is new.[/dim]"
        )

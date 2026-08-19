"""The remaining output formats, and the one place that picks between them.

Every format is a pure function of the :class:`ScanResult`, so the CLI never
has to know how a format is built — only which one was asked for.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from lory_scanner.core.severity import SEVERITY_ORDER, SEVERITY_STYLE
from lory_scanner.engine.scanner import ScanResult
from lory_scanner.report import lory, sarif

#: Every value `--format` accepts. `describe` reports this list, so a caller
#: can discover the formats instead of hardcoding them.
FORMATS = ("table", "json", "sarif", "lory-json", "lory-cache", "csv", "markdown")

#: Formats meant for a machine. The CLI keeps its progress and summary chatter
#: off stdout for these, so the output is parseable without a --quiet flag.
MACHINE_FORMATS = frozenset({"json", "sarif", "lory-json", "lory-cache", "csv"})


def render(result: ScanResult, fmt: str, version: str) -> str:
    if fmt == "json":
        return render_json(result, version)
    if fmt == "sarif":
        return sarif.render(result, version)
    if fmt in ("lory-json", "lory-cache"):
        return lory.render(result)
    if fmt == "csv":
        return render_csv(result)
    if fmt == "markdown":
        return render_markdown(result)
    raise ValueError(f"unknown format: {fmt}")


def render_json(result: ScanResult, version: str) -> str:
    """The native format: findings plus the stats that explain the run."""
    from lory_scanner import CONTRACT_VERSION

    return json.dumps(
        {
            "tool": "lory-scan",
            "version": version,
            "contract_version": CONTRACT_VERSION,
            "scan": result.stats_dict(),
            "findings": [f.to_dict() for f in result.findings],
        },
        indent=2,
    )


def render_csv(result: ScanResult) -> str:
    columns = [
        "key", "severity", "confidence", "rule_id", "path", "line",
        "title", "cwe", "category", "match",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for finding in result.findings:
        writer.writerow(finding.to_dict())
    return buffer.getvalue()


def render_markdown(result: ScanResult) -> str:
    """A report to paste into a pull request or a ticket."""
    tally = result.severity_counts()
    lines = [
        "# Security scan",
        "",
        f"`lory-scan` scanned **{result.stats.scanned} files** in "
        f"{result.duration_ms} ms with {result.rules_run} rules "
        f"and found **{len(result.findings)}** findings.",
        "",
        "| " + " | ".join(s.title() for s in SEVERITY_ORDER) + " |",
        "|" + "---|" * len(SEVERITY_ORDER),
        "| " + " | ".join(str(tally[s]) for s in SEVERITY_ORDER) + " |",
        "",
    ]

    if not result.findings:
        lines.append("No findings at or above the configured severity floor.")
        return "\n".join(lines)

    for finding in result.findings:
        lines += [
            f"## {finding.severity.upper()} — {finding.title}",
            "",
            f"- **Where:** `{finding.location}`",
            f"- **Rule:** `{finding.rule_id}` ({finding.confidence} confidence)",
        ]
        if finding.cwe:
            lines.append(f"- **CWE:** {finding.cwe}")
        lines += ["", "```", finding.snippet, "```", ""]
        if finding.description:
            lines += [finding.description, ""]
        if finding.remediation:
            lines += [f"**Fix:** {finding.remediation}", ""]

    return "\n".join(lines)


# ── the terminal view ───────────────────────────────────────────────────────


def print_table(console: Any, result: ScanResult, show_snippets: bool = True) -> None:
    """The default human view: one block per finding, worst first.

    A table of one-line rows was the first shape this took, and it was worse:
    the whole value of a static finding is the line of code, and a truncated
    cell in a 100-column terminal hid exactly that.
    """
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text

    if not result.findings:
        console.print("[green]No findings.[/green]")
        print_summary(console, result)
        return

    for finding in result.findings:
        style = SEVERITY_STYLE.get(finding.severity, "")
        header = Text()
        header.append(f" {finding.severity.upper()} ", style=style)
        header.append(f" {finding.title}", style="bold")

        body = Table.grid(padding=(0, 1))
        body.add_column(style="dim", justify="right")
        body.add_column(overflow="fold")
        body.add_row("where", f"[link=file://{finding.path}]{finding.location}[/]")
        body.add_row("rule", f"{finding.rule_id}  [dim]({finding.confidence} confidence)[/dim]")
        if finding.cwe:
            body.add_row("cwe", finding.cwe)
        body.add_row("id", finding.key)

        if show_snippets and finding.snippet:
            body.add_row(
                "code",
                Syntax(
                    finding.snippet, _lexer(finding.language),
                    theme="ansi_dark", line_numbers=False, word_wrap=True,
                ),
            )
        if finding.description:
            body.add_row("why", finding.description)
        if finding.remediation:
            body.add_row("fix", finding.remediation)
        if finding.suppressed_by:
            body.add_row("note", f"[yellow]suppressed by: {finding.suppressed_by}[/yellow]")

        console.print(Panel(body, title=header, title_align="left", border_style=style or "dim"))

    print_summary(console, result)


def print_summary(console: Any, result: ScanResult) -> None:
    """The line a reader takes away, plus what the run did not look at."""
    from rich.text import Text

    tally = result.severity_counts()
    line = Text()
    for severity in SEVERITY_ORDER:
        if tally[severity]:
            line.append(f" {tally[severity]} {severity} ", style=SEVERITY_STYLE[severity])
            line.append(" ")

    if line.plain.strip():
        console.print(line)

    console.print(
        f"[dim]{result.stats.scanned} files · {result.rules_run} rules · "
        f"{result.duration_ms} ms[/dim]"
    )

    notes = []
    if result.suppressed:
        notes.append(f"{result.suppressed} suppressed inline")
    if result.baselined:
        notes.append(f"{result.baselined} in baseline")
    if result.filtered:
        notes.append(f"{result.filtered} below thresholds")
    if result.truncated:
        notes.append("output truncated by max_findings")
    if notes:
        console.print(f"[dim]not shown: {', '.join(notes)}[/dim]")


def _lexer(language: str) -> str:
    return {
        "javascript": "javascript", "typescript": "typescript", "python": "python",
        "php": "php", "ruby": "ruby", "go": "go", "java": "java", "csharp": "csharp",
        "rust": "rust", "shell": "bash", "sql": "sql", "yaml": "yaml", "json": "json",
        "html": "html", "terraform": "terraform", "dockerfile": "docker",
    }.get(language, "text")

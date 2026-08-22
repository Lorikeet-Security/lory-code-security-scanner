"""Shared CLI plumbing: consoles, exit codes, and the scan-shaped options.

`scan` and `sync` take the same forty-odd options because they are the same
scan with a different destination. Declaring them once, here, is what keeps
them from drifting apart.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import click
from rich.console import Console

from lory_scanner.core.config import ScanConfig
from lory_scanner.core.config import load as load_config
from lory_scanner.core.severity import SEVERITY_ORDER
from lory_scanner.engine.scanner import Scanner

#: Findings go to stdout so they can be piped; everything else goes to stderr
#: so piping stdout never captures a progress line as data.
console = Console()
err_console = Console(stderr=True)

#: 0 clean · 1 findings at or above --fail-on · 2 the scan could not run.
#: Documented in `lory-scan describe`, because a caller branching on these
#: should be able to read them rather than assume them.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
#: Ctrl-C. The shell convention (128 + SIGINT), kept distinct from 1 so an
#: abandoned scan is not mistaken for a failing one.
EXIT_INTERRUPTED = 130

F = TypeVar("F", bound=Callable[..., Any])


def die(message: str) -> None:
    err_console.print(f"[bold red]error:[/bold red] {message}")
    sys.exit(EXIT_ERROR)


def scan_options(func: F) -> F:
    """Every option that shapes a scan, applied to `scan` and `sync` alike."""
    options = [
        click.option("--config", "config_path", type=click.Path(dir_okay=False),
                     envvar="LORY_SCAN_CONFIG",
                     help="Config file. Default: .lory-scan.yml at the scan root or above."),
        click.option("--rules", "rule_dirs", multiple=True,
                     type=click.Path(exists=True, file_okay=True),
                     help="Extra rule file or directory. Repeatable."),
        click.option("--no-default-rules", is_flag=True, default=None,
                     help="Use only --rules, not the bundled ruleset."),
        click.option("--select", multiple=True, metavar="GLOB",
                     help="Only run rules matching this id glob. Repeatable."),
        click.option("--ignore-rule", "ignore_rules", multiple=True, metavar="GLOB",
                     help="Skip rules matching this id glob. Repeatable."),
        click.option("--category", "categories", multiple=True,
                     help="Only run rules in this category. Repeatable."),
        click.option("--include", multiple=True, metavar="GLOB",
                     help="Only scan paths matching this glob. Repeatable."),
        click.option("--exclude", multiple=True, metavar="GLOB",
                     help="Skip paths matching this glob. Repeatable."),
        click.option("--min-severity", type=click.Choice(SEVERITY_ORDER),
                     help="Drop findings below this severity.  [default: info]"),
        click.option("--min-confidence", type=click.Choice(["high", "medium", "low"]),
                     help="Drop findings below this confidence.  [default: low]"),
        click.option("--fail-on", type=click.Choice([*SEVERITY_ORDER, "never"]),
                     help="Exit 1 when a finding reaches this severity.  [default: high]"),
        click.option("--no-entropy", "entropy", flag_value=False, default=None,
                     help="Skip generic high-entropy secret detection."),
        click.option("--entropy-threshold", type=float,
                     help="Bits per character before a string counts as secret-like."),
        click.option("--no-gitignore", "respect_gitignore", flag_value=False, default=None,
                     help="Scan files git ignores."),
        click.option("--no-suppressions", "suppressions", flag_value=False, default=None,
                     help="Do not honour lory-scan:ignore comments."),
        click.option("--ignore-suppressions", is_flag=True,
                     help="Report suppressed findings anyway, marked as suppressed."),
        click.option("--baseline", type=click.Path(dir_okay=False),
                     help="Suppress findings whose fingerprint is in this baseline."),
        click.option("--max-file-size", "max_file_bytes", type=int, metavar="BYTES",
                     help="Skip files larger than this.  [default: 2000000]"),
        click.option("--max-findings", type=int, metavar="N",
                     help="Stop after N findings. 0 means no cap."),
        click.option("--diff", metavar="REF",
                     help="Only scan files changed against this git ref."),
        click.option("--staged", is_flag=True, help="Only scan files staged in git."),
        click.option("--jobs", "-j", type=int, metavar="N",
                     help="Worker processes to scan with. 0 picks a number from the "
                          "machine's cores; 1 stays in this process."),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def build_scanner(
    path: str,
    config_path: str | None,
    ignore_suppressions: bool = False,
    **flags: Any,
) -> tuple[Scanner, ScanConfig]:
    """Resolve config + flags into a ready Scanner.

    Flags whose value is None were not given, and :meth:`ScanConfig.merge_cli`
    leaves those alone — which is what lets a config file value survive a flag
    the user did not type.
    """
    root = Path(path).expanduser().resolve()

    # `jobs` shapes how the scan runs, not what it finds, so it is a Scanner
    # argument rather than part of the config a repository commits.
    jobs = flags.pop("jobs", None)

    cfg = load_config(config_path, root)
    cfg = cfg.merge_cli(
        rule_dirs=[Path(p) for p in flags.pop("rule_dirs", ()) or ()] or None,
        baseline=Path(flags["baseline"]) if flags.get("baseline") else None,
        **{k: v for k, v in flags.items() if k != "baseline"},
    ).check()

    return Scanner(cfg, ignore_suppressions=ignore_suppressions, jobs=jobs), cfg

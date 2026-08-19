"""``lory-scan init`` — set a repository up to be scanned, and keep it that way.

Installing the scanner is one problem; wiring it into a project is another, and
the second one is where adoption usually stalls. A team runs one scan, sees a
hundred findings on code written before anyone here was hired, and never runs
it again.

So this writes four things, each of which can be declined:

* ``.lory-scan.yml`` — a starting policy, with the noisy dials pre-set
* a baseline — everything that exists today, marked known, so tomorrow's diff
  is about tomorrow's code
* a pre-commit hook — the scan that catches it before it is committed
* a CI workflow — the scan that catches it if the hook was skipped

Nothing is overwritten without asking, and everything it writes is a plain file
the team can read and edit.
"""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass, field
from pathlib import Path

import click

from lory_scanner.cli.common import EXIT_OK, console, die, err_console
from lory_scanner.core.config import CONFIG_NAMES
from lory_scanner.core.errors import ScannerError
from lory_scanner.engine.scanner import Scanner, baseline_document

BASELINE_NAME = ".lory-scan-baseline.json"
HOOK_PATH = Path(".git") / "hooks" / "pre-commit"
WORKFLOW_PATH = Path(".github") / "workflows" / "security-scan.yml"

CONFIG_TEMPLATE = """\
# lory-scan — https://github.com/Lorikeet-Security/lory-code-security-scanner
#
# Written by `lory-scan init`. Every key is optional; see
# .lory-scan.example.yml in the scanner's repository for the full set.

# Findings below this confidence are hidden. The scanner matches patterns and
# cannot always tell whether a sink is reachable, so `medium` is the setting
# that makes a first scan readable. Drop to `low` when you want everything.
min_confidence: {min_confidence}

# CI fails at this severity and above.
fail_on: {fail_on}

# Findings recorded here are treated as already known. Delete the file, or this
# line, to see the whole backlog again.
{baseline_line}
exclude:
  - "**/fixtures/**"
  - "**/testdata/**"

# Rules that are wrong for this codebase everywhere. For a single line you have
# reviewed, prefer a `# lory-scan:ignore[rule.id] -- why` comment next to it.
ignore_rules: []
"""

HOOK_TEMPLATE = """\
#!/bin/sh
# Written by `lory-scan init`.
#
# Scans only what is staged, so the cost is proportional to the commit. Skip it
# for one commit with `git commit --no-verify` when you need to.
{baseline_export}
exec lory-scan scan --staged --fail-on {fail_on} --quiet {baseline_flag}
"""

WORKFLOW_TEMPLATE = """\
# Written by `lory-scan init`.
#
# lory-scan:ignore-file[ci.unpinned-action] -- the actions below are pinned to
# major tags rather than commit SHAs. That is this file's own advice not taken:
# it is the trade-off GitHub's own docs make for first-party actions, and a
# generated file should not hand you a finding about itself on day one. Delete
# this line and pin the SHAs if your threat model wants them.
name: Security scan

on:
  push:
    branches: [{default_branch}]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  lory-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          # --diff needs history to compare against.
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install lory-code-security-scanner

      # Gate on what this change introduced, not on the whole backlog.
      - name: Scan changed files
        run: |
          lory-scan scan \\
            --diff origin/${{{{ github.base_ref || '{default_branch}' }}}} \\
            --fail-on {fail_on} {baseline_flag}

      # And publish everything to the Security tab, pass or fail.
      - name: Full scan for code scanning
        if: always()
        run: lory-scan scan --format sarif --out lory-scan.sarif --fail-on never

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: lory-scan.sarif
"""


@dataclass
class Plan:
    """What init decided to write, so the summary can report it honestly."""

    root: Path
    written: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def record(self, path: Path, did_write: bool, reason: str = "") -> None:
        # Relative to the repository: an absolute path wraps across three lines
        # in a normal terminal and buries the filename that matters.
        try:
            shown = str(path.relative_to(self.root))
        except ValueError:
            shown = str(path)
        (self.written if did_write else self.skipped).append(
            shown if did_write else f"{shown} ({reason})"
        )


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--baseline/--no-baseline", default=None,
              help="Record today's findings as known. Asked for if not given.")
@click.option("--hook/--no-hook", default=None,
              help="Install a pre-commit hook. Asked for if not given.")
@click.option("--ci/--no-ci", default=None,
              help="Write a GitHub Actions workflow. Asked for if not given.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]),
              default="high", show_default=True,
              help="Severity at which the hook and CI fail.")
@click.option("--min-confidence", type=click.Choice(["high", "medium", "low"]),
              default="medium", show_default=True,
              help="Confidence floor written into the config.")
@click.option("--default-branch", default="main", show_default=True,
              help="Branch the CI workflow compares against.")
@click.option("--force", is_flag=True, help="Overwrite files that already exist.")
@click.option("--yes", "-y", is_flag=True, help="Accept every default; ask nothing.")
def init(
    path: str, baseline: bool | None, hook: bool | None, ci: bool | None,
    fail_on: str, min_confidence: str, default_branch: str, force: bool, yes: bool,
) -> None:
    """Set this repository up for scanning.

    Writes a config, optionally records a baseline of what already exists, and
    installs the hook and CI job that keep new code from adding to it.

    \b
      lory-scan init              Ask about each piece.
      lory-scan init --yes        Take the defaults.
      lory-scan init --no-hook    Everything except the pre-commit hook.

    Run it again after changing your mind: it never overwrites without asking.
    """
    root = Path(path).resolve()
    plan = Plan(root=root)

    console.print(f"[bold]Setting up lory-scan in {root}[/bold]\n")

    baseline_path = root / BASELINE_NAME
    want_baseline = _decide(
        baseline, yes,
        "Record today's findings as a baseline, so future scans show only new ones?",
        default=True,
    )

    # The baseline is written first: the config points at it, and there is no
    # point naming a file that was declined.
    baseline_written = False
    if want_baseline:
        baseline_written = _write_baseline(root, baseline_path, force, plan)

    _write_config(root, plan, force, min_confidence, fail_on,
                  baseline_written or baseline_path.exists())

    if _decide(hook, yes, "Install a pre-commit hook that scans staged files?", default=True):
        _write_hook(root, plan, force, fail_on, baseline_written or baseline_path.exists())

    if _decide(ci, yes, "Write a GitHub Actions workflow?", default=True):
        _write_workflow(root, plan, force, fail_on, default_branch,
                        baseline_written or baseline_path.exists())

    _summarise(plan)
    raise SystemExit(EXIT_OK)


def _decide(flag: bool | None, yes: bool, question: str, default: bool) -> bool:
    """A flag, else the default under --yes, else ask."""
    if flag is not None:
        return flag
    if yes:
        return default
    return click.confirm(question, default=default)


def _write_config(
    root: Path, plan: Plan, force: bool, min_confidence: str, fail_on: str, has_baseline: bool
) -> None:
    existing = next((root / name for name in CONFIG_NAMES if (root / name).is_file()), None)
    target = existing or (root / CONFIG_NAMES[0])

    if existing and not _may_overwrite(target, force):
        plan.record(target, False, "kept, already exists")
        return

    body = CONFIG_TEMPLATE.format(
        min_confidence=min_confidence,
        fail_on=fail_on,
        baseline_line=f"baseline: {BASELINE_NAME}\n" if has_baseline else "",
    )
    target.write_text(body)
    plan.record(target, True)


def _write_baseline(root: Path, target: Path, force: bool, plan: Plan) -> bool:
    if target.exists() and not _may_overwrite(target, force):
        plan.record(target, False, "kept, already exists")
        return True

    from lory_scanner.core.config import ScanConfig

    console.print("[dim]scanning to record what already exists…[/dim]")
    try:
        result = Scanner(ScanConfig(root=root)).run()
    except ScannerError as exc:
        die(str(exc))
        return False

    target.write_text(json.dumps(baseline_document(result), indent=2))
    plan.record(target, True)
    console.print(
        f"[dim]  {len(result.findings)} existing findings recorded as known[/dim]"
    )
    return True


def _write_hook(root: Path, plan: Plan, force: bool, fail_on: str, has_baseline: bool) -> None:
    target = root / HOOK_PATH

    if not (root / ".git").is_dir():
        plan.record(target, False, "not a git checkout")
        return
    if target.exists() and not _may_overwrite(target, force):
        plan.record(target, False, "kept, already exists")
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(HOOK_TEMPLATE.format(
        fail_on=fail_on,
        baseline_export="",
        baseline_flag=f"--baseline {BASELINE_NAME}" if has_baseline else "",
    ))
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    plan.record(target, True)


def _write_workflow(
    root: Path, plan: Plan, force: bool, fail_on: str, default_branch: str, has_baseline: bool
) -> None:
    target = root / WORKFLOW_PATH
    if target.exists() and not _may_overwrite(target, force):
        plan.record(target, False, "kept, already exists")
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(WORKFLOW_TEMPLATE.format(
        fail_on=fail_on,
        default_branch=default_branch,
        baseline_flag=f"\\\n            --baseline {BASELINE_NAME}" if has_baseline else "",
    ))
    plan.record(target, True)


def _may_overwrite(target: Path, force: bool) -> bool:
    if force:
        return True
    return click.confirm(f"{target} exists. Replace it?", default=False)


def _summarise(plan: Plan) -> None:
    console.print()
    for line in plan.written:
        console.print(f"  [green]+[/green] {line}")
    for line in plan.skipped:
        console.print(f"  [dim]·[/dim] [dim]{line}[/dim]")

    if not plan.written:
        err_console.print("\n[yellow]Nothing written.[/yellow]")
        return

    console.print(
        "\n[bold]Done.[/bold] Next:\n"
        "  [cyan]lory-scan scan[/cyan]            see where you stand\n"
        "  [cyan]lory-scan scan --diff main[/cyan]  what your branch adds\n"
        "\n[dim]Commit the config and baseline so the whole team scans the "
        "same way.[/dim]"
    )

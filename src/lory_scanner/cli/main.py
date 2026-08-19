"""Root command group for ``lory-scan``."""

from __future__ import annotations

import click

from lory_scanner import __version__
from lory_scanner.cli.describe import describe
from lory_scanner.cli.init_cmd import init
from lory_scanner.cli.rules_cmd import rules
from lory_scanner.cli.scan import scan, sync


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="lory-scan",
                      message=f"lory-code-security-scanner v{__version__}")
def main() -> None:
    """Find security problems in a source tree, on this machine.

    Nothing leaves your computer. There is no account, no API key, and no
    network call in a scan — the rules are files in this package and they run
    against files on your disk.

    \b
    ──────────────────────────────────────────────────────────────────────────
    GETTING STARTED
    ──────────────────────────────────────────────────────────────────────────
      1.  lory-scan scan                 Scan the current directory.
      2.  lory-scan init                 Wire it into this repo, for good.
      3.  lory-scan scan --diff main     Scan only what your branch changed.
      4.  lory-scan sync                 Hand the findings to `lory tui`.

    \b
    ──────────────────────────────────────────────────────────────────────────
    COMMANDS
    ──────────────────────────────────────────────────────────────────────────
      scan       Scan a path and report findings.
      init       Set this repository up: config, baseline, hook, CI.
      sync       Scan, and write the findings cache the `lory` TUI reads.
      rules      list / show / validate the detection rules.
      describe   Print the machine-readable integration contract.

    \b
    ──────────────────────────────────────────────────────────────────────────
    WITH THE FINDINGS TUI
    ──────────────────────────────────────────────────────────────────────────
    `lory-code-security` triages findings and asks Lory how to fix them, but
    scans nothing itself. This tool is the other half:

    \b
      lory-scan sync            scan this repo into .lory_state/findings.json
      lory tui --cached         triage what it found, no credential needed

    Platform findings already in that cache are kept, so the two sources sit
    side by side rather than overwriting each other.

    \b
    ──────────────────────────────────────────────────────────────────────────
    WHAT IT FINDS, AND WHAT IT DOES NOT
    ──────────────────────────────────────────────────────────────────────────
    Pattern matches with metadata: injection sinks, hardcoded credentials,
    weak crypto, unsafe deserialisation, dangerous configuration. Every
    finding carries a confidence, because a match is a lead and not a proof.

    It does not build a call graph or prove reachability. Treat a finding as a
    question to answer, not a verdict — and use `lory-scan:ignore[rule.id]`
    to record the answer when it is "this one is fine".
    """


main.add_command(init)
main.add_command(scan)
main.add_command(sync)
main.add_command(rules)
main.add_command(describe)


if __name__ == "__main__":  # pragma: no cover
    main()

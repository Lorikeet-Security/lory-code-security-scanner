"""Root command group for ``lory-scan``, and the process entry point."""

from __future__ import annotations

import signal
import sys

import click

from lory_scanner import __version__
from lory_scanner.cli.common import EXIT_ERROR, EXIT_INTERRUPTED, err_console
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


def run() -> None:
    """What the ``lory-scan`` script calls.

    Two things the click group cannot do for itself:

    *Encoding.* A scan of a repository containing any non-ASCII character —
    a name, a comment, an em-dash in a rule's remediation — writes text that a
    C-locale stdout cannot encode, and Python raises rather than degrading.
    That is a crash on the first run inside a bare container, which is exactly
    where CI runs. The streams are reconfigured to replace what they cannot
    encode instead.

    *Filesystem errors.* ``--out`` into a directory that does not exist is an
    ordinary typo, and a traceback is the wrong answer to a typo.

    *Interrupts.* Click turns Ctrl-C into exit 1, which in this tool's contract
    means "findings at or above the threshold". A caller branching on the exit
    code would read an abandoned scan as a failed one, so an interrupt exits
    130 instead.
    """
    _configure_streams()
    signal.signal(signal.SIGINT, _on_interrupt)

    try:
        # Click exits by raising SystemExit, which passes straight through.
        main()
    except OSError as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        raise SystemExit(EXIT_ERROR) from exc
    except KeyboardInterrupt:  # pragma: no cover — the handler normally wins
        raise SystemExit(EXIT_INTERRUPTED) from None


def _on_interrupt(signum: int, frame: object) -> None:
    """Exit 130 on Ctrl-C, before click can report it as exit 1."""
    err_console.print("[dim]interrupted[/dim]")
    raise SystemExit(EXIT_INTERRUPTED)


def _configure_streams() -> None:
    """Make stdout and stderr survive characters they cannot encode."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            # Not a reconfigurable text stream — a pipe wrapper, or a stream
            # something else already replaced. Nothing to harden.
            continue


if __name__ == "__main__":  # pragma: no cover
    run()

"""``lory-scan describe`` — the integration contract, as data.

A tool that shells out to this one should not have to hardcode its flags, its
exit codes, or the shape of its output. It runs ``lory-scan describe``, reads
the version and ``contract_version``, and decides whether it understands this
scanner before it depends on it.

That is how `lory-code-security` finds and calls the scanner: `lory scan`
probes for the binary, checks the contract, then invokes the command named in
``integration.lory.command``.
"""

from __future__ import annotations

import json
import shutil
import sys

import click

from lory_scanner import CONTRACT_VERSION, __version__
from lory_scanner.cli.common import console
from lory_scanner.core.config import CONFIG_NAMES, DEFAULT_STATE_DIR
from lory_scanner.core.severity import CONFIDENCE_LEVELS, SEVERITY_ORDER
from lory_scanner.engine.rules import load_rules
from lory_scanner.report.finding import LORY_STORE, Finding
from lory_scanner.report.formats import FORMATS, MACHINE_FORMATS
from lory_scanner.report.lory import CACHE_FILENAME


@click.command()
@click.option("--json", "as_json", is_flag=True, default=True,
              help="Emit JSON. On by default; this command exists to be parsed.")
def describe(as_json: bool) -> None:
    """Print the machine-readable contract this tool honours.

    Anything a caller needs in order to integrate — how to invoke a scan, what
    the exit codes mean, which fields a finding carries, and where the findings
    TUI's cache lives.
    """
    payload = contract()

    if as_json:
        click.echo(json.dumps(payload, indent=2))
        return

    console.print_json(data=payload)


def contract() -> dict:
    """The contract document. Also used by the tests, so it cannot drift."""
    try:
        ruleset = load_rules()
        rule_summary = {
            "count": len(ruleset),
            "categories": ruleset.categories(),
            "languages": ruleset.languages(),
        }
    except Exception as exc:  # noqa: BLE001 — describe must answer even if rules are broken
        rule_summary = {"count": 0, "error": str(exc)}

    return {
        "tool": "lory-scan",
        "version": __version__,
        "contract_version": CONTRACT_VERSION,
        "executable": shutil.which("lory-scan") or sys.argv[0],
        "python": sys.version.split()[0],
        "description": (
            "Local static security scanner. Runs entirely on this machine; no "
            "source, findings, or credentials leave it."
        ),
        "invocation": {
            "scan": ["lory-scan", "scan", "PATH"],
            "machine_readable": ["lory-scan", "scan", "PATH", "--format", "json"],
            "for_lory_tui": ["lory-scan", "scan", "PATH", "--format", "lory-json", "--quiet"],
            "write_tui_cache": ["lory-scan", "sync", "PATH"],
            "changed_only": ["lory-scan", "scan", "PATH", "--diff", "origin/main"],
            "notes": (
                "Findings go to stdout; progress, warnings, and errors go to stderr. "
                "A machine-readable --format never writes anything but the document "
                "to stdout, so no --quiet flag is needed to parse it."
            ),
        },
        "exit_codes": {
            "0": "no findings at or above --fail-on",
            "1": "findings at or above --fail-on (default: high)",
            "2": "the scan could not run — bad config, bad rules, unreadable path",
        },
        "formats": {
            "available": list(FORMATS),
            "machine_readable": sorted(MACHINE_FORMATS),
            "default": "table",
        },
        "finding_fields": sorted(_sample_finding().to_dict()),
        "severities": list(SEVERITY_ORDER),
        "confidence_levels": list(CONFIDENCE_LEVELS),
        "config": {
            "filenames": list(CONFIG_NAMES),
            "env": ["LORY_SCAN_CONFIG"],
            "search": "the scan root, then upwards to the repository root",
        },
        "capabilities": {
            "diff_scan": True,
            "staged_scan": True,
            "baselines": True,
            "inline_suppressions": True,
            "custom_rules": True,
            "entropy_secrets": True,
            "sarif": True,
            "offline": True,
        },
        "integration": {
            "lory": {
                "package": "lory-code-security",
                "repository": "https://github.com/Lorikeet-Security/lory-findings-tui",
                "command": ["lory-scan", "sync", "PATH"],
                "stdout_command": [
                    "lory-scan", "scan", "PATH", "--format", "lory-json", "--quiet"
                ],
                "cache_path": f"{DEFAULT_STATE_DIR}/{CACHE_FILENAME}",
                "cache_envelope": {
                    "fetched_at": "ISO-8601 timestamp",
                    "source": "lory-scan",
                    "findings": "list of rows accepted by lory's Finding.from_row",
                },
                "row_fields": sorted(_sample_finding().to_lory_row()),
                "store": LORY_STORE,
                "ref_format": f"{LORY_STORE}-<10 hex chars>",
                "identity": (
                    "ref is derived from a hash of rule id, path, and matched text — "
                    "stable across runs and across edits elsewhere in the file, so "
                    "triage state stays attached to the finding it was made about."
                ),
                "merge_behaviour": (
                    "sync keeps rows from other stores already in the cache, so a "
                    "local scan never removes findings pulled from the platform."
                ),
            }
        },
        "rules": rule_summary,
        "privacy": {
            "network_calls": "none",
            "telemetry": "none",
            "secrets_in_output": "redacted — entropy findings report a prefix and a length",
        },
    }


def _sample_finding() -> Finding:
    """A throwaway finding, used only to enumerate field names."""
    return Finding(rule_id="example.rule", title="Example", severity="info", path="x", line=1)

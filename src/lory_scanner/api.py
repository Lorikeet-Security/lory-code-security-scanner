"""The Python API.

The CLI is the supported interface — it is what the findings TUI calls, and
what CI calls. This module exists for the case where a caller is already a
Python process and would rather not pay for a subprocess::

    from lory_scanner import scan
    result = scan("~/src/myapp", min_severity="medium")
    for finding in result.findings:
        print(finding.key, finding.location, finding.title)

Keyword arguments here mirror the CLI flags one-for-one, and both funnel into
the same :class:`~lory_scanner.core.config.ScanConfig`, so there is one set of
semantics rather than two that drift.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lory_scanner.core.config import DEFAULT_STATE_DIR, ScanConfig
from lory_scanner.core.config import load as load_config
from lory_scanner.engine.scanner import Scanner, ScanResult
from lory_scanner.report import lory


def scan(
    path: str | Path = ".",
    *,
    config: str | Path | None = None,
    diff: str | None = None,
    staged: bool = False,
    ignore_suppressions: bool = False,
    jobs: int | None = None,
    **overrides: Any,
) -> ScanResult:
    """Scan a tree and return the result.

    ``path`` may be a directory or a single file. ``config`` names a
    ``.lory-scan.yml``; when omitted, one is looked for at the scan root and
    upwards to the repository top. Any remaining keyword argument overrides a
    :class:`ScanConfig` field — ``min_severity``, ``select``, ``entropy``, and
    the rest.

    ``diff`` restricts the scan to files changed against that git ref;
    ``staged`` restricts it to the index.
    """
    root = Path(path).expanduser().resolve()
    cfg = load_config(config, root).merge_cli(**overrides).check()
    scanner = Scanner(cfg, ignore_suppressions=ignore_suppressions, jobs=jobs)

    if diff is not None or staged:
        return scanner.run_diff(diff, staged)
    return scanner.run()


def scan_to_lory_cache(
    path: str | Path = ".",
    state_dir: str | Path | None = None,
    *,
    merge: bool = True,
    **kwargs: Any,
) -> tuple[ScanResult, Path]:
    """Scan, then write the findings cache that `lory-code-security` reads.

    Returns the result and the path written. This is what ``lory-scan sync``
    does; it is exposed here so the TUI can do it in-process when the scanner
    happens to be installed alongside it.
    """
    result = scan(path, **kwargs)
    target = Path(state_dir) if state_dir else (Path(path).expanduser() / DEFAULT_STATE_DIR)
    written = lory.write_cache(result, target, merge=merge)
    return result, written


def lory_rows(result: ScanResult) -> list[dict[str, Any]]:
    """Findings as rows in the findings TUI's own vocabulary."""
    return lory.rows(result)


__all__ = ["scan", "scan_to_lory_cache", "lory_rows", "ScanConfig", "ScanResult"]

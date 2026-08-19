"""Output for `lory-code-security`, the findings TUI.

Two shapes, one contract:

``lory-json``
    ``{"fetched_at": …, "findings": [row, …]}`` on stdout, for a caller that
    wants to pipe or post-process.

``lory-cache``
    The same document written to ``<state_dir>/findings.json``, which is
    exactly where that tool keeps its findings cache. Once it is written,
    ``lory findings list --cached`` and ``lory tui --cached`` read the local
    scan with no change on their side and no credential involved.

The envelope key is ``fetched_at`` rather than ``scanned_at`` because that is
the key the TUI reads. Matching its vocabulary is the whole point of this
module; the scanner's own names live in the native JSON format.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lory_scanner.engine.scanner import ScanResult

#: Filename the TUI expects inside its state directory.
CACHE_FILENAME = "findings.json"


def rows(result: ScanResult) -> list[dict[str, Any]]:
    """Findings as TUI rows, most severe first."""
    return [f.to_lory_row(result.scanned_at) for f in result.findings]


def document(result: ScanResult) -> dict[str, Any]:
    """The cache envelope the TUI's ``FindingStore.load_cache`` reads."""
    return {
        "fetched_at": result.scanned_at,
        # Provenance, so a reader can tell a local scan from a platform pull.
        # The TUI ignores unknown envelope keys.
        "source": "lory-scan",
        "scan": {
            "root": str(result.root),
            "files_scanned": result.stats.scanned,
            "rules_run": result.rules_run,
            "duration_ms": result.duration_ms,
        },
        "findings": rows(result),
    }


def render(result: ScanResult) -> str:
    return json.dumps(document(result), indent=2)


def write_cache(result: ScanResult, state_dir: Path, merge: bool = True) -> Path:
    """Write the TUI's findings cache and return the path written.

    ``merge`` keeps any findings already in the cache that this scan did not
    produce — platform findings pulled over MCP, most importantly. Overwriting
    them would make running a local scan look like the platform had gone
    quiet. Scanner findings are replaced wholesale, since a fixed one should
    disappear.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / CACHE_FILENAME

    payload = document(result)

    if merge:
        payload["findings"] = _merge(_existing(path), payload["findings"])

    path.write_text(json.dumps(payload, indent=2))
    return path


def _existing(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    if isinstance(data, dict):
        found = data.get("findings", [])
    else:
        found = data
    return [row for row in found if isinstance(row, dict)]


def _merge(existing: list[dict[str, Any]], fresh: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fresh scan rows, plus every non-scanner row that was already cached."""
    kept = [row for row in existing if str(row.get("store") or "") != "scan"]
    return [*fresh, *kept]

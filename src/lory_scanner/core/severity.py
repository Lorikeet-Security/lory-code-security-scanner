"""Severity ordering, shared by filtering, exit codes, and every report format."""

from __future__ import annotations

#: Most to least severe. The order is load-bearing: `rank` indexes into it,
#: and "at or above" comparisons are `<=` on the rank.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}

#: Confidence is not severity. A critical finding the engine is unsure about is
#: still critical; confidence tells the reader how much triage it deserves.
CONFIDENCE_LEVELS: tuple[str, ...] = ("high", "medium", "low")

#: Rich styles, one per severity, used by the table report.
SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def rank(severity: str) -> int:
    """Position in :data:`SEVERITY_ORDER`; unknown severities sort last."""
    return SEVERITY_RANK.get(str(severity).lower(), len(SEVERITY_ORDER))


def normalise(severity: str) -> str:
    """Coerce a severity to one of the five, defaulting to ``medium``.

    Rule loading rejects unknown severities outright, so this only smooths
    over severities that arrive from a baseline file or an old cache.
    """
    value = str(severity).strip().lower()
    return value if value in SEVERITY_RANK else "medium"


def at_or_above(severity: str, threshold: str) -> bool:
    """Whether ``severity`` is at least as severe as ``threshold``."""
    return rank(severity) <= rank(threshold)


def counts(severities: list[str]) -> dict[str, int]:
    """Tally by severity, in severity order, including zeroes.

    Zeroes are kept so a summary line has a stable shape across runs — a
    disappearing column reads as a formatting glitch, not as good news.
    """
    tally = dict.fromkeys(SEVERITY_ORDER, 0)
    for severity in severities:
        key = normalise(severity)
        tally[key] += 1
    return tally

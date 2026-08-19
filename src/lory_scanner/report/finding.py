"""The Finding model: what one detection is, and how it is identified.

Identity matters more than it looks. A finding is triaged, suppressed,
baselined, and re-found on the next run — all of which need the same finding to
answer to the same name across runs. Line numbers do not survive an edit above
the finding, so identity here is a hash of the rule, the file, and the matched
text, with an occurrence index to separate two identical matches in one file.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from lory_scanner.core.severity import normalise

#: Prefix for the finding refs handed to the findings TUI. The TUI resolves a
#: finding by `ref` and namespaces its stores by the prefix, so scanner
#: findings can never collide with platform ones.
LORY_STORE = "scan"


@dataclass
class Finding:
    """One detection, in one file, at one line."""

    rule_id: str
    title: str
    severity: str
    path: str
    line: int

    column: int = 0
    end_line: int = 0
    #: The matched text, truncated. Secrets arrive here already redacted.
    match: str = ""
    #: The source line the match sits on, for report context.
    snippet: str = ""
    #: Lines either side of the match, for the table and SARIF context.
    context: list[str] = field(default_factory=list)

    category: str = "misc"
    cwe: str = ""
    owasp: str = ""
    confidence: str = "medium"
    language: str = ""
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    #: Nth identical match of this rule in this file, from 0. Part of identity.
    occurrence: int = 0
    #: Set when a suppression comment was found but ignored via
    #: `--ignore-suppressions`, so an audit can see what is normally hidden.
    suppressed_by: str = ""

    def __post_init__(self) -> None:
        self.severity = normalise(self.severity)
        if not self.end_line:
            self.end_line = self.line

    @property
    def fingerprint(self) -> str:
        """Stable identity across runs, and across edits elsewhere in the file.

        Deliberately excludes the line number: a finding that moves because
        someone added an import above it is the same finding, and a baseline
        that forgot that would go stale on every commit.
        """
        material = "␟".join(
            [self.rule_id, self.path, _normalise_match(self.match), str(self.occurrence)]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    @property
    def key(self) -> str:
        """How this finding is named everywhere, including in the TUI."""
        return f"{LORY_STORE}-{self.fingerprint[:10]}"

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        """The native JSON shape. Stable; see CONTRACT_VERSION."""
        return {
            "key": self.key,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "path": self.path,
            "line": self.line,
            "end_line": self.end_line,
            "column": self.column,
            "language": self.language,
            "match": self.match,
            "snippet": self.snippet,
            "description": self.description,
            "remediation": self.remediation,
            "references": list(self.references),
            "tags": list(self.tags),
            "suppressed_by": self.suppressed_by,
        }

    def to_lory_row(self, scanned_at: str | None = None) -> dict[str, Any]:
        """The shape `lory-code-security` reads.

        Field-for-field what that tool's ``Finding.from_row`` consumes, so its
        cache, list, show, trace, fix, and TUI work on a locally scanned
        finding with no change on its side. The scanner's own fields ride
        along and survive in the TUI's ``raw`` dict.

        ``affected_asset`` is ``path:line`` on purpose: that tool's `trace`
        derives search tokens from the asset string, and a real path is the
        strongest token it can get.
        """
        return {
            "ref": self.key,
            "store": LORY_STORE,
            # The TUI needs an int id. Derived from the fingerprint so it is
            # stable across runs rather than a position in this run's list.
            "id": int(self.fingerprint[:8], 16),
            "title": self.title,
            "severity": self.severity,
            "status": "open",
            "affected_asset": self.location,
            "category": self.category,
            "cwe_id": self.cwe,
            "cvss_score": None,
            "cvss_vector": "",
            "project_id": None,
            "description": self._lory_description(),
            "evidence": self._lory_evidence(),
            "remediation": self._lory_remediation(),
            "discovered_at": scanned_at or datetime.now(UTC).isoformat(),
            "source": "lory_scan",
            "engagement_id": None,
            "vector": "sast",
            # Scanner-native fields. The TUI keeps unknown keys in `raw`, so
            # nothing here is lost and nothing there has to know about them.
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "confidence": self.confidence,
            "path": self.path,
            "line": self.line,
            "language": self.language,
        }

    def _lory_description(self) -> str:
        parts = [self.description or self.title]
        parts.append(
            f"Detected by local rule {self.rule_id} "
            f"({self.confidence} confidence) at {self.location}."
        )
        parts.append(
            "This is a static match found on your machine, not a verified "
            "exploit. Confirm it is reachable before treating it as proven."
        )
        return "\n\n".join(parts)

    def _lory_evidence(self) -> str:
        lines = [f"{self.location}", ""]
        if self.context:
            lines.extend(self.context)
        elif self.snippet:
            lines.append(self.snippet)
        if self.match and self.match not in (self.snippet or ""):
            lines += ["", f"matched: {self.match}"]
        return "\n".join(lines)

    def _lory_remediation(self) -> str:
        parts = [self.remediation] if self.remediation else []
        if self.references:
            parts.append("References:\n" + "\n".join(f"- {r}" for r in self.references))
        return "\n\n".join(parts)


def _normalise_match(match: str) -> str:
    """Collapse whitespace so reindentation does not change identity."""
    return " ".join(match.split())


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by path and line, so output is deterministic.

    Determinism is not cosmetic here: CI diffs the output, and a scanner whose
    row order wobbled between runs would show changes that are not changes.
    """
    from lory_scanner.core.severity import rank

    return sorted(
        findings,
        key=lambda f: (rank(f.severity), f.path, f.line, f.rule_id, f.column),
    )

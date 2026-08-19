"""SARIF 2.1.0 — the format GitHub code scanning and Defender ingest.

Rule metadata is emitted once in ``tool.driver.rules`` and referenced by index,
which is what makes the rule description show up in a code-scanning alert
rather than a bare message.

``partialFingerprints`` carries the scanner's own fingerprint, so GitHub tracks
an alert across commits that move the code instead of closing it and opening a
new one.
"""

from __future__ import annotations

import json
from typing import Any

from lory_scanner.engine.scanner import ScanResult
from lory_scanner.report.finding import Finding

#: SARIF has three levels; the five severities fold onto them. `info` maps to
#: `note` rather than being dropped: the reader decides what to act on.
LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

#: GitHub sorts and filters on this, not on `level`, so both are emitted.
SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def render(result: ScanResult, version: str) -> str:
    rules, index_of = _rule_descriptors(result.findings)

    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "lory-scan",
                            "version": version,
                            "informationUri": (
                                "https://github.com/Lorikeet-Security/"
                                "lory-code-security-scanner"
                            ),
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": result.scanned_at,
                        }
                    ],
                    "results": [
                        _result(f, index_of[f.rule_id]) for f in result.findings
                    ],
                }
            ],
        },
        indent=2,
    )


def _rule_descriptors(findings: list[Finding]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """One descriptor per rule that actually fired, plus a rule_id → index map."""
    descriptors: list[dict[str, Any]] = []
    index_of: dict[str, int] = {}

    for finding in findings:
        if finding.rule_id in index_of:
            continue
        index_of[finding.rule_id] = len(descriptors)

        descriptor: dict[str, Any] = {
            "id": finding.rule_id,
            "name": _camel(finding.rule_id),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description or finding.title},
            "defaultConfiguration": {"level": LEVEL.get(finding.severity, "warning")},
            "properties": {
                "tags": _tags(finding),
                "security-severity": SECURITY_SEVERITY.get(finding.severity, "5.5"),
                "precision": finding.confidence,
            },
        }
        if finding.remediation:
            descriptor["help"] = {
                "text": finding.remediation,
                "markdown": _help_markdown(finding),
            }
        descriptors.append(descriptor)

    return descriptors, index_of


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVEL.get(finding.severity, "warning"),
        "message": {"text": f"{finding.title} ({finding.severity})"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {
                        "startLine": max(1, finding.line),
                        "endLine": max(1, finding.end_line),
                        # SARIF columns are 1-based.
                        "startColumn": max(1, finding.column + 1),
                        "snippet": {"text": finding.snippet},
                    },
                }
            }
        ],
        "partialFingerprints": {"loryScanFingerprint/v1": finding.fingerprint},
        "properties": {
            "confidence": finding.confidence,
            "category": finding.category,
            "cwe": finding.cwe,
        },
    }


def _tags(finding: Finding) -> list[str]:
    tags = ["security", finding.category, *finding.tags]
    if finding.cwe:
        # GitHub renders `external/cwe/cwe-89` as a linked CWE reference.
        tags.append(f"external/cwe/{finding.cwe.lower()}")
    return [t for t in dict.fromkeys(tags) if t]


def _help_markdown(finding: Finding) -> str:
    parts = [f"**{finding.title}**", "", finding.remediation]
    if finding.references:
        parts += ["", "References:", *[f"- {r}" for r in finding.references]]
    return "\n".join(parts)


def _camel(rule_id: str) -> str:
    """`python.sql-string-concat` → `PythonSqlStringConcat`."""
    words = rule_id.replace(".", "-").split("-")
    return "".join(w.capitalize() for w in words if w)

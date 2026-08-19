"""Output formats, and the contract with the findings TUI."""

from __future__ import annotations

import csv
import io
import json

from lory_scanner import CONTRACT_VERSION
from lory_scanner.engine.scanner import Scanner
from lory_scanner.report import formats, lory
from lory_scanner.report.finding import Finding, sort_findings

SHELL_TRUE = 'subprocess.run(f"ping {host}", shell=True)\n'


def run(tree, config, files=None):
    tree(files or {"app.py": SHELL_TRUE})
    return Scanner(config, jobs=1).run()


# ── native JSON ─────────────────────────────────────────────────────────────


def test_json_carries_the_contract_version(tree, config):
    payload = json.loads(formats.render_json(run(tree, config), "0.1.0"))
    assert payload["tool"] == "lory-scan"
    assert payload["contract_version"] == CONTRACT_VERSION
    assert payload["scan"]["files"]["scanned"] == 1
    assert payload["findings"][0]["rule_id"] == "python.subprocess-shell-true"


def test_csv_has_one_row_per_finding(tree, config):
    result = run(tree, config, {"a.py": SHELL_TRUE, "b.py": SHELL_TRUE})
    rows = list(csv.DictReader(io.StringIO(formats.render_csv(result))))
    assert len(rows) == 2
    assert {r["path"] for r in rows} == {"a.py", "b.py"}


def test_markdown_mentions_every_finding(tree, config):
    text = formats.render_markdown(run(tree, config))
    assert "Subprocess invoked with shell=True" in text
    assert "app.py:1" in text


def test_every_declared_format_renders(tree, config):
    result = run(tree, config)
    for fmt in formats.FORMATS:
        if fmt == "table":
            continue  # rendered by Rich to a console, not returned as text
        assert formats.render(result, fmt, "0.1.0")


# ── SARIF ───────────────────────────────────────────────────────────────────


def test_sarif_is_well_formed(tree, config):
    payload = json.loads(formats.render(run(tree, config), "sarif", "0.1.0"))
    assert payload["version"] == "2.1.0"

    run_block = payload["runs"][0]
    assert run_block["tool"]["driver"]["name"] == "lory-scan"

    result = run_block["results"][0]
    rule = run_block["tool"]["driver"]["rules"][result["ruleIndex"]]
    assert rule["id"] == result["ruleId"]
    assert result["level"] in ("error", "warning", "note")

    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1
    # SARIF columns are 1-based; a 0 would be rejected by strict consumers.
    assert region["startColumn"] >= 1


def test_sarif_fingerprints_let_github_track_an_alert(tree, config):
    result = run(tree, config)
    payload = json.loads(formats.render(result, "sarif", "0.1.0"))
    printed = payload["runs"][0]["results"][0]["partialFingerprints"]
    assert printed["loryScanFingerprint/v1"] == result.findings[0].fingerprint


# ── the lory-code-security contract ─────────────────────────────────────────
#
# These pin the integration. The field names below are the ones that tool's
# `Finding.from_row` reads; changing one here without changing it there breaks
# the handoff silently, with findings that load but arrive blank.

LORY_ROW_FIELDS = {
    "id", "title", "severity", "status", "affected_asset", "category",
    "cwe_id", "cvss_score", "cvss_vector", "project_id", "description",
    "evidence", "remediation", "discovered_at", "source", "engagement_id",
    "vector", "ref", "store",
}


def test_lory_row_has_every_field_the_tui_reads(tree, config):
    row = lory.rows(run(tree, config))[0]
    assert LORY_ROW_FIELDS <= set(row), LORY_ROW_FIELDS - set(row)


def test_lory_row_is_addressable_by_ref(tree, config):
    row = lory.rows(run(tree, config))[0]
    assert row["ref"].startswith("scan-")
    assert row["store"] == "scan"
    # The TUI keys findings by ref, and needs an int id it can print.
    assert isinstance(row["id"], int)


def test_lory_row_points_at_the_source_line(tree, config):
    """`lory trace` derives its search tokens from affected_asset."""
    row = lory.rows(run(tree, config))[0]
    assert row["affected_asset"] == "app.py:1"


def test_lory_row_body_is_filled_in(tree, config):
    """The TUI treats a finding with no description or evidence as a stub
    and tries to fetch the rest over MCP, which a local scan cannot answer."""
    row = lory.rows(run(tree, config))[0]
    assert row["description"]
    assert row["evidence"]


def test_lory_cache_envelope(tree, config, tmp_path):
    result = run(tree, config)
    state = tmp_path / "state"
    path = lory.write_cache(result, state)

    assert path == state / "findings.json"
    payload = json.loads(path.read_text())
    assert payload["fetched_at"] == result.scanned_at
    assert len(payload["findings"]) == 1


def test_cache_write_keeps_platform_findings(tree, config, tmp_path):
    """A local scan must not make findings pulled from the platform vanish."""
    state = tmp_path / "state"
    state.mkdir()
    (state / "findings.json").write_text(json.dumps({
        "fetched_at": "2026-01-01T00:00:00Z",
        "findings": [
            {"ref": "engagement-1652", "store": "engagement", "id": 1652,
             "title": "Platform finding", "severity": "high"},
            {"ref": "scan-deadbeef01", "store": "scan", "id": 1,
             "title": "Stale scanner finding", "severity": "low"},
        ],
    }))

    lory.write_cache(run(tree, config), state)
    payload = json.loads((state / "findings.json").read_text())
    refs = [row["ref"] for row in payload["findings"]]

    assert "engagement-1652" in refs, "platform findings must survive a local scan"
    assert "scan-deadbeef01" not in refs, "a fixed scanner finding must disappear"


def test_cache_replace_drops_platform_findings(tree, config, tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "findings.json").write_text(json.dumps({
        "findings": [{"ref": "engagement-1", "store": "engagement", "id": 1}]
    }))

    lory.write_cache(run(tree, config), state, merge=False)
    payload = json.loads((state / "findings.json").read_text())
    assert all(row["store"] == "scan" for row in payload["findings"])


def test_cache_survives_a_corrupt_existing_file(tree, config, tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "findings.json").write_text("{not json at all")

    path = lory.write_cache(run(tree, config), state)
    assert json.loads(path.read_text())["findings"]


# ── ordering ────────────────────────────────────────────────────────────────


def test_sort_is_deterministic():
    findings = [
        Finding(rule_id="b", title="B", severity="low", path="z.py", line=9),
        Finding(rule_id="a", title="A", severity="critical", path="a.py", line=2),
        Finding(rule_id="c", title="C", severity="critical", path="a.py", line=1),
    ]
    ordered = [f.rule_id for f in sort_findings(findings)]
    assert ordered == ["c", "a", "b"]
    assert [f.rule_id for f in sort_findings(list(reversed(findings)))] == ordered

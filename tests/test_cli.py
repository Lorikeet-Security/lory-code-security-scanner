"""The command line: exit codes, formats, config resolution, describe."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from lory_scanner.cli.main import main

SHELL_TRUE = 'subprocess.run(f"ping {host}", shell=True)\n'
CLEAN = "import os\n\n\ndef main():\n    return os.getcwd()\n"


@pytest.fixture
def cli():
    return CliRunner()


def write(tmp_path, files: dict[str, str]):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return tmp_path


# ── exit codes ──────────────────────────────────────────────────────────────


def test_findings_exit_1(cli, tmp_path):
    write(tmp_path, {"app.py": SHELL_TRUE})
    result = cli.invoke(main, ["scan", str(tmp_path), "-f", "json", "--no-gitignore"])
    assert result.exit_code == 1


def test_clean_tree_exits_0(cli, tmp_path):
    write(tmp_path, {"app.py": CLEAN})
    result = cli.invoke(main, ["scan", str(tmp_path), "-f", "json", "--no-gitignore"])
    assert result.exit_code == 0


def test_fail_on_never_exits_0_with_findings(cli, tmp_path):
    write(tmp_path, {"app.py": SHELL_TRUE})
    result = cli.invoke(
        main, ["scan", str(tmp_path), "-f", "json", "--fail-on", "never", "--no-gitignore"]
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["findings"]


def test_fail_on_threshold_is_respected(cli, tmp_path):
    write(tmp_path, {"a.py": "import tempfile\ntempfile.mktemp()\n"})  # medium
    assert cli.invoke(
        main, ["scan", str(tmp_path), "-f", "json", "--fail-on", "high", "--no-gitignore"]
    ).exit_code == 0
    assert cli.invoke(
        main, ["scan", str(tmp_path), "-f", "json", "--fail-on", "medium", "--no-gitignore"]
    ).exit_code == 1


def test_unreadable_path_exits_2(cli, tmp_path):
    result = cli.invoke(main, ["scan", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_bad_config_exits_2(cli, tmp_path):
    write(tmp_path, {"app.py": CLEAN, ".lory-scan.yml": "min_severity: catastrophic\n"})
    result = cli.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "min_severity" in result.output


def test_unknown_config_key_is_an_error(cli, tmp_path):
    """A typo in a policy file must not be read as "no policy"."""
    write(tmp_path, {"app.py": CLEAN, ".lory-scan.yml": "min_severtiy: high\n"})
    result = cli.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "unknown key" in result.output


# ── output ──────────────────────────────────────────────────────────────────


def test_json_goes_to_stdout_clean(cli, tmp_path):
    """A machine format must be parseable without passing --quiet."""
    write(tmp_path, {"app.py": SHELL_TRUE})
    result = cli.invoke(main, ["scan", str(tmp_path), "-f", "json", "--no-gitignore"])
    json.loads(result.output)


def test_out_writes_a_file(cli, tmp_path):
    write(tmp_path, {"app.py": SHELL_TRUE})
    target = tmp_path / "out.sarif"
    result = cli.invoke(
        main, ["scan", str(tmp_path), "-f", "sarif", "-o", str(target), "--no-gitignore"]
    )
    assert result.exit_code == 1
    assert json.loads(target.read_text())["version"] == "2.1.0"


def test_table_is_the_default(cli, tmp_path):
    write(tmp_path, {"app.py": SHELL_TRUE})
    result = cli.invoke(main, ["scan", str(tmp_path), "--no-gitignore"])
    assert "shell=True" in result.output


# ── sync, the TUI handoff ───────────────────────────────────────────────────


def test_sync_writes_the_tui_cache(cli, tmp_path):
    write(tmp_path, {"app.py": SHELL_TRUE})
    result = cli.invoke(main, ["sync", str(tmp_path), "--no-gitignore"])

    cache = tmp_path / ".lory_state" / "findings.json"
    assert cache.exists()
    payload = json.loads(cache.read_text())
    assert payload["findings"][0]["ref"].startswith("scan-")
    assert "lory tui --cached" in result.output


def test_sync_honours_state_dir(cli, tmp_path):
    write(tmp_path, {"app.py": SHELL_TRUE})
    elsewhere = tmp_path / "somewhere"
    cli.invoke(
        main, ["sync", str(tmp_path), "--state-dir", str(elsewhere), "--no-gitignore"]
    )
    assert (elsewhere / "findings.json").exists()


def test_emit_lory_cache_alongside_another_format(cli, tmp_path):
    write(tmp_path, {"app.py": SHELL_TRUE})
    result = cli.invoke(
        main, ["scan", str(tmp_path), "-f", "json", "--emit-lory-cache", "--no-gitignore"]
    )
    json.loads(result.output)
    assert (tmp_path / ".lory_state" / "findings.json").exists()


# ── baselines ───────────────────────────────────────────────────────────────


def test_write_baseline_then_scan_clean(cli, tmp_path):
    write(tmp_path, {"app.py": SHELL_TRUE})
    baseline = tmp_path / "base.json"

    assert cli.invoke(
        main, ["scan", str(tmp_path), "--write-baseline", str(baseline), "--no-gitignore"]
    ).exit_code == 0
    assert json.loads(baseline.read_text())["fingerprints"]

    result = cli.invoke(
        main, ["scan", str(tmp_path), "-f", "json", "--baseline", str(baseline), "--no-gitignore"]
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["findings"] == []


# ── config file ─────────────────────────────────────────────────────────────


def test_config_file_is_found_from_the_scan_root(cli, tmp_path):
    write(tmp_path, {
        "app.py": SHELL_TRUE,
        ".lory-scan.yml": "ignore_rules:\n  - python.subprocess-shell-true\n",
    })
    result = cli.invoke(main, ["scan", str(tmp_path), "-f", "json", "--no-gitignore"])
    assert json.loads(result.output)["findings"] == []


def test_cli_flag_adds_to_config_file_values(cli, tmp_path):
    """A flag must not silently discard a repository's agreed excludes."""
    write(tmp_path, {
        "vendor_x/a.py": SHELL_TRUE,
        "other/b.py": SHELL_TRUE,
        ".lory-scan.yml": "exclude:\n  - 'vendor_x/**'\n",
    })
    result = cli.invoke(
        main, ["scan", str(tmp_path), "-f", "json", "--exclude", "other/**", "--no-gitignore"]
    )
    assert json.loads(result.output)["findings"] == []


# ── rules and describe ──────────────────────────────────────────────────────


def test_rules_list(cli):
    result = cli.invoke(main, ["rules", "list", "--json"])
    assert result.exit_code == 0
    rules = json.loads(result.output)
    assert any(r["id"] == "python.pickle-loads" for r in rules)


def test_rules_show(cli):
    result = cli.invoke(main, ["rules", "show", "python.pickle-loads", "--json"])
    assert json.loads(result.output)["cwe"] == "CWE-502"


def test_rules_show_unknown_id_exits_2(cli):
    assert cli.invoke(main, ["rules", "show", "no.such.rule"]).exit_code == 2


def test_rules_validate_passes_on_the_bundled_set(cli):
    result = cli.invoke(main, ["rules", "validate"])
    assert result.exit_code == 0
    assert "self-tests passed" in result.output


def test_describe_is_a_usable_contract(cli):
    """What a caller integrating against this tool reads before it commits."""
    payload = json.loads(cli.invoke(main, ["describe"]).output)

    assert payload["tool"] == "lory-scan"
    assert payload["contract_version"] >= 1
    assert payload["exit_codes"]["1"]
    assert "lory-json" in payload["formats"]["available"]

    integration = payload["integration"]["lory"]
    assert integration["cache_path"] == ".lory_state/findings.json"
    assert integration["command"][:2] == ["lory-scan", "sync"]
    assert "ref" in integration["row_fields"]
    assert payload["rules"]["count"] > 50


def test_version_flag(cli):
    result = cli.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "lory-code-security-scanner" in result.output

"""`lory-scan init` — wiring a repository up, and what it writes."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from lory_scanner.cli.init_cmd import BASELINE_NAME, HOOK_PATH, WORKFLOW_PATH
from lory_scanner.cli.main import main

VULNERABLE = 'subprocess.run(f"ping {host}", shell=True)\n'


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(VULNERABLE)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def init(repo: Path, *args: str):
    return CliRunner().invoke(main, ["init", str(repo), "--yes", *args])


def test_writes_the_full_set(repo):
    result = init(repo)
    assert result.exit_code == 0

    assert (repo / ".lory-scan.yml").is_file()
    assert (repo / BASELINE_NAME).is_file()
    assert (repo / HOOK_PATH).is_file()
    assert (repo / WORKFLOW_PATH).is_file()


def test_config_is_valid_and_points_at_the_baseline(repo):
    init(repo)
    config = yaml.safe_load((repo / ".lory-scan.yml").read_text())

    assert config["baseline"] == BASELINE_NAME
    assert config["min_confidence"] == "medium"
    assert config["fail_on"] == "high"

    # And the scanner accepts what it wrote.
    result = CliRunner().invoke(main, ["scan", str(repo), "-f", "json"])
    assert result.exit_code == 0


def test_the_baseline_silences_what_already_exists(repo):
    """The point of init: today's backlog stops being tomorrow's noise."""
    init(repo)

    clean = CliRunner().invoke(main, ["scan", str(repo), "-f", "json"])
    assert json.loads(clean.output)["findings"] == []

    (repo / "new.py").write_text("import pickle\npickle.loads(x)\n")
    after = CliRunner().invoke(main, ["scan", str(repo), "-f", "json"])
    assert [f["rule_id"] for f in json.loads(after.output)["findings"]] == [
        "python.pickle-loads"
    ]


def test_baseline_records_what_it_silenced(repo):
    """A bare list of hashes is unreviewable, so entries carry their finding."""
    init(repo)
    entry = json.loads((repo / BASELINE_NAME).read_text())["fingerprints"][0]
    assert entry["rule_id"] == "python.subprocess-shell-true"
    assert entry["path"] == "app.py"
    assert entry["fingerprint"]


def test_hook_is_executable_and_scans_only_staged_files(repo):
    init(repo)
    hook = repo / HOOK_PATH
    assert os.access(hook, os.X_OK)

    body = hook.read_text()
    assert "--staged" in body
    assert "--fail-on high" in body
    assert f"--baseline {BASELINE_NAME}" in body


def test_workflow_is_valid_and_gates_on_the_diff(repo):
    init(repo)
    workflow = yaml.safe_load((repo / WORKFLOW_PATH).read_text())

    steps = workflow["jobs"]["lory-scan"]["steps"]
    commands = " ".join(step.get("run", "") for step in steps)
    assert "--diff origin/" in commands
    assert "--fail-on high" in commands
    assert "sarif" in commands


def test_the_workflow_it_writes_does_not_trip_the_scanner(repo):
    """A generated file must not hand the user a finding about itself."""
    init(repo)
    result = CliRunner().invoke(main, ["scan", str(repo), "-f", "json"])
    paths = {f["path"] for f in json.loads(result.output)["findings"]}
    assert str(WORKFLOW_PATH) not in paths


def test_nothing_is_overwritten_without_force(repo):
    (repo / ".lory-scan.yml").write_text("# hand-written\nmin_severity: low\n")
    init(repo, "--no-baseline", "--no-hook", "--no-ci")
    assert "hand-written" in (repo / ".lory-scan.yml").read_text()


def test_force_overwrites(repo):
    (repo / ".lory-scan.yml").write_text("# hand-written\n")
    init(repo, "--force", "--no-baseline", "--no-hook", "--no-ci")
    assert "hand-written" not in (repo / ".lory-scan.yml").read_text()


def test_pieces_can_be_declined(repo):
    init(repo, "--no-hook", "--no-ci", "--no-baseline")
    assert (repo / ".lory-scan.yml").is_file()
    assert not (repo / BASELINE_NAME).exists()
    assert not (repo / HOOK_PATH).exists()
    assert not (repo / WORKFLOW_PATH).exists()


def test_hook_is_skipped_outside_a_checkout(tmp_path):
    (tmp_path / "app.py").write_text(VULNERABLE)
    result = init(tmp_path, "--no-ci", "--no-baseline")

    assert result.exit_code == 0
    assert not (tmp_path / HOOK_PATH).exists()
    assert "not a git checkout" in result.output


def test_fail_on_flows_into_hook_and_ci(repo):
    init(repo, "--fail-on", "critical")
    assert "--fail-on critical" in (repo / HOOK_PATH).read_text()
    assert "--fail-on critical" in (repo / WORKFLOW_PATH).read_text()

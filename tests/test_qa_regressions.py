"""Regressions found by QA, each pinned so it cannot come back.

Every test here corresponds to a bug that shipped in a working build and was
found by using the tool rather than by reading it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from lory_scanner.cli.common import EXIT_ERROR, EXIT_FINDINGS, EXIT_INTERRUPTED, EXIT_OK
from lory_scanner.cli.init_cmd import HOOK_PATH
from lory_scanner.cli.main import main
from lory_scanner.engine.scanner import Scanner

CANARY = "CANARYvalue9182736455647382910abcXYZ"


# ── A secret must not survive in a neighbouring finding's context ────────────


def test_secret_is_masked_in_other_findings_context(tree, config):
    """A credential two lines from an unrelated finding was printed in full.

    Findings carry context either side, and a rule with nothing to do with
    secrets redacts nothing — so `docker.latest-tag` reported an API key that
    happened to sit on the next line.
    """
    tree({"Dockerfile": f"FROM node:latest\nENV API_KEY={CANARY}\n"})
    findings = Scanner(config, jobs=1).run().findings

    assert any(f.rule_id == "docker.latest-tag" for f in findings), "expected the neighbour"
    for finding in findings:
        blob = json.dumps([finding.to_dict(), finding.to_lory_row(), finding.context])
        assert CANARY not in blob, f"{finding.rule_id} leaked the secret"


def test_secret_is_masked_across_every_finding_in_the_file(tree, config):
    tree({"b.env": f"DATABASE_URL=postgres://user:{CANARY}@db:5432/x\nAPI_TOKEN={CANARY}\n"})
    result = Scanner(config, jobs=1).run()

    assert result.findings
    dumped = json.dumps([f.to_lory_row() for f in result.findings])
    assert CANARY not in dumped


def test_masking_does_not_disturb_ordinary_findings(tree, config):
    """The masking pass must not corrupt code that contains no secret."""
    tree({"app.py": 'subprocess.run(f"ping {host}", shell=True)\n'})
    finding = Scanner(config, jobs=1).run().findings[0]
    assert "shell=True" in finding.snippet


# ── A typo in --out is not a crash ──────────────────────────────────────────


def test_unwritable_out_is_a_clean_error(tmp_path):
    (tmp_path / "app.py").write_text("import pickle\npickle.loads(x)\n")
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "-f", "json", "-o", str(tmp_path / "no" / "such" / "out.json")],
    )
    assert result.exit_code == EXIT_ERROR
    assert result.exception is None or isinstance(result.exception, SystemExit)


# ── init must never block on a prompt ───────────────────────────────────────


def test_init_keeps_existing_files_without_a_terminal(tmp_path):
    """With no tty, a confirmation prompt never returns. It hung the command."""
    (tmp_path / "app.py").write_text("import pickle\npickle.loads(x)\n")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".lory-scan.yml").write_text("# hand-written\n")

    runner = CliRunner()
    result = runner.invoke(main, ["init", str(tmp_path), "--no-baseline", "--no-ci"])

    assert result.exit_code == EXIT_OK
    assert "hand-written" in (tmp_path / ".lory-scan.yml").read_text()


def test_init_yes_does_not_replace_edited_files(tmp_path):
    """--yes accepts defaults, and the default for "replace your file" is no."""
    (tmp_path / "app.py").write_text("import pickle\npickle.loads(x)\n")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    CliRunner().invoke(main, ["init", str(tmp_path), "--yes"])

    hook = tmp_path / HOOK_PATH
    hook.write_text("#!/bin/sh\necho mine\n")
    CliRunner().invoke(main, ["init", str(tmp_path), "--yes"])

    assert "echo mine" in hook.read_text()


# ── Output must survive a stream that cannot encode it ──────────────────────


@pytest.mark.skipif(os.name == "nt", reason="POSIX stream semantics")
def test_scan_survives_an_ascii_only_stdout(tmp_path):
    """A C-locale container is where CI runs, and any non-ASCII crashed it.

    Run out of process: the failure was in encoding on the real stdout, which
    an in-process runner replaces.
    """
    (tmp_path / "app.py").write_text(
        '# café — naïve\nsubprocess.run(f"ping {host}", shell=True)\n'
    )

    proc = subprocess.run(
        [sys.executable, "-m", "lory_scanner", "scan", str(tmp_path), "--fail-on", "never"],
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "ascii", "LC_ALL": "C", "LANG": "C"},
        cwd=Path(__file__).resolve().parent.parent,
    )

    assert proc.returncode == 0, proc.stderr.decode(errors="replace")[-2000:]
    assert b"Traceback" not in proc.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX stream semantics")
def test_json_is_still_valid_on_an_ascii_only_stdout(tmp_path):
    (tmp_path / "app.py").write_text('# café\nsubprocess.run(cmd, shell=True)\n')

    proc = subprocess.run(
        [sys.executable, "-m", "lory_scanner", "scan", str(tmp_path),
         "-f", "json", "--fail-on", "never"],
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "ascii", "LC_ALL": "C"},
        cwd=Path(__file__).resolve().parent.parent,
    )

    assert proc.returncode == 0
    json.loads(proc.stdout.decode("ascii"))


# ── Exit codes stay distinct ────────────────────────────────────────────────


def test_exit_codes_are_distinct():
    """An interrupt reported as 1 would read as "findings at or above threshold"."""
    assert len({EXIT_OK, EXIT_FINDINGS, EXIT_ERROR, EXIT_INTERRUPTED}) == 4
    assert EXIT_INTERRUPTED == 130


def test_describe_documents_every_exit_code():
    payload = json.loads(CliRunner().invoke(main, ["describe"]).output)
    for code in (EXIT_OK, EXIT_FINDINGS, EXIT_ERROR, EXIT_INTERRUPTED):
        assert str(code) in payload["exit_codes"]

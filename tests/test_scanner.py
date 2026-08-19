"""The engine: matching, filtering, suppression, baselines, identity."""

from __future__ import annotations

import json

from lory_scanner.core.config import ScanConfig
from lory_scanner.engine.scanner import Scanner, baseline_document

SHELL_TRUE = 'subprocess.run(f"ping {host}", shell=True)\n'


def scan(config: ScanConfig, **kwargs):
    return Scanner(config, jobs=1, **kwargs).run()


def test_finds_a_known_problem(tree, config):
    tree({"app.py": SHELL_TRUE})
    result = scan(config)
    assert [f.rule_id for f in result.findings] == ["python.subprocess-shell-true"]
    assert result.findings[0].line == 1
    assert result.findings[0].path == "app.py"


def test_clean_tree_reports_nothing(tree, config):
    tree({"app.py": "import os\n\n\ndef main():\n    return os.getcwd()\n"})
    assert scan(config).findings == []


def test_language_gating(tree, config):
    """A PHP rule must not fire on a Python file that happens to contain PHP."""
    tree({"notes.py": '# system("ping " . $_GET["host"]);\n'})
    assert [f.rule_id for f in scan(config).findings] == []


def test_findings_are_sorted_by_severity(tree, config):
    tree({
        "a.py": "import tempfile\npath = tempfile.mktemp()\n",   # medium
        "b.py": SHELL_TRUE,                                        # high
        "c.py": "import pickle\npickle.loads(data)\n",             # critical
    })
    severities = [f.severity for f in scan(config).findings]
    assert severities == sorted(severities, key=["critical", "high", "medium", "low", "info"].index)


def test_min_severity_filters(tree, config):
    tree({"a.py": "import tempfile\npath = tempfile.mktemp()\n"})
    assert scan(config).findings
    result = scan(ScanConfig(root=config.root, respect_gitignore=False, min_severity="high"))
    assert result.findings == []
    assert result.filtered == 1


def test_ignore_rule_and_select(tree, config):
    tree({"app.py": SHELL_TRUE})
    ignored = ScanConfig(
        root=config.root, respect_gitignore=False,
        ignore_rules=["python.subprocess-*"],
    )
    assert scan(ignored).findings == []

    selected = ScanConfig(
        root=config.root, respect_gitignore=False, select=["php.*"]
    )
    assert scan(selected).findings == []


def test_severity_override(tree, config):
    tree({"app.py": SHELL_TRUE})
    config.severity_overrides = {"python.subprocess-shell-true": "low"}
    assert scan(config).findings[0].severity == "low"


def test_excluded_paths_are_not_scanned(tree, config):
    tree({"vendor/lib.py": SHELL_TRUE, "app.py": SHELL_TRUE})
    paths = {f.path for f in scan(config).findings}
    assert paths == {"app.py"}


def test_include_narrows_the_scan(tree, config):
    tree({"src/a.py": SHELL_TRUE, "other/b.py": SHELL_TRUE})
    config.include = ["src/**"]
    assert {f.path for f in scan(config).findings} == {"src/a.py"}


# ── suppressions ────────────────────────────────────────────────────────────


def test_trailing_suppression(tree, config):
    tree({"app.py": SHELL_TRUE.rstrip() + "  # lory-scan:ignore\n"})
    result = scan(config)
    assert result.findings == []
    assert result.suppressed == 1


def test_suppression_on_the_line_above(tree, config):
    tree({"app.py": "# lory-scan:ignore\n" + SHELL_TRUE})
    assert scan(config).findings == []


def test_targeted_suppression_only_silences_its_rule(tree, config):
    tree({"app.py": SHELL_TRUE.rstrip() + "  # lory-scan:ignore[some.other.rule]\n"})
    assert [f.rule_id for f in scan(config).findings] == ["python.subprocess-shell-true"]


def test_suppressions_can_be_disabled(tree, config):
    tree({"app.py": SHELL_TRUE.rstrip() + "  # lory-scan:ignore\n"})
    config.suppressions = False
    assert len(scan(config).findings) == 1


def test_ignore_suppressions_reports_them_marked(tree, config):
    tree({"app.py": SHELL_TRUE.rstrip() + "  # lory-scan:ignore -- reviewed\n"})
    result = Scanner(config, jobs=1, ignore_suppressions=True).run()
    assert len(result.findings) == 1
    assert result.findings[0].suppressed_by == "reviewed"


# ── identity and baselines ──────────────────────────────────────────────────


def test_fingerprint_survives_an_edit_above_the_finding(tree, config):
    """Triage state has to stay attached when code moves down a file."""
    root = tree({"app.py": SHELL_TRUE})
    before = scan(config).findings[0]

    (root / "app.py").write_text("import os\nimport sys\n\n" + SHELL_TRUE)
    after = scan(config).findings[0]

    assert after.line != before.line
    assert after.fingerprint == before.fingerprint
    assert after.key == before.key


def test_fingerprint_changes_when_the_code_changes(tree, config):
    root = tree({"app.py": SHELL_TRUE})
    before = scan(config).findings[0]
    (root / "app.py").write_text('subprocess.run(f"traceroute {host}", shell=True)\n')
    assert scan(config).findings[0].fingerprint != before.fingerprint


def test_identical_matches_in_one_file_stay_distinct(tree, config):
    tree({"app.py": SHELL_TRUE + SHELL_TRUE})
    findings = scan(config).findings
    assert len(findings) == 2
    assert findings[0].fingerprint != findings[1].fingerprint


def test_baseline_suppresses_known_findings(tree, config, tmp_path):
    root = tree({"app.py": SHELL_TRUE})
    baseline = tmp_path / "base.json"
    baseline.write_text(json.dumps(baseline_document(scan(config))))

    config.baseline = baseline
    result = scan(config)
    assert result.findings == []
    assert result.baselined == 1

    (root / "app.py").write_text(SHELL_TRUE + "import pickle\npickle.loads(x)\n")
    assert [f.rule_id for f in scan(config).findings] == ["python.pickle-loads"]


# ── the engine's own guarantees ─────────────────────────────────────────────


def test_one_finding_per_rule_per_line(tree, config):
    """Several alternatives of one rule on one line are one problem."""
    php = '<?php $r = mysqli_query($c, "SELECT * FROM t WHERE id = " . $_GET[\'id\']);\n'
    tree({"legacy.php": php})
    hits = [f for f in scan(config).findings if f.rule_id == "php.sql-superglobal-in-query"]
    assert len(hits) == 1


def test_parallel_and_sequential_agree(tree, config):
    """The pool must not change what a scan finds — only how fast."""
    files = {f"pkg/mod{i}.py": SHELL_TRUE for i in range(60)}
    files["legacy.php"] = '<?php echo "hi " . $_GET["name"];\n'
    tree(files)

    sequential = Scanner(config, jobs=1).run()
    parallel = Scanner(config, jobs=4).run()

    assert [f.key for f in sequential.findings] == [f.key for f in parallel.findings]


def test_entropy_finding_redacts_the_secret(tree, config):
    """A findings file must not become a second copy of the credential."""
    secret = "Zx9Qw3Rt7Yu1Pa5Sd8Fg2Hj4Kl6Mn0Bv"
    tree({"settings.py": f'API_SECRET_KEY = "{secret}"\n'})
    findings = [f for f in scan(config).findings if "entropy" in f.rule_id]
    assert findings, "a high-entropy secret assignment should be found"
    dumped = json.dumps(findings[0].to_dict())
    assert secret not in dumped


def test_entropy_ignores_environment_references(tree, config):
    tree({"settings.py": 'API_SECRET_KEY = os.environ["API_SECRET_KEY"]\n'})
    assert [f for f in scan(config).findings if "entropy" in f.rule_id] == []


def test_entropy_can_be_switched_off(tree, config):
    tree({"settings.py": 'API_SECRET_KEY = "Zx9Qw3Rt7Yu1Pa5Sd8Fg2Hj4Kl6Mn0Bv"\n'})
    config.entropy = False
    assert [f for f in scan(config).findings if "entropy" in f.rule_id] == []


def test_binary_and_oversized_files_are_skipped(tree, config):
    root = tree({"app.py": SHELL_TRUE})
    (root / "blob.py").write_bytes(b"\x00\x01\x02" + SHELL_TRUE.encode())
    (root / "huge.py").write_text(SHELL_TRUE + "# padding\n" * 5000)
    config.max_file_bytes = 200

    result = scan(config)
    assert {f.path for f in result.findings} == {"app.py"}
    assert result.stats.skipped_binary == 1
    assert result.stats.skipped_large == 1


def test_max_findings_caps_output(tree, config):
    tree({f"m{i}.py": SHELL_TRUE for i in range(20)})
    config.max_findings = 5
    result = scan(config)
    assert len(result.findings) == 5
    assert result.truncated


def test_custom_rules_directory(tree, config, tmp_path):
    rules = tmp_path / "custom"
    rules.mkdir()
    (rules / "house.yml").write_text("""
rules:
  - id: house.no-todo-security
    title: Security TODO left in code
    severity: low
    languages: [python]
    pattern: 'TODO.{0,20}security'
    remediation: Resolve it or file it.
    description: A security TODO in shipped code.
""")
    tree({"app.py": "# TODO fix security here\n"})
    config.rule_dirs = [rules]
    assert [f.rule_id for f in scan(config).findings] == ["house.no-todo-security"]


def test_scan_result_exit_decision(tree, config):
    tree({"a.py": "import tempfile\ntempfile.mktemp()\n"})
    result = scan(config)
    assert result.should_fail("medium")
    assert not result.should_fail("high")
    assert not result.should_fail("never")


def test_rules_run_count_reflects_selection(tree, config):
    tree({"app.py": SHELL_TRUE})
    config.select = ["python.*"]
    result = scan(config)
    assert 0 < result.rules_run < result.rules_loaded


# ── file-level suppressions ─────────────────────────────────────────────────


def test_ignore_file_silences_the_whole_file(tree, config):
    tree({"fixtures.py": "# lory-scan:ignore-file -- fixtures, wrong on purpose\n"
                         + SHELL_TRUE + "import pickle\npickle.loads(x)\n"})
    result = scan(config)
    assert result.findings == []
    assert result.suppressed == 2


def test_ignore_file_accepts_rule_globs(tree, config):
    """A file can excuse one family without going blind to everything."""
    tree({"rules.py": "# lory-scan:ignore-file[python.subprocess-*] -- documented example\n"
                      + SHELL_TRUE + "import pickle\npickle.loads(x)\n"})
    assert [f.rule_id for f in scan(config).findings] == ["python.pickle-loads"]


def test_ignore_file_applies_from_anywhere_in_the_file(tree, config):
    tree({"a.py": SHELL_TRUE + "\n# lory-scan:ignore-file\n"})
    assert scan(config).findings == []


def test_line_suppression_accepts_a_rule_glob(tree, config):
    tree({"app.py": SHELL_TRUE.rstrip() + "  # lory-scan:ignore[python.subprocess-*]\n"})
    assert scan(config).findings == []


def test_the_bundled_rule_files_do_not_report_themselves(config):
    """`rules validate` examples are real credentials in shape, by design."""
    from lory_scanner.core.config import ScanConfig
    from lory_scanner.engine.rules import BUNDLED_RULES_DIR

    result = Scanner(
        ScanConfig(root=BUNDLED_RULES_DIR, respect_gitignore=False), jobs=1
    ).run()
    assert result.findings == [], [f.location for f in result.findings]

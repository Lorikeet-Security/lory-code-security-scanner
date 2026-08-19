"""Rule loading, validation, and the bundled ruleset's own self-tests."""

from __future__ import annotations

import pytest

from lory_scanner.core.errors import RuleError
from lory_scanner.engine.rules import BUNDLED_RULES_DIR, load_rules


def write(tmp_path, body: str):
    path = tmp_path / "rules.yml"
    path.write_text(body)
    return path


def test_bundled_rules_load():
    ruleset = load_rules()
    assert len(ruleset) > 50
    assert ruleset.by_id("python.subprocess-shell-true") is not None


def test_every_bundled_rule_has_actionable_metadata():
    """A finding with no CWE and no fix is a complaint, not a report."""
    for rule in load_rules():
        assert rule.title, f"{rule.id} has no title"
        assert rule.remediation, f"{rule.id} has no remediation"
        assert rule.description, f"{rule.id} has no description"


def test_bundled_rule_examples_all_pass():
    """The examples are the guard on prefilters, which fail silently."""
    checked = 0
    for rule in load_rules():
        for example in rule.examples:
            assert rule.matches(example), f"{rule.id} should match {example!r}"
            checked += 1
        for example in rule.counterexamples:
            assert not rule.matches(example), f"{rule.id} should not match {example!r}"
            checked += 1
    assert checked > 50, "the bundled rules should carry meaningful self-tests"


def test_rule_ids_are_unique_across_bundled_files():
    seen: set[str] = set()
    for rule in load_rules():
        assert rule.id not in seen
        seen.add(rule.id)


def test_bad_regex_is_rejected(tmp_path):
    path = write(tmp_path, """
rules:
  - id: bad.rule
    title: Bad
    severity: high
    pattern: '([unclosed'
""")
    with pytest.raises(RuleError, match="bad regex"):
        load_rules(dirs=[path], include_bundled=False)


def test_unknown_severity_is_rejected(tmp_path):
    path = write(tmp_path, """
rules:
  - id: bad.rule
    title: Bad
    severity: catastrophic
    pattern: 'x'
""")
    with pytest.raises(RuleError, match="severity must be one of"):
        load_rules(dirs=[path], include_bundled=False)


def test_missing_pattern_is_rejected(tmp_path):
    path = write(tmp_path, """
rules:
  - id: bad.rule
    title: Bad
    severity: high
""")
    with pytest.raises(RuleError, match="no 'pattern'"):
        load_rules(dirs=[path], include_bundled=False)


def test_malformed_id_is_rejected(tmp_path):
    path = write(tmp_path, """
rules:
  - id: Bad Rule ID
    title: Bad
    severity: high
    pattern: 'x'
""")
    with pytest.raises(RuleError, match="must be lowercase words"):
        load_rules(dirs=[path], include_bundled=False)


def test_local_rule_overrides_bundled_one(tmp_path):
    """A team retunes a noisy rule by reusing its id, without forking."""
    path = write(tmp_path, """
rules:
  - id: python.subprocess-shell-true
    title: Locally retuned
    severity: low
    pattern: 'shell=True'
""")
    ruleset = load_rules(dirs=[path])
    rule = ruleset.by_id("python.subprocess-shell-true")
    assert rule is not None
    assert rule.title == "Locally retuned"
    assert rule.severity == "low"


def test_duplicate_id_within_one_file_is_rejected(tmp_path):
    path = write(tmp_path, """
rules:
  - id: a.rule
    title: One
    severity: low
    pattern: 'x'
  - id: a.rule
    title: Two
    severity: low
    pattern: 'y'
""")
    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rules(dirs=[path], include_bundled=False)


def test_cwe_is_normalised(tmp_path):
    path = write(tmp_path, """
rules:
  - id: a.rule
    title: One
    severity: low
    pattern: 'x'
    cwe: 89
  - id: b.rule
    title: Two
    severity: low
    pattern: 'y'
    cwe: CWE-79
""")
    ruleset = load_rules(dirs=[path], include_bundled=False)
    assert ruleset.by_id("a.rule").cwe == "CWE-89"
    assert ruleset.by_id("b.rule").cwe == "CWE-79"


def test_prefilter_is_never_derived_from_an_alternation(tmp_path):
    """The one derivation that would lose findings, checked directly.

    `AKIA|ASIA` shares no mandatory literal; deriving "akia" would make the
    rule blind to every ASIA key, and nothing in a scan would report that.
    """
    path = write(tmp_path, """
rules:
  - id: a.rule
    title: One
    severity: low
    pattern: '(?:AKIA|ASIA)[A-Z0-9]{16}'
""")
    rule = load_rules(dirs=[path], include_bundled=False).by_id("a.rule")
    assert rule.prefilters == ()
    assert rule.matches("ASIAY34FZKBOKMUTVV7A")


def test_derived_prefilter_keeps_the_rule_matching(tmp_path):
    path = write(tmp_path, """
rules:
  - id: a.rule
    title: One
    severity: low
    pattern: 'subprocess\\.run'
""")
    rule = load_rules(dirs=[path], include_bundled=False).by_id("a.rule")
    assert rule.prefilters == ("subprocess",)
    assert rule.matches("subprocess.run(cmd)")
    assert not rule.may_match("os.system(cmd)")


def test_rules_directory_ships_with_the_package():
    assert BUNDLED_RULES_DIR.is_dir()
    assert list(BUNDLED_RULES_DIR.glob("*.yml"))

"""File discovery, glob semantics, config loading, and the Python API."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from lory_scanner import api
from lory_scanner.core.config import DEFAULT_EXCLUDES, ScanConfig
from lory_scanner.core.config import load as load_config
from lory_scanner.core.errors import ConfigError, TargetError
from lory_scanner.engine.languages import detect
from lory_scanner.engine.walker import GlobSet, Walker, changed_files, path_matches

SHELL_TRUE = 'subprocess.run(f"ping {host}", shell=True)\n'


def walk(root: Path, **kwargs):
    walker = Walker(root, DEFAULT_EXCLUDES, respect_gitignore=False, **kwargs)
    return sorted(source.relpath for source in walker.walk()), walker.stats


# ── globs ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("relpath", "pattern", "expected"),
    [
        ("node_modules/react/index.js", "**/node_modules/**", True),
        ("a/b/node_modules/x.js", "**/node_modules/**", True),
        ("src/app.py", "**/node_modules/**", False),
        (".env.production", "**/.env*", True),
        ("config/.env.local", "**/.env*", True),
        ("src/deep/a.py", "src/**", True),
        ("other/a.py", "src/**", False),
        ("app.min.js", "**/*.min.js", True),
        ("tests/test_x.py", "tests", True),
    ],
)
def test_path_matching(relpath, pattern, expected):
    assert path_matches(relpath, pattern) is expected
    assert GlobSet([pattern]).matches(relpath) is expected


def test_globset_matches_the_reference_for_the_default_excludes():
    """The compiled matcher is an optimisation; it must not change meaning."""
    compiled = GlobSet(DEFAULT_EXCLUDES)
    samples = [
        "src/app.py", "node_modules/a/b.js", "vendor/lib.php", "dist/out.js",
        "a/b/c/__pycache__/x.pyc", "package-lock.json", "assets/app.min.js",
        ".venv/lib/site.py", "README.md", "a/.git/config", "src/build.py",
    ]
    for sample in samples:
        reference = any(path_matches(sample, p) for p in DEFAULT_EXCLUDES)
        assert compiled.matches(sample) is reference, sample


# ── discovery ───────────────────────────────────────────────────────────────


def test_default_excludes_prune_vendored_trees(tmp_path):
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "i.js").write_text(SHELL_TRUE)
    (tmp_path / "app.py").write_text(SHELL_TRUE)

    files, _ = walk(tmp_path)
    assert files == ["app.py"]


def test_unknown_file_types_are_skipped(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "photo.jpeg").write_bytes(b"\xff\xd8\xff")
    files, stats = walk(tmp_path)
    assert files == ["app.py"]
    assert stats.skipped_unknown_type == 1


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path.parent / "outside_tree"
    outside.mkdir(exist_ok=True)
    (outside / "secret.py").write_text(SHELL_TRUE)
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "link").symlink_to(outside)

    files, _ = walk(tmp_path)
    assert files == ["app.py"]


def test_language_detection():
    assert detect(Path("a/b.py")) == "python"
    assert detect(Path("Dockerfile")) == "dockerfile"
    assert detect(Path("Dockerfile.web")) == "dockerfile"
    assert detect(Path(".env.production")) == "env"
    assert detect(Path("main.tf")) == "terraform"
    assert detect(Path("photo.png")) == ""


# ── git integration ─────────────────────────────────────────────────────────


def git_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    return tmp_path


def commit(root: Path, message: str = "c") -> None:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", message], check=True)


@pytest.mark.skipif(not __import__("shutil").which("git"), reason="git not installed")
def test_gitignored_files_are_skipped(tmp_path):
    root = git_repo(tmp_path)
    (root / ".gitignore").write_text("ignored.py\n")
    (root / "ignored.py").write_text(SHELL_TRUE)
    (root / "app.py").write_text(SHELL_TRUE)
    commit(root)

    walker = Walker(root, DEFAULT_EXCLUDES, respect_gitignore=True)
    # .gitignore itself is not a language this tool scans, so it never appears.
    assert sorted(s.relpath for s in walker.walk()) == ["app.py"]


@pytest.mark.skipif(not __import__("shutil").which("git"), reason="git not installed")
def test_no_gitignore_reaches_ignored_files(tmp_path):
    root = git_repo(tmp_path)
    (root / ".gitignore").write_text("ignored.py\n")
    (root / "ignored.py").write_text(SHELL_TRUE)
    commit(root)

    files, _ = walk(root)
    assert "ignored.py" in files


@pytest.mark.skipif(not __import__("shutil").which("git"), reason="git not installed")
def test_diff_scans_only_changed_files(tmp_path):
    root = git_repo(tmp_path)
    (root / "old.py").write_text(SHELL_TRUE)
    commit(root)
    (root / "new.py").write_text(SHELL_TRUE)
    commit(root, "second")

    changed = changed_files(root, "HEAD~1", staged=False)
    assert [p.name for p in changed] == ["new.py"]

    result = api.scan(root, diff="HEAD~1", respect_gitignore=False)
    assert {f.path for f in result.findings} == {"new.py"}


def test_diff_outside_a_repo_is_an_error(tmp_path):
    with pytest.raises(TargetError):
        changed_files(tmp_path, "HEAD", staged=False)


# ── config ──────────────────────────────────────────────────────────────────


def test_missing_config_is_not_an_error(tmp_path):
    cfg = load_config(None, tmp_path)
    assert cfg.min_severity == "info"
    assert cfg.fail_on == "high"
    assert cfg.source is None


def test_config_is_found_above_the_scan_root(tmp_path):
    """Policy belongs to the repository, not to the directory you cd into."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".lory-scan.yml").write_text("min_severity: high\n")
    nested = tmp_path / "services" / "api"
    nested.mkdir(parents=True)

    assert load_config(None, nested).min_severity == "high"


def test_config_search_stops_at_the_repository_root(tmp_path):
    (tmp_path / ".lory-scan.yml").write_text("min_severity: high\n")
    inner = tmp_path / "repo"
    inner.mkdir()
    (inner / ".git").mkdir()

    assert load_config(None, inner).min_severity == "info"


def test_relative_paths_resolve_against_the_config_file(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "rules").mkdir()
    (tmp_path / ".lory-scan.yml").write_text("rule_dirs:\n  - rules\n")

    cfg = load_config(None, tmp_path / "sub" if (tmp_path / "sub").exists() else tmp_path)
    assert cfg.rule_dirs == [tmp_path / "rules"]


def test_explicit_missing_config_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="config file not found"):
        load_config(tmp_path / "nope.yml", tmp_path)


def test_invalid_yaml_is_an_error(tmp_path):
    path = tmp_path / ".lory-scan.yml"
    path.write_text("exclude: [unclosed\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(path, tmp_path)


def test_validation_reports_every_problem_at_once(tmp_path):
    cfg = ScanConfig(root=tmp_path, min_severity="nope", entropy_threshold=99)
    errors = cfg.validate()
    assert len(errors) == 2


def test_merge_cli_ignores_unset_flags(tmp_path):
    cfg = ScanConfig(root=tmp_path, min_severity="high")
    assert cfg.merge_cli(min_severity=None).min_severity == "high"
    assert cfg.merge_cli(min_severity="low").min_severity == "low"


def test_merge_cli_accumulates_lists(tmp_path):
    cfg = ScanConfig(root=tmp_path, exclude=["a/**"])
    assert cfg.merge_cli(exclude=["b/**"]).exclude == ["a/**", "b/**"]


# ── the Python API ──────────────────────────────────────────────────────────


def test_api_scan(tmp_path):
    (tmp_path / "app.py").write_text(SHELL_TRUE)
    result = api.scan(tmp_path, respect_gitignore=False)
    assert result.findings[0].rule_id == "python.subprocess-shell-true"


def test_api_scan_accepts_a_single_file(tmp_path):
    target = tmp_path / "app.py"
    target.write_text(SHELL_TRUE)
    assert api.scan(target, respect_gitignore=False).findings


def test_api_scan_to_lory_cache(tmp_path):
    (tmp_path / "app.py").write_text(SHELL_TRUE)
    result, path = api.scan_to_lory_cache(tmp_path, respect_gitignore=False)
    assert path.exists()
    assert api.lory_rows(result)[0]["ref"].startswith("scan-")

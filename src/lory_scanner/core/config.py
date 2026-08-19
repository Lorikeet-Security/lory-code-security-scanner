"""Scan configuration: defaults, ``.lory-scan.yml``, then CLI flags.

Precedence is the ordinary one — a flag beats the file, the file beats the
default — and it is applied in one place (:meth:`ScanConfig.merge_cli`) so
there is no second, quieter set of precedence rules hiding in the CLI module.

The file is optional. A repository with no ``.lory-scan.yml`` scans with the
bundled rules and sensible excludes, which is the common case.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from lory_scanner.core.errors import ConfigError
from lory_scanner.core.severity import SEVERITY_ORDER

#: Looked for in the scan root, nearest first, when ``--config`` is not given.
CONFIG_NAMES = (".lory-scan.yml", ".lory-scan.yaml")

#: Directories never worth walking. Vendored and generated trees produce
#: findings nobody can act on, and they dominate the runtime of a naive walk.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "**/.git/**",
    "**/node_modules/**",
    "**/vendor/**",
    "**/bower_components/**",
    "**/dist/**",
    "**/build/**",
    "**/out/**",
    "**/target/**",
    "**/.next/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/venv/**",
    "**/.tox/**",
    "**/.mypy_cache/**",
    "**/.pytest_cache/**",
    "**/.ruff_cache/**",
    "**/coverage/**",
    "**/htmlcov/**",
    "**/.idea/**",
    "**/.vscode/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
    "**/*.lock",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/poetry.lock",
    "**/Cargo.lock",
    "**/composer.lock",
    # This tool's own output. A findings file quotes the lines it found, so
    # scanning one turns every reported secret into a second finding — and the
    # scan after that finds those. Excluded by default; --no-default-excludes
    # still reaches them.
    "**/.lory_state/**",
    "**/.lory-scan-baseline.json",
)

#: A file larger than this is almost certainly generated, bundled, or data.
DEFAULT_MAX_FILE_BYTES = 2_000_000

#: Where the findings TUI keeps its cache. `lory-scan sync` writes here.
DEFAULT_STATE_DIR = Path(".lory_state")


@dataclass
class ScanConfig:
    """Everything a scan needs to know, after merging file and flags."""

    #: The tree to scan. Findings report paths relative to it.
    root: Path = field(default_factory=Path.cwd)

    #: Extra glob patterns to skip, on top of :data:`DEFAULT_EXCLUDES`.
    exclude: list[str] = field(default_factory=list)
    #: When non-empty, only paths matching one of these globs are scanned.
    include: list[str] = field(default_factory=list)
    #: Replace the built-in excludes rather than adding to them. For the rare
    #: audit that genuinely wants to look inside vendor/.
    no_default_excludes: bool = False

    #: Directories of extra rule files, loaded after the bundled ones.
    rule_dirs: list[Path] = field(default_factory=list)
    #: Skip the bundled rules entirely and use only `rule_dirs`.
    no_default_rules: bool = False
    #: Rule id globs to keep (empty means all) and to drop.
    select: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    #: Categories to keep (empty means all).
    categories: list[str] = field(default_factory=list)
    #: Per-rule severity overrides, ``{rule_id: severity}``.
    severity_overrides: dict[str, str] = field(default_factory=dict)

    #: Drop findings below this severity before reporting.
    min_severity: str = "info"
    #: Exit 1 when a finding at or above this severity survives.
    fail_on: str = "high"
    #: Drop findings below this confidence. "low" keeps everything.
    min_confidence: str = "low"

    #: Generic high-entropy string detection, over and above the secret rules.
    entropy: bool = True
    #: Shannon-entropy floor for a generic secret. Lower finds more and is
    #: noisier; this default was set against real repositories.
    entropy_threshold: float = 4.0

    #: Honour ``lory-scan:ignore`` comments in the source.
    suppressions: bool = True
    #: Honour .gitignore, when the tree is a git checkout.
    respect_gitignore: bool = True

    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    #: Stop after this many findings. 0 means no cap.
    max_findings: int = 0

    #: Fingerprints to treat as already-known.
    baseline: Path | None = None

    #: Where `sync` (and `--emit-lory-cache`) writes the TUI's findings cache.
    state_dir: Path = field(default=DEFAULT_STATE_DIR)

    #: Which config file, if any, produced these values. Reported by `describe`
    #: and by the table footer so a surprising result is traceable.
    source: Path | None = None

    def validate(self) -> list[str]:
        errors: list[str] = []

        if not self.root.exists():
            errors.append(f"path to scan does not exist: {self.root}")
        elif not self.root.is_dir() and not self.root.is_file():
            errors.append(f"path to scan is neither a file nor a directory: {self.root}")

        for name, value in (
            ("min_severity", self.min_severity),
            ("fail_on", self.fail_on),
        ):
            if value not in SEVERITY_ORDER and value != "never":
                errors.append(
                    f"{name} must be one of {', '.join(SEVERITY_ORDER)} (or 'never'), "
                    f"got {value!r}"
                )

        if self.min_confidence not in ("high", "medium", "low"):
            errors.append(
                f"min_confidence must be high, medium, or low, got {self.min_confidence!r}"
            )

        if not 0 < self.entropy_threshold <= 8:
            errors.append("entropy_threshold must be between 0 and 8 (bits per character)")

        if self.max_file_bytes < 1:
            errors.append("max_file_bytes must be >= 1")

        for directory in self.rule_dirs:
            if not directory.exists():
                errors.append(f"rule directory does not exist: {directory}")

        if self.baseline is not None and not self.baseline.exists():
            errors.append(f"baseline file does not exist: {self.baseline}")

        if self.no_default_rules and not self.rule_dirs:
            errors.append("no_default_rules is set but no rule_dirs were given: nothing would run")

        return errors

    def check(self) -> ScanConfig:
        """Raise :class:`ConfigError` if anything is invalid; else return self."""
        errors = self.validate()
        if errors:
            raise ConfigError("invalid scan configuration:\n  - " + "\n  - ".join(errors))
        return self

    def effective_excludes(self) -> list[str]:
        if self.no_default_excludes:
            return list(self.exclude)
        return [*DEFAULT_EXCLUDES, *self.exclude]

    def merge_cli(self, **overrides: Any) -> ScanConfig:
        """Apply CLI flags over file values.

        ``None`` means "the flag was not given". List-valued flags accumulate
        onto the file's list rather than replacing it, because a flag that
        silently discarded a repository's agreed excludes would be a footgun.
        """
        accumulate = {"exclude", "include", "rule_dirs", "select", "ignore_rules", "categories"}
        merged: dict[str, Any] = {}

        for key, value in overrides.items():
            if value is None:
                continue
            if key in accumulate:
                value = list(value)
                if not value:
                    continue
                merged[key] = [*getattr(self, key), *value]
            else:
                merged[key] = value

        return replace(self, **merged)


def find_config(root: Path) -> Path | None:
    """Locate ``.lory-scan.yml`` at the scan root, or above it up to the repo top.

    Looking upward matters when someone scans a subdirectory: the policy still
    belongs to the repository, not to the directory they happened to `cd` into.
    The walk stops at a ``.git`` directory, or at the filesystem root.
    """
    current = root if root.is_dir() else root.parent
    current = current.resolve()

    while True:
        for name in CONFIG_NAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        if (current / ".git").exists() or current.parent == current:
            return None
        current = current.parent


def load(path: str | Path | None, root: Path) -> ScanConfig:
    """Load config for a scan of ``root``.

    ``path`` is an explicit ``--config``; when it is None the file is looked
    for, and its absence is not an error.
    """
    root = Path(root).expanduser()

    if path is not None:
        config_path: Path | None = Path(path)
        if config_path is not None and not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
    else:
        config_path = find_config(root)

    if config_path is None:
        return ScanConfig(root=root)

    try:
        raw = yaml.safe_load(config_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{config_path} is not valid YAML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{config_path} must contain a YAML mapping at the top level")

    unknown = set(raw) - _KNOWN_KEYS
    if unknown:
        raise ConfigError(
            f"{config_path} has unknown key(s): {', '.join(sorted(unknown))}. "
            f"Known keys: {', '.join(sorted(_KNOWN_KEYS))}"
        )

    # Rule dirs and the baseline are written relative to the config file, which
    # is the only interpretation that survives being scanned from elsewhere.
    base = config_path.parent

    return ScanConfig(
        root=root,
        exclude=_strings(raw, "exclude"),
        include=_strings(raw, "include"),
        no_default_excludes=_bool(raw, "no_default_excludes", False),
        rule_dirs=[_resolve(base, p) for p in _strings(raw, "rule_dirs")],
        no_default_rules=_bool(raw, "no_default_rules", False),
        select=_strings(raw, "select"),
        ignore_rules=_strings(raw, "ignore_rules"),
        categories=_strings(raw, "categories"),
        severity_overrides=_severity_map(raw.get("severity_overrides"), config_path),
        min_severity=_word(raw, "min_severity", "info"),
        fail_on=_word(raw, "fail_on", "high"),
        min_confidence=_word(raw, "min_confidence", "low"),
        entropy=_bool(raw, "entropy", True),
        entropy_threshold=float(raw.get("entropy_threshold", 4.0)),
        suppressions=_bool(raw, "suppressions", True),
        respect_gitignore=_bool(raw, "respect_gitignore", True),
        max_file_bytes=int(raw.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)),
        max_findings=int(raw.get("max_findings", 0)),
        baseline=_resolve(base, raw["baseline"]) if raw.get("baseline") else None,
        state_dir=_resolve(base, raw["state_dir"]) if raw.get("state_dir") else DEFAULT_STATE_DIR,
        source=config_path,
    )


_KNOWN_KEYS = {
    "exclude", "include", "no_default_excludes", "rule_dirs", "no_default_rules",
    "select", "ignore_rules", "categories", "severity_overrides", "min_severity",
    "fail_on", "min_confidence", "entropy", "entropy_threshold", "suppressions",
    "respect_gitignore", "max_file_bytes", "max_findings", "baseline", "state_dir",
}


def _resolve(base: Path, value: Any) -> Path:
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else (base / path)


def _strings(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key) or []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        raise ConfigError(f"{key} must be a string or a list of strings")
    return [str(v) for v in value]


def _word(raw: dict[str, Any], key: str, default: str) -> str:
    value = raw.get(key, default)
    return str(value).strip().lower()


def _bool(raw: dict[str, Any], key: str, default: bool) -> bool:
    value = raw.get(key, default)
    if isinstance(value, bool):
        return value
    word = str(value).strip().lower()
    if word in ("true", "yes", "on", "1"):
        return True
    if word in ("false", "no", "off", "0", ""):
        return False
    raise ConfigError(f"{key} must be true or false, got {value!r}")


def _severity_map(value: Any, path: Path) -> dict[str, str]:
    if not value:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: severity_overrides must be a mapping of rule id to severity")
    out: dict[str, str] = {}
    for rule_id, severity in value.items():
        word = str(severity).strip().lower()
        if word not in SEVERITY_ORDER:
            raise ConfigError(
                f"{path}: severity_overrides[{rule_id}] must be one of "
                f"{', '.join(SEVERITY_ORDER)}, got {severity!r}"
            )
        out[str(rule_id)] = word
    return out

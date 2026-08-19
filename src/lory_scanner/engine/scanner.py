"""The scan itself: rules over files, then the filters that decide what survives.

Order is deliberate. Match first, then suppress, then baseline, then severity
and confidence floors — so a suppression comment is honoured before a baseline
is consulted, and a finding dropped by the severity floor is not silently
written into a baseline as "known".
"""

from __future__ import annotations

import fnmatch
import os
import time
from collections.abc import Iterable
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lory_scanner.core.config import ScanConfig
from lory_scanner.core.severity import CONFIDENCE_LEVELS, at_or_above, counts
from lory_scanner.engine import suppress as suppress_mod
from lory_scanner.engine.entropy import find_candidates, mask
from lory_scanner.engine.rules import Rule, RuleSet, load_rules
from lory_scanner.engine.walker import (
    SourceFile,
    Walker,
    WalkStats,
    changed_files,
    path_matches,
)
from lory_scanner.report.finding import Finding, sort_findings

#: Lines of context kept either side of a match.
CONTEXT_LINES = 2

#: How much of a matched string is carried into a finding. Long enough to
#: identify, short enough that a report is not a copy of the source.
MAX_MATCH_CHARS = 240

#: The generic entropy detector's pseudo-rule id, so it can be selected,
#: ignored, suppressed, and baselined like any other rule.
ENTROPY_RULE_ID = "secrets.high-entropy-assignment"


@dataclass
class ScanResult:
    """Everything one scan produced."""

    findings: list[Finding] = field(default_factory=list)
    stats: WalkStats = field(default_factory=WalkStats)
    rules_loaded: int = 0
    rules_run: int = 0
    duration_ms: int = 0
    scanned_at: str = ""
    root: Path = field(default_factory=Path.cwd)
    #: Findings dropped by a suppression comment, a baseline, or a floor.
    suppressed: int = 0
    baselined: int = 0
    filtered: int = 0
    truncated: bool = False

    def severity_counts(self) -> dict[str, int]:
        return counts([f.severity for f in self.findings])

    def worst_severity(self) -> str | None:
        return self.findings[0].severity if self.findings else None

    def should_fail(self, threshold: str) -> bool:
        """Whether this run trips the ``--fail-on`` threshold."""
        if threshold == "never":
            return False
        return any(at_or_above(f.severity, threshold) for f in self.findings)

    def stats_dict(self) -> dict[str, Any]:
        return {
            "scanned_at": self.scanned_at,
            "root": str(self.root),
            "duration_ms": self.duration_ms,
            "rules_loaded": self.rules_loaded,
            "rules_run": self.rules_run,
            "files": self.stats.as_dict(),
            "findings_reported": len(self.findings),
            "findings_suppressed": self.suppressed,
            "findings_baselined": self.baselined,
            "findings_filtered": self.filtered,
            "truncated": self.truncated,
            "severity_counts": self.severity_counts(),
        }


class Scanner:
    """Runs a configured scan. One instance, one scan."""

    def __init__(
        self,
        config: ScanConfig,
        ruleset: RuleSet | None = None,
        ignore_suppressions: bool = False,
        jobs: int | None = None,
    ) -> None:
        self.config = config
        self.ignore_suppressions = ignore_suppressions
        self.jobs = jobs
        self.ruleset = ruleset or load_rules(
            dirs=config.rule_dirs, include_bundled=not config.no_default_rules
        )
        self.active: list[Rule] = _select_rules(self.ruleset, config)
        self.baseline: frozenset[str] = _load_baseline(config.baseline)

    # ── running ─────────────────────────────────────────────────────────────

    def run(self, paths: list[Path] | None = None) -> ScanResult:
        started = time.perf_counter()
        scanned_at = datetime.now(UTC).isoformat()

        walker = Walker(
            root=self.config.root,
            excludes=self.config.effective_excludes(),
            includes=self.config.include,
            max_bytes=self.config.max_file_bytes,
            respect_gitignore=self.config.respect_gitignore,
            paths=paths,
        )

        candidates = walker.candidates()
        workers = _resolve_jobs(self.jobs)

        if workers > 1 and len(candidates) >= PARALLEL_THRESHOLD:
            raw, truncated = self._run_parallel(candidates, walker, workers)
        else:
            raw, truncated = self._run_sequential(candidates, walker)

        kept, dropped = self._filter(raw)
        if truncated:
            kept = kept[: self.config.max_findings]

        return ScanResult(
            findings=sort_findings(kept),
            stats=walker.stats,
            rules_loaded=len(self.ruleset),
            rules_run=len(self.active),
            duration_ms=int((time.perf_counter() - started) * 1000),
            scanned_at=scanned_at,
            root=self.config.root,
            truncated=truncated,
            **dropped,
        )

    def _run_sequential(
        self, candidates: list[Path], walker: Walker
    ) -> tuple[list[Finding], bool]:
        raw: list[Finding] = []
        for path in candidates:
            source = walker.read(path)
            if source is None:
                continue
            raw.extend(self.scan_file(source))
            if self.config.max_findings and len(raw) >= self.config.max_findings:
                return raw, True
        return raw, False

    def _run_parallel(
        self, candidates: list[Path], walker: Walker, workers: int
    ) -> tuple[list[Finding], bool]:
        """Scan in worker processes, falling back to one process if that fails.

        A pool can fail to start for reasons that have nothing to do with the
        scan — a sandbox with no /dev/shm, a restricted container, a platform
        without fork. None of those should turn "scan my code" into an error,
        so the fallback is silent and the result is identical, just slower.
        """
        # Longest-processing-time-first. File sizes in a repository span
        # four orders of magnitude, and a pool fed in directory order spends
        # its last stretch with three workers idle while the fourth finishes
        # the one 600 KB file it happened to be given. Starting with the
        # largest files leaves only small ones to even out the tail.
        ordered = sorted(candidates, key=_size, reverse=True)
        chunks = [ordered[i : i + CHUNK_SIZE] for i in range(0, len(ordered), CHUNK_SIZE)]
        raw: list[Finding] = []

        try:
            with ProcessPoolExecutor(
                max_workers=workers,
                initializer=_init_worker,
                initargs=(self.config, self.ignore_suppressions),
            ) as pool:
                for findings, stats in pool.map(_scan_chunk, chunks):
                    raw.extend(findings)
                    walker.stats.scanned += int(stats["scanned"])
                    walker.stats.skipped_binary += int(stats["skipped_binary"])
                    walker.stats.unreadable.extend(stats["unreadable"])
        except (OSError, RuntimeError, ImportError):
            walker.stats.scanned = 0
            walker.stats.skipped_binary = 0
            walker.stats.unreadable.clear()
            return self._run_sequential(candidates, walker)

        # max_findings is a reporting cap, not a reason to leave workers
        # half-finished, so it is applied after the pool drains.
        if self.config.max_findings and len(raw) >= self.config.max_findings:
            return raw, True
        return raw, False

    def run_diff(self, ref: str | None, staged: bool) -> ScanResult:
        """Scan only what changed — the mode that belongs in a pre-commit hook."""
        return self.run(paths=changed_files(self.config.root, ref, staged))

    # ── one file ────────────────────────────────────────────────────────────

    def scan_file(self, source: SourceFile) -> list[Finding]:
        findings: list[Finding] = []
        lines = source.lines
        lowered = source.text.lower()
        seen: dict[str, int] = {}

        for rule in self.active:
            if not rule.applies_to_language(source.language):
                continue
            if not _path_allowed(source, rule):
                continue
            # The cheapest possible rejection: none of the literals every
            # match must contain is anywhere in the file, so no regex can hit.
            if not rule.may_match(lowered):
                continue
            if rule.requires and not rule.requires.search(source.text):
                continue
            if rule.not_requires and rule.not_requires.search(source.text):
                continue

            findings.extend(self._run_rule(rule, source, lines, seen))

        if self.config.entropy and _rule_enabled(ENTROPY_RULE_ID, self.config):
            findings.extend(self._run_entropy(source, lines, seen))

        return _one_per_line(findings)

    def _run_rule(
        self, rule: Rule, source: SourceFile, lines: list[str], seen: dict[str, int]
    ) -> list[Finding]:
        out: list[Finding] = []

        for pattern in rule.patterns:
            for match in pattern.finditer(source.text):
                # A pattern anchored with `^\s*` can begin on the newline that
                # ends the previous line, which reports the finding one line
                # early with a blank snippet — and leaves a redaction looking
                # for text that no longer matches what was captured. Skipping
                # the leading whitespace puts the finding on the line a reader
                # would point at.
                raw = match.group(0)
                start = match.start() + (len(raw) - len(raw.lstrip()))
                text = raw.strip()

                line_no = source.text.count("\n", 0, start) + 1
                line_text = lines[line_no - 1] if line_no <= len(lines) else ""

                if any(veto.search(line_text) for veto in rule.not_patterns):
                    continue

                out.append(
                    self._build(
                        # A rule in the secrets category matched the
                        # credential itself, so the finding must not carry it.
                        redact=_secret_span(text) if rule.category == "secrets" else "",
                        rule_id=rule.id,
                        title=rule.title,
                        severity=self.config.severity_overrides.get(rule.id, rule.severity),
                        source=source,
                        lines=lines,
                        line_no=line_no,
                        column=start - source.text.rfind("\n", 0, start) - 1,
                        match_text=text,
                        seen=seen,
                        category=rule.category,
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                        confidence=rule.confidence,
                        description=rule.description,
                        remediation=rule.remediation,
                        references=list(rule.references),
                        tags=list(rule.tags),
                    )
                )
        return out

    def _run_entropy(
        self, source: SourceFile, lines: list[str], seen: dict[str, int]
    ) -> list[Finding]:
        out: list[Finding] = []

        for index, line in enumerate(lines, start=1):
            for candidate in find_candidates(line, self.config.entropy_threshold):
                out.append(
                    self._build(
                        rule_id=ENTROPY_RULE_ID,
                        title=f"Possible hardcoded secret in {candidate.name}",
                        severity=self.config.severity_overrides.get(
                            ENTROPY_RULE_ID, "high"
                        ),
                        source=source,
                        lines=lines,
                        line_no=index,
                        column=candidate.column,
                        # Redacted: a findings file should not become a second
                        # copy of the credential it is reporting.
                        match_text=candidate.redacted,
                        redact=candidate.value,
                        seen=seen,
                        category="secrets",
                        cwe="CWE-798",
                        owasp="A07:2021 Identification and Authentication Failures",
                        confidence="low",
                        description=(
                            f"{candidate.name} is assigned a {len(candidate.value)}-character "
                            f"literal with {candidate.entropy} bits of entropy per character, "
                            "which is characteristic of a real credential rather than a "
                            "placeholder. The value is redacted in this report."
                        ),
                        remediation=(
                            "If this is a live credential, rotate it first — it is in the "
                            "repository history, not only in the working tree. Then read it "
                            "from the environment or a secret manager at runtime."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/798.html",
                            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                        ],
                        tags=["secret", "entropy"],
                    )
                )
        return out

    def _build(
        self,
        *,
        rule_id: str,
        title: str,
        severity: str,
        source: SourceFile,
        lines: list[str],
        line_no: int,
        column: int,
        match_text: str,
        seen: dict[str, int],
        redact: str = "",
        **meta: Any,
    ) -> Finding:
        """Assemble one finding, including its per-file occurrence index.

        ``redact`` names a literal secret that must not survive into the
        finding. It is masked in the matched text, the source line, and the
        context — a report that quoted the line would leak the credential just
        as effectively as the code does.
        """
        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
        flat = " ".join(match_text.split())[:MAX_MATCH_CHARS]
        context = _context(lines, line_no)

        if redact:
            masked = mask(redact)
            # Both spellings: the stored match collapses whitespace, so the
            # raw form alone would miss it.
            for form in {redact, " ".join(redact.split())}:
                snippet = snippet.replace(form, masked)
                flat = flat.replace(form, masked)
                context = [line.replace(form, masked) for line in context]

        # Occurrence disambiguates two byte-identical matches of one rule in
        # one file, which would otherwise share a fingerprint and collapse.
        occurrence_key = f"{rule_id}␟{flat}"
        occurrence = seen.get(occurrence_key, 0)
        seen[occurrence_key] = occurrence + 1

        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            path=source.relpath,
            line=line_no,
            column=max(0, column),
            end_line=line_no + flat.count("\n"),
            match=flat,
            snippet=snippet,
            context=context,
            language=source.language,
            occurrence=occurrence,
            **meta,
        )

    # ── filtering ───────────────────────────────────────────────────────────

    def _filter(self, findings: list[Finding]) -> tuple[list[Finding], dict[str, int]]:
        """Apply suppressions, the baseline, and the severity/confidence floors."""
        suppressions_by_file: dict[str, suppress_mod.Suppressions] = {}
        kept: list[Finding] = []
        dropped = {"suppressed": 0, "baselined": 0, "filtered": 0}

        for finding in findings:
            if self.config.suppressions:
                table = suppressions_by_file.get(finding.path)
                if table is None:
                    table = self._suppressions_for(finding.path)
                    suppressions_by_file[finding.path] = table

                hit = suppress_mod.is_suppressed(table, finding.line, finding.rule_id)
                if hit is not None:
                    if not self.ignore_suppressions:
                        dropped["suppressed"] += 1
                        continue
                    finding.suppressed_by = (
                        hit.reason or f"lory-scan:ignore at line {hit.line}"
                    )

            if finding.fingerprint in self.baseline:
                dropped["baselined"] += 1
                continue

            if not at_or_above(finding.severity, self.config.min_severity):
                dropped["filtered"] += 1
                continue

            if _confidence_rank(finding.confidence) > _confidence_rank(
                self.config.min_confidence
            ):
                dropped["filtered"] += 1
                continue

            kept.append(finding)

        return kept, dropped

    def _suppressions_for(self, relpath: str) -> suppress_mod.Suppressions:
        path = self.config.root / relpath
        try:
            return suppress_mod.parse(path.read_text(errors="replace"))
        except OSError:
            return suppress_mod.Suppressions()


def _context(lines: list[str], line_no: int) -> list[str]:
    start = max(0, line_no - 1 - CONTEXT_LINES)
    end = min(len(lines), line_no + CONTEXT_LINES)
    return [f"{n + 1:>5} | {lines[n]}" for n in range(start, end)]


def _select_rules(ruleset: RuleSet, config: ScanConfig) -> list[Rule]:
    """Narrow the loaded rules to the ones this run should execute."""
    active = []
    for rule in ruleset:
        if not _rule_enabled(rule.id, config):
            continue
        if config.categories and rule.category not in config.categories:
            continue
        active.append(rule)
    return active


def _rule_enabled(rule_id: str, config: ScanConfig) -> bool:
    """`--select` is an allowlist; `--ignore-rule` is a denylist that wins."""
    if config.select and not any(fnmatch.fnmatch(rule_id, p) for p in config.select):
        return False
    return not any(fnmatch.fnmatch(rule_id, p) for p in config.ignore_rules)


def _path_allowed(source: SourceFile, rule: Rule) -> bool:
    """Whether a rule's `paths:` scoping admits this file.

    Tested against the path within the repository as well as the path within
    the scan. Without that, `lory-scan scan .github` would quietly skip every
    rule scoped to `**/.github/workflows/*.yml` — the rules most worth running
    on exactly those files — and report a clean result.
    """
    candidates = {source.relpath, source.project_path}

    if rule.paths and not any(
        path_matches(candidate, pattern)
        for pattern in rule.paths
        for candidate in candidates
    ):
        return False

    return not any(
        path_matches(candidate, pattern)
        for pattern in rule.exclude_paths
        for candidate in candidates
    )


def _one_per_line(findings: list[Finding]) -> list[Finding]:
    """Collapse repeat hits of one rule on one line into a single finding.

    A rule with several alternative patterns often has more than one of them
    match the same line — three ways of spelling "SQL with a superglobal in it"
    all fire on the same statement. They are one problem and one fix, and
    reporting them three times makes a scan look noisier than it is while
    burying the finding that only appeared once.

    The longest match wins, since it is the one that saw the most of the
    construct.
    """
    best: dict[tuple[str, int], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.line)
        current = best.get(key)
        if current is None or len(finding.match) > len(current.match):
            best[key] = finding
    return list(best.values())


def _confidence_rank(confidence: str) -> int:
    try:
        return CONFIDENCE_LEVELS.index(str(confidence).lower())
    except ValueError:
        return len(CONFIDENCE_LEVELS)


def _load_baseline(path: Path | None) -> frozenset[str]:
    """Read the fingerprints a baseline marks as already-known."""
    if path is None:
        return frozenset()

    import json

    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return frozenset()

    if isinstance(data, dict):
        entries: Iterable[Any] = data.get("fingerprints") or data.get("findings") or []
    else:
        entries = data

    out: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            out.add(entry)
        elif isinstance(entry, dict) and entry.get("fingerprint"):
            out.add(str(entry["fingerprint"]))
    return frozenset(out)


#: Exported for the CLI's `--write-baseline`.
def baseline_document(result: ScanResult) -> dict[str, Any]:
    """The baseline file's contents: fingerprints plus enough to read it by eye.

    A bare list of hashes is unreviewable, and a baseline nobody can review is
    a place bugs go to be forgotten. Each entry carries what it silences.
    """
    return {
        "generated_at": result.scanned_at,
        "tool": "lory-scan",
        "count": len(result.findings),
        "fingerprints": [
            {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "path": f.path,
                "line": f.line,
                "title": f.title,
            }
            for f in result.findings
        ],
    }


# ── parallel scanning ───────────────────────────────────────────────────────
#
# The regex pass is CPU-bound and `re` does not release the GIL, so threads buy
# nothing here and processes are the only option. Each worker builds its own
# Scanner once — rules are compiled per process rather than pickled — and then
# reads and scans whole chunks of files, so the per-task overhead is amortised
# instead of paid per file.

#: Below this many files the pool costs more to start than it saves.
PARALLEL_THRESHOLD = 200

#: Files handed to a worker at a time.
CHUNK_SIZE = 16

_WORKER: Scanner | None = None


def _init_worker(config: ScanConfig, ignore_suppressions: bool) -> None:
    global _WORKER
    _WORKER = Scanner(config, ignore_suppressions=ignore_suppressions)


def _scan_chunk(paths: list[Path]) -> tuple[list[Finding], dict[str, Any]]:
    """Read and scan a chunk of files in a worker process."""
    assert _WORKER is not None
    walker = Walker(
        root=_WORKER.config.root,
        excludes=[],
        max_bytes=_WORKER.config.max_file_bytes,
        respect_gitignore=False,
    )

    findings: list[Finding] = []
    for path in paths:
        source = walker.read(path)
        if source is not None:
            findings.extend(_WORKER.scan_file(source))

    return findings, walker.stats.as_dict()


def _secret_span(text: str) -> str:
    """The part of a secret match that must not appear in a report.

    Usually the whole match. The exception is an assignment, where the name is
    the most useful thing in the finding — `ENV NPM_TOKEN=…` says far more
    than `ENV …` — so only the value is masked.

    The name is kept only when the match cannot be a URI: a connection string
    carries its password *before* an @ and after a colon, and a rule that
    tried to be helpful there would print the credential it is reporting.
    """
    if "=" in text and "@" not in text and "//" not in text:
        value = text.split("=", 1)[1].strip().strip("\"'")
        if len(value) >= 8:
            return value
    return text


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _resolve_jobs(jobs: int | None) -> int:
    """How many worker processes to use. 0 or None means "decide for me"."""
    if jobs and jobs > 0:
        return jobs
    return max(1, min(os.cpu_count() or 1, 8))

"""Rules: the model, the loader, and validation.

A rule is a regex with enough metadata around it to be actionable — what it
is, how bad it is, which CWE it maps to, and what to do about it. Rules live
in YAML so a team can add their own without touching Python, and so the
bundled set is reviewable as data.

The engine deliberately stops at regex. It does not parse or build a call
graph, and it says so: every finding carries a confidence, and the report
formats show it. A lead a human confirms in ten seconds beats a "proof" that
took a parser for every language in the tree and still guessed at the edges.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from lory_scanner.core.errors import RuleError
from lory_scanner.core.severity import CONFIDENCE_LEVELS, SEVERITY_ORDER

#: Shipped with the package. `--no-default-rules` skips these.
BUNDLED_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

#: Rules with no `languages:` key apply to every text file.
ANY_LANGUAGE = "any"

_REQUIRED_FIELDS = ("id", "title", "severity")

#: Regex metacharacters. A run of characters containing none of these is a
#: literal the whole pattern must contain, which makes a cheap prefilter.
_META = set(r".^$*+?{}[]\|()")


@dataclass(frozen=True)
class Rule:
    """One detection, compiled and ready to run."""

    id: str
    title: str
    severity: str
    #: Any-of: a file matching one pattern is a hit. Kept as a list because
    #: most real rules are "this sink, spelled any of these ways".
    patterns: tuple[re.Pattern[str], ...] = ()
    #: Vetoes evaluated against the matched line. A hit is dropped if any
    #: fires — the cheapest way to encode "except when it's already safe".
    not_patterns: tuple[re.Pattern[str], ...] = ()
    #: File-level precondition: the file must also contain this, or the rule
    #: does not run. For "unsafe only in a file that also does X".
    requires: re.Pattern[str] | None = None
    #: File-level veto: the rule does not run if the file contains this. For
    #: "missing mitigation" rules, where the mitigation is a line somewhere
    #: else in the file — a USER instruction, a call to helmet(), a
    #: setFeature() that hardens the parser built three lines earlier.
    not_requires: re.Pattern[str] | None = None

    languages: frozenset[str] = frozenset({ANY_LANGUAGE})
    #: Path globs the rule is restricted to / excluded from.
    paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()

    category: str = "misc"
    cwe: str = ""
    owasp: str = ""
    confidence: str = "medium"
    description: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    #: Lowercased literals, at least one of which every match must contain.
    #: When a file contains none of them the rule cannot match and is skipped
    #: without running a single regex. This is most of the engine's speed: on
    #: a real repository it takes the scan from minutes to seconds.
    #:
    #: Derived automatically from a mandatory literal in the pattern, or
    #: declared in the rule as `prefilter:` / `prefilters:` when the pattern is
    #: an alternation and no single literal is mandatory. A wrong prefilter
    #: silently loses findings, so the automatic derivation is deliberately
    #: timid and a declared one is the author's responsibility.
    prefilters: tuple[str, ...] = ()

    #: Strings this rule must flag, and strings it must not. `lory-scan rules
    #: validate` runs them, which is the only reliable check on a declared
    #: prefilter: a mistyped one silences the rule completely and no amount of
    #: reading the regex reveals it.
    #:
    #: Written with placeholders (``sk_live_{a:24}``) and expanded at load
    #: time — see :func:`expand_example`.
    examples: tuple[str, ...] = ()
    counterexamples: tuple[str, ...] = ()

    #: Which file this rule was read from, for `rules show` and error messages.
    origin: str = ""

    def applies_to_language(self, language: str) -> bool:
        return ANY_LANGUAGE in self.languages or language in self.languages

    def matches(self, text: str) -> bool:
        """Whether this rule fires on one string, prefilter and vetoes included.

        The whole pipeline, so an example exercises what a scan would do
        rather than the patterns alone.
        """
        if not self.may_match(text.lower()):
            return False
        if self.requires and not self.requires.search(text):
            return False
        if self.not_requires and self.not_requires.search(text):
            return False
        if any(veto.search(text) for veto in self.not_patterns):
            return False
        return any(pattern.search(text) for pattern in self.patterns)

    def may_match(self, lowered_text: str) -> bool:
        """Whether this rule could possibly match, judged on literals alone."""
        if not self.prefilters:
            return True
        return any(literal in lowered_text for literal in self.prefilters)


@dataclass
class RuleSet:
    """The loaded rules, indexed for the ways the engine asks for them."""

    rules: list[Rule] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def by_id(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def for_language(self, language: str) -> list[Rule]:
        return [r for r in self.rules if r.applies_to_language(language)]

    def categories(self) -> list[str]:
        return sorted({r.category for r in self.rules})

    def languages(self) -> list[str]:
        seen: set[str] = set()
        for rule in self.rules:
            seen |= set(rule.languages)
        return sorted(seen)


def load_rules(
    dirs: list[Path] | None = None,
    include_bundled: bool = True,
) -> RuleSet:
    """Load rules from the bundled directory and any extra directories.

    Later files win: a local rule reusing a bundled rule's id replaces it,
    which is how a team retunes a noisy rule without forking the package.
    """
    paths: list[Path] = []
    if include_bundled:
        paths.append(BUNDLED_RULES_DIR)
    paths.extend(dirs or [])

    by_id: dict[str, Rule] = {}
    for directory in paths:
        for path in _rule_files(directory):
            for rule in _load_file(path):
                by_id[rule.id] = rule

    if not by_id:
        raise RuleError(
            "no rules loaded. Check --rules paths, or drop --no-default-rules "
            "to use the bundled set."
        )

    return RuleSet(sorted(by_id.values(), key=lambda r: r.id))


def _rule_files(directory: Path) -> list[Path]:
    if directory.is_file():
        return [directory]
    if not directory.is_dir():
        raise RuleError(f"rule path is not a directory: {directory}")
    return sorted(p for p in directory.rglob("*.y*ml") if p.is_file())


def _load_file(path: Path) -> list[Rule]:
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise RuleError(f"{path} is not valid YAML: {exc}") from exc
    except OSError as exc:
        raise RuleError(f"cannot read rule file {path}: {exc}") from exc

    if not isinstance(raw, dict) or "rules" not in raw:
        raise RuleError(f"{path} must be a mapping with a top-level 'rules:' list")

    entries = raw.get("rules")
    if not isinstance(entries, list):
        raise RuleError(f"{path}: 'rules' must be a list")

    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise RuleError(f"{path}: 'defaults' must be a mapping")

    seen: set[str] = set()
    rules: list[Rule] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise RuleError(f"{path}: rule #{index + 1} is not a mapping")
        rule = _build(dict(defaults) | entry, path, index)
        if rule.id in seen:
            raise RuleError(f"{path}: duplicate rule id {rule.id!r} within the same file")
        seen.add(rule.id)
        rules.append(rule)
    return rules


def _build(entry: dict[str, Any], path: Path, index: int) -> Rule:
    where = f"{path}: rule #{index + 1}"

    for key in _REQUIRED_FIELDS:
        if not entry.get(key):
            raise RuleError(f"{where} is missing required field {key!r}")

    rule_id = str(entry["id"]).strip()
    if not re.fullmatch(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*", rule_id):
        raise RuleError(
            f"{where}: id {rule_id!r} must be lowercase words joined by '.' or '-' "
            "(e.g. python.subprocess-shell-true)"
        )

    severity = str(entry["severity"]).strip().lower()
    if severity not in SEVERITY_ORDER:
        raise RuleError(
            f"{where} ({rule_id}): severity must be one of {', '.join(SEVERITY_ORDER)}, "
            f"got {entry['severity']!r}"
        )

    confidence = str(entry.get("confidence", "medium")).strip().lower()
    if confidence not in CONFIDENCE_LEVELS:
        raise RuleError(
            f"{where} ({rule_id}): confidence must be one of "
            f"{', '.join(CONFIDENCE_LEVELS)}, got {entry['confidence']!r}"
        )

    patterns = _pattern_list(entry, "pattern", "patterns", where, rule_id)
    if not patterns:
        raise RuleError(f"{where} ({rule_id}) has no 'pattern' or 'patterns'")

    flags = re.MULTILINE
    if entry.get("ignore_case", True):
        flags |= re.IGNORECASE
    if entry.get("dotall", False):
        flags |= re.DOTALL

    compiled = tuple(_compile(p, flags, where, rule_id) for p in patterns)
    not_patterns = tuple(
        _compile(p, flags, where, rule_id)
        for p in _pattern_list(entry, "not_pattern", "not_patterns", where, rule_id)
    )

    requires_raw = entry.get("requires")
    requires = _compile(str(requires_raw), flags, where, rule_id) if requires_raw else None

    not_requires_raw = entry.get("not_requires")
    not_requires = (
        _compile(str(not_requires_raw), flags, where, rule_id) if not_requires_raw else None
    )

    languages = entry.get("languages") or entry.get("language") or [ANY_LANGUAGE]
    if isinstance(languages, str):
        languages = [languages]

    return Rule(
        id=rule_id,
        title=str(entry["title"]).strip(),
        severity=severity,
        patterns=compiled,
        not_patterns=not_patterns,
        requires=requires,
        not_requires=not_requires,
        languages=frozenset(str(lang).strip().lower() for lang in languages),
        paths=tuple(_strings(entry.get("paths"))),
        exclude_paths=tuple(_strings(entry.get("exclude_paths"))),
        category=str(entry.get("category", "misc")).strip().lower(),
        cwe=_cwe(entry.get("cwe")),
        owasp=str(entry.get("owasp", "")).strip(),
        confidence=confidence,
        description=_text(entry.get("description")),
        remediation=_text(entry.get("remediation")),
        references=tuple(_strings(entry.get("references"))),
        tags=tuple(_strings(entry.get("tags"))),
        prefilters=_prefilters(entry, patterns, where, rule_id),
        examples=tuple(expand_example(e) for e in _strings(entry.get("examples"))),
        counterexamples=tuple(
            expand_example(e) for e in _strings(entry.get("counterexamples"))
        ),
        origin=str(path),
    )


#: Character sets a placeholder can draw from.
_ALPHABETS = {
    "a": string.ascii_lowercase + string.ascii_uppercase + string.digits,
    "u": string.ascii_uppercase + string.digits,
    "h": string.digits + "abcdef",
    "d": string.digits,
}

#: ``{a:24}`` — 24 characters from alphabet ``a``.
_PLACEHOLDER = re.compile(r"\{(?P<kind>[auhd]):(?P<count>\d{1,3})\}")


def expand_example(text: str) -> str:
    """Fill in the placeholders in a rule example.

    A secret rule needs an example shaped exactly like the credential it
    detects — that is the whole point of the self-test. Committing one is not
    an option: a repository full of realistic keys is rejected by GitHub's push
    protection, and anything that trains a reader to click through that warning
    is worse than the inconvenience.

    So examples carry a shape rather than a value, and it is filled in here::

        sk_live_{a:24}          →  sk_live_ + 24 alphanumerics
        twilio_sid = "AC{h:32}" →  AC + 32 hex characters

    The expansion is deterministic — the alphabet, cycled — so a self-test
    failure is reproducible rather than a flake, and no realistic credential
    ever exists in the source.
    """

    def fill(match: re.Match[str]) -> str:
        alphabet = _ALPHABETS[match.group("kind")]
        count = int(match.group("count"))
        return "".join(alphabet[i % len(alphabet)] for i in range(count))

    return _PLACEHOLDER.sub(fill, text)


def _compile(pattern: str, flags: int, where: str, rule_id: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise RuleError(f"{where} ({rule_id}): bad regex {pattern!r}: {exc}") from exc


def _pattern_list(
    entry: dict[str, Any], single: str, plural: str, where: str, rule_id: str
) -> list[str]:
    out: list[str] = []
    if entry.get(single):
        out.append(str(entry[single]))
    value = entry.get(plural)
    if value:
        if isinstance(value, str):
            raise RuleError(
            f"{where} ({rule_id}): {plural!r} must be a list; use {single!r} for one"
        )
        out.extend(str(v) for v in value)
    return out


def _strings(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _text(value: Any) -> str:
    """Collapse a YAML folded block into one paragraph."""
    return " ".join(str(value or "").split())


def _cwe(value: Any) -> str:
    """Normalise ``89``, ``"89"``, or ``"CWE-89"`` to ``CWE-89``."""
    if value in (None, ""):
        return ""
    text = str(value).strip().upper()
    if text.startswith("CWE-"):
        return text
    return f"CWE-{text}"


def _prefilters(
    entry: dict[str, Any], patterns: list[str], where: str, rule_id: str
) -> tuple[str, ...]:
    """Resolve a rule's prefilter literals.

    A declared `prefilter:` or `prefilters:` wins, because the author can see
    an alternation's branches and the automatic derivation deliberately will
    not guess at them. Declaring one is a promise that every possible match
    contains one of these strings; the check below catches the easiest way to
    break that promise — a literal that is not in any pattern at all.
    """
    declared = _strings(entry.get("prefilters")) or _strings(entry.get("prefilter"))
    if declared:
        return tuple(literal.lower() for literal in declared)

    derived = _common_literal(patterns)
    return (derived,) if derived else ()


def _common_literal(patterns: list[str]) -> str:
    """The longest literal every pattern contains, for prefiltering.

    Only safe when *every* alternative shares it — a rule whose patterns have
    no common literal gets no prefilter and always runs its regexes.
    """
    candidates = [_literals(p) for p in patterns]
    if not candidates or any(not c for c in candidates):
        return ""

    shared = set(candidates[0])
    for group in candidates[1:]:
        shared &= set(group)
    if not shared:
        return ""
    return max(shared, key=len).lower()


def _literals(pattern: str) -> list[str]:
    """Runs of 4+ literal characters a match must contain.

    Only *mandatory* literals qualify. A literal inside an alternation or a
    group may not be present in a given match, so using one as a prefilter
    would skip files that really do match — a false negative, which is the one
    class of bug a scanner cannot afford. The reading is therefore narrow:

    * any ``|`` in the pattern disqualifies the whole thing
    * anything inside ``( )`` or ``[ ]`` is ignored
    * a character followed by ``?``, ``*``, or ``{`` is optional, so the run
      ends before it

    Being too conservative costs a prefilter, which costs speed. Being too
    clever costs findings.
    """
    if "|" in pattern.replace(r"\|", ""):
        return []

    runs: list[str] = []
    current: list[str] = []
    depth = 0
    index = 0

    while index < len(pattern):
        char = pattern[index]

        if char == "\\":
            current = _flush(current, runs)
            index += 2
            continue

        if char in "([":
            depth += 1
            current = _flush(current, runs)
            index += 1
            continue
        if char in ")]":
            depth = max(0, depth - 1)
            current = _flush(current, runs)
            index += 1
            continue

        if depth or char in _META:
            current = _flush(current, runs)
        elif index + 1 < len(pattern) and pattern[index + 1] in "?*{":
            # The next character quantifies this one, so this one is optional.
            current = _flush(current, runs)
        else:
            current.append(char)
        index += 1

    _flush(current, runs)
    return [r for r in runs if len(r) >= 4]


def _flush(current: list[str], runs: list[str]) -> list[str]:
    if current:
        runs.append("".join(current))
    return []

"""Inline suppressions.

A scanner without a way to say "I looked at this, it is fine" gets its output
ignored wholesale, which is worse than a false negative. The comment is the
record of that decision and lives next to the code it excuses.

Two spellings, both accepted at the end of the offending line or on the line
directly above it::

    query = build(raw)          # lory-scan:ignore
    query = build(raw)          # lory-scan:ignore[python.sql-string-concat]

The bare form suppresses every rule on that line; the bracketed form suppresses
only the rules named, which is the form worth encouraging — a blanket ignore
also hides the *next* bug someone introduces on that line.

A whole file can be excused with ``lory-scan:ignore-file``, anywhere in it::

    # lory-scan:ignore-file[secrets.*] -- sample credentials, invented

That exists for files whose *content is the subject*: a rule file full of
credential patterns, a fixture that is wrong on purpose, documentation showing
what a leaked key looks like. Rule ids accept globs, so a file can excuse one
family without going blind to everything else.

`--ignore-suppressions` re-enables everything, for an audit that needs to see
what has been waved through.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

#: `lory-scan:ignore`, `lory-scan: ignore`, `lory scan ignore`, plus an
#: optional bracketed rule list and an optional ` -- reason`.
SUPPRESSION = re.compile(
    r"lory[\-\s]?scan\s*[:\s]\s*ignore(?P<file>-file)?"
    r"(?:\s*\[(?P<rules>[^\]]*)\])?"
    r"(?:\s*(?:--|—|:)\s*(?P<reason>.+))?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Suppression:
    """One ``lory-scan:ignore`` comment."""

    line: int
    #: Empty means "every rule on the target line".
    rules: frozenset[str]
    reason: str = ""

    def covers(self, rule_id: str) -> bool:
        """Whether this suppression applies to a rule.

        Ids are matched as globs, the same way `--ignore-rule` treats them, so
        `secrets.*` excuses a family without naming every member.
        """
        if not self.rules:
            return True
        return any(fnmatch.fnmatch(rule_id, pattern) for pattern in self.rules)


@dataclass
class Suppressions:
    """Every suppression comment in one file."""

    #: Line number → the comment that suppresses that line.
    by_line: dict[int, Suppression] = field(default_factory=dict)
    #: Comments that apply to the whole file.
    whole_file: list[Suppression] = field(default_factory=list)

    def covering(self, line: int, rule_id: str) -> Suppression | None:
        """The suppression that excuses this finding, if any."""
        for suppression in self.whole_file:
            if suppression.covers(rule_id):
                return suppression

        found = self.by_line.get(line)
        if found is not None and found.covers(rule_id):
            return found
        return None


def parse(text: str) -> Suppressions:
    """Read every suppression comment in a file.

    A line comment on line N suppresses line N (trailing form) and line N+1
    (the own-line form). When both apply to the same target, the more specific
    one — the trailing comment — wins, because it is unambiguous about which
    line its author was looking at.
    """
    found = Suppressions()

    for number, line in enumerate(text.splitlines(), start=1):
        match = SUPPRESSION.search(line)
        if not match:
            continue

        rules = frozenset(
            part.strip() for part in (match.group("rules") or "").split(",") if part.strip()
        )
        suppression = Suppression(
            line=number, rules=rules, reason=(match.group("reason") or "").strip()
        )

        if match.group("file"):
            found.whole_file.append(suppression)
        elif _is_own_line_comment(line, match.start()):
            # Applies to the code below it; do not clobber a trailing comment
            # already recorded for that line.
            found.by_line.setdefault(number + 1, suppression)
        else:
            found.by_line[number] = suppression

    return found


def _is_own_line_comment(line: str, offset: int) -> bool:
    """Whether the comment is alone on its line rather than trailing code.

    Approximated by what precedes it: only comment openers and whitespace.
    Cheap, language-agnostic, and wrong only in cases where both readings
    suppress something the author meant to suppress anyway.
    """
    before = line[:offset].strip()
    return before in ("", "#", "//", "/*", "*", "<!--", "--", ";", "%", "'''", '"""', "*/")


def is_suppressed(suppressions: Suppressions, line: int, rule_id: str) -> Suppression | None:
    """The suppression covering this finding, if any."""
    return suppressions.covering(line, rule_id)

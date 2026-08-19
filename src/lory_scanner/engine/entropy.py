"""Generic secret detection by entropy.

The secret rules in ``rules/secrets.yml`` catch credentials with a recognisable
shape — ``AKIA…``, ``ghp_…``, ``sk_live_…``. This module catches the rest: a
long random-looking string assigned to a secret-sounding name.

Entropy alone is a bad detector. A minified bundle, a base64 image, a lockfile
hash, and a UUID are all high-entropy and none is a secret. So entropy is the
*last* gate here, not the first: the string must be assigned to a name that
suggests a credential, survive a list of obvious placeholders, and only then be
measured.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

#: `SECRET = "value"`, `"secret": "value"`, `secret: value`, `SECRET=value`.
#: The name is captured so the report can say which one, and the value's
#: position is captured so the finding points at the value, not the line.
ASSIGNMENT = re.compile(
    r"""
    (?P<name>[A-Za-z_][A-Za-z0-9_.\-]{2,40})      # the name being assigned
    \s* ["']? \s* (?: [:=] {1,2} | =>            # : = == => (JSON, YAML, PHP)
    ) \s*
    (?P<quote>["'`]?)
    (?P<value>[A-Za-z0-9+/=_\-.~]{16,200})        # the candidate secret
    (?P=quote)
    """,
    re.VERBOSE,
)

#: A name has to look like a credential. Matching the *name* first is what
#: keeps this from firing on every hash and identifier in the tree.
SECRET_NAME = re.compile(
    r"(?:^|[_.\-])(?:"
    r"secret|passwd|password|passphrase|token|api[_.\-]?key|apikey|access[_.\-]?key|"
    r"secret[_.\-]?key|private[_.\-]?key|client[_.\-]?secret|auth|credential|"
    r"bearer|session[_.\-]?key|encryption[_.\-]?key|signing[_.\-]?key|salt|"
    r"master[_.\-]?key|refresh[_.\-]?token|webhook[_.\-]?secret"
    r")(?:$|[_.\-])",
    re.IGNORECASE,
)

#: Values that look random but are placeholders, references, or examples.
PLACEHOLDER = re.compile(
    r"^(?:"
    r"x{4,}|\.{3,}|-{4,}|"
    r"(?:your|my|the|some|test|demo|sample|example|placeholder|dummy|fake|change|"
    r"insert|replace|enter|todo|fixme|redacted|removed|hidden|none|null|nil|"
    r"undefined|empty|default)[_.\-]?.*|"
    r".*(?:example|placeholder|changeme|change[_.\-]?me|yourkeyhere|xxxxx|"
    r"notreal|dummy|redacted|<.*>)"
    r")$",
    re.IGNORECASE,
)

#: A value that is an interpolation is a *reference* to a secret, which is the
#: correct thing to find in source. ${VAR}, {{ var }}, %s, os.environ[...].
INTERPOLATED = re.compile(r"\$\{|\$\(|\{\{|%\(|<%|process\.env|os\.environ|getenv|ENV\[")

#: Shapes that are high-entropy by construction and are not credentials.
NOT_A_SECRET = (
    # UUIDs — ubiquitous as identifiers.
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    # Git object ids and content hashes.
    re.compile(r"^[0-9a-f]{40}$", re.I),
    re.compile(r"^[0-9a-f]{64}$", re.I),
    # Subresource-integrity and lockfile digests.
    re.compile(r"^sha(?:256|384|512)-", re.I),
    # A path, a URL, or a dotted module name is not a credential.
    re.compile(r"^(?:/|\./|\.\./|[a-z]+://)"),
    re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){2,}$"),
    # Semantic versions and date-like values.
    re.compile(r"^v?\d+\.\d+\.\d+"),
)

#: Above this share of one repeated character the string is padding or a mask.
_MAX_REPEAT_SHARE = 0.5


@dataclass
class SecretCandidate:
    """A high-entropy assignment worth a human look."""

    name: str
    value: str
    entropy: float
    #: 0-based offset of the value within the line, for column reporting.
    column: int

    @property
    def redacted(self) -> str:
        return mask(self.value)


def mask(value: str) -> str:
    """Identify a secret without reproducing it.

    A finding has to name the string well enough that a human can find it in
    the file, without the report becoming a second copy of the credential —
    findings files get committed, pasted into tickets, and uploaded to
    code-scanning dashboards. A short prefix plus the length does that; the
    line number does the rest.
    """
    if len(value) <= 8:
        return "…" * 3
    return f"{value[:4]}…[redacted, {len(value)} chars]"


def shannon(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    length = len(value)
    total = 0.0
    for count in _tally(value).values():
        p = count / length
        total -= p * math.log2(p)
    return total


def _tally(value: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    return counts


def find_candidates(line: str, threshold: float = 4.0) -> list[SecretCandidate]:
    """Secret-looking assignments on one line, in order.

    Every gate here exists because of a class of false positive, in the order
    that rejects the most for the least work.
    """
    out: list[SecretCandidate] = []

    for match in ASSIGNMENT.finditer(line):
        name = match.group("name")
        value = match.group("value")

        if not SECRET_NAME.search(name):
            continue
        if INTERPOLATED.search(line):
            continue
        if PLACEHOLDER.match(value):
            continue
        if any(pattern.match(value) for pattern in NOT_A_SECRET):
            continue
        if _mostly_one_character(value):
            continue

        entropy = shannon(value)
        if entropy < threshold:
            continue

        out.append(
            SecretCandidate(
                name=name, value=value, entropy=round(entropy, 2),
                column=match.start("value"),
            )
        )

    return out


def _mostly_one_character(value: str) -> bool:
    """Reject a value that is one character repeated, and mask strings."""
    counts = _tally(value)
    return max(counts.values()) / len(value) > _MAX_REPEAT_SHARE

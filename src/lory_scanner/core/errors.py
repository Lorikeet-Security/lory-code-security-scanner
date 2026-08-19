"""Error types.

Everything the CLI is prepared to explain derives from :class:`ScannerError`;
``cli.main`` turns one into a one-line message and exit code 2. Anything else
is a bug and gets a traceback, which is the correct outcome for a bug.
"""

from __future__ import annotations


class ScannerError(Exception):
    """Base class for every error this tool raises deliberately."""


class ConfigError(ScannerError):
    """The config file is missing a value, malformed, or self-contradictory."""


class RuleError(ScannerError):
    """A rule file is malformed: bad YAML, bad regex, or missing metadata."""


class TargetError(ScannerError):
    """The path to scan does not exist, or git could not resolve a diff range."""

"""lory-scan — a local static security scanner for source trees.

This is the half of the Lorikeet toolchain that *does* the finding. Its
companion, `lory-code-security <https://github.com/Lorikeet-Security/lory-findings-tui>`_,
triages findings and asks Lory how to fix them but scans nothing itself. This
tool scans, emits findings in the shape that TUI already reads, and never sends
your source anywhere: every rule runs on this machine.

Public API — see :mod:`lory_scanner.api` for the callable surface::

    from lory_scanner import scan
    result = scan("path/to/repo")
"""

from lory_scanner.api import scan, scan_to_lory_cache

#: Distribution version.
__version__ = "0.1.0"

#: The output contract the TUI (or any other consumer) integrates against.
#:
#: Bumped only when a consumer would have to change: a removed field, a
#: renamed key, a changed exit code. Added fields do not bump it. ``lory-scan
#: describe`` reports this number, so a caller can refuse a contract it does
#: not understand instead of misreading the output.
CONTRACT_VERSION = 1

__all__ = ["scan", "scan_to_lory_cache", "__version__", "CONTRACT_VERSION"]

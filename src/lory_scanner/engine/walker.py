"""File discovery: what gets scanned, and what is skipped and why.

Skipping is a security decision as much as a speed one. A scanner that walks
node_modules produces a wall of findings in code its user cannot change, and
the real finding in their own `src/` scrolls off the top.

Three filters, cheapest first: the exclude globs, then .gitignore (only in a
git checkout, delegated to git itself so the semantics match exactly), then
size and binary sniffing.
"""

from __future__ import annotations

import fnmatch
import re
import shutil
import subprocess
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from lory_scanner.core.errors import TargetError
from lory_scanner.engine.languages import detect

#: Read this much to decide whether a file is binary.
_SNIFF_BYTES = 8192


@dataclass
class SourceFile:
    """One file to scan, already read."""

    path: Path
    #: Path as reported in findings: relative to the scan root, POSIX style.
    relpath: str
    language: str
    text: str
    #: Path relative to the repository root, which is not the same thing when
    #: someone scans a subdirectory. Rules scoped with `paths:` match against
    #: this as well, so `**/.github/workflows/*.yml` still means that file
    #: whether the scan was pointed at the repo or at `.github`.
    project_path: str = ""

    def __post_init__(self) -> None:
        if not self.project_path:
            self.project_path = self.relpath

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass
class WalkStats:
    """What the walk saw. Reported by `--verbose` and in the JSON envelope."""

    considered: int = 0
    scanned: int = 0
    skipped_excluded: int = 0
    skipped_gitignored: int = 0
    skipped_binary: int = 0
    skipped_large: int = 0
    skipped_unknown_type: int = 0
    unreadable: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, int | list[str]]:
        return {
            "considered": self.considered,
            "scanned": self.scanned,
            "skipped_excluded": self.skipped_excluded,
            "skipped_gitignored": self.skipped_gitignored,
            "skipped_binary": self.skipped_binary,
            "skipped_large": self.skipped_large,
            "skipped_unknown_type": self.skipped_unknown_type,
            "unreadable": self.unreadable,
        }


class Walker:
    """Yields the files a scan should read."""

    def __init__(
        self,
        root: Path,
        excludes: list[str],
        includes: list[str] | None = None,
        max_bytes: int = 2_000_000,
        respect_gitignore: bool = True,
        paths: list[Path] | None = None,
    ) -> None:
        self.root = root.resolve()
        self.excludes = GlobSet(excludes)
        self.includes = GlobSet(includes or [])
        self.max_bytes = max_bytes
        self.respect_gitignore = respect_gitignore
        #: An explicit file list (from `--diff`, or from naming files on the
        #: command line). None means "walk the tree".
        self.paths = paths
        self.stats = WalkStats()
        self._ignored: frozenset[str] = frozenset()
        #: The repository this scan sits inside, when it is a git checkout.
        self.project_root = _git_toplevel(self.root) or self.root

    def walk(self) -> Iterator[SourceFile]:
        """Every file to scan, read and ready."""
        for path in self.candidates():
            source = self.read(path)
            if source is not None:
                yield source

    def candidates(self) -> list[Path]:
        """Paths that survive every filter that does not need the contents.

        Split out from reading so a parallel scan can hand paths to worker
        processes and let each one do its own IO — the read and the regex pass
        are the expensive halves, and both parallelise.
        """
        if self.paths is not None:
            found = list(self.paths)
        else:
            # In a git checkout, ask git for the file list. It already knows
            # what is ignored, and one index read is dramatically cheaper than
            # asking it about each path afterwards — `git check-ignore` on a
            # few thousand paths can take half a minute on a large repository,
            # which was most of a scan's wall time before this.
            found = _git_files(self.root) if self.respect_gitignore else None
            if found is None:
                found = list(self._walk_tree())
                if self.respect_gitignore:
                    self._ignored = _git_ignored(self.root, found)

        keep: list[Path] = []
        for path in found:
            self.stats.considered += 1
            if self._accept(path):
                keep.append(path)
        return keep

    def _accept(self, path: Path) -> bool:
        """Filters that need only the path: excludes, gitignore, type, size.

        Ordered by cost. The glob and extension tests are string work; is_file
        and stat are syscalls, and on a large repository most paths are
        rejected before either is reached.
        """
        relpath = self._relpath(path)

        if self.excludes.matches(relpath):
            self.stats.skipped_excluded += 1
            return False

        if relpath in self._ignored:
            self.stats.skipped_gitignored += 1
            return False

        if self.includes and not self.includes.matches(relpath):
            self.stats.skipped_excluded += 1
            return False

        if not detect(path):
            self.stats.skipped_unknown_type += 1
            return False

        if not path.is_file():
            return False

        try:
            size = path.stat().st_size
        except OSError as exc:
            self.stats.unreadable.append(f"{relpath}: {exc.strerror or exc}")
            return False

        if size > self.max_bytes:
            self.stats.skipped_large += 1
            return False

        return True

    def read(self, path: Path) -> SourceFile | None:
        """Read one accepted path, or record why it could not be scanned."""
        relpath = self._relpath(path)

        try:
            blob = path.read_bytes()
        except OSError as exc:
            self.stats.unreadable.append(f"{relpath}: {exc.strerror or exc}")
            return None

        if b"\x00" in blob[:_SNIFF_BYTES]:
            self.stats.skipped_binary += 1
            return None

        self.stats.scanned += 1
        return SourceFile(
            path=path,
            relpath=relpath,
            language=detect(path),
            text=blob.decode("utf-8", errors="replace"),
            project_path=self._project_path(path, relpath),
        )

    def _walk_tree(self) -> Iterator[Path]:
        """Depth-first, pruning excluded directories rather than filtering later.

        Pruning is the difference between skipping node_modules and stat-ing
        every file inside it first.
        """
        if self.root.is_file():
            yield self.root
            return

        stack = [self.root]
        while stack:
            current = stack.pop()
            try:
                entries = sorted(current.iterdir())
            except OSError as exc:
                self.stats.unreadable.append(f"{current}: {exc.strerror or exc}")
                continue

            for entry in entries:
                if entry.is_symlink():
                    # Following symlinks risks leaving the tree entirely, and
                    # cycles. The target is scanned on its own if it is inside.
                    continue
                if entry.is_dir():
                    if self._excluded_dir(entry):
                        self.stats.skipped_excluded += 1
                        continue
                    stack.append(entry)
                elif entry.is_file():
                    yield entry

    def _project_path(self, path: Path, relpath: str) -> str:
        """Where this file sits in the repository, not in the scan."""
        if self.project_root == self.root:
            return relpath
        try:
            return path.relative_to(self.project_root).as_posix()
        except ValueError:
            return relpath

    def _relpath(self, path: Path) -> str:
        """Path as reported in findings: relative to the scan root, POSIX style.

        The cheap comparison is tried first — every path from the walk is
        already absolute and under the resolved root — and resolve() is paid
        for only when that fails, which means a path given explicitly on the
        command line or through --diff.
        """
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            pass
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def _excluded_dir(self, path: Path) -> bool:
        # A directory matches a `**/name/**` pattern only once something is
        # appended, so it is tested as a prefix of a file inside it.
        return self.excludes.matches(self._relpath(path) + "/x")


class GlobSet:
    """A set of path globs, compiled into one regex.

    The walker tests every candidate path against every exclude pattern, and
    on a repository where git lists tens of thousands of tracked files that is
    the hot loop of the whole scan — one `fnmatch` call per pattern per path
    added tens of seconds. Translating the patterns once and matching them as
    a single alternation turns it into one regex call per path.

    The semantics are :func:`path_matches`, which stays as the readable
    reference for the few places that test a handful of patterns.
    """

    __slots__ = ("_regex", "patterns")

    def __init__(self, patterns: Iterable[str]) -> None:
        self.patterns = list(patterns)
        globs: list[str] = []
        for pattern in self.patterns:
            globs.extend(_alternatives(pattern))
        # Each translation anchors its own end, so the alternation is safe to
        # test with `match`.
        self._regex = (
            re.compile("|".join(f"(?:{fnmatch.translate(g)})" for g in globs))
            if globs
            else None
        )

    def __bool__(self) -> bool:
        return self._regex is not None

    def matches(self, relpath: str) -> bool:
        return self._regex is not None and self._regex.match(relpath) is not None


def _alternatives(pattern: str) -> list[str]:
    """Every glob spelling of one pattern, mirroring :func:`path_matches`.

    Expressed as globs rather than as edits to a translated regex: what
    `fnmatch.translate` emits differs between Python versions — the anchor and
    the group syntax both changed in 3.13 — and reaching into its output broke
    on a newer interpreter. Handing it a glob is the stable contract.
    """
    out = [pattern]

    # `**/x` also matches `x` at the root. fnmatch reads `**` as `*`, which
    # already crosses separators, so only the leading segment needs removing.
    if pattern.startswith("**/"):
        out.append(pattern[3:])

    # `src/**` covers everything beneath src/.
    if pattern.endswith("/**"):
        out.append(pattern[:-3].rstrip("/") + "/*")

    # A bare name matches that file anywhere, and that directory at any depth.
    if "/" not in pattern:
        out.append(f"*/{pattern}")
        out.append(f"{pattern}/*")
        out.append(f"*/{pattern}/*")

    return out


def path_matches(relpath: str, pattern: str) -> bool:
    """Whether a repo-relative path matches one glob, the way a user expects.

    fnmatch alone is not enough for the patterns people actually write:

    * ``**/.env*`` has to match ``.env.local`` at the top level, where there is
      no directory to match the ``**`` against
    * ``src/**`` has to match ``src/a/b.py``, which fnmatch reads as requiring
      a literal ``**`` segment
    * ``node_modules`` — a bare name — has to match the directory anywhere

    Getting this wrong is quiet in both directions: a rule scoped to a path
    that never matches simply never fires, and nothing reports that it did not.
    """
    name = relpath.rsplit("/", 1)[-1]

    if fnmatch.fnmatch(relpath, pattern) or fnmatch.fnmatch(name, pattern):
        return True

    # `**/x` should also match `x` sitting at the root.
    if pattern.startswith("**/") and fnmatch.fnmatch(relpath, pattern[3:]):
        return True

    # `src/**` covers everything beneath src/.
    if pattern.endswith("/**") and relpath.startswith(pattern[:-3].rstrip("/") + "/"):
        return True

    # A bare name matches that directory at any depth.
    if "/" not in pattern and f"/{pattern}/" in f"/{relpath}/":
        return True

    return False


def _git_toplevel(root: Path) -> Path | None:
    """The repository root above ``root``, or None outside a checkout."""
    if not shutil.which("git"):
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return Path(proc.stdout.strip())


def _git_files(root: Path) -> list[Path] | None:
    """Every file git tracks or would track, or None if this is not a checkout.

    ``--cached`` covers tracked files and ``--others --exclude-standard``
    covers new ones that are not ignored, which together are exactly the files
    a developer thinks of as "in the repo". Ignored files never appear, so no
    second filtering pass is needed.
    """
    if not shutil.which("git") or not _in_git_repo(root):
        return None

    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others",
             "--exclude-standard", "-z"],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if proc.returncode != 0:
        return None

    files: list[Path] = []
    for name in proc.stdout.split("\0"):
        if not name:
            continue
        path = root / name
        # `--cached` lists files that are staged but deleted on disk, and
        # submodule entries, neither of which can be read.
        if path.is_file() and not path.is_symlink():
            files.append(path)
    return files


def _git_ignored(root: Path, candidates: list[Path]) -> frozenset[str]:
    """Ask git which of these paths are ignored.

    Delegated rather than reimplemented: .gitignore has precedence rules,
    negations, and nested files, and a half-implementation would skip files
    the user expects scanned. If git is absent or this is not a checkout, the
    exclude globs alone do the work.
    """
    if not candidates or not shutil.which("git") or not (root / ".git").exists():
        return frozenset()

    payload = "\n".join(str(p) for p in candidates)
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--stdin"],
            input=payload, capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()

    # 0 = some ignored, 1 = none ignored, 128 = not a repo. Only 0 has output.
    if proc.returncode not in (0, 1):
        return frozenset()

    ignored: set[str] = set()
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        path = Path(line.strip())
        try:
            ignored.add(path.resolve().relative_to(root).as_posix())
        except ValueError:
            ignored.add(path.as_posix())
    return frozenset(ignored)


def changed_files(root: Path, ref: str | None, staged: bool) -> list[Path]:
    """Files changed against a git ref, for `--diff` and `--staged`.

    Deleted files are dropped: there is nothing to scan and reporting them
    would put findings on code that no longer exists.
    """
    if not shutil.which("git"):
        raise TargetError("--diff needs git on PATH")
    if not (root / ".git").exists() and not _in_git_repo(root):
        raise TargetError(f"--diff needs a git checkout; {root} is not one")

    cmd = ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=d"]
    if staged:
        cmd.append("--cached")
    if ref:
        cmd.append(ref)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise TargetError(f"git diff failed: {exc}") from exc

    if proc.returncode != 0:
        detail = proc.stderr.strip().splitlines()
        raise TargetError(
            f"git diff failed: {detail[0] if detail else f'exit {proc.returncode}'}"
        )

    files = []
    for line in proc.stdout.splitlines():
        if line.strip():
            candidate = (root / line.strip()).resolve()
            if candidate.is_file():
                files.append(candidate)
    return files


def _in_git_repo(root: Path) -> bool:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"

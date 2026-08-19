"""Shared fixtures: a temporary repository to scan."""

from __future__ import annotations

from pathlib import Path

import pytest

from lory_scanner.core.config import ScanConfig


@pytest.fixture
def tree(tmp_path: Path):
    """Write files into a temp directory and return the root.

    Used as ``tree({"app.py": "...", "sub/x.js": "..."})``.
    """

    def build(files: dict[str, str]) -> Path:
        for name, content in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return tmp_path

    return build


@pytest.fixture
def config(tmp_path: Path) -> ScanConfig:
    """A config pinned to the temp tree, with git lookups switched off.

    Tests must not depend on whether the temp directory happens to sit inside
    a checkout — on this repository's own CI it does.
    """
    return ScanConfig(root=tmp_path, respect_gitignore=False)

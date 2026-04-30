"""Unit test for the ``zynksec-scans/`` parent directory permission.

Phase 3 cleanup item #1 regression guard.  ``_scan_root`` does
``mkdir(mode=0o700)`` for the per-scan leaf, but pre-fix the
``zynksec-scans/`` PARENT was created with the system umask
(typically 0755).  On a multi-process container, a 0755 parent
lets any other UID enumerate in-flight scan UUIDs by listing
``/tmp/zynksec-scans/`` — a metadata leak even though the leaf
contents stay protected.

The fix forces the parent to 0o700 on every call.  This test
runs the function against a private tempdir (so it doesn't
depend on global ``/tmp`` state) and asserts the mode is
exactly 0o700 on both the parent and the leaf.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from zynksec_scanners.repo.cloner import _scan_root


def test_scan_root_parent_is_0700(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``zynksec-scans/`` parent is created with — and stays at — mode 0o700.

    Even when the parent already exists with a permissive mode (we
    pre-create at 0o755 to simulate a host that has a stale dir from
    before the fix), ``_scan_root`` must clamp it back to 0o700.
    """
    monkeypatch.setattr(
        "zynksec_scanners.repo.cloner.tempfile.gettempdir",
        lambda: str(tmp_path),
    )

    # Pre-create the parent with permissive perms — simulates a host
    # whose pre-fix worker left a 0o755 ``zynksec-scans/`` behind.
    permissive_parent = tmp_path / "zynksec-scans"
    permissive_parent.mkdir(mode=0o755)
    assert stat.S_IMODE(permissive_parent.stat().st_mode) == 0o755

    leaf = _scan_root("test-scan-id")
    parent = leaf.parent

    # The parent is the pre-existing permissive dir; the fix must
    # have clamped it to 0o700.
    assert parent == permissive_parent
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700, (
        f"zynksec-scans/ parent is {oct(stat.S_IMODE(parent.stat().st_mode))}, "
        "expected 0o700 — the fix didn't reach an existing permissive dir"
    )

    # Leaf dir also at 0o700.
    assert (
        stat.S_IMODE(leaf.stat().st_mode) == 0o700
    ), f"per-scan leaf is {oct(stat.S_IMODE(leaf.stat().st_mode))}, expected 0o700"


def test_scan_root_creates_parent_at_0700_when_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Cold-start case: parent doesn't exist yet → ``_scan_root`` creates it 0o700."""
    monkeypatch.setattr(
        "zynksec_scanners.repo.cloner.tempfile.gettempdir",
        lambda: str(tmp_path),
    )
    assert not (tmp_path / "zynksec-scans").exists()

    leaf = _scan_root("fresh-scan-id")
    parent = leaf.parent

    assert parent.exists()
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(leaf.stat().st_mode) == 0o700

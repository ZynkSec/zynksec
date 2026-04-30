"""Unit tests for SemgrepPlugin's severity classifier + preview truncator.

Phase 3 Sprint 2.  These are pure-function helpers — no
subprocess, no I/O — so they belong in the unit suite alongside
:mod:`tests.unit.test_gitleaks_classify`.

Coverage:
  * Severity mapping INFO/WARNING/ERROR → low/medium/high.
  * Critical escalation: severity=ERROR + impact=HIGH.
  * Single-signal HIGH-impact (without ERROR) does NOT escalate.
  * Single-signal ERROR (without HIGH-impact) does NOT escalate.
  * Truncator collapses multi-line matches and caps length.
  * Truncator preserves short matches verbatim.
"""

from __future__ import annotations

import pytest
from zynksec_scanners.semgrep.plugin import (
    _PREVIEW_MAX_LEN,
    _classify_severity,
    _truncate_preview,
)


@pytest.mark.parametrize(
    ("semgrep_severity", "impact", "expected"),
    [
        ("INFO", None, "low"),
        ("INFO", "HIGH", "low"),  # impact alone doesn't escalate
        ("WARNING", None, "medium"),
        ("WARNING", "HIGH", "medium"),  # WARNING+HIGH stays medium
        ("ERROR", None, "high"),
        ("ERROR", "LOW", "high"),
        ("ERROR", "MEDIUM", "high"),
        ("ERROR", "HIGH", "critical"),  # only ERROR+HIGH escalates
        ("error", "high", "critical"),  # case-insensitive
        ("", None, "low"),  # unknown levels default low
        ("UNKNOWN", None, "low"),
    ],
)
def test_classify_severity(semgrep_severity: str, impact: str | None, expected: str) -> None:
    """Conjunction of (semgrep_severity, impact) → our 4-level enum.

    The conjunction-required-for-critical rule means a single
    HIGH signal isn't enough — that's the conservative choice
    that keeps critical reserved for the rules Semgrep itself
    flags as both highest-confidence AND highest-impact.
    """
    assert _classify_severity(semgrep_severity, impact) == expected


def test_truncate_preview_short_match_passes_through() -> None:
    """Snippets shorter than the cap are returned verbatim."""
    short = "    eval(user_input)"
    assert _truncate_preview(short) == short


def test_truncate_preview_collapses_multiline() -> None:
    """Multi-line matches are joined with single spaces."""
    multi = "if x:\n    eval(user_input)\nelse:\n    pass"
    out = _truncate_preview(multi)
    assert "\n" not in out
    assert "if x:" in out
    assert "eval(user_input)" in out


def test_truncate_preview_caps_at_max_len() -> None:
    """Long matches are truncated and trail with ``...``."""
    long_line = "x" * 500
    out = _truncate_preview(long_line)
    assert len(out) == _PREVIEW_MAX_LEN
    assert out.endswith("...")
    # The non-truncation portion is exactly _PREVIEW_MAX_LEN-3 chars.
    assert out[:-3] == "x" * (_PREVIEW_MAX_LEN - 3)


def test_truncate_preview_handles_empty_input() -> None:
    """Empty / None-shaped input returns empty string, not None."""
    assert _truncate_preview("") == ""
    # ``None`` is type-erased to str at the call site, but
    # exercise the fallback to be safe.
    assert _truncate_preview(None) == ""  # type: ignore[arg-type]


def test_semgrep_normalize_strips_repo_prefix(tmp_path: object) -> None:
    """SemgrepPlugin.normalize emits repo-relative file paths.

    Semgrep prints the absolute path of every match
    (``/tmp/zynksec-scans/<scan_id>/repo/foo.py``); CodeFinding
    rows must persist repo-relative paths so cross-scan dedup
    works and operator UIs render sensibly.  This test runs the
    plugin's ``normalize`` against a synthesised RawScanResult
    and asserts the absolute path is stripped to repo-relative.
    """
    from pathlib import Path  # noqa: PLC0415
    from uuid import uuid4  # noqa: PLC0415

    from zynksec_scanners.repo.cloner import RepoHandle  # noqa: PLC0415
    from zynksec_scanners.semgrep.plugin import SemgrepPlugin  # noqa: PLC0415
    from zynksec_scanners.types import (  # noqa: PLC0415
        RawScanResult,
        ScanContext,
        ScanProfile,
        ScanTarget,
    )

    repo_root = Path(str(tmp_path)) / "repo"
    repo_root.mkdir(parents=True)

    plugin = SemgrepPlugin(semgrep_bin="/usr/bin/true")
    plugin._handle = RepoHandle(  # type: ignore[assignment]
        path=repo_root,
        git_url="https://github.com/synthetic/repo.git",
    )

    target = ScanTarget(
        kind="repo",
        url="https://github.com/synthetic/repo.git",
        project_id=uuid4(),
        scan_id=uuid4(),
        scan_profile=ScanProfile.PASSIVE,
    )
    raw = RawScanResult(
        engine="semgrep",
        payload={
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                    "path": f"{repo_root}/semgrep-plants/eval_handler.py",
                    "start": {"line": 5, "col": 12},
                    "extra": {"severity": "WARNING", "lines": "    eval(x)"},
                },
                # Already-relative path passes through unchanged.
                {
                    "check_id": "python.lang.security.audit.x.y",
                    "path": "already/relative.py",
                    "start": {"line": 1, "col": 1},
                    "extra": {"severity": "INFO", "lines": "x"},
                },
            ]
        },
    )

    findings = list(plugin.normalize(raw, ScanContext(target=target)))
    paths = [f.file_path for f in findings]
    assert "semgrep-plants/eval_handler.py" in paths, paths
    assert "already/relative.py" in paths, paths
    # No absolute paths (every entry is repo-relative).
    for p in paths:
        assert not p.startswith("/"), f"absolute path leaked into normalize output: {p!r}"

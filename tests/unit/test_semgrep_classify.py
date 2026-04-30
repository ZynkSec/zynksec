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

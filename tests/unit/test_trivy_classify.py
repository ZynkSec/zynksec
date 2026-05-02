"""Unit tests for TrivyPlugin pure-function helpers.

Phase 3 Sprint 4.  Severity-mapping (direct lowercase, not a
boundary computation like OSV's CVSS bucket logic) + the
preview formatter + the ``StartLine`` extractor — all pure,
no subprocess / no I/O.

Coverage:
  * Direct-map severity for each canonical Trivy level.
  * Fallback to ``"medium"`` for ``UNKNOWN`` / missing /
    misshapen values.
  * Preview format with both fields, title-only, description-only,
    empty.
  * Preview truncation for pathologically long inputs.
  * StartLine extraction returns ``None`` for missing,
    zero, negative, and non-integer values; positive ints
    pass through.
  * ``OFFLINE_FLAGS`` invariant — the three flags that make this
    plugin offline must always be present in ``build_argv``;
    a regression that drops one would silently re-enable
    network calls.
"""

from __future__ import annotations

from typing import Any

import pytest
from zynksec_scanners.trivy.plugin import (
    _PREVIEW_MAX_LEN,
    TrivyPlugin,
    _build_preview,
    _classify_severity,
    _start_line,
)


@pytest.mark.parametrize(
    ("trivy_severity", "expected"),
    [
        # Direct map for the four canonical levels.
        ("LOW", "low"),
        ("MEDIUM", "medium"),
        ("HIGH", "high"),
        ("CRITICAL", "critical"),
        # Case-insensitive defensive parsing — Trivy's JSON
        # always emits upper-case but a future schema tweak
        # shouldn't silently mis-bucket findings.
        ("low", "low"),
        ("Critical", "critical"),
        # Anything else (UNKNOWN, missing, garbage) falls back
        # to medium — never suppress, never artificially escalate.
        ("UNKNOWN", "medium"),
        ("INFO", "medium"),
        (None, "medium"),
        ("", "medium"),
        ("8.7", "medium"),  # not a CVSS scanner — strings only
    ],
)
def test_classify_severity(trivy_severity: str | None, expected: str) -> None:
    """Direct-map Trivy severity → 4-level enum."""
    assert _classify_severity(trivy_severity) == expected


def test_build_preview_with_title_and_description() -> None:
    """Canonical happy path — both fields present."""
    out = _build_preview(
        "':latest' tag used",
        "When using a 'FROM' statement you should use a specific tag.",
    )
    assert out == (
        "':latest' tag used: " "When using a 'FROM' statement you should use a specific tag."
    )
    assert len(out) < _PREVIEW_MAX_LEN


def test_build_preview_title_only() -> None:
    """Title without description — no trailing colon-space."""
    out = _build_preview("Privileged container", "")
    assert out == "Privileged container"


def test_build_preview_description_only() -> None:
    """Description without title — render description alone."""
    out = _build_preview("", "Container has privileged=true.")
    assert out == "Container has privileged=true."


def test_build_preview_both_empty() -> None:
    """Defensive fallback for the rare case both fields are blank."""
    out = _build_preview("", "")
    assert out == "(no description)"


def test_build_preview_truncates_long_input() -> None:
    """Pathologically long description truncates with ellipsis."""
    long_desc = "x" * 500
    out = _build_preview("DS001", long_desc)
    assert len(out) == _PREVIEW_MAX_LEN
    assert out.endswith("...")


def test_build_preview_strips_whitespace() -> None:
    """Leading/trailing whitespace on either field is stripped."""
    out = _build_preview("  DS001  ", "\n missing healthcheck \n")
    assert out == "DS001: missing healthcheck"


@pytest.mark.parametrize(
    ("misconfig", "expected"),
    [
        # Happy path — Trivy provides a positive line number.
        ({"CauseMetadata": {"StartLine": 7}}, 7),
        ({"CauseMetadata": {"StartLine": 1}}, 1),
        # Missing CauseMetadata entirely.
        ({}, None),
        # Missing StartLine within CauseMetadata.
        ({"CauseMetadata": {}}, None),
        # Trivy uses 0 as a sentinel for "no line available" on
        # some rules (e.g., DS-0026 "No HEALTHCHECK"); treat it
        # as None so the row honours migration 0009 instead of
        # carrying a bogus line=0.
        ({"CauseMetadata": {"StartLine": 0}}, None),
        # Negative — defensive against future Trivy versions.
        ({"CauseMetadata": {"StartLine": -1}}, None),
        # Non-integer — Trivy's schema is typed but we don't
        # trust input across the subprocess boundary.
        ({"CauseMetadata": {"StartLine": "7"}}, None),
        ({"CauseMetadata": {"StartLine": None}}, None),
    ],
)
def test_start_line(misconfig: dict[str, Any], expected: int | None) -> None:
    """``CauseMetadata.StartLine`` extractor."""
    assert _start_line(misconfig) == expected


def test_offline_flags_present_in_argv() -> None:
    """The three flags that make this plugin offline must ALWAYS be
    present in the constructed argv.

    A regression that drops ``--offline-scan`` (or the two siblings)
    would silently turn the scanner into a network-dependent one —
    breaking the "works in air-gapped CI" reliability property AND
    opening a window for upstream tampering during the policy fetch.
    """
    plugin = TrivyPlugin(trivy_bin="trivy")
    argv = plugin.build_argv("/tmp/repo")  # noqa: S108 — synthetic argv probe, no FS access
    for flag in TrivyPlugin.OFFLINE_FLAGS:
        assert flag in argv, f"offline flag {flag!r} missing from argv {argv!r}"
    # ``--scanners misconfig`` is also load-bearing — without it
    # Trivy defaults to vuln+secret scanning (overlap with
    # OSV-Scanner / Gitleaks).  Pin it.
    assert "--scanners" in argv
    assert argv[argv.index("--scanners") + 1] == "misconfig"

"""Unit tests for OsvScannerPlugin pure-function helpers.

Phase 3 Sprint 3.  CVSS-derived severity mapping + the
redacted-preview formatter — both pure, no subprocess / no I/O.

Coverage:
  * Severity buckets at the standard NIST CVSS 3.x boundaries
    (3.9/4.0, 6.9/7.0, 8.9/9.0, the 0.0 floor and 10.0 ceiling).
  * Unparseable / missing CVSS scores fall back to ``"medium"``
    (conservative middle).
  * Preview format for fixed and unfixed advisories.
  * Preview truncation for pathologically long inputs.
  * Fix-version extraction from a synthesised ``vulnerabilities[]``
    payload — picks the right ``affected[]`` entry for the
    target (name, ecosystem) pair.
"""

from __future__ import annotations

from typing import Any

import pytest
from zynksec_scanners.osv.plugin import (
    _PREVIEW_MAX_LEN,
    _build_preview,
    _classify_severity,
    _first_fixed_version,
)


@pytest.mark.parametrize(
    ("max_severity", "expected"),
    [
        # Boundary cases at NIST CVSS 3.x severity-rating cut-offs.
        ("0.0", "low"),
        ("3.9", "low"),
        ("4.0", "medium"),
        ("6.9", "medium"),
        ("7.0", "high"),
        ("8.9", "high"),
        ("9.0", "critical"),
        ("10.0", "critical"),
        # Common spot values from real OSV advisories.
        ("5.3", "medium"),
        ("7.2", "high"),
        ("8.1", "high"),
        # Missing / empty / non-numeric all fall back to medium —
        # never suppress, never artificially escalate.
        (None, "medium"),
        ("", "medium"),
        ("not-a-number", "medium"),
        ("HIGH", "medium"),
    ],
)
def test_classify_severity(max_severity: str | None, expected: str) -> None:
    """Map OSV ``max_severity`` → 4-level enum at the standard
    NIST CVSS 3.x boundaries; fall back to medium on garbage.
    """
    assert _classify_severity(max_severity) == expected


def test_build_preview_with_fix() -> None:
    """The canonical happy path — pkg + installed + fixed."""
    out = _build_preview("lodash", "4.17.20", "4.17.21")
    assert out == "lodash@4.17.20 → 4.17.21"
    # Length far below the cap; arrows / spaces preserved.
    assert len(out) < _PREVIEW_MAX_LEN


def test_build_preview_no_fix() -> None:
    """Unfixed advisory — explicit ``no fix`` rather than empty
    string so operators can read the preview unaided.
    """
    out = _build_preview("ancient-lib", "1.0.0", None)
    assert out == "ancient-lib@1.0.0 → no fix"


def test_build_preview_truncates_long_input() -> None:
    """A pathologically long package name still fits the column."""
    long_name = "a" * 500
    out = _build_preview(long_name, "1.0.0", "1.0.1")
    assert len(out) == _PREVIEW_MAX_LEN
    assert out.endswith("...")


def _osv_vuln(
    *,
    vuln_id: str,
    name: str,
    ecosystem: str,
    fixed: str | None,
) -> dict[str, Any]:
    """Build a synthetic OSV ``vulnerabilities[]`` entry — concise
    factory for the fix-extraction tests.
    """
    events: list[dict[str, str]] = [{"introduced": "0"}]
    if fixed is not None:
        events.append({"fixed": fixed})
    return {
        "id": vuln_id,
        "affected": [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "ranges": [{"type": "SEMVER", "events": events}],
            }
        ],
    }


def test_first_fixed_version_picks_matching_package() -> None:
    """``vulnerabilities[]`` may contain multiple ``affected[]``
    packages (one advisory covering many libraries); pick the
    one matching our (name, ecosystem) pair.
    """
    vulns = [
        _osv_vuln(
            vuln_id="GHSA-29mw-wpgm-hmr9",
            name="lodash",
            ecosystem="npm",
            fixed="4.17.21",
        ),
    ]
    out = _first_fixed_version(
        vulns,
        target_id="GHSA-29mw-wpgm-hmr9",
        package_name="lodash",
        package_ecosystem="npm",
    )
    assert out == "4.17.21"


def test_first_fixed_version_returns_none_when_no_fix() -> None:
    """Unfixed advisories return ``None`` → caller renders
    ``"no fix"`` in the preview.
    """
    vulns = [
        _osv_vuln(
            vuln_id="GHSA-unfixed",
            name="ancient-lib",
            ecosystem="npm",
            fixed=None,
        ),
    ]
    out = _first_fixed_version(
        vulns,
        target_id="GHSA-unfixed",
        package_name="ancient-lib",
        package_ecosystem="npm",
    )
    assert out is None


def test_first_fixed_version_skips_unrelated_packages() -> None:
    """An advisory covering ``lodash-es`` (different package)
    must NOT contribute its fix version to a ``lodash`` finding.
    """
    vulns = [
        {
            "id": "GHSA-multi",
            "affected": [
                {
                    "package": {"name": "lodash-es", "ecosystem": "npm"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"fixed": "9.9.9"}]},
                    ],
                },
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"fixed": "4.17.21"}]},
                    ],
                },
            ],
        }
    ]
    out = _first_fixed_version(
        vulns,
        target_id="GHSA-multi",
        package_name="lodash",
        package_ecosystem="npm",
    )
    assert out == "4.17.21"


def test_first_fixed_version_returns_none_for_nonexistent_id() -> None:
    """A target_id that doesn't appear in the vulnerabilities list
    yields None — the caller renders ``"no fix"`` and operators
    can see the preview is missing fix info.
    """
    vulns = [
        _osv_vuln(
            vuln_id="GHSA-other",
            name="lodash",
            ecosystem="npm",
            fixed="4.17.21",
        ),
    ]
    out = _first_fixed_version(
        vulns,
        target_id="GHSA-not-in-list",
        package_name="lodash",
        package_ecosystem="npm",
    )
    assert out is None

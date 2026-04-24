"""End-to-end: real ZAP scan of real Juice Shop producing real Findings.

This is the Phase-0 exit-criteria test (docs/04 §0.2 #3, #4).  A full
ZAP baseline on Juice Shop typically completes in 3-4 minutes; we
budget 5 minutes before failing.

No mocks.  If this test finds zero findings, ZAP isn't actually
scanning — treat it as a bug, not a flake.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import httpx
import pytest

_POLL_BUDGET_S = 300.0  # 5 minutes — docs/04 §0.19 risk table ceiling
_POLL_INTERVAL_S = 2.0
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_REAL_SEVERITIES = {"low", "medium", "high", "critical"}


def _poll_until_completed(client: httpx.Client, scan_id: str) -> dict[str, Any]:
    """Poll GET /api/v1/scans/{id} until terminal or timeout."""
    deadline = time.monotonic() + _POLL_BUDGET_S
    seen_statuses: list[str] = []
    body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        status_value = str(body.get("status", ""))
        if not seen_statuses or seen_statuses[-1] != status_value:
            seen_statuses.append(status_value)
        if status_value == "completed":
            return body
        if status_value == "failed":
            pytest.fail(f"scan transitioned to failed: {body}")
        time.sleep(_POLL_INTERVAL_S)
    pytest.fail(
        f"scan {scan_id} did not complete within {_POLL_BUDGET_S:.0f}s; "
        f"statuses seen: {seen_statuses}"
    )


def test_full_scan_against_juice_shop_produces_at_least_one_finding(
    api_client: httpx.Client,
) -> None:
    """POST a real scan, wait up to 5 min, verify ≥ 1 structured finding."""

    response = api_client.post(
        "/api/v1/scans",
        json={"target_url": "http://juice-shop:3000/"},
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    uuid.UUID(scan_id)

    body = _poll_until_completed(api_client, scan_id)
    findings = body.get("findings", [])
    assert isinstance(findings, list), body
    assert len(findings) >= 1, f"ZAP produced zero findings against juice-shop: {body}"

    # At least one finding must carry a real severity (not just "info")
    # and a non-empty ZAP rule id.
    serious_findings = [
        f
        for f in findings
        if f.get("severity", {}).get("level") in _REAL_SEVERITIES
        and (f.get("evidence", {}).get("rule_id") or "").strip()
    ]
    assert serious_findings, f"no low/medium/high/critical finding: {findings[:3]}"

    # Every finding must have a 64-char hex fingerprint (the sha256).
    for finding in findings:
        fingerprint = str(finding.get("fingerprint", ""))
        assert _FINGERPRINT_RE.match(
            fingerprint
        ), f"bad fingerprint shape: {fingerprint!r} on {finding.get('taxonomy')}"

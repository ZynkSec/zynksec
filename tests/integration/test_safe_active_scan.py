"""SAFE_ACTIVE end-to-end against juice-shop — Phase 1 Sprint 2 exit test.

Proves the constrained active-scan profile actually does extra work
on top of PASSIVE.  Two scans, same target:

    1. PASSIVE     — spider + passive analysers only
    2. SAFE_ACTIVE — spider + passive + ``zynksec_safe`` active scan

If SAFE_ACTIVE doesn't return strictly more findings than PASSIVE on
juice-shop (~327 PASSIVE findings, expect 350+ SAFE_ACTIVE on a clean
session), one of three things is broken: the policy disabled
everything useful, the active-scan poll never reaches 100, or the
plugin is silently re-running PASSIVE.

CLAUDE.md §7 — real Postgres, real Redis, real ZAP, real juice-shop.
No mocks.  ZAP's session is reset in :meth:`ZapPlugin.prepare` so the
two scans see independent baselines (without that, alerts accumulate
across scans for the daemon's lifetime and the comparison is
dishonest).

The 15-minute ``@pytest.mark.timeout(900)`` is a generous wall-clock
ceiling — the SAFE policy completes in ~5-8 minutes locally, plus
~30 seconds for the PASSIVE warm-up.  If this trips, the policy
constants in :mod:`zynksec_scanners.zap.plugin` need revisiting, NOT
the timeout.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx
import pytest

# 13 minutes — leaves slack inside the 15-minute pytest-timeout for
# fixture teardown.  Each scan polls under the same budget; in practice
# PASSIVE returns inside a minute.
_POLL_BUDGET_S = 780.0
_POLL_INTERVAL_S = 2.0


def _poll_until_completed(client: httpx.Client, scan_id: str) -> dict[str, Any]:
    """Poll GET /api/v1/scans/{id} until terminal or budget hit."""
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
            pytest.fail(f"scan {scan_id} transitioned to failed: {body}")
        time.sleep(_POLL_INTERVAL_S)
    pytest.fail(
        f"scan {scan_id} did not complete within {_POLL_BUDGET_S:.0f}s; "
        f"statuses seen: {seen_statuses}"
    )


def _post_scan(client: httpx.Client, profile: str) -> str:
    """POST a scan with the given profile, return its id."""
    response = client.post(
        "/api/v1/scans",
        json={"target_url": "http://juice-shop:3000/", "scan_profile": profile},
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["scan_profile"] == profile
    scan_id = body["id"]
    uuid.UUID(scan_id)
    return scan_id


@pytest.mark.timeout(900)
def test_post_scan_with_safe_active_completes_and_finds_more_than_passive(
    api_client: httpx.Client,
) -> None:
    """SAFE_ACTIVE returns strictly more findings than PASSIVE on juice-shop."""
    # Run PASSIVE first to seed a baseline count.  ZAP's session is
    # reset at the start of every scan (ZapPlugin.prepare) so the
    # SAFE_ACTIVE scan sees an independent baseline.
    passive_id = _post_scan(api_client, "PASSIVE")
    passive_body = _poll_until_completed(api_client, passive_id)
    passive_findings = passive_body.get("findings", [])
    passive_count = len(passive_findings)
    assert passive_count > 0, f"PASSIVE produced zero findings: {passive_body}"

    safe_active_id = _post_scan(api_client, "SAFE_ACTIVE")
    safe_active_body = _poll_until_completed(api_client, safe_active_id)
    safe_active_findings = safe_active_body.get("findings", [])
    safe_active_count = len(safe_active_findings)

    # The whole point of SAFE_ACTIVE: it must add findings on top of
    # what PASSIVE detects.  Equal counts mean the active scan ran but
    # found nothing new (policy too restrictive) or didn't run at all.
    assert safe_active_count > passive_count, (
        f"SAFE_ACTIVE ({safe_active_count}) did not exceed PASSIVE "
        f"({passive_count}) — policy may be over-restricted or the "
        f"active scan didn't run. SAFE_ACTIVE body keys: "
        f"{sorted(safe_active_body.keys())}"
    )
    assert safe_active_body["scan_profile"] == "SAFE_ACTIVE"

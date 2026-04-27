"""scan_profile request validation — Phase 1 Sprint 3.

Asserts the Pydantic-rejection path for invalid ``scan_profile``
values.  The 202-accept path for each implemented profile is covered
in the dedicated integration tests:

    - PASSIVE       → ``test_scans_roundtrip.py``
    - SAFE_ACTIVE   → ``test_safe_active_scan.py``
    - AGGRESSIVE    → ``test_aggressive_scan.py`` (opt-in)

The Sprint 1/2 ``..._is_accepted`` tests that lived here were deleted
in Sprint 3: they fire-and-forgot scans against full juice-shop and
combined badly with the new ``worker_concurrency=1`` setting (queued
scans starved subsequent tests).  Their assertions (202 + scan_profile
echo) already run inside the dedicated tests above, so deletion is a
DRY simplification, not a coverage loss.

No mocks (CLAUDE.md §7) — this test needs a live API process, which
the session-scoped compose fixture in ``conftest.py`` provides.
"""

from __future__ import annotations

import httpx


def test_post_scan_with_invalid_profile_returns_pydantic_422(
    api_client: httpx.Client,
) -> None:
    """Unknown profile strings are rejected by Pydantic before the
    router runs — 422 from FastAPI's RequestValidationError handler
    (default ``{"detail": [...]}`` shape, distinct from the canonical
    ZynksecError envelope)."""
    response = api_client.post(
        "/api/v1/scans",
        json={
            "target_url": "http://juice-shop:3000/",
            "scan_profile": "FOOBAR",
        },
    )
    assert response.status_code == 422, response.text
    body = response.json()
    detail = body["detail"]
    assert any("scan_profile" in str(err.get("loc", ())) for err in detail), body

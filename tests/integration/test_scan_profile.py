"""scan_profile request validation — Phase 1 Sprint 3.

Asserts the API surface around the ``scan_profile`` field:

    1. ``SAFE_ACTIVE`` is accepted (202).  Full plugin-level run is
       covered by ``test_safe_active_scan.py``.
    2. ``AGGRESSIVE`` is accepted (202) from Sprint 3 on.  Full
       plugin-level run lives in ``test_aggressive_scan.py``
       (opt-in via ``RUN_AGGRESSIVE_TESTS=1``).
    3. Pydantic rejects arbitrary strings with FastAPI's default 422.

No mocks (CLAUDE.md §7) — these tests need a live API process, which
the session-scoped compose fixture in ``conftest.py`` provides.
"""

from __future__ import annotations

import httpx


def test_post_scan_with_safe_active_is_accepted(
    api_client: httpx.Client,
) -> None:
    """SAFE_ACTIVE returns 202 with the field echoed in the response body."""
    response = api_client.post(
        "/api/v1/scans",
        json={
            "target_url": "http://juice-shop:3000/",
            "scan_profile": "SAFE_ACTIVE",
        },
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["scan_profile"] == "SAFE_ACTIVE"
    assert body["status"] == "queued"


def test_post_scan_with_aggressive_is_accepted(
    api_client: httpx.Client,
) -> None:
    """AGGRESSIVE returns 202 from Sprint 3 — was a descriptive 422
    in Sprints 1 and 2.  This test stays cheap (no scan run); the full
    AGGRESSIVE→worker→ZAP→findings flow is opt-in in
    ``test_aggressive_scan.py``."""
    response = api_client.post(
        "/api/v1/scans",
        json={
            "target_url": "http://juice-shop:3000/",
            "scan_profile": "AGGRESSIVE",
        },
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["scan_profile"] == "AGGRESSIVE"
    assert body["status"] == "queued"


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

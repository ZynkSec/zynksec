"""scan_profile request validation — Phase 1 Sprint 2.

Asserts the API surface around the ``scan_profile`` field:

    1. ``SAFE_ACTIVE`` is now accepted (202) — was a descriptive 422
       in Sprint 1.  The full SAFE_ACTIVE→worker→ZAP→findings flow is
       covered by ``test_safe_active_scan.py`` (long-running).
    2. ``AGGRESSIVE`` still returns the descriptive
       ``scan_profile_not_implemented`` 422; the roadmap pointer in the
       message now names Sprint 3.
    3. Pydantic rejects arbitrary strings with FastAPI's default 422.

No mocks (CLAUDE.md §7) — these tests need a live API process, which
the session-scoped compose fixture in ``conftest.py`` provides.
"""

from __future__ import annotations

import httpx


def test_post_scan_with_safe_active_is_accepted(
    api_client: httpx.Client,
) -> None:
    """SAFE_ACTIVE is implemented from Sprint 2 — 202 with the field
    echoed in the response body.  The full active-scan run lives in
    ``test_safe_active_scan.py`` so this test stays cheap."""
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


def test_post_scan_with_aggressive_returns_descriptive_422(
    api_client: httpx.Client,
) -> None:
    """AGGRESSIVE is reserved but not implemented — descriptive 422
    pointing at Phase 1 Sprint 3."""
    response = api_client.post(
        "/api/v1/scans",
        json={
            "target_url": "http://juice-shop:3000/",
            "scan_profile": "AGGRESSIVE",
        },
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "scan_profile_not_implemented"
    assert "AGGRESSIVE" in body["message"]
    assert "not yet implemented" in body["message"]
    # Roadmap pointer is part of the contract — a future copy-edit
    # that drops it would erase the user's "what next" signal.
    assert "Sprint 3" in body["message"]
    # Canonical {code, message, request_id} envelope (CLAUDE.md §4) —
    # request_id must carry the correlation_id, not just be shaped like it.
    assert body["request_id"]


def test_post_scan_with_invalid_profile_returns_pydantic_422(
    api_client: httpx.Client,
) -> None:
    """Unknown profile strings are rejected by Pydantic before the router
    runs — 422 from FastAPI's RequestValidationError handler, distinct
    from the :class:`ScanProfileNotImplemented` shape above."""
    response = api_client.post(
        "/api/v1/scans",
        json={
            "target_url": "http://juice-shop:3000/",
            "scan_profile": "FOOBAR",
        },
    )
    assert response.status_code == 422, response.text
    # FastAPI's default validation-error body is ``{"detail": [...]}``;
    # the offending location is reported under ``loc`` so we can be sure
    # the rejection is about ``scan_profile`` and not some other field.
    body = response.json()
    detail = body["detail"]
    assert any("scan_profile" in str(err.get("loc", ())) for err in detail), body

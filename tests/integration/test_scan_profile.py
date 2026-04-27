"""scan_profile request validation — Phase 1 Sprint 1.

Asserts the API surface around the new ``scan_profile`` field:

    1. Pydantic accepts every :class:`ScanProfile` value but rejects
       arbitrary strings with the standard 422.
    2. The router returns a descriptive 422
       (``scan_profile_not_implemented``) for ``SAFE_ACTIVE`` and
       ``AGGRESSIVE`` so users don't hit a Celery
       :class:`NotImplementedError` downstream.

The happy-path that *runs* a scan with ``scan_profile=PASSIVE`` lives
in ``test_scans_roundtrip.py`` (real worker pickup) — duplicating the
poll-until-running here would just cost time without adding signal.

No mocks (CLAUDE.md §7) — these tests still need a live API process,
which the session-scoped compose fixture in ``conftest.py`` provides.
"""

from __future__ import annotations

import httpx


def test_post_scan_with_safe_active_returns_descriptive_422(
    api_client: httpx.Client,
) -> None:
    """SAFE_ACTIVE is reserved but not implemented — 422 with the
    ``scan_profile_not_implemented`` code, message names the profile."""
    response = api_client.post(
        "/api/v1/scans",
        json={
            "target_url": "http://juice-shop:3000/",
            "scan_profile": "SAFE_ACTIVE",
        },
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "scan_profile_not_implemented"
    assert "SAFE_ACTIVE" in body["message"]
    assert "not yet implemented" in body["message"]


def test_post_scan_with_aggressive_returns_descriptive_422(
    api_client: httpx.Client,
) -> None:
    """AGGRESSIVE is reserved but not implemented — same shape as SAFE_ACTIVE."""
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

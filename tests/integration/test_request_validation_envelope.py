"""Phase 2 debt-paydown: Pydantic validation failures use the canonical envelope.

Pre-paydown, ``RequestValidationError`` bypassed the
``ZynksecError``-based handler and surfaced as FastAPI's default
``{"detail": [...]}`` shape, breaking the CLAUDE.md §4 contract that
every 4xx body has the same four keys
(``code, message, request_id, details``).

This test pins the canonical shape on a known-bad payload (missing
required field) so a future regression to FastAPI's default handler
fails loudly.  No mocks (CLAUDE.md §7).
"""

from __future__ import annotations

import httpx


def test_pydantic_validation_failure_returns_canonical_envelope(
    api_client: httpx.Client,
) -> None:
    """POST a Target without the required ``url`` field; Pydantic
    rejects it BEFORE the router body runs.  The response must
    carry exactly the canonical envelope keys with a stable
    machine-readable code, the human-readable message, the
    correlation id under ``request_id``, and the original Pydantic
    error list under ``details.errors``."""
    response = api_client.post(
        "/api/v1/targets",
        json={"name": "missing-url"},  # required ``url`` field absent
    )
    assert response.status_code == 422, response.text
    body = response.json()

    # Canonical envelope shape — same four top-level keys as every
    # other 4xx (ZynksecError-derived) response.
    assert set(body.keys()) == {"code", "message", "request_id", "details"}, body

    assert body["code"] == "request_validation_error"
    assert body["message"] == "request body or parameters failed validation"
    # request_id is the same correlation id bound by the middleware;
    # the response also echoes it in the X-Correlation-Id header.
    assert body["request_id"]
    assert response.headers["X-Correlation-Id"] == body["request_id"]

    # details.errors preserves the Pydantic per-field info verbatim
    # so clients that want field-level introspection still have it.
    errors = body["details"]["errors"]
    assert isinstance(errors, list)
    assert errors, "expected at least one Pydantic error entry"
    assert any("url" in str(err.get("loc", ())) for err in errors), errors

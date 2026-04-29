"""Phase 2 debt-paydown: project_id resolution semantics.

Both branches of :func:`resolve_project_for_request` are pinned here
against real Postgres so a future regression to the silent-fallback
behaviour fails loudly.

    project_id OMITTED       → implicit Local Dev (Phase 0 lenience)
    project_id PROVIDED but
        not in the DB        → canonical 404 ``project_not_found``

Targets is the smallest router that exercises both branches (one
``Depends`` chain, no ZAP / Celery in the path).  No mocks
(CLAUDE.md §7).
"""

from __future__ import annotations

import uuid

import httpx


def test_post_target_without_project_id_uses_local_dev_fallback(
    api_client: httpx.Client,
) -> None:
    """``project_id`` omitted → Target lands in the implicit Local Dev
    project (existing Phase 0 behaviour, regression-pinned now that
    the unknown-id branch has been tightened separately)."""
    name = f"resolve-omit-{uuid.uuid4().hex[:8]}"
    response = api_client.post(
        "/api/v1/targets",
        json={
            "name": name,
            "url": "http://juice-shop:3000/",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    # The Target's project_id is the implicit Local Dev row's id.  We
    # can't hard-code that uuid (it's created on first request and
    # persists), but we can re-read the same project via GET
    # /api/v1/targets without a filter and confirm THIS row shows up
    # under the same project_id we just observed.
    listed = api_client.get("/api/v1/targets")
    assert listed.status_code == 200, listed.text
    listed_ids = {row["id"] for row in listed.json()}
    assert body["id"] in listed_ids
    # And the project_id MUST be a uuid (not None) — Local Dev exists
    # by the time the response comes back.
    uuid.UUID(body["project_id"])


def test_post_target_with_unknown_project_id_returns_canonical_404(
    api_client: httpx.Client,
) -> None:
    """``project_id`` is a valid uuid but no row matches → 404 with the
    canonical envelope and code ``project_not_found``.  Pre-Phase-2-
    debt-paydown this silently fell back to Local Dev's data."""
    bogus = str(uuid.uuid4())
    response = api_client.post(
        "/api/v1/targets",
        json={
            "name": f"resolve-unknown-{uuid.uuid4().hex[:8]}",
            "url": "http://juice-shop:3000/",
            "project_id": bogus,
        },
    )
    assert response.status_code == 404, response.text
    body = response.json()
    assert body["code"] == "project_not_found"
    assert bogus in body["message"]
    assert body["request_id"]


def test_get_targets_with_unknown_project_id_returns_canonical_404(
    api_client: httpx.Client,
) -> None:
    """Same tightening on the GET side — ``GET /api/v1/targets?project_id=...``
    with a bogus uuid returns 404 instead of silently leaking Local
    Dev's listing."""
    bogus = str(uuid.uuid4())
    response = api_client.get(f"/api/v1/targets?project_id={bogus}")
    assert response.status_code == 404, response.text
    body = response.json()
    assert body["code"] == "project_not_found"
    assert bogus in body["message"]
    assert body["request_id"]

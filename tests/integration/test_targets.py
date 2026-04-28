"""Target CRUD + uniqueness — Phase 2 Sprint 1.

Real Postgres + Redis (no mocks per CLAUDE.md §7).  Tests run against
the same session-scoped compose stack the rest of the integration
suite uses; the new ``targets`` table comes from migration 0003 which
the conftest applies before yielding to tests.
"""

from __future__ import annotations

import uuid

import httpx


def _post_target(client: httpx.Client, name: str, url: str = "http://juice-shop:3000/") -> dict:
    """Helper — create a Target and return the parsed response body."""
    response = client.post("/api/v1/targets", json={"name": name, "url": url})
    assert response.status_code == 201, response.text
    return response.json()


def test_target_crud_round_trip(api_client: httpx.Client) -> None:
    """Create → list → get → delete in sequence; every transition is the
    documented status code with the documented body shape."""
    name = f"crud-{uuid.uuid4().hex[:8]}"
    created = _post_target(api_client, name=name, url="http://juice-shop:3000/")

    target_id = created["id"]
    uuid.UUID(target_id)
    assert created["name"] == name
    # Pydantic ``HttpUrl`` normalises to a trailing slash on bare-domain
    # inputs — the assertion is loose enough to absorb that.
    assert created["url"].rstrip("/") == "http://juice-shop:3000"
    assert created["kind"] == "web_app"
    assert "created_at" in created
    assert "updated_at" in created

    # GET-list — newly-created Target must appear.
    list_response = api_client.get("/api/v1/targets")
    assert list_response.status_code == 200, list_response.text
    listed = list_response.json()
    assert any(t["id"] == target_id for t in listed)

    # GET-one
    get_response = api_client.get(f"/api/v1/targets/{target_id}")
    assert get_response.status_code == 200, get_response.text
    fetched = get_response.json()
    assert fetched["id"] == target_id
    assert fetched["name"] == name

    # DELETE — 204 No Content, then GET-one returns 404 canonical envelope.
    delete_response = api_client.delete(f"/api/v1/targets/{target_id}")
    assert delete_response.status_code == 204, delete_response.text

    after_delete = api_client.get(f"/api/v1/targets/{target_id}")
    assert after_delete.status_code == 404, after_delete.text
    body = after_delete.json()
    assert body["code"] == "target_not_found"
    assert target_id in body["message"]
    # Canonical envelope: request_id carries the correlation_id.
    assert body["request_id"]


def test_get_unknown_target_returns_canonical_404(api_client: httpx.Client) -> None:
    """GET /targets/{random-uuid} → canonical envelope 404."""
    random_id = str(uuid.uuid4())
    response = api_client.get(f"/api/v1/targets/{random_id}")
    assert response.status_code == 404, response.text
    body = response.json()
    assert body["code"] == "target_not_found"
    assert random_id in body["message"]
    assert body["request_id"]


def test_create_target_with_duplicate_name_returns_canonical_409(
    api_client: httpx.Client,
) -> None:
    """Same ``(project_id, name)`` twice → 409 ``target_name_conflict``.

    The unique constraint sits on ``targets(project_id, name)``; the
    handler catches ``IntegrityError`` and surfaces the canonical
    envelope rather than a 500 traceback.
    """
    name = f"dup-{uuid.uuid4().hex[:8]}"
    _post_target(api_client, name=name)

    second = api_client.post(
        "/api/v1/targets",
        json={"name": name, "url": "http://juice-shop:3000/"},
    )
    assert second.status_code == 409, second.text
    body = second.json()
    assert body["code"] == "target_name_conflict"
    assert name in body["message"]
    assert body["request_id"]

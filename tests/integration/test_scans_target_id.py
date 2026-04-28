"""Scan creation via target_id (new path) and target_url (legacy) — Sprint 2 P1.

Asserts the four cases the Phase 2 Sprint 1 prompt calls out:

    1. ``target_id`` set: scan persists with ``target_id`` populated;
       response embeds the ``target`` summary (id + name + url).
    2. ``target_url`` set: legacy path; ``target_id`` stays null;
       response ``target`` is ``null``.
    3. BOTH set: 422 canonical-envelope ``scan_target_spec_conflict``.
    4. NEITHER set: 422 canonical-envelope ``scan_target_spec_conflict``.

Plus the unknown-``target_id`` 404 ``target_not_found`` path so the
canonical envelope on Target lookup is also covered.

Real Postgres + Redis (CLAUDE.md §7).  These tests don't wait for ZAP
to complete — they just check the create-handler shape; the worker
will pick the scan up and run it asynchronously, but our assertions
land before that completes.
"""

from __future__ import annotations

import uuid

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import Scan


def _create_target(client: httpx.Client) -> dict:
    """Helper — POST a fresh Target so each test starts clean."""
    name = f"scan-target-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/targets",
        json={"name": name, "url": "http://juice-shop:3000/"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_create_scan_with_target_id_links_correctly(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """``target_id`` path: response includes the embedded target;
    DB row links to the same Target."""
    target = _create_target(api_client)

    response = api_client.post(
        "/api/v1/scans",
        json={"target_id": target["id"]},
    )
    assert response.status_code == 202, response.text
    body = response.json()

    # Response embeds the Target summary: {id, name, url}.
    assert body["target"] is not None, body
    assert body["target"]["id"] == target["id"]
    assert body["target"]["name"] == target["name"]
    assert body["target"]["url"].rstrip("/") == target["url"].rstrip("/")
    # ``target_url`` mirrors ``target.url`` so legacy clients that
    # read the flat field still work.
    assert body["target_url"].rstrip("/") == target["url"].rstrip("/")

    # DB row carries the FK.
    scan_id = body["id"]
    row = db_session.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
    assert row.target_id == uuid.UUID(target["id"])


def test_create_scan_with_target_url_legacy_path_leaves_target_id_null(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """``target_url`` path: scan persists with ``target_id`` null;
    response ``target`` field is null too."""
    response = api_client.post(
        "/api/v1/scans",
        json={"target_url": "http://juice-shop:3000/"},
    )
    assert response.status_code == 202, response.text
    body = response.json()

    assert body.get("target") is None, body
    assert body["target_url"].rstrip("/") == "http://juice-shop:3000"

    scan_id = body["id"]
    row = db_session.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
    assert row.target_id is None
    assert row.target_url.rstrip("/") == "http://juice-shop:3000"


def test_create_scan_with_both_target_id_and_target_url_returns_422(
    api_client: httpx.Client,
) -> None:
    """Both fields set → canonical-envelope 422 ``scan_target_spec_conflict``."""
    target = _create_target(api_client)

    response = api_client.post(
        "/api/v1/scans",
        json={
            "target_id": target["id"],
            "target_url": "http://juice-shop:3000/",
        },
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "scan_target_spec_conflict"
    assert "exactly one" in body["message"].lower()
    assert body["request_id"]


def test_create_scan_with_neither_target_id_nor_target_url_returns_422(
    api_client: httpx.Client,
) -> None:
    """Both fields omitted → canonical-envelope 422 ``scan_target_spec_conflict``.

    Same error code as the both-set case so a single client-side
    handler can recognise "you specified the target wrong" without
    branching on shape.
    """
    response = api_client.post("/api/v1/scans", json={})
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "scan_target_spec_conflict"
    assert "exactly one" in body["message"].lower()
    assert body["request_id"]


def test_create_scan_with_unknown_target_id_returns_canonical_404(
    api_client: httpx.Client,
) -> None:
    """``target_id`` that doesn't resolve → 404 ``target_not_found``."""
    random_id = str(uuid.uuid4())
    response = api_client.post(
        "/api/v1/scans",
        json={"target_id": random_id},
    )
    assert response.status_code == 404, response.text
    body = response.json()
    assert body["code"] == "target_not_found"
    assert random_id in body["message"]
    assert body["request_id"]


def test_delete_target_with_scans_returns_canonical_409(
    api_client: httpx.Client,
) -> None:
    """A Target with at least one scan referencing it can't be deleted —
    canonical envelope ``target_has_scans``, status 409, ``details``
    includes the actual ``scan_count``."""
    target = _create_target(api_client)

    # Create a scan against this target so the delete is blocked.
    scan_response = api_client.post("/api/v1/scans", json={"target_id": target["id"]})
    assert scan_response.status_code == 202, scan_response.text

    delete_response = api_client.delete(f"/api/v1/targets/{target['id']}")
    assert delete_response.status_code == 409, delete_response.text
    body = delete_response.json()
    assert body["code"] == "target_has_scans"
    assert body["request_id"]
    assert body["details"]["scan_count"] >= 1

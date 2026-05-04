"""GET /api/v1/scans list endpoint — Phase 4 Sprint 1.

Real Postgres + Redis (CLAUDE.md §7).  No mocks.  The list endpoint
is the precondition for the frontend's scan list page; this test
pins the contract that:

  * results are project-scoped (the implicit Local Dev project when
    ``project_id`` is omitted, like the sibling targets / scan-groups
    list endpoints);
  * order is ``created_at DESC`` so the newest scan is first;
  * each row carries a non-null ``findings_count`` (per the list
    contract — detail responses leave it ``None``);
  * the list rows have ``findings == []`` and ``code_findings == []``
    even for scans with persisted findings (drill-in to
    ``GET /api/v1/scans/{id}`` is the contract for the populated
    lists).
"""

from __future__ import annotations

import uuid

import httpx
from sqlalchemy.orm import Session


def _create_scan(client: httpx.Client) -> dict:
    """Create a scan via the legacy ``target_url`` path so the test
    doesn't depend on the gitfixture / juice-shop reachability —
    we only care that the row lands in the project, not that the
    worker completes the scan.
    """
    response = client.post(
        "/api/v1/scans",
        json={"target_url": "http://juice-shop:3000/"},
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_list_scans_returns_project_scoped_newest_first(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """POST 3 scans, GET the list, assert order + per-row contract."""
    del db_session  # the API contract is what we're verifying

    a = _create_scan(api_client)
    b = _create_scan(api_client)
    c = _create_scan(api_client)
    created_ids = [a["id"], b["id"], c["id"]]

    response = api_client.get("/api/v1/scans")
    assert response.status_code == 200, response.text
    scans = response.json()
    assert isinstance(scans, list)

    # Project-scoped: every row's project_id is the implicit Local
    # Dev project.  Don't pin the exact UUID — it varies across
    # CI vs. local stacks — but assert all rows share one.
    project_ids = {s["project_id"] for s in scans}
    assert len(project_ids) == 1, project_ids

    # The three scans we just created are present, in newest-first
    # order (most recent POST first).  Other scans from prior tests
    # in the suite may sit further down the list — assert the
    # relative ordering of OUR three rather than the absolute first
    # three positions, so this test stays parallel-friendly with
    # the rest of the integration suite.
    indices = {s["id"]: i for i, s in enumerate(scans) if s["id"] in created_ids}
    assert set(indices) == set(
        created_ids
    ), f"created scans missing from list; got ids={[s['id'] for s in scans]!r}"
    # Newest first: c (last POST) appears before b appears before a.
    assert indices[c["id"]] < indices[b["id"]] < indices[a["id"]], indices

    # Per-row contract: findings_count is an int (>=0), and the
    # populated lists are empty even though the scan rows exist.
    for s in scans:
        assert isinstance(s["findings_count"], int), s
        assert s["findings_count"] >= 0, s
        assert s["findings"] == [], s["id"]
        assert s["code_findings"] == [], s["id"]


def test_list_scans_unknown_project_returns_404(api_client: httpx.Client) -> None:
    """An explicit ``project_id`` that doesn't exist surfaces as the
    canonical-envelope 404 ``project_not_found`` — same path as
    the sibling list endpoints.
    """
    bogus = uuid.uuid4()
    response = api_client.get(f"/api/v1/scans?project_id={bogus}")
    assert response.status_code == 404, response.text
    body = response.json()
    assert body["code"] == "project_not_found", body
    assert body["request_id"], body

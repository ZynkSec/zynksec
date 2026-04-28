"""ScanGroup multi-target round-trip — Phase 2 Sprint 2.

Real Postgres + Redis + ZAP, no mocks (CLAUDE.md §7).  Tests:

    1. Two-target PASSIVE round-trip — both children complete,
       summary rolls up correctly, both link to the same group.
    2. Validation: unknown target_id (atomic — no group/children
       created), duplicate target_ids, empty list (Pydantic).
    3. Partial failure: one valid web_app target + one ``kind=repo``
       target (the ZapPlugin's ``supports`` returns False for
       non-web_app kinds, so that child fails fast).  Group ends
       ``partial_failure`` with the correct summary; the surviving
       child still has findings.
"""

from __future__ import annotations

import time
import uuid

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from zynksec_db import Finding, Project, Scan, ScanGroup

# Same poll budget pattern as other integration tests.  Each
# child runs PASSIVE on a juice-shop subpath so total wall-clock
# is dominated by 2 × ~30 s = ~60 s plus group bookkeeping.
_POLL_BUDGET_S = 240.0
_POLL_INTERVAL_S = 2.0


def _create_target(client: httpx.Client, *, kind: str = "web_app", url: str | None = None) -> dict:
    """Helper — POST a fresh Target so each test starts clean."""
    name = f"sg-target-{kind}-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/targets",
        json={
            "name": name,
            "url": url or "http://juice-shop:3000/",
            "kind": kind,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _poll_group_terminal(client: httpx.Client, group_id: str) -> dict:
    """Poll GET /scan-groups/{id} until status terminal or budget hit."""
    terminal = {"completed", "failed", "partial_failure"}
    deadline = time.monotonic() + _POLL_BUDGET_S
    seen: list[str] = []
    body: dict = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/scan-groups/{group_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        if not seen or seen[-1] != body["status"]:
            seen.append(body["status"])
        if body["status"] in terminal:
            return body
        time.sleep(_POLL_INTERVAL_S)
    pytest.fail(
        f"scan_group {group_id} did not reach terminal within {_POLL_BUDGET_S:.0f}s; "
        f"statuses seen: {seen}"
    )


def test_scan_group_two_target_passive_round_trip(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Two PASSIVE children against juice-shop subpaths; both complete."""
    t1 = _create_target(
        api_client,
        url="http://juice-shop:3000/rest/products/search?q=apple",
    )
    t2 = _create_target(
        api_client,
        url="http://juice-shop:3000/rest/products/search?q=banana",
    )

    response = api_client.post(
        "/api/v1/scan-groups",
        json={
            "target_ids": [t1["id"], t2["id"]],
            "name": "two-target-passive-test",
            "scan_profile": "PASSIVE",
        },
    )
    assert response.status_code == 202, response.text
    posted = response.json()
    assert posted["status"] == "queued"
    assert posted["scan_profile"] == "PASSIVE"
    assert len(posted["child_scan_ids"]) == 2
    assert posted["summary"] == {
        "total": 2,
        "queued": 2,
        "running": 0,
        "completed": 0,
        "failed": 0,
    }

    group_id = posted["id"]
    body = _poll_group_terminal(api_client, group_id)
    assert body["status"] == "completed", body
    assert body["summary"]["completed"] == 2
    assert body["summary"]["failed"] == 0
    assert body["completed_at"] is not None

    # DB-level invariants: both children link to this group.
    children = (
        db_session.execute(select(Scan).where(Scan.scan_group_id == uuid.UUID(group_id)))
        .scalars()
        .all()
    )
    assert len(children) == 2
    assert all(str(c.scan_group_id) == group_id for c in children)

    # API-level: GET /api/v1/scans/{child_id} surfaces the parent
    # ``scan_group_id`` so a client following ``child_scan_ids`` can
    # see the link both ways (Sprint-2 added the field to ScanRead).
    a_child_id = posted["child_scan_ids"][0]
    child_response = api_client.get(f"/api/v1/scans/{a_child_id}")
    assert child_response.status_code == 200, child_response.text
    assert child_response.json()["scan_group_id"] == group_id


def test_scan_group_with_unknown_target_id_returns_canonical_422_atomically(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Unknown target_id → 422 ``unknown_target_ids``, NO rows created."""
    valid = _create_target(api_client)
    bogus = str(uuid.uuid4())
    valid_uuid = uuid.UUID(valid["id"])

    pre_groups = db_session.execute(select(ScanGroup)).scalars().all()
    pre_group_count = len(pre_groups)
    # Scoped to the GOOD target_id so this delta isn't muddied by
    # scans created in other tests against juice-shop's bare URL.
    pre_scan_count = db_session.execute(
        select(func.count()).select_from(Scan).where(Scan.target_id == valid_uuid)
    ).scalar_one()

    response = api_client.post(
        "/api/v1/scan-groups",
        json={"target_ids": [valid["id"], bogus], "scan_profile": "PASSIVE"},
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "unknown_target_ids"
    assert bogus in body["details"]["unknown_target_ids"]
    assert body["request_id"]

    # Atomicity: no group created AND no orphan child Scan rows
    # with the GOOD target_id slipped through either.  Scope the
    # Scan delta to the specific target_id used here so concurrent
    # fixture activity (other tests' scans against juice-shop)
    # can't perturb the assertion.
    db_session.expire_all()
    post_groups = db_session.execute(select(ScanGroup)).scalars().all()
    assert len(post_groups) == pre_group_count
    post_scan_count = db_session.execute(
        select(func.count()).select_from(Scan).where(Scan.target_id == valid_uuid)
    ).scalar_one()
    assert post_scan_count == pre_scan_count


def test_scan_group_with_cross_project_target_id_returns_canonical_422(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Target lives in project A; POST /scan-groups names project B
    referencing it → 422 ``unknown_target_ids`` (same code AND same
    message string as the truly-missing case so existence doesn't
    leak across project boundaries).  No ScanGroup row created.

    No HTTP endpoint creates Projects directly today (Phase 0 only
    has the implicit Local Dev project), so this test inserts the
    two project rows via ``db_session`` to exercise the cross-
    project branch in ``create_scan_group``.
    """
    project_a = Project(name=f"sg-cross-A-{uuid.uuid4().hex[:8]}")
    project_b = Project(name=f"sg-cross-B-{uuid.uuid4().hex[:8]}")
    db_session.add_all([project_a, project_b])
    db_session.commit()

    # Target lives in project A.
    target_a_response = api_client.post(
        "/api/v1/targets",
        json={
            "name": f"sg-cross-target-{uuid.uuid4().hex[:8]}",
            "url": "http://juice-shop:3000/",
            "project_id": str(project_a.id),
        },
    )
    assert target_a_response.status_code == 201, target_a_response.text
    target_a = target_a_response.json()

    pre_groups = db_session.execute(select(ScanGroup)).scalars().all()
    pre_group_count = len(pre_groups)

    # POST scan-group from project B referencing project A's target.
    response = api_client.post(
        "/api/v1/scan-groups",
        json={
            "target_ids": [target_a["id"]],
            "project_id": str(project_b.id),
            "scan_profile": "PASSIVE",
        },
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "unknown_target_ids"
    # Existence MUST NOT leak: the message string is identical to the
    # truly-missing case so a client can't tell them apart.
    assert body["message"] == "one or more target_ids do not exist in this project"
    assert target_a["id"] in body["details"]["unknown_target_ids"]
    assert body["request_id"]

    # Atomicity: no ScanGroup row created.
    db_session.expire_all()
    post_groups = db_session.execute(select(ScanGroup)).scalars().all()
    assert len(post_groups) == pre_group_count


def test_scan_group_with_duplicate_target_ids_returns_canonical_422(
    api_client: httpx.Client,
) -> None:
    """Same target_id listed twice → 422 ``duplicate_target_ids``."""
    target = _create_target(api_client)
    response = api_client.post(
        "/api/v1/scan-groups",
        json={"target_ids": [target["id"], target["id"]], "scan_profile": "PASSIVE"},
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "duplicate_target_ids"
    assert target["id"] in body["details"]["duplicate_target_ids"]
    assert body["request_id"]


def test_scan_group_with_empty_target_ids_returns_pydantic_422(
    api_client: httpx.Client,
) -> None:
    """Empty list → Pydantic 422 (default ``{"detail": [...]}`` shape).

    The prompt explicitly calls for the Pydantic ``min_length=1``
    treatment on this case, distinct from the canonical envelope
    used for unknown / duplicate ids.
    """
    response = api_client.post(
        "/api/v1/scan-groups",
        json={"target_ids": [], "scan_profile": "PASSIVE"},
    )
    assert response.status_code == 422, response.text
    body = response.json()
    detail = body["detail"]
    assert any("target_ids" in str(err.get("loc", ())) for err in detail), body


def test_scan_group_partial_failure_when_one_child_target_kind_unsupported(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Mix one ``web_app`` Target and one ``repo`` Target; the ZapPlugin
    rejects ``kind=repo`` (``supports()`` returns False) so that child
    fails fast.  Group should end ``partial_failure`` with summary
    ``{completed: 1, failed: 1}``."""
    web = _create_target(
        api_client,
        url="http://juice-shop:3000/rest/products/search?q=apple",
    )
    # ``kind=repo`` is allowed by Pydantic + ORM, but the plugin's
    # ``supported_target_kinds = {"web_app"}`` rejects it before any
    # ZAP API call — fast deterministic failure.
    repo = _create_target(
        api_client,
        kind="repo",
        url="http://juice-shop:3000/",
    )

    response = api_client.post(
        "/api/v1/scan-groups",
        json={"target_ids": [web["id"], repo["id"]], "scan_profile": "PASSIVE"},
    )
    assert response.status_code == 202, response.text
    group_id = response.json()["id"]

    body = _poll_group_terminal(api_client, group_id)
    assert body["status"] == "partial_failure", body
    assert body["summary"]["completed"] == 1
    assert body["summary"]["failed"] == 1
    assert body["summary"]["total"] == 2

    # The web_app child should have completed and persisted findings;
    # the repo child should be marked failed.
    children = (
        db_session.execute(select(Scan).where(Scan.scan_group_id == uuid.UUID(group_id)))
        .scalars()
        .all()
    )
    by_target = {c.target_id: c for c in children}
    surviving_child = by_target[uuid.UUID(web["id"])]
    assert surviving_child.status == "completed"
    assert by_target[uuid.UUID(repo["id"])].status == "failed"

    # The whole point of partial_failure: the surviving child still
    # produced real findings.  Without this assertion the test would
    # pass even if the worker silently lost findings on the success
    # path.
    surviving_finding_count = db_session.execute(
        select(func.count()).select_from(Finding).where(Finding.scan_id == surviving_child.id)
    ).scalar_one()
    assert surviving_finding_count > 0, (
        f"surviving child {surviving_child.id} has 0 findings; "
        "expected at least one from PASSIVE on the juice-shop SQLi subpath"
    )

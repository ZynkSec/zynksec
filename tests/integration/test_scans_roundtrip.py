"""End-to-end: POST /api/v1/scans -> Celery -> Postgres -> GET.

No mocks.  Real Postgres, real Redis, real Celery worker running in
Docker Compose.  Asserts the scan transitions queued -> running ->
completed within a 10-second budget.
"""

from __future__ import annotations

import time
import uuid

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import Scan

_POLL_BUDGET_S = 10.0
_POLL_INTERVAL_S = 0.25


def _poll_until_completed(client: httpx.Client, scan_id: str) -> dict[str, object]:
    """Poll GET /api/v1/scans/{id} until status='completed' or timeout."""
    deadline = time.monotonic() + _POLL_BUDGET_S
    seen_statuses: list[str] = []
    body: dict[str, object] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        status_value = body.get("status")
        assert isinstance(status_value, str)
        if not seen_statuses or seen_statuses[-1] != status_value:
            seen_statuses.append(status_value)
        if status_value == "completed":
            # Sanity: we must have observed `queued` (at POST time) and
            # either `running` or jumped straight through.  The worker
            # is deliberately slow enough (sleep 1) that the API should
            # see `running` at least once.
            assert "running" in seen_statuses or "queued" in seen_statuses
            return body
        if status_value == "failed":
            pytest.fail(f"scan transitioned to failed: {body}")
        time.sleep(_POLL_INTERVAL_S)
    pytest.fail(
        f"scan {scan_id} did not complete within {_POLL_BUDGET_S}s; "
        f"statuses seen: {seen_statuses}"
    )


def test_post_scans_returns_202_and_scan_completes_via_worker(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """POST a scan, poll until completed, then verify the DB row directly."""

    response = api_client.post(
        "/api/v1/scans",
        json={"target_url": "http://juice-shop:3000/"},
    )
    assert response.status_code == 202, response.text
    posted_body = response.json()

    scan_id = posted_body["id"]
    # Must be a valid UUID.
    uuid.UUID(scan_id)
    assert posted_body["status"] == "queued"

    completed_body = _poll_until_completed(api_client, scan_id)
    assert completed_body["status"] == "completed"
    assert completed_body["started_at"] is not None
    assert completed_body["completed_at"] is not None

    # Second assertion: the row exists in Postgres with the terminal
    # status.  Hitting the DB directly catches API/DB drift.
    stmt = select(Scan).where(Scan.id == uuid.UUID(scan_id))
    row = db_session.execute(stmt).scalar_one()
    assert row.status == "completed"
    assert str(row.id) == scan_id

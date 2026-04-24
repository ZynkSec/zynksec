"""End-to-end: POST /api/v1/scans -> Celery -> Postgres -> GET.

Fast smoke check: confirms the API/Celery/worker pipe works by asserting
the scan leaves the ``queued`` status (i.e. the worker picked it up).
The full "does ZAP actually find something on juice-shop" proof lives
in ``test_zap_against_juice_shop.py`` and takes minutes.

No mocks (CLAUDE.md §7).
"""

from __future__ import annotations

import time
import uuid

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import Scan

# The worker has to pick up the task and transition the Scan row to
# ``running`` before this test passes.  Week 2 used a 10 s budget with
# a no-op task; Week 3's worker does real ZAP work so it spends a
# bit longer in ``queued`` and ``running``.  We only need to see the
# transition out of ``queued`` to prove the pipe.
_POLL_BUDGET_S = 30.0
_POLL_INTERVAL_S = 0.5


def _poll_until_off_queued(client: httpx.Client, scan_id: str) -> dict[str, object]:
    """Poll GET /api/v1/scans/{id} until status != 'queued' or timeout."""
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
        if status_value != "queued":
            return body
        time.sleep(_POLL_INTERVAL_S)
    pytest.fail(
        f"scan {scan_id} stayed queued for {_POLL_BUDGET_S}s; " f"statuses seen: {seen_statuses}"
    )


def test_post_scan_leaves_queued_once_worker_picks_up(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """POST a scan, verify the worker picks it up, row exists in DB."""

    response = api_client.post(
        "/api/v1/scans",
        json={"target_url": "http://juice-shop:3000/"},
    )
    assert response.status_code == 202, response.text
    posted_body = response.json()

    scan_id = posted_body["id"]
    uuid.UUID(scan_id)  # must be a valid UUID
    assert posted_body["status"] == "queued"
    assert posted_body["findings"] == []

    body = _poll_until_off_queued(api_client, scan_id)
    assert body["status"] in {"running", "completed", "failed"}

    # Direct DB check — catches API/DB drift.
    stmt = select(Scan).where(Scan.id == uuid.UUID(scan_id))
    row = db_session.execute(stmt).scalar_one()
    assert str(row.id) == scan_id
    assert row.status in {"running", "completed", "failed"}

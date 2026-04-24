"""End-to-end: correlation_id survives api → celery → worker → scanner.

Proves the Week-4 observability contract in practice, not just in
theory.  POSTs a scan without an inbound ``X-Correlation-Id`` header,
captures the one the middleware generated, waits for the scan to
complete, then searches the api + worker containers' log streams for
that id in three distinct layers:

    1. at least one api log line  (the request handler)
    2. at least one worker log line (the celery task runner)
    3. at least one scanner log line (ZapPlugin emitting progress)

No mocks — real compose stack, real Redis broker, real ZAP (CLAUDE.md
§7).
"""

from __future__ import annotations

import subprocess  # noqa: S404 — controlled, list-form invocations
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_POLL_BUDGET_S = 300.0
_POLL_INTERVAL_S = 2.0


def _compose(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(_REPO_ROOT / "docker-compose.yml"),
        "-f",
        str(_REPO_ROOT / "target-lab" / "compose-targets.yml"),
        "-f",
        str(_REPO_ROOT / "tests" / "integration" / "docker-compose.test.yml"),
        "--profile",
        "dev",
        "--profile",
        "lab",
        *args,
    ]


def _poll_until_completed(client: httpx.Client, scan_id: str) -> dict[str, Any]:
    """Poll GET /api/v1/scans/{id} until terminal or timeout."""
    deadline = time.monotonic() + _POLL_BUDGET_S
    seen_statuses: list[str] = []
    body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        status_value = str(body.get("status", ""))
        if not seen_statuses or seen_statuses[-1] != status_value:
            seen_statuses.append(status_value)
        if status_value == "completed":
            return body
        if status_value == "failed":
            pytest.fail(f"scan transitioned to failed: {body}")
        time.sleep(_POLL_INTERVAL_S)
    pytest.fail(
        f"scan {scan_id} did not complete within {_POLL_BUDGET_S:.0f}s; "
        f"statuses seen: {seen_statuses}"
    )


def _logs_since(service: str, elapsed_s: float) -> str:
    """Tail a compose service's logs going back ``elapsed_s`` seconds."""
    # +5 s cushion — docker's --since is clock-wall, ours is monotonic.
    window = max(1, int(elapsed_s) + 5)
    result = subprocess.run(  # noqa: S603 — list-form, no user input
        _compose("logs", "--no-color", f"--since={window}s", service),
        cwd=str(_REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr


def test_correlation_id_propagates_api_to_celery_to_scanner(
    api_client: httpx.Client,
) -> None:
    """One id ties a POST request, a Celery task, and scanner progress together."""
    test_start = time.monotonic()

    # No inbound X-Correlation-Id — the middleware MUST generate one
    # and echo it back in the response header.
    response = api_client.post(
        "/api/v1/scans",
        json={"target_url": "http://juice-shop:3000/"},
    )
    assert response.status_code == 202, response.text
    correlation_id = response.headers.get("X-Correlation-Id")
    assert correlation_id is not None, "middleware did not echo X-Correlation-Id"
    # Must be a valid UUIDv4.
    uuid.UUID(correlation_id)

    scan_id = response.json()["id"]
    uuid.UUID(scan_id)

    # Wait for the scan to finish so the worker + scanner have had a
    # chance to emit logs under this correlation_id.
    _poll_until_completed(api_client, scan_id)

    # Now harvest api + worker logs and prove the id shows up in three
    # distinct layers.  Scanner lines are emitted by the worker process
    # (same container, same stream) — we disambiguate by the ``zap.*``
    # event prefix that only ZapPlugin / ZapClient use.
    elapsed = time.monotonic() - test_start
    api_logs = _logs_since("api", elapsed)
    worker_logs = _logs_since("worker", elapsed)

    assert correlation_id in api_logs, (
        f"correlation_id {correlation_id} not found in api logs — middleware did not "
        "bind it to structlog contextvars. First 500 chars:\n" + api_logs[:500]
    )
    assert correlation_id in worker_logs, (
        f"correlation_id {correlation_id} not found in worker logs — Celery task "
        "prerun signal did not bind headers to contextvars. First 500 chars:\n" + worker_logs[:500]
    )

    # structlog's JSONRenderer emits ``"event": "zap.run.start"`` or
    # ``"event":"zap.run.start"`` depending on dumper flags — match
    # both spacings defensively.
    scanner_markers = ('"event":"zap.', '"event": "zap.')
    scanner_lines = [
        line
        for line in worker_logs.splitlines()
        if correlation_id in line and any(marker in line for marker in scanner_markers)
    ]
    assert scanner_lines, (
        f"no ZapPlugin log line carried correlation_id {correlation_id} — scanner is "
        "still on stdlib logging (no structlog contextvar merge). Worker log "
        "excerpt:\n" + worker_logs[-1000:]
    )

"""End-to-end: ``/api/v1/ready`` returns 503 when a dep is unreachable.

Proves the Week-4 readiness contract: orchestrator probes see an
honest signal — 200 only when Postgres + Redis are both reachable,
503 otherwise with per-dep status in the body.

The test pauses Redis (``docker compose pause redis``) rather than
stopping it: pause is instant, restartable, and doesn't trigger a
Compose restart of the service.  The ``finally`` block unpauses
unconditionally so a failed assertion doesn't leave a ticking dep
bomb for the next test in the session.
"""

from __future__ import annotations

import subprocess  # noqa: S404 — controlled, list-form invocations
import time
from pathlib import Path

import httpx
import pytest

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]

# Upper bound on how long the /ready probe is allowed to notice that
# redis has been paused.  The endpoint's own per-check timeout is 1 s,
# so 5 s is plenty of headroom for docker's pause to take effect plus
# a poll cycle.
_READY_FLIP_TIMEOUT_S = 5.0


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


def _run(cmd: list[str]) -> None:
    subprocess.run(  # noqa: S603 — list-form, no user input
        cmd,
        cwd=str(_REPO_ROOT),
        check=True,
        capture_output=True,
        text=True,
    )


def _get_ready(client: httpx.Client) -> httpx.Response:
    return client.get("/api/v1/ready")


def _poll_until_status(
    client: httpx.Client,
    expected: int,
    *,
    timeout_s: float,
) -> httpx.Response:
    """Poll /ready until it returns ``expected`` or the timeout elapses."""
    deadline = time.monotonic() + timeout_s
    last = _get_ready(client)
    while time.monotonic() < deadline:
        last = _get_ready(client)
        if last.status_code == expected:
            return last
        time.sleep(0.25)
    return last


def test_ready_flips_to_503_when_redis_paused(api_client: httpx.Client) -> None:
    """Pause redis, watch /ready go 503, unpause, watch it return."""
    initial = _get_ready(api_client)
    assert initial.status_code == 200, initial.text
    assert initial.json() == {
        "status": "ready",
        "checks": {"db": "ok", "redis": "ok"},
    }

    try:
        _run(_compose("pause", "redis"))
        not_ready = _poll_until_status(api_client, 503, timeout_s=_READY_FLIP_TIMEOUT_S)
        assert not_ready.status_code == 503, (
            f"expected 503 once redis was paused, got {not_ready.status_code}: " f"{not_ready.text}"
        )
        body = not_ready.json()
        assert body["status"] == "not_ready", body
        assert body["checks"]["db"] == "ok", body
        assert body["checks"]["redis"].startswith("down"), body
    finally:
        # Must always unpause — a failed assertion above must not leak
        # a paused redis into the next test or the next session.
        try:
            _run(_compose("unpause", "redis"))
        except subprocess.CalledProcessError:
            # Already unpaused (idempotent rescue).  Better to swallow
            # than to mask the original failure.
            pytest.skip  # noqa: B018 — explicit-no-op intent

    recovered = _poll_until_status(api_client, 200, timeout_s=_READY_FLIP_TIMEOUT_S)
    assert recovered.status_code == 200, (
        f"/ready did not return to 200 after unpausing redis: "
        f"{recovered.status_code} {recovered.text}"
    )
    assert recovered.json()["checks"]["redis"] == "ok"

"""Shared pytest fixtures for the integration test suite.

CLAUDE.md §7: integration tests hit real Postgres, real Redis, real
Celery, and — from Week 3 on — a real ZAP container scanning real
Juice Shop.  No mocks.

The session-scoped fixture brings up the full stack via:

    docker compose \
      -f docker-compose.yml \
      -f target-lab/compose-targets.yml \
      -f tests/integration/docker-compose.test.yml \
      --profile dev --profile lab \
      up -d --build

then waits for the API (``/api/v1/health``) and ZAP (container health)
before yielding.  Set ``ZYNKSEC_TEST_KEEP_STACK=1`` to skip the
compose up/down — useful locally and required in CI (the workflow
manages the stack itself).
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404 — controlled, list-form invocations only
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
TEST_OVERLAY: Path = REPO_ROOT / "tests" / "integration" / "docker-compose.test.yml"
TARGET_LAB: Path = REPO_ROOT / "target-lab" / "compose-targets.yml"

API_BASE_URL = "http://localhost:8000"
# The test overlay publishes Postgres on host port 55432.
TEST_DATABASE_URL = "postgresql+psycopg://zynksec:changeme-local-only@localhost:55432/zynksec"

_KEEP_STACK = os.environ.get("ZYNKSEC_TEST_KEEP_STACK") == "1"

# Cold-boot budgets tuned for a fresh runner:
#  - api:       ~60 s (uvicorn starts fast after DB/broker are healthy)
#  - zap:       ~120 s (ZAP's JVM + DB + plugin loading is slow)
_API_READY_TIMEOUT_S = 90
_ZAP_READY_TIMEOUT_S = 180


def _compose(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(REPO_ROOT / "docker-compose.yml"),
        "-f",
        str(TARGET_LAB),
        "-f",
        str(TEST_OVERLAY),
        "--profile",
        "dev",
        "--profile",
        "lab",
        *args,
    ]


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Subprocess wrapper — list-form only (CLAUDE.md §6, no shell=True)."""
    return subprocess.run(  # noqa: S603 — list-form, no user input
        cmd,
        cwd=str(REPO_ROOT),
        check=check,
        capture_output=True,
        text=True,
    )


def _wait_for_api(timeout_s: int) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = "unknown"
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{API_BASE_URL}/api/v1/health", timeout=2.0)
        except httpx.HTTPError as exc:
            last_err = f"{type(exc).__name__}: {exc}"
        else:
            if response.status_code == 200:
                return
            last_err = f"status {response.status_code}"
        time.sleep(1)
    raise RuntimeError(f"API never became healthy within {timeout_s}s: {last_err}")


def _wait_for_container_healthy(container: str, timeout_s: int) -> None:
    """Poll ``docker inspect`` until the container reports 'healthy'."""
    deadline = time.monotonic() + timeout_s
    last_status = "unknown"
    while time.monotonic() < deadline:
        result = _run(
            [
                "docker",
                "inspect",
                "--format={{.State.Health.Status}}",
                container,
            ],
            check=False,
        )
        last_status = result.stdout.strip() or last_status
        if last_status == "healthy":
            return
        time.sleep(2)
    raise RuntimeError(
        f"container {container} not healthy within {timeout_s}s (last={last_status})"
    )


@pytest.fixture(scope="session", autouse=True)
def _compose_up() -> Iterator[None]:
    """Bring up the full stack (api + worker1/worker2 + zap1/zap2 +
    juice-shop) for the whole test session.  Leading underscore
    satisfies PT004.  Phase 2 Sprint 3 introduced the multi-instance
    ZAP topology — each worker pins to one ZAP daemon and consumes
    from one Celery queue (zap_q_1 / zap_q_2).
    """

    if not _KEEP_STACK:
        _run(
            _compose(
                "up",
                "-d",
                "--build",
                "postgres",
                "redis",
                "worker1",
                "worker2",
                "api",
                "mailpit",
                "zap1",
                "zap2",
                "juice-shop",
            )
        )

    try:
        _wait_for_api(timeout_s=_API_READY_TIMEOUT_S)
        _wait_for_container_healthy("zynksec-zap1", timeout_s=_ZAP_READY_TIMEOUT_S)
        _wait_for_container_healthy("zynksec-zap2", timeout_s=_ZAP_READY_TIMEOUT_S)
        _wait_for_container_healthy("zynksec-juice-shop", timeout_s=_ZAP_READY_TIMEOUT_S)
        # Apply migrations (idempotent — CI also runs this).
        _run(
            _compose(
                "exec",
                "-T",
                "api",
                "alembic",
                "-c",
                "apps/api/alembic.ini",
                "upgrade",
                "head",
            )
        )
        yield
    finally:
        if not _KEEP_STACK:
            _run(_compose("down", "-v"), check=False)


@pytest.fixture
def api_client() -> Iterator[httpx.Client]:
    """Per-test HTTP client against the API."""
    with httpx.Client(base_url=API_BASE_URL, timeout=10.0) as client:
        yield client


@pytest.fixture
def db_session() -> Iterator[Session]:
    """Per-test SQLAlchemy session against the real Postgres."""
    engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()

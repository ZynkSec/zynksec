"""Shared pytest fixtures for the integration test suite.

CLAUDE.md §7: integration tests must hit real services — no mocks on
Postgres, Redis, or Celery.  These fixtures bring up the real compose
stack once per pytest session, apply Alembic migrations, and expose an
HTTP client + a SQLAlchemy session to tests.

Expected runtime: ~30 seconds cold, ~5 seconds warm (compose services
persist between local test runs via --keep-stack).
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

API_BASE_URL = "http://localhost:8000"
# The test overlay publishes Postgres on host port 55432; see
# ``docker-compose.test.yml`` for the rationale.
TEST_DATABASE_URL = "postgresql+psycopg://zynksec:changeme-local-only@localhost:55432/zynksec"

# Set to "1" in CI (or locally) to skip compose up/down — useful when
# developers bring the stack up themselves and iterate on tests.
_KEEP_STACK = os.environ.get("ZYNKSEC_TEST_KEEP_STACK") == "1"


def _compose(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(REPO_ROOT / "docker-compose.yml"),
        "-f",
        str(TEST_OVERLAY),
        "--profile",
        "dev",
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


def _wait_for_api(timeout_s: int = 60) -> None:
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


@pytest.fixture(scope="session", autouse=True)
def _compose_up() -> Iterator[None]:
    """Bring up the full Week-2 stack for the whole test session.

    Leading underscore satisfies pytest-style PT004 — this fixture is
    autouse and yields nothing useful, it just manages the stack.
    """

    if not _KEEP_STACK:
        _run(
            _compose(
                "up",
                "-d",
                "postgres",
                "redis",
                "worker",
                "api",
                "mailpit",
            )
        )

    try:
        _wait_for_api(timeout_s=90)
        # Apply migrations against the now-healthy Postgres.  Idempotent —
        # running twice (CI runs it once already, then we run it again) is
        # fine because Alembic records applied revisions.
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
    """Per-test SQLAlchemy session against the real Postgres.

    The engine is disposed at fixture teardown so we don't leak
    connections between tests.
    """
    engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()

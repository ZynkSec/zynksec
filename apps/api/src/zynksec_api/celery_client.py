"""Celery client used by the API to enqueue scan tasks.

The API only *sends* tasks — it never waits for results or reads
the result backend.  Broker URL comes from :class:`Settings`.

Per CLAUDE.md §5: task *arguments* are primitives only (string UUIDs,
ints, dicts of primitives).  The worker re-fetches the full object
from the DB.  Week-4 observability adds correlation tracing via
Celery's first-class ``headers`` channel (which is separate from args
— metadata, not payload) so a request's correlation_id survives the
Redis-broker hop into the worker process.
"""

from __future__ import annotations

from functools import lru_cache

import structlog
from celery import Celery

from zynksec_api.config import get_settings


@lru_cache(maxsize=1)
def get_celery_client() -> Celery:
    """Build the Celery client once per process."""

    settings = get_settings()
    app = Celery("zynksec-api-client", broker=settings.celery_broker_url)
    # Match the worker's serialization/queue config so tasks route
    # and decode correctly.
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        task_default_queue="scans",
    )
    return app


def _current_correlation_id() -> str | None:
    """Pull the correlation_id bound by CorrelationIdMiddleware, if any."""
    bound = structlog.contextvars.get_contextvars()
    if isinstance(bound, dict):
        value = bound.get("correlation_id")
        return str(value) if value is not None else None
    return None


def enqueue_scan(scan_id: str) -> None:
    """Send the ``scan.run`` task with a string UUID argument.

    Attaches the current request's ``correlation_id`` to the task's
    Celery headers (docs/04 Week-4 observability) so the worker's
    ``task_prerun`` signal handler can bind it to structlog's
    contextvars before user code runs.
    """
    headers: dict[str, str] = {}
    correlation_id = _current_correlation_id()
    if correlation_id is not None:
        headers["correlation_id"] = correlation_id
    get_celery_client().send_task(
        "scan.run",
        args=[scan_id],
        queue="scans",
        headers=headers,
    )

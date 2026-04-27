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


def enqueue_scan(scan_id: str, scan_profile: str) -> None:
    """Send the ``scan.run`` task with primitive arguments.

    ``scan_profile`` is the enum's wire form (``"PASSIVE"``, ...) — the
    worker reconstructs the :class:`ScanProfile` inside the task body
    so the Celery payload stays primitive (CLAUDE.md §5).

    Also passes the current request's ``correlation_id`` as a kwarg
    (docs/04 Week-4 observability).  Celery's ``headers=`` channel
    looked like the cleaner home for it architecturally, but custom
    headers don't round-trip reliably through the Redis broker under
    task protocol v2; kwargs do, and keep the wiring straightforward.
    """
    kwargs: dict[str, str] = {"scan_profile": scan_profile}
    correlation_id = _current_correlation_id()
    if correlation_id is not None:
        kwargs["correlation_id"] = correlation_id
    get_celery_client().send_task(
        "scan.run",
        args=[scan_id],
        kwargs=kwargs,
        queue="scans",
    )

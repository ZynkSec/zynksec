"""Celery client used by the API to enqueue scan tasks.

The API only *sends* tasks — it never waits for results or reads
the result backend.  Broker URL comes from :class:`Settings`.

Per CLAUDE.md §5: task *arguments* are primitives only (string UUIDs,
ints, dicts of primitives).  The worker re-fetches the full object
from the DB.  Week-4 observability adds correlation tracing via
Celery's first-class ``headers`` channel (which is separate from args
— metadata, not payload) so a request's correlation_id survives the
Redis-broker hop into the worker process.

Phase 2 Sprint 3: queue routing is now per-call.  Each ZAP+worker
pair owns its own queue (``zap_q_1`` / ``zap_q_2`` / ...) and the
caller decides which queue a scan lands on.  ScanGroup children are
dispatched round-robin across queues; legacy single-scan POSTs use
a rotation cursor.  No more ``scan_group.process`` umbrella task —
each child Scan is its own ``scan.run`` and rolls up the parent
group atomically when it terminates.
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
    # Match the worker's serialization config so payloads decode
    # correctly.  ``task_default_queue`` is intentionally NOT set —
    # every send_task call below specifies an explicit per-pair queue
    # so a missing default is the right safety: a regression that
    # forgets to route would surface as a Celery error rather than
    # silently land on a queue no worker consumes from.
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
    )
    return app


def _current_correlation_id() -> str | None:
    """Pull the correlation_id bound by CorrelationIdMiddleware, if any."""
    bound = structlog.contextvars.get_contextvars()
    if isinstance(bound, dict):
        value = bound.get("correlation_id")
        return str(value) if value is not None else None
    return None


def enqueue_scan_to_queue(scan_id: str, scan_profile: str, queue: str) -> None:
    """Send the ``scan.run`` task for ``scan_id`` to a specific queue.

    ``queue`` selects which ZAP+worker pair runs this scan — one of
    ``zap_q_1`` / ``zap_q_2`` / ... up to ``ZAP_INSTANCE_COUNT``.
    The router computes the queue name from
    :func:`zynksec_schema.zap_queue_for_index` (round-robin for
    ScanGroup children, rotation cursor for legacy single-scan
    POSTs) and persists it on the Scan row's ``assigned_queue``
    field for auditing.

    ``scan_profile`` is the enum's wire form (``"PASSIVE"``, ...) —
    the worker reconstructs the :class:`ScanProfile` inside the
    task body so the Celery payload stays primitive (CLAUDE.md §5).

    ``correlation_id`` propagates as a kwarg, same path as before:
    Celery's ``headers=`` channel doesn't round-trip reliably through
    Redis under task protocol v2; kwargs do, and keep the wiring
    straightforward.  The worker's ``task_prerun`` signal binds it
    to structlog contextvars on receipt.
    """
    kwargs: dict[str, str] = {"scan_profile": scan_profile}
    correlation_id = _current_correlation_id()
    if correlation_id is not None:
        kwargs["correlation_id"] = correlation_id
    get_celery_client().send_task(
        "scan.run",
        args=[scan_id],
        kwargs=kwargs,
        queue=queue,
    )

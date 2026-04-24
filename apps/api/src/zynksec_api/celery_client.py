"""Celery client used by the API to enqueue scan tasks.

The API only *sends* tasks — it never waits for results or reads
the result backend.  Broker URL comes from :class:`Settings`.

Per CLAUDE.md §5: task arguments are primitives only (string UUIDs,
ints, dicts of primitives).  The worker re-fetches the full object
from the DB.
"""

from __future__ import annotations

from functools import lru_cache

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


def enqueue_scan(scan_id: str) -> None:
    """Send the ``scan.run`` task with a string UUID argument."""
    get_celery_client().send_task("scan.run", args=[scan_id], queue="scans")

"""Celery app — the broker/backend config plus shared structured logging.

CLAUDE.md §5: task arguments are primitives only.  The worker
re-fetches rich objects from the DB.  Queue routing is explicit
(``scans``) so Week-3 scanner-class-specific queues slot in without
changing callers.

Week-4 observability: ``task_prerun`` binds the API-supplied
``correlation_id`` header to structlog's contextvars so every log
line the worker + the scanner plugin emit during the task carries
the same id the API emitted for the originating request.  Headers
are Celery's first-class metadata channel — separate from task
``args`` — so the primitives-only arg contract is unchanged.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from celery import Celery
from celery.signals import task_postrun, task_prerun

from zynksec_worker.config import get_settings

_settings = get_settings()

celery_app = Celery(
    "zynksec",
    broker=_settings.celery_broker_url,
    backend=_settings.celery_result_backend,
)

celery_app.conf.update(
    task_acks_late=True,
    task_serializer="json",
    accept_content=["json"],
    task_default_queue="scans",
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
)

# Discover tasks in zynksec_worker.tasks.
celery_app.autodiscover_tasks(["zynksec_worker"])


def _configure_logging() -> None:
    """JSON structured logging — mirrors apps/api/logging_config.py.

    Duplicated for Phase 0 (docs/04 §0.14 plans to promote the shared
    config into packages/shared-schema; not in this session's scope).
    Honours ``ZYNKSEC_LOG_FORMAT=console`` for local dev.
    """

    level = getattr(logging, _settings.zynksec_log_level.upper(), logging.INFO)

    renderer: structlog.types.Processor
    if _settings.zynksec_log_format == "console":
        renderer = structlog.dev.ConsoleRenderer(colors=False)
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
        force=True,
    )


_configure_logging()


@task_prerun.connect  # type: ignore[misc]
def _bind_correlation_id(
    task_id: str | None = None,
    task: Any = None,
    *args: Any,
    **kwargs: Any,
) -> None:
    """Bind the API-supplied correlation_id to structlog contextvars.

    Celery's ``task.request.headers`` is where ``apps/api``'s
    ``enqueue_scan`` stashes the correlation_id.  If the task arrived
    without one (e.g. replay from a dead-letter queue), we generate
    nothing — downstream logs will simply omit the field rather than
    correlate to a misleading id.
    """
    del args, kwargs
    correlation_id: str | None = None
    if task is not None:
        headers = getattr(task.request, "headers", None) or {}
        if isinstance(headers, dict):
            raw = headers.get("correlation_id")
            if raw is not None:
                correlation_id = str(raw)
    structlog.contextvars.clear_contextvars()
    bindings: dict[str, Any] = {
        "celery_task_id": task_id,
        "celery_task_name": getattr(task, "name", None) if task is not None else None,
    }
    if correlation_id is not None:
        bindings["correlation_id"] = correlation_id
    structlog.contextvars.bind_contextvars(**bindings)


@task_postrun.connect  # type: ignore[misc]
def _clear_correlation_id(*args: Any, **kwargs: Any) -> None:
    """Clear contextvars after each task so IDs don't leak between tasks."""
    del args, kwargs
    structlog.contextvars.clear_contextvars()

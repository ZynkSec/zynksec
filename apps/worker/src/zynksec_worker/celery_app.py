"""Celery app — the broker/backend config plus shared structured logging.

CLAUDE.md §5: task arguments are primitives only.  The worker
re-fetches rich objects from the DB.  Queue routing is explicit
(``scans``) so Week-3 scanner-class-specific queues slot in without
changing callers.
"""

from __future__ import annotations

import logging
import sys

import structlog
from celery import Celery

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
    """

    level = getattr(logging, _settings.zynksec_log_level.upper(), logging.INFO)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
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

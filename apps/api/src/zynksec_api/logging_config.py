"""Structured logging configuration.

Emits JSON on stdout so container logs flow into Loki / `docker logs`
without further processing (docs/04 §0.14).  This module will be
promoted into ``packages/shared-schema`` in Week 2 so the worker
consumes the identical config.
"""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(log_level: str = "INFO") -> None:
    """Install structlog as the stdlib logging processor.

    Idempotent — safe to call more than once (e.g. in tests and in
    the FastAPI lifespan hook).
    """

    level = getattr(logging, log_level.upper(), logging.INFO)

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logs (uvicorn, etc.) through the same JSON pipeline.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
        force=True,
    )

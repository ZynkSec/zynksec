"""Structured logging configuration.

Emits JSON on stdout by default so container logs flow into Loki /
`docker logs | jq` without further processing (docs/04 §0.14).  Dev
opt-in: ``ZYNKSEC_LOG_FORMAT=console`` switches to structlog's coloured
console renderer for local debugging.

The worker's Celery module re-implements the same pipeline with its
own bootstrap order; keep the two in sync until they're promoted into
``packages/shared-schema`` (out of Week-4 scope).
"""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """Install structlog as the stdlib logging processor.

    Idempotent — safe to call more than once (e.g. in tests and in
    the FastAPI lifespan hook).  ``log_format="console"`` renders
    human-readable lines; anything else (default ``"json"``) renders
    JSON-per-line.
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

    renderer: structlog.types.Processor
    if log_format == "console":
        renderer = structlog.dev.ConsoleRenderer(colors=False)
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logs (uvicorn, etc.) through the same pipeline.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
        force=True,
    )

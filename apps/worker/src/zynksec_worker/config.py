"""Worker configuration.

Duplicates the Celery + DB + log-level subset of
``apps/api/src/zynksec_api/config.py``.  Chosen over a cross-app
import so ``apps/worker`` stays install-free of ``apps/api``.

TODO(phase-1): promote the shared fields into ``packages/config`` —
see ``docs/decisions/`` once the folder exists.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkerSettings(BaseSettings):
    """Minimum config the worker needs — read from env / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        frozen=True,
        extra="ignore",
    )

    zynksec_log_level: str = "INFO"
    zynksec_log_format: Literal["json", "console"] = "json"
    database_url: str = "postgresql+psycopg://zynksec:changeme-local-only@postgres:5432/zynksec"
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"
    # ZAP — the worker's only external HTTP dep in Phase 0.
    zap_api_url: str = "http://zap:8090"
    zap_api_key: str = "changeme-local-only"


@lru_cache(maxsize=1)
def get_settings() -> WorkerSettings:
    """Cached factory — the whole worker process shares one instance."""
    return WorkerSettings()

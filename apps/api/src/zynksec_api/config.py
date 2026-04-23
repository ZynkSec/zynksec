"""Application settings.

Single source of truth for every environment variable the API (and
the future worker) consumes.  Backed by ``pydantic-settings`` so
values are parsed, type-checked, and immutable once constructed.

CLAUDE.md §5: the worker MUST import from this module instead of
re-parsing env itself, so drift is impossible.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed, frozen configuration object.

    Reads from process environment; `.env` is loaded in dev and is
    gitignored.  `.env.example` at the repo root documents every
    variable accepted here (docs/04 §0.8).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        frozen=True,
        extra="ignore",
    )

    # ---------- Core ----------
    zynksec_env: Literal["dev", "test", "prod"] = "dev"
    zynksec_log_level: str = "INFO"
    # Defaults to loopback so an accidental launch outside Docker does
    # not bind to every interface (Ruff S104 / Bandit B104).  Compose
    # overrides via ZYNKSEC_API_HOST.
    zynksec_api_host: str = "127.0.0.1"
    zynksec_api_port: int = 8000

    # ---------- PostgreSQL ----------
    postgres_user: str = "zynksec"
    postgres_password: SecretStr = SecretStr("changeme-local-only")
    postgres_db: str = "zynksec"
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    database_url: str = Field(
        default="postgresql+psycopg://zynksec:changeme-local-only@postgres:5432/zynksec",
    )

    # ---------- Redis / Celery ----------
    redis_url: str = "redis://redis:6379/0"
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"

    # ---------- ZAP ----------
    zap_api_url: str = "http://zap:8090"
    zap_api_key: SecretStr = SecretStr("changeme-local-only")
    zap_default_profile: str = "baseline"

    # ---------- Mailpit (dev only) ----------
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_from: str = "zynksec@localhost"

    # ---------- GlitchTip (optional) ----------
    glitchtip_dsn: str = ""

    # ---------- App ----------
    app_secret_key: SecretStr = SecretStr("please-generate-a-32-byte-base64-value")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """FastAPI dependency — cached so every request reuses the same
    parsed Settings (CLAUDE.md §3 — dependency injection).
    """
    return Settings()

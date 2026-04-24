"""Zynksec Celery worker."""

# Initialise Sentry BEFORE any other app module imports so uncaught
# exceptions during boot (config parsing, Celery app construction,
# task autodiscovery) still get captured.  No-ops when SENTRY_DSN is
# empty (Week-4 commit 4).
from zynksec_worker.observability import init_sentry as _init_sentry

_init_sentry("worker")

__version__ = "0.0.0"

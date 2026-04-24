"""Zynksec FastAPI service."""

# Initialise Sentry BEFORE any other app module imports so uncaught
# exceptions during boot (config parsing, DB engine construction,
# router wiring) still get captured.  No-ops when SENTRY_DSN is empty
# (Week-4 commit 4).
from zynksec_api.observability import init_sentry as _init_sentry

_init_sentry("api")

__version__ = "0.0.0"

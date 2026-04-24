"""Factory that wires a :class:`ZapPlugin` from worker settings.

The Celery task imports ``build_zap_plugin`` and then immediately
erases the concrete type by assigning the result to a variable typed
as :class:`ScannerPlugin`.  That keeps the Dependency-Inversion rule
honoured (CLAUDE.md §3) — no other module in ``apps/worker`` names
``ZapPlugin``.
"""

from __future__ import annotations

from zynksec_scanners.zap import ZapClient, ZapPlugin

from zynksec_worker.config import WorkerSettings


def build_zap_plugin(settings: WorkerSettings) -> ZapPlugin:
    """Build a :class:`ZapPlugin` from worker settings.

    The returned plugin owns the underlying :class:`ZapClient`.  The
    task calls ``teardown`` at the end of the scan; the client is
    closed implicitly when the plugin goes out of scope (Phase 1 adds
    an explicit ``close`` hook if we start reusing clients across tasks).
    """
    client = ZapClient(
        base_url=settings.zap_api_url,
        api_key=settings.zap_api_key,
    )
    return ZapPlugin(client=client)

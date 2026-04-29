"""Celery queue naming for the multi-instance ZAP fan-out.

Phase 2 Sprint 3 introduced N parallel ZAP+worker pairs.  Each worker
process pins to ONE ZAP daemon and consumes from ONE Celery queue;
the API dispatches each scan onto a specific per-pair queue
(round-robin for ScanGroup children, rotation cursor for the legacy
single-scan POST path).  The mapping from instance index to queue
name lives here so the API and the worker never disagree.

The function is the single source of truth — both sides import it.
``i`` is 1-based to match the compose service names (``zap1``,
``worker1``) and the ``WORKER_ZAP_INDEX`` env var the worker reads.
"""

from __future__ import annotations


def zap_queue_for_index(i: int) -> str:
    """Return the Celery queue name for ZAP instance ``i`` (1-based).

    >>> zap_queue_for_index(1)
    'zap_q_1'
    >>> zap_queue_for_index(2)
    'zap_q_2'
    """
    if i < 1:
        raise ValueError(f"zap instance index is 1-based; got {i}")
    return f"zap_q_{i}"

"""Celery queue naming for the multi-scanner-family fan-out.

Phase 2 Sprint 3 introduced N parallel ZAP+worker pairs.  Each worker
process pins to ONE ZAP daemon and consumes from ONE per-pair queue;
the API dispatches each scan onto a specific queue (round-robin for
ScanGroup children, rotation cursor for the legacy single-scan POST
path).

Phase 3 Sprint 1 adds a second scanner family (gitleaks / repo
scanners) on its own queue (:data:`CODE_QUEUE`).  Code workers don't
need round-robin because they have no daemon to coordinate against
— a single queue served by however many code-worker replicas the
operator runs.

These functions are the single source of truth — API + worker
both import them.  ``i`` is 1-based on :func:`zap_queue_for_index`
to match the compose service names (``zap1``, ``worker1``) and the
``WORKER_ZAP_INDEX`` env var the worker reads.
"""

from __future__ import annotations

#: Celery queue for the repo-scanner family (gitleaks; Phase 3
#: Sprint 2+: semgrep, trivy, OSV, syft, grype).  One queue served
#: by the ``code-worker`` service in compose; no round-robin
#: required.
CODE_QUEUE: str = "code_q"


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


def code_queue() -> str:
    """Return the Celery queue name for the repo-scanner family.

    Trivial wrapper around :data:`CODE_QUEUE` so callers don't
    spread the literal across the codebase — if a future sprint
    adds per-scanner-family queues (``gitleaks_q``, ``semgrep_q``,
    ...), changing this function updates every dispatcher in one
    edit.

    >>> code_queue()
    'code_q'
    """
    return CODE_QUEUE

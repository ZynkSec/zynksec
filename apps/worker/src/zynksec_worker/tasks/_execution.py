"""Shared scan-execution helper used by ``scan.run``.

Phase 2 Sprint 2: lifted out of ``tasks/scan.py`` so multi-target
groups can iterate children through the same code path the
single-scan task uses.

Phase 2 Sprint 3: the ``scan_group.process`` task is gone — each
child of a ScanGroup is now its own ``scan.run`` task on a per-pair
Celery queue.  ``execute_scan`` performs the group rollup itself
(``mark_running_if_queued`` on entry, ``mark_terminal_if_all_children_done``
after the child's terminal status commits) so no coordinator task
is needed.

The helper is sync + blocking (matches Celery's prefork-pool model)
and returns ``True`` on completion, ``False`` on failure.  The
``scan.run`` caller propagates the failure to Celery so retry / DLQ
wiring can react.
"""

from __future__ import annotations

import uuid
from functools import lru_cache

import structlog
from sqlalchemy.orm import Session, sessionmaker
from zynksec_db import Finding as FindingRow
from zynksec_db import (
    FindingRepository,
    Scan,
    ScanGroupRepository,
    ScanRepository,
    engine_from_url,
    make_session_factory,
)
from zynksec_scanners import ScannerPlugin, ScanTarget
from zynksec_scanners.types import TargetKind
from zynksec_schema import Finding, ScanProfile, zap_queue_for_index

from zynksec_worker.config import get_settings
from zynksec_worker.runners import build_zap_plugin

_log = structlog.get_logger(__name__)

_scan_repo = ScanRepository()
_finding_repo = FindingRepository()
_group_repo = ScanGroupRepository()


@lru_cache(maxsize=1)
def session_factory() -> sessionmaker[Session]:
    """Cache one engine + session factory per worker process."""
    engine = engine_from_url(get_settings().database_url)
    return make_session_factory(engine)


def _load_target_and_group_id(
    factory: sessionmaker[Session],
    scan_uuid: uuid.UUID,
    scan_profile: ScanProfile,
) -> tuple[ScanTarget, uuid.UUID | None]:
    """Load the Scan row and construct a :class:`ScanTarget` for the plugin.

    When the Scan links to a persistent :class:`zynksec_db.Target`
    (Phase 2 Sprint 1+), the target's ``kind`` flows through to the
    runtime ``ScanTarget`` so the plugin's ``supports()`` gate can
    reject unsupported kinds.  Legacy ``target_url``-only scans
    (``scan.target_id IS NULL``) keep the historical ``"web_app"``
    default — that path has no kind information to thread through.

    Also returns the parent ``scan_group_id`` (or ``None`` for legacy
    single-scan POSTs) so the caller can drive group-rollup hooks
    without re-querying the Scan row.
    """
    with factory() as session:
        scan = session.get(Scan, scan_uuid)
        if scan is None:
            raise RuntimeError(f"Scan {scan_uuid} vanished between enqueue and dispatch")
        target_row = scan.target  # eager-loaded via SQLAlchemy relationship
        kind: TargetKind = target_row.kind if target_row is not None else "web_app"  # type: ignore[assignment]
        target = ScanTarget(
            kind=kind,
            url=scan.target_url,
            project_id=scan.project_id,
            scan_id=scan.id,
            scan_profile=scan_profile,
        )
        return target, scan.scan_group_id


def _finding_to_row(finding: Finding) -> FindingRow:
    """Convert a Pydantic :class:`Finding` to the SQLAlchemy row shape."""
    return FindingRow(
        id=finding.id,
        scan_id=finding.scan_id,
        fingerprint=finding.fingerprint,
        schema_version=finding.schema_version,
        taxonomy_zynksec_id=finding.taxonomy.zynksec_id,
        cwe=finding.taxonomy.cwe,
        owasp_top10=finding.taxonomy.owasp_top10,
        severity_level=finding.severity.level,
        severity_confidence=finding.severity.confidence,
        location_url=finding.location.url,
        location_method=finding.location.method,
        location_parameter=finding.location.parameter,
        evidence_engine=finding.evidence.engine,
        evidence_rule_id=finding.evidence.rule_id,
        evidence_request=finding.evidence.request,
        evidence_response_excerpt=finding.evidence.response_excerpt,
        lifecycle_status=finding.lifecycle.status,
        first_seen_at=finding.lifecycle.first_seen_at,
        last_seen_at=finding.lifecycle.last_seen_at,
    )


def _mark(
    factory: sessionmaker[Session],
    action: str,
    scan_uuid: uuid.UUID,
    *,
    reason: str | None = None,
) -> None:
    """Tiny helper so status-transition boilerplate doesn't dominate the task."""
    with factory() as session:
        try:
            if action == "running":
                _scan_repo.mark_running(session, scan_uuid)
            elif action == "completed":
                _scan_repo.mark_completed(session, scan_uuid)
            elif action == "failed":
                _scan_repo.mark_failed(session, scan_uuid, reason=reason or "")
            else:
                raise AssertionError(f"unknown status transition: {action}")
            session.commit()
        except Exception:
            session.rollback()
            raise


def _flip_group_running(
    factory: sessionmaker[Session],
    scan_group_uuid: uuid.UUID,
) -> bool:
    """Idempotent ``queued -> running`` for the parent ScanGroup.

    Called by the first child to enter ``execute_scan``; subsequent
    children no-op cleanly because :meth:`mark_running_if_queued`
    only updates rows whose status is currently ``queued``.
    """
    with factory() as session:
        try:
            flipped = _group_repo.mark_running_if_queued(session, scan_group_uuid)
            session.commit()
            return flipped
        except Exception:
            session.rollback()
            raise


def _rollup_group_if_terminal(
    factory: sessionmaker[Session],
    scan_group_uuid: uuid.UUID,
) -> str | None:
    """Best-effort group-terminal promotion (last-child-wins).

    Returns the terminal status the group settled at, or ``None`` if
    the group still has non-terminal children (this child is not the
    last) or was already terminal.  Errors are caught and logged so
    a transient DB blip after the child's terminal mark doesn't
    leave the child failed AND the group stuck — the next child to
    finish will retry the rollup.
    """
    with factory() as session:
        try:
            terminal = _group_repo.mark_terminal_if_all_children_done(session, scan_group_uuid)
            session.commit()
            return terminal
        except Exception as exc:
            session.rollback()
            _log.exception(
                "scan.run.group_rollup_failed",
                scan_group_id=str(scan_group_uuid),
                error=str(exc),
            )
            return None


def execute_scan(scan_uuid: uuid.UUID, profile: ScanProfile) -> bool:
    """Run one scan against one target end-to-end.

    Returns ``True`` if the scan completed (with or without
    findings), ``False`` if it failed during the plugin's
    prepare/run/normalize/persist phase (DB row marked ``failed``
    and the failure logged via ``scan.run.failed``).

    May raise from the early-boundary calls — ``_mark(factory,
    "running", ...)``, ``_load_target_and_group_id(...)``, or
    ``build_zap_plugin(settings)`` — when DB connectivity or
    settings load fail before the inner ``try/except`` is reached.
    ``scan.run`` lets the exception propagate so Celery records a
    failed task (retry / DLQ wiring lives there).

    Phase 2 Sprint 3 group-rollup: if the Scan belongs to a
    ScanGroup, the helper drives the parent's status transitions
    inline — flips the group from ``queued`` to ``running`` on
    entry (idempotent; only the first child wins the flip) and
    promotes the group to its terminal status after the child's
    own status commits (atomic last-child-wins via
    ``mark_terminal_if_all_children_done``).  No coordinator task
    is needed; per-child Celery tasks roll up the group on their own.

    Structlog bindings: ``scan_id`` always; ``scan_group_id`` when
    set; ``zap_index`` + ``assigned_queue`` from worker config so
    every log line carries the worker/ZAP pair the scan executed
    on (debugging cross-pair regressions in Sprint 3+).  All
    bindings are cleared in ``finally`` so the next task on this
    worker doesn't inherit stale ids.
    """
    scan_id_str = str(scan_uuid)
    factory = session_factory()
    settings = get_settings()

    # Worker-pair bindings stay constant for the lifetime of this
    # process (the worker is pinned to one ZAP / one queue) but
    # binding them per-task makes the JSON log lines self-contained
    # — every entry advertises which pair produced it without the
    # reader needing to correlate with worker startup logs.
    zap_index = settings.worker_zap_index
    assigned_queue = zap_queue_for_index(zap_index)

    structlog.contextvars.bind_contextvars(
        scan_id=scan_id_str,
        zap_index=zap_index,
        assigned_queue=assigned_queue,
    )
    bound_group_id = False
    try:
        _log.info("scan.run.start", scan_id=scan_id_str, scan_profile=profile.value)

        target, scan_group_uuid = _load_target_and_group_id(factory, scan_uuid, profile)
        if scan_group_uuid is not None:
            structlog.contextvars.bind_contextvars(scan_group_id=str(scan_group_uuid))
            bound_group_id = True
            # First child to start the group flips queued -> running;
            # subsequent children no-op cleanly inside the UPDATE.
            if _flip_group_running(factory, scan_group_uuid):
                _log.info(
                    "scan_group.flipped_running",
                    scan_group_id=str(scan_group_uuid),
                )

        _mark(factory, "running", scan_uuid)

        plugin: ScannerPlugin = build_zap_plugin(settings)

        if not plugin.supports(target):
            _mark(factory, "failed", scan_uuid, reason="no scanner supports this target")
            _log.error(
                "scan.run.unsupported_target",
                scan_id=scan_id_str,
                kind=target.kind,
                url=target.url,
            )
            if scan_group_uuid is not None:
                _maybe_log_group_terminal(scan_group_uuid, factory)
            return False

        context = None
        try:
            context = plugin.prepare(target)
            _log.info(
                "scan.run.prepared",
                scan_id=scan_id_str,
                engine_version=context.metadata.get("engine_version"),
            )

            raw = plugin.run(context)
            findings = list(plugin.normalize(raw, context))
            _log.info("scan.run.normalized", scan_id=scan_id_str, count=len(findings))

            if findings:
                with factory() as session:
                    try:
                        _finding_repo.add_many(
                            session,
                            [_finding_to_row(f) for f in findings],
                        )
                        session.commit()
                    except Exception:
                        session.rollback()
                        raise

            _mark(factory, "completed", scan_uuid)
            _log.info("scan.run.complete", scan_id=scan_id_str, findings=len(findings))
            if scan_group_uuid is not None:
                _maybe_log_group_terminal(scan_group_uuid, factory)
            return True
        except Exception as exc:
            _log.exception("scan.run.failed", scan_id=scan_id_str, error=str(exc))
            try:
                _mark(factory, "failed", scan_uuid, reason=str(exc))
            except Exception as secondary:  # noqa: BLE001 — best-effort bookkeeping
                _log.error(
                    "scan.run.mark_failed_errored",
                    scan_id=scan_id_str,
                    error=str(secondary),
                )
            if scan_group_uuid is not None:
                _maybe_log_group_terminal(scan_group_uuid, factory)
            return False
        finally:
            if context is not None:
                try:
                    plugin.teardown(context)
                except Exception as te:  # noqa: BLE001 — teardown is best-effort
                    _log.warning(
                        "scan.run.teardown_failed",
                        scan_id=scan_id_str,
                        error=str(te),
                    )
    finally:
        # Clear per-task bindings so the next task on this worker
        # doesn't inherit stale ids.  ``zap_index`` / ``assigned_queue``
        # could in principle stay bound (they're constant for the
        # process) but clearing them keeps the symmetry simple —
        # ``task_prerun`` re-binds correlation_id from scratch on
        # every task too.
        keys = ["scan_id", "zap_index", "assigned_queue"]
        if bound_group_id:
            keys.append("scan_group_id")
        structlog.contextvars.unbind_contextvars(*keys)


def _maybe_log_group_terminal(
    scan_group_uuid: uuid.UUID,
    factory: sessionmaker[Session],
) -> None:
    """Run rollup; if this child was the last one, log the terminal status.

    Pulled out so the three call sites (unsupported-target, success,
    plugin failure) stay one-liners and don't accidentally diverge.
    """
    terminal = _rollup_group_if_terminal(factory, scan_group_uuid)
    if terminal is not None:
        _log.info(
            "scan_group.flipped_terminal",
            scan_group_id=str(scan_group_uuid),
            terminal_status=terminal,
        )

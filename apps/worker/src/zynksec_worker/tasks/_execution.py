"""Shared scan-execution helper used by ``scan.run`` and
``scan_group.process``.

Phase 2 Sprint 2: lifted out of ``tasks/scan.py`` so multi-target
groups can iterate children through the same code path the
single-scan task uses.  Single source of truth for "what does it
mean to run one scan against one target" — both task entry points
just thread the right primitive arguments in.

The helper is sync + blocking (matches Celery's prefork-pool model)
and returns ``True`` on completion, ``False`` on failure.  The
caller decides whether to propagate (single-scan task: re-raise so
Celery sees the task as failed) or to swallow (group task:
continue to the next child).
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
    ScanRepository,
    engine_from_url,
    make_session_factory,
)
from zynksec_scanners import ScannerPlugin, ScanTarget
from zynksec_scanners.types import TargetKind
from zynksec_schema import Finding, ScanProfile

from zynksec_worker.config import get_settings
from zynksec_worker.runners import build_zap_plugin

_log = structlog.get_logger(__name__)

_scan_repo = ScanRepository()
_finding_repo = FindingRepository()


@lru_cache(maxsize=1)
def session_factory() -> sessionmaker[Session]:
    """Cache one engine + session factory per worker process."""
    engine = engine_from_url(get_settings().database_url)
    return make_session_factory(engine)


def _load_target(
    factory: sessionmaker[Session],
    scan_uuid: uuid.UUID,
    scan_profile: ScanProfile,
) -> ScanTarget:
    """Load the Scan row and construct a :class:`ScanTarget` for the plugin.

    When the Scan links to a persistent :class:`zynksec_db.Target`
    (Phase 2 Sprint 1+), the target's ``kind`` flows through to the
    runtime ``ScanTarget`` so the plugin's ``supports()`` gate can
    reject unsupported kinds.  Legacy ``target_url``-only scans
    (``scan.target_id IS NULL``) keep the historical ``"web_app"``
    default — that path has no kind information to thread through.
    """
    with factory() as session:
        scan = session.get(Scan, scan_uuid)
        if scan is None:
            raise RuntimeError(f"Scan {scan_uuid} vanished between enqueue and dispatch")
        target_row = scan.target  # eager-loaded via SQLAlchemy relationship
        kind: TargetKind = target_row.kind if target_row is not None else "web_app"  # type: ignore[assignment]
        return ScanTarget(
            kind=kind,
            url=scan.target_url,
            project_id=scan.project_id,
            scan_id=scan.id,
            scan_profile=scan_profile,
        )


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


def execute_scan(scan_uuid: uuid.UUID, profile: ScanProfile) -> bool:
    """Run one scan against one target end-to-end.

    Returns ``True`` if the scan completed (with or without
    findings), ``False`` if it failed during the plugin's
    prepare/run/normalize/persist phase (DB row marked ``failed``
    and the failure logged via ``scan.run.failed``).

    May raise from the early-boundary calls — ``_mark(factory,
    "running", ...)``, ``_load_target(...)``, or
    ``build_zap_plugin(settings)`` — when DB connectivity or
    settings load fail before the inner ``try/except`` is reached.
    The caller decides what to do with those:

    * ``scan.run`` lets the exception propagate so Celery records
      a failed task (retry / DLQ wiring lives there).
    * ``scan_group.process`` wraps the call in defense-in-depth
      ``try/except`` so a transient blip on one child doesn't
      abort the whole group.

    The Scan's ``scan_id`` is bound to structlog contextvars at
    entry so every log line emitted while this child runs (the
    plugin progress lines, finding-persist lines, status
    transitions) carries it; the bound var is cleared in
    ``finally`` — including on the propagating-exception path —
    so a subsequent child in the same task doesn't inherit a
    stale id.
    """
    scan_id_str = str(scan_uuid)
    factory = session_factory()
    settings = get_settings()

    structlog.contextvars.bind_contextvars(scan_id=scan_id_str)
    try:
        _log.info("scan.run.start", scan_id=scan_id_str, scan_profile=profile.value)
        _mark(factory, "running", scan_uuid)

        target = _load_target(factory, scan_uuid, profile)
        plugin: ScannerPlugin = build_zap_plugin(settings)

        if not plugin.supports(target):
            _mark(factory, "failed", scan_uuid, reason="no scanner supports this target")
            _log.error(
                "scan.run.unsupported_target",
                scan_id=scan_id_str,
                kind=target.kind,
                url=target.url,
            )
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
        # Clear the per-child binding so subsequent log lines in
        # the same Celery task (e.g. the next iteration of a
        # ScanGroup) don't carry a stale scan_id.
        structlog.contextvars.unbind_contextvars("scan_id")

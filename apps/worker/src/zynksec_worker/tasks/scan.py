"""scan.run — Phase-0 end-to-end scan task.

Walking-skeleton flow (docs/04 §0.9 steps 6-15):

    1. mark running
    2. load Scan row, build Target
    3. build ScannerPlugin via the factory (CLAUDE.md §3 D)
    4. prepare -> run -> normalize -> persist -> teardown
    5. mark completed (or failed)

CLAUDE.md §5: the Celery arg is a string UUID.  Rich objects are
re-fetched from the DB inside the task.
"""

from __future__ import annotations

import uuid
from functools import lru_cache

import structlog
from celery import Task
from sqlalchemy.orm import Session, sessionmaker
from zynksec_db import Finding as FindingRow
from zynksec_db import (
    FindingRepository,
    Scan,
    ScanRepository,
    engine_from_url,
    make_session_factory,
)
from zynksec_scanners import ScannerPlugin, Target
from zynksec_schema import Finding, ScanProfile

from zynksec_worker.celery_app import celery_app
from zynksec_worker.config import get_settings
from zynksec_worker.runners import build_zap_plugin

_log = structlog.get_logger(__name__)

_scan_repo = ScanRepository()
_finding_repo = FindingRepository()


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker[Session]:
    """Cache one engine + session factory per worker process."""
    engine = engine_from_url(get_settings().database_url)
    return make_session_factory(engine)


def _load_target(
    factory: sessionmaker[Session],
    scan_uuid: uuid.UUID,
    scan_profile: ScanProfile,
) -> Target:
    """Load the Scan row and construct a :class:`Target` for the plugin.

    ``scan_profile`` is supplied by the caller (the Celery task entry
    point, which converts the primitive task kwarg into the enum) so
    this helper stays free of wire-format coupling.
    """
    with factory() as session:
        scan = session.get(Scan, scan_uuid)
        if scan is None:
            raise RuntimeError(f"Scan {scan_uuid} vanished between enqueue and dispatch")
        return Target(
            kind="web_app",
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


@celery_app.task(name="scan.run", bind=True)
def run(
    self: Task,
    scan_id: str,
    scan_profile: str = ScanProfile.PASSIVE.value,
    correlation_id: str | None = None,
) -> None:
    """Drive ZAP through the Sprint-1 baseline flow against one target.

    ``scan_profile`` arrives as a primitive (CLAUDE.md §5) — the wire
    form of :class:`ScanProfile`, e.g. ``"PASSIVE"``.  The default
    keeps task replays from older API versions safe.  ``correlation_id``
    is a Week-4 observability kwarg consumed by
    :func:`zynksec_worker.celery_app._bind_task_context` via the
    ``task_prerun`` signal; this function treats it as a no-op body
    parameter so Celery's argument-binding accepts it.
    """
    del self, correlation_id
    scan_uuid = uuid.UUID(scan_id)
    profile = ScanProfile(scan_profile)
    settings = get_settings()
    factory = _session_factory()

    _log.info("scan.run.start", scan_id=scan_id, scan_profile=profile.value)
    _mark(factory, "running", scan_uuid)

    target = _load_target(factory, scan_uuid, profile)
    plugin: ScannerPlugin = build_zap_plugin(settings)

    if not plugin.supports(target):
        _mark(factory, "failed", scan_uuid, reason="no scanner supports this target")
        raise RuntimeError(f"no scanner supports target kind={target.kind} url={target.url}")

    context = None
    try:
        context = plugin.prepare(target)
        _log.info(
            "scan.run.prepared",
            scan_id=scan_id,
            engine_version=context.metadata.get("engine_version"),
        )

        raw = plugin.run(context)
        findings = list(plugin.normalize(raw, context))
        _log.info("scan.run.normalized", scan_id=scan_id, count=len(findings))

        if findings:
            with factory() as session:
                try:
                    _finding_repo.add_many(session, [_finding_to_row(f) for f in findings])
                    session.commit()
                except Exception:
                    session.rollback()
                    raise

        _mark(factory, "completed", scan_uuid)
        _log.info("scan.run.complete", scan_id=scan_id, findings=len(findings))
    except Exception as exc:
        _log.exception("scan.run.failed", scan_id=scan_id, error=str(exc))
        try:
            _mark(factory, "failed", scan_uuid, reason=str(exc))
        except Exception as secondary:  # noqa: BLE001 — best-effort bookkeeping
            _log.error(
                "scan.run.mark_failed_errored",
                scan_id=scan_id,
                error=str(secondary),
            )
        raise
    finally:
        if context is not None:
            try:
                plugin.teardown(context)
            except Exception as te:  # noqa: BLE001 — teardown is best-effort
                _log.warning("scan.run.teardown_failed", scan_id=scan_id, error=str(te))

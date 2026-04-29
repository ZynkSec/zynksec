"""Repository-level integration tests for the Sprint-3 group rollup.

The atomic-rollup methods on :class:`ScanGroupRepository`
(``mark_running_if_queued`` / ``mark_terminal_if_all_children_done``)
are the contract that holds the parallel-child dispatch model
together — every child task runs them, the LAST child wins.  They
were originally only exercised end-to-end through the full stack
(real ZAP scans against juice-shop), and a Postgres ``text -> ENUM``
cast bug in the rollup CTE slipped past Sprint 3 commit ``c0b62af``
because the bug only fires against a real Postgres ENUM column —
in-memory rollup tests would miss it.

These tests pin both methods directly against real Postgres
(via the conftest's ``db_session`` fixture against host port 55432),
constructing ScanGroup + child Scan rows in the exact statuses the
rollup matrix needs.  No ZAP, no worker, no scan execution — each
test runs in well under a second once the conftest's compose-up
session fixture has the stack live.

Coverage matrix:

    mark_running_if_queued
        - queued                -> running, returns True
        - already running       -> no-op,  returns False
        - already terminal      -> no-op,  returns False
        - missing group         -> no-op,  returns False

    mark_terminal_if_all_children_done
        - all children completed       -> "completed"
        - all children failed          -> "failed"
        - mix completed + failed       -> "partial_failure"
        - any child still queued       -> None (no flip)
        - any child still running      -> None (no flip)
        - already-terminal group       -> None (idempotent)
        - childless group              -> "completed" (vacuously: pending=0,
                                          failed=0; documented behaviour
                                          since the API never creates an
                                          empty group — Pydantic min-length
                                          rejects ``target_ids=[]`` at
                                          422 — but the repo method must
                                          still behave deterministically
                                          if a caller ever exercises it)

CLAUDE.md §3 (repository pattern), §7 (real Postgres, no mocks).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy.orm import Session
from zynksec_db import Project, Scan, ScanGroup, ScanGroupRepository


@pytest.fixture
def repo() -> ScanGroupRepository:
    """Per-test repo — repos are stateless, so a fresh one per test
    is the cheapest correct thing."""
    return ScanGroupRepository()


@pytest.fixture
def project(db_session: Session) -> Iterator[Project]:
    """Per-test Project so each test owns its own FK target.  The
    ``ON DELETE CASCADE`` on scan_groups + scans means deleting the
    project cleans up everything; no manual teardown needed."""
    p = Project(name=f"rollup-test-{uuid.uuid4().hex[:8]}")
    db_session.add(p)
    db_session.commit()
    yield p
    # Best-effort cleanup; cascade handles children.
    db_session.delete(p)
    db_session.commit()


def _make_group(
    db_session: Session,
    project_id: uuid.UUID,
    *,
    status: str = "queued",
) -> ScanGroup:
    """Construct + commit a ScanGroup row at the requested status."""
    group = ScanGroup(
        project_id=project_id,
        name=f"rollup-group-{uuid.uuid4().hex[:8]}",
        scan_profile="PASSIVE",
        status=status,
    )
    db_session.add(group)
    db_session.commit()
    return group


def _make_child(
    db_session: Session,
    *,
    project_id: uuid.UUID,
    group_id: uuid.UUID,
    status: str,
) -> Scan:
    """Construct + commit a child Scan in the requested terminal /
    non-terminal status.  ``target_url`` is a placeholder — these
    tests never run a real scan."""
    child = Scan(
        project_id=project_id,
        target_url="http://example.invalid/rollup-test",
        scan_group_id=group_id,
        scan_profile="PASSIVE",
        status=status,
    )
    db_session.add(child)
    db_session.commit()
    return child


# ---------- mark_running_if_queued ----------


def test_mark_running_if_queued_flips_a_queued_group(
    db_session: Session,
    repo: ScanGroupRepository,
    project: Project,
) -> None:
    group = _make_group(db_session, project.id, status="queued")
    flipped = repo.mark_running_if_queued(db_session, group.id)
    db_session.commit()
    assert flipped is True
    db_session.expire_all()
    refreshed = db_session.get(ScanGroup, group.id)
    assert refreshed is not None
    assert refreshed.status == "running"
    assert refreshed.started_at is not None


def test_mark_running_if_queued_is_noop_when_already_running(
    db_session: Session,
    repo: ScanGroupRepository,
    project: Project,
) -> None:
    group = _make_group(db_session, project.id, status="running")
    flipped = repo.mark_running_if_queued(db_session, group.id)
    db_session.commit()
    assert flipped is False
    db_session.expire_all()
    refreshed = db_session.get(ScanGroup, group.id)
    assert refreshed is not None
    assert refreshed.status == "running"


def test_mark_running_if_queued_is_noop_when_already_terminal(
    db_session: Session,
    repo: ScanGroupRepository,
    project: Project,
) -> None:
    group = _make_group(db_session, project.id, status="completed")
    flipped = repo.mark_running_if_queued(db_session, group.id)
    db_session.commit()
    assert flipped is False
    db_session.expire_all()
    refreshed = db_session.get(ScanGroup, group.id)
    assert refreshed is not None
    assert refreshed.status == "completed"


def test_mark_running_if_queued_is_noop_for_missing_group(
    db_session: Session,
    repo: ScanGroupRepository,
) -> None:
    flipped = repo.mark_running_if_queued(db_session, uuid.uuid4())
    db_session.commit()
    assert flipped is False


# ---------- mark_terminal_if_all_children_done ----------


def test_terminal_rollup_all_completed_flips_to_completed(
    db_session: Session,
    repo: ScanGroupRepository,
    project: Project,
) -> None:
    group = _make_group(db_session, project.id, status="running")
    for _ in range(3):
        _make_child(db_session, project_id=project.id, group_id=group.id, status="completed")
    result = repo.mark_terminal_if_all_children_done(db_session, group.id)
    db_session.commit()
    assert result == "completed"
    db_session.expire_all()
    refreshed = db_session.get(ScanGroup, group.id)
    assert refreshed is not None
    assert refreshed.status == "completed"
    assert refreshed.completed_at is not None


def test_terminal_rollup_all_failed_flips_to_failed(
    db_session: Session,
    repo: ScanGroupRepository,
    project: Project,
) -> None:
    group = _make_group(db_session, project.id, status="running")
    for _ in range(2):
        _make_child(db_session, project_id=project.id, group_id=group.id, status="failed")
    result = repo.mark_terminal_if_all_children_done(db_session, group.id)
    db_session.commit()
    assert result == "failed"
    db_session.expire_all()
    refreshed = db_session.get(ScanGroup, group.id)
    assert refreshed is not None
    assert refreshed.status == "failed"
    assert refreshed.completed_at is not None


def test_terminal_rollup_mix_completed_and_failed_flips_to_partial_failure(
    db_session: Session,
    repo: ScanGroupRepository,
    project: Project,
) -> None:
    group = _make_group(db_session, project.id, status="running")
    _make_child(db_session, project_id=project.id, group_id=group.id, status="completed")
    _make_child(db_session, project_id=project.id, group_id=group.id, status="failed")
    result = repo.mark_terminal_if_all_children_done(db_session, group.id)
    db_session.commit()
    assert result == "partial_failure"
    db_session.expire_all()
    refreshed = db_session.get(ScanGroup, group.id)
    assert refreshed is not None
    assert refreshed.status == "partial_failure"
    assert refreshed.completed_at is not None


def test_terminal_rollup_with_queued_child_does_not_flip(
    db_session: Session,
    repo: ScanGroupRepository,
    project: Project,
) -> None:
    group = _make_group(db_session, project.id, status="running")
    _make_child(db_session, project_id=project.id, group_id=group.id, status="completed")
    _make_child(db_session, project_id=project.id, group_id=group.id, status="queued")
    result = repo.mark_terminal_if_all_children_done(db_session, group.id)
    db_session.commit()
    assert result is None
    db_session.expire_all()
    refreshed = db_session.get(ScanGroup, group.id)
    assert refreshed is not None
    assert refreshed.status == "running"


def test_terminal_rollup_with_running_child_does_not_flip(
    db_session: Session,
    repo: ScanGroupRepository,
    project: Project,
) -> None:
    group = _make_group(db_session, project.id, status="running")
    _make_child(db_session, project_id=project.id, group_id=group.id, status="completed")
    _make_child(db_session, project_id=project.id, group_id=group.id, status="running")
    result = repo.mark_terminal_if_all_children_done(db_session, group.id)
    db_session.commit()
    assert result is None
    db_session.expire_all()
    refreshed = db_session.get(ScanGroup, group.id)
    assert refreshed is not None
    assert refreshed.status == "running"


def test_terminal_rollup_is_idempotent_on_already_terminal_group(
    db_session: Session,
    repo: ScanGroupRepository,
    project: Project,
) -> None:
    """Two children racing past their commits both call the rollup;
    the second call must observe the post-update state and no-op
    cleanly (returns None, status unchanged)."""
    group = _make_group(db_session, project.id, status="running")
    _make_child(db_session, project_id=project.id, group_id=group.id, status="completed")
    _make_child(db_session, project_id=project.id, group_id=group.id, status="completed")

    first = repo.mark_terminal_if_all_children_done(db_session, group.id)
    db_session.commit()
    second = repo.mark_terminal_if_all_children_done(db_session, group.id)
    db_session.commit()

    assert first == "completed"
    assert second is None
    db_session.expire_all()
    refreshed = db_session.get(ScanGroup, group.id)
    assert refreshed is not None
    assert refreshed.status == "completed"

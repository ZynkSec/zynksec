# zynksec-db

Persistence layer for Zynksec — SQLAlchemy 2.x declarative models,
session helpers, and repository classes. Shared by `apps/api` and
`apps/worker` so ORM models live in exactly one place (CLAUDE.md §5).

## What lives here

- `base.Base` — DeclarativeBase with the CLAUDE.md §4 naming
  convention so Alembic auto-generates predictable constraint names.
- `session.engine_from_url`, `session.make_session_factory` —
  stateless helpers. Callers own the engine/session lifecycle.
- `models/` — `Project`, `Scan`, `Finding` (Phase-0 subset per
  `docs/04_phase0_scaffolding.md` §0.11).
- `repositories/` — `Repository[T]` generic base plus
  `ScanRepository` (state-machine transitions) and
  `FindingRepository` (batch insert). Routers and tasks depend on
  these, never on raw sessions.

## Status

Phase 0 Week 2. `mypy --strict` is not extended to this package yet —
SQLAlchemy 2.x typed-mapping generates `Any` in a few places that
require stub gymnastics to satisfy strict mode. Phase 1 tightens.

# zynksec-schema

Canonical schemas for Zynksec — most importantly the `Finding` model,
which is the project's lingua franca (CLAUDE.md §5, docs/03 §5).

Anything emitted by a scanner or consumed by the API serialises via
this package. `mypy --strict` runs on this tree in CI; breaking changes
bump `schema_version` and require a migration plan.

## Status

Phase 0 Week 1: scaffold only. Week 3 implements the Phase-0 Finding
subset (docs/04 §0.11). Phase 1 expands to full Finding v1 (docs/03
§5).

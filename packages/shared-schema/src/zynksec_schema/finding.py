"""Canonical Finding schema — Zynksec's lingua franca.

Implements the Phase-0 subset defined in
``docs/04_phase0_scaffolding.md`` §0.11.  The full Finding v1 schema
(``docs/03_architecture.md`` §5) lands in Phase 1; the set of fields
here is deliberately a proper subset of v1 so the upgrade is additive.

All models are ``frozen=True, extra="forbid"`` — Pydantic enforces
immutability and rejects unknown keys (CLAUDE.md §3).  ``mypy --strict``
is the gate on this module.

The **fingerprint formula is FROZEN**.  Any change requires bumping
``schema_version`` and writing a migration plan.  See
:mod:`zynksec_schema.fingerprint` for the formula.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
LifecycleStatus = Literal["open", "fixed", "ignored"]
Engine = Literal["zap"]


class Taxonomy(BaseModel):
    """Classification metadata — how this finding maps to public catalogs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    zynksec_id: str
    cwe: int | None = None
    owasp_top10: str | None = None


class Severity(BaseModel):
    """Engine-reported severity bucket + confidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    level: SeverityLevel
    confidence: Confidence


class Location(BaseModel):
    """Where on the target surface the finding was observed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str
    method: str
    parameter: str | None = None


class Evidence(BaseModel):
    """What proves this finding is real — engine + rule + request/response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    engine: Engine
    rule_id: str
    request: str
    response_excerpt: str


class Lifecycle(BaseModel):
    """When this finding first appeared and when it was last seen."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: LifecycleStatus
    first_seen_at: datetime
    last_seen_at: datetime


class Finding(BaseModel):
    """Phase-0 Finding — one normalised result of a scan.

    Scanners emit these via :meth:`ScannerPlugin.normalize`; the
    worker persists them via ``FindingRepository.add_many``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: uuid.UUID
    fingerprint: str
    schema_version: int = 1
    scan_id: uuid.UUID

    taxonomy: Taxonomy
    severity: Severity
    location: Location
    evidence: Evidence
    lifecycle: Lifecycle

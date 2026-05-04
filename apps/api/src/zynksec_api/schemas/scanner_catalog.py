"""ScannerCatalog response model — Phase 4 Sprint 2.

Wire shape for ``GET /api/v1/scanners``.  Powers the dashboard's
"New Scan" form: per-kind list of available scanners + which is
the registered default + the scan-profile choices that apply
to that kind.

Sourced from :mod:`zynksec_scanners.registry` at request time —
the endpoint MUST NOT hardcode the response or the frontend
would silently drift from a future scanner addition.

The shape is keyed on ``TargetKind`` so the frontend can pick
the relevant entry once it knows the target's kind, instead of
filtering a flat list client-side.  Mirrors the pattern of
``ScanGroupRead.summary`` (server pre-shapes the payload for
the most common consumer; clients don't re-aggregate).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from zynksec_api.schemas.target import TargetKindLiteral


class ScannerEntry(BaseModel):
    """One scanner entry in a kind's available list."""

    model_config = ConfigDict(frozen=True)

    name: str
    is_default: bool


class KindCatalog(BaseModel):
    """Per-kind capability bundle — scanners + scan profiles.

    ``scan_profiles`` is empty for kinds where the engine doesn't
    expose intensity (currently ``repo``: gitleaks / semgrep /
    osv-scanner / trivy all run in their single-mode shape;
    Phase 3 plugins declare ``supported_intensities = {PASSIVE}``
    only).  ``web_app`` and ``api`` carry the three ZAP profiles
    PASSIVE / SAFE_ACTIVE / AGGRESSIVE.
    """

    model_config = ConfigDict(frozen=True)

    scanners: list[ScannerEntry]
    scan_profiles: list[str]


class ScannerCatalog(BaseModel):
    """Top-level response — kind → :class:`KindCatalog` mapping.

    Pydantic validates the keys are exactly the three known
    target kinds (web_app / api / repo) so a future kind
    addition is a deliberate edit, not silent.
    """

    model_config = ConfigDict(frozen=True)

    kinds: dict[TargetKindLiteral, KindCatalog]

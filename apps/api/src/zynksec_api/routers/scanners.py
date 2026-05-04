"""Scanners metadata endpoint — Phase 4 Sprint 2.

``GET /api/v1/scanners`` exposes the per-kind plugin registry +
scan-profile catalogue so the dashboard's "New Scan" form can
render kind-aware pickers without hardcoding scanner names that
would silently drift on future plugin additions.

Pure metadata: no auth, no project scoping, no DB query.  The
response is shaped by reading the registry directly so a future
``register_scanner(...)`` call automatically reflects in the
catalogue without router edits.
"""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter
from zynksec_scanners import (
    default_scanner_for,
    scan_profiles_for_kind,
    scanners_for_kind,
)
from zynksec_scanners.types import TargetKind

from zynksec_api.schemas import KindCatalog, ScannerCatalog, ScannerEntry

router = APIRouter(prefix="/api/v1/scanners", tags=["scanners"])

# The three target kinds the platform knows about; mirrors
# ``TargetKindLiteral`` in the schemas module.  Pinned here so a
# future kind addition (e.g. "container_image") fails loudly at
# import time when the plugin lands without updating this list.
_KINDS: tuple[TargetKind, ...] = ("web_app", "api", "repo")


@router.get(
    "",
    response_model=ScannerCatalog,
    summary="Per-kind scanner + scan-profile catalogue",
)
def get_scanner_catalog() -> ScannerCatalog:
    """Return the per-kind catalogue of available scanners and scan
    profiles.

    Each kind block carries:
      * ``scanners`` — list of registered scanner names + a flag
        marking which one the API resolves to when the client
        omits ``scanner`` from the POST body.  Sorted with the
        default first (so a UI rendering top-to-bottom honours
        the implicit choice).
      * ``scan_profiles`` — ordered list of ``ScanProfile`` enum
        values applicable to this kind (empty for ``kind=repo``;
        the three ZAP intensities for ``web_app`` / ``api``).
    """
    out: dict[TargetKind, KindCatalog] = {}
    for kind in _KINDS:
        names = scanners_for_kind(kind)
        try:
            default_name = default_scanner_for(kind)
        except KeyError:
            # No default registered for this kind — registry
            # invariant violated.  Surface as an empty default
            # rather than a 500; the dashboard renders the picker
            # without a pre-selection so the operator picks
            # explicitly.
            default_name = None
        # Stable ordering: default first, then the rest alphabetical.
        ordered = sorted(names, key=lambda n: (n != default_name, n))
        out[kind] = KindCatalog(
            scanners=[ScannerEntry(name=name, is_default=name == default_name) for name in ordered],
            scan_profiles=scan_profiles_for_kind(kind),
        )
    # ``cast`` is the cheapest path that keeps mypy happy on the
    # ``dict[TargetKind, ...]`` → ``dict[TargetKindLiteral, ...]``
    # crossing — both literals describe the same set of values.
    return ScannerCatalog(kinds=cast(dict, out))

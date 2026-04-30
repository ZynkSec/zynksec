"""Multi-scanner registry: target-kind ↔ scanner-name mapping.

Phase 3 Sprint 1 introduced the second scanner family (Gitleaks)
alongside ZAP and a name-only registry: one scanner per kind.

Phase 3 Sprint 2 generalises the registry to support multiple
scanners per kind with a per-kind default.  The dispatch surface
expands from "which scanner runs this kind?" to "which scanner runs
this kind, and which one was explicitly requested if any?".

Shape:

  * ``SCANNER_ZAP`` / ``SCANNER_GITLEAKS`` / ``SCANNER_SEMGREP`` —
    canonical scanner-name string constants.  Compared by string
    equality across the API + worker; both processes need to agree.

  * Internal :class:`_ScannerEntry` carries each scanner's
    ``supported_kinds`` set + a ``default_for_kinds`` set
    (subset of ``supported_kinds``).

  * Public helpers:
      - :func:`default_scanner_for(kind)` — name of the per-kind
        default scanner.
      - :func:`scanners_for_kind(kind)` — the set of all
        registered scanner names that support this kind.
      - :func:`resolve_scanner(kind, name)` — given a kind and
        optional explicit scanner name, returns the scanner name
        to use.  Validates the explicit name against
        ``scanners_for_kind``; raises :class:`UnknownScanner` on
        mismatch.
      - :func:`scanner_for_kind(kind)` — backward-compat alias for
        :func:`default_scanner_for`.  Sprint 1 callers don't need
        to change.

Why not a class hierarchy? A registry of ``Type[ScannerPlugin]``
would couple this module to every plugin's import graph (so
``apps/api`` would suddenly need the worker's ZAP client + the
code-worker's gitleaks / semgrep dependencies).  A name-only
registry keeps the API package import-light and lets each app
wire its own plugin instances via runner factories.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from zynksec_scanners.types import TargetKind

#: Canonical scanner-name strings — opaque tokens compared by string
#: equality.  The worker turns these into concrete plugin instances
#: via per-scanner runner factories; the API turns them into Celery
#: queue names via :mod:`zynksec_schema.queues`.
SCANNER_ZAP: str = "zap"
SCANNER_GITLEAKS: str = "gitleaks"
SCANNER_SEMGREP: str = "semgrep"
SCANNER_OSV: str = "osv-scanner"


class UnknownScanner(KeyError):  # noqa: N818 — matches existing KeyError-shape convention
    """Raised when a caller asks for a scanner name that isn't registered
    for a given target kind.

    Subclasses :class:`KeyError` so existing ``except KeyError``
    handlers keep working; the API canonical-envelope handler maps
    this to a 422 ``unknown_scanner`` response (see
    :mod:`zynksec_api.exceptions`).
    """


@dataclass(frozen=True)
class _ScannerEntry:
    """Internal record of a scanner's kind support + default mapping."""

    name: str
    supported_kinds: frozenset[TargetKind]
    default_for_kinds: frozenset[TargetKind] = field(default_factory=frozenset)


_REGISTRY: dict[str, _ScannerEntry] = {
    SCANNER_ZAP: _ScannerEntry(
        name=SCANNER_ZAP,
        # ZAP is the default for both ``web_app`` AND ``api`` —
        # ``api`` Targets are scanned via ZAP's OpenAPI-spec mode
        # for now (a dedicated API-fuzz scanner is later-Phase-3
        # scope).
        supported_kinds=frozenset({"web_app", "api"}),
        default_for_kinds=frozenset({"web_app", "api"}),
    ),
    SCANNER_GITLEAKS: _ScannerEntry(
        name=SCANNER_GITLEAKS,
        supported_kinds=frozenset({"repo"}),
        # Backward compat: ``kind=repo`` keeps defaulting to
        # gitleaks.  Sprint 2 introduces Semgrep as an opt-in
        # alternative; an explicit ``scanner="semgrep"`` is needed
        # to switch.
        default_for_kinds=frozenset({"repo"}),
    ),
    SCANNER_SEMGREP: _ScannerEntry(
        name=SCANNER_SEMGREP,
        supported_kinds=frozenset({"repo"}),
        # Phase 3 Sprint 2: opt-in only.  Defaults stay with
        # gitleaks so the existing kind=repo flow is unchanged.
        default_for_kinds=frozenset(),
    ),
    SCANNER_OSV: _ScannerEntry(
        name=SCANNER_OSV,
        supported_kinds=frozenset({"repo"}),
        # Phase 3 Sprint 3: opt-in only.  Defaults stay with
        # gitleaks (preserves the kind=repo backward-compat
        # contract from Sprint 1).  Opt in via explicit
        # ``scanner="osv-scanner"`` to scan a repo's lockfiles.
        default_for_kinds=frozenset(),
    ),
}


def default_scanner_for(kind: TargetKind) -> str:
    """Return the per-kind default scanner name.

    Raises :class:`KeyError` if no scanner is registered as default
    for this kind — that's a registry-vs-schema mismatch and should
    fail loudly rather than silently fall back.
    """
    for entry in _REGISTRY.values():
        if kind in entry.default_for_kinds:
            return entry.name
    raise KeyError(f"no default scanner registered for kind {kind!r}")


def scanners_for_kind(kind: TargetKind) -> set[str]:
    """Return every registered scanner name that supports this kind."""
    return {entry.name for entry in _REGISTRY.values() if kind in entry.supported_kinds}


def resolve_scanner(kind: TargetKind, name: str | None) -> str:
    """Pick the scanner name to use given a kind and optional explicit name.

    ``name=None`` resolves to the per-kind default.  An explicit
    name must be registered AND support this kind, else
    :class:`UnknownScanner` (subclass of :class:`KeyError`) is
    raised so the API can surface a canonical 422
    ``unknown_scanner``.

    The exception's ``.args[0]`` is the offending ``name`` — the
    handler walks ``scanners_for_kind(kind)`` to populate the
    ``details.available`` list.
    """
    if name is None:
        return default_scanner_for(kind)
    if name not in _REGISTRY:
        raise UnknownScanner(name)
    entry = _REGISTRY[name]
    if kind not in entry.supported_kinds:
        raise UnknownScanner(name)
    return name


def scanner_for_kind(kind: TargetKind) -> str:
    """Backward-compat alias for :func:`default_scanner_for`.

    Sprint 1 callers (``apps/api/.../routers/*.py``,
    ``apps/worker/.../tasks/_execution.py``) keep working without
    edits.  New callers should use :func:`resolve_scanner` or the
    explicit per-kind helpers.
    """
    return default_scanner_for(kind)

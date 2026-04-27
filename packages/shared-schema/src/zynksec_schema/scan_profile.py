"""Scan-profile enum — the single source of truth for engine intensity.

Phase 1 Sprint 1 promotes :class:`ScanProfile` out of the scanners
package and into shared-schema so the API request body, the worker
task signature, and the plugin contract all import from the same
place.  Values are the wire format the API accepts and persists
(``"PASSIVE"``, ``"SAFE_ACTIVE"``, ``"AGGRESSIVE"``).

Sprint 1 ships ``PASSIVE`` only.  ``SAFE_ACTIVE`` and ``AGGRESSIVE`` are
declared so the OpenAPI spec advertises them as valid for clients
planning ahead, and so the schema-layer change is one-shot rather than
drip-fed; the API rejects them with a descriptive 422 until their
implementations land in upcoming sprints.
"""

from __future__ import annotations

from enum import StrEnum


class ScanProfile(StrEnum):
    """How aggressively the engine probes the target."""

    PASSIVE = "PASSIVE"
    SAFE_ACTIVE = "SAFE_ACTIVE"
    AGGRESSIVE = "AGGRESSIVE"

"""Finding response model + converter from the SQLAlchemy row.

The API's wire format for a finding IS the canonical Pydantic
``Finding`` from :mod:`zynksec_schema` — no API-specific DTO.  This
module re-exports it as :data:`FindingRead` (so imports in routers
read naturally) and ships a converter that maps the flat DB row to
the nested Pydantic shape.
"""

from __future__ import annotations

from zynksec_db import Finding as FindingRow
from zynksec_schema import (
    Evidence,
    Finding,
    Lifecycle,
    Location,
    Severity,
    Taxonomy,
)

# Re-export so routers can `from ...schemas.finding import FindingRead`.
FindingRead = Finding


def finding_from_row(row: FindingRow) -> FindingRead:
    """Turn a flat SQLAlchemy Finding row into the canonical nested form."""
    return FindingRead(
        id=row.id,
        fingerprint=row.fingerprint,
        schema_version=row.schema_version,
        scan_id=row.scan_id,
        taxonomy=Taxonomy(
            zynksec_id=row.taxonomy_zynksec_id,
            cwe=row.cwe,
            owasp_top10=row.owasp_top10,
        ),
        severity=Severity(
            level=row.severity_level,  # type: ignore[arg-type]
            confidence=row.severity_confidence,  # type: ignore[arg-type]
        ),
        location=Location(
            url=row.location_url,
            method=row.location_method,
            parameter=row.location_parameter,
        ),
        evidence=Evidence(
            engine=row.evidence_engine,  # type: ignore[arg-type]
            rule_id=row.evidence_rule_id,
            request=row.evidence_request,
            response_excerpt=row.evidence_response_excerpt,
        ),
        lifecycle=Lifecycle(
            status=row.lifecycle_status,  # type: ignore[arg-type]
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
        ),
    )

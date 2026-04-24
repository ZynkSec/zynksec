"""CWE → OWASP Top 10 (2021) lookup.

Hand-curated to cover the CWEs ZAP routinely emits.  Misses fall back
to ``None`` — better to leave the taxonomy empty than to guess wrong.
Phase 1 can swap this for a richer, data-driven mapping.
"""

from __future__ import annotations

_CWE_TO_OWASP_TOP10: dict[int, str] = {
    # A01:2021 Broken Access Control
    22: "A01:2021",  # Path Traversal
    200: "A01:2021",  # Information Exposure
    352: "A01:2021",  # CSRF
    # A03:2021 Injection
    20: "A03:2021",  # Improper Input Validation
    77: "A03:2021",  # Command Injection
    79: "A03:2021",  # Cross-site Scripting
    89: "A03:2021",  # SQL Injection
    94: "A03:2021",  # Code Injection
    # A04:2021 Insecure Design
    209: "A04:2021",  # Information Exposure Through an Error Message
    # A05:2021 Security Misconfiguration
    16: "A05:2021",  # Configuration
    693: "A05:2021",  # Protection Mechanism Failure
    1021: "A05:2021",  # Improper Restriction of Rendered UI Layers (clickjacking)
    # A07:2021 Identification & Authentication Failures
    287: "A07:2021",  # Improper Authentication
    # A08:2021 Software & Data Integrity Failures
    502: "A08:2021",  # Deserialization
    # A10:2021 Server-Side Request Forgery
    918: "A10:2021",
}


def owasp_for_cwe(cwe: int | None) -> str | None:
    """Return the OWASP Top-10 bucket for a CWE id, or ``None``."""
    if cwe is None:
        return None
    return _CWE_TO_OWASP_TOP10.get(cwe)

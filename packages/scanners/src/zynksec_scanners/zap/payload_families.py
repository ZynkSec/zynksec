"""ZAP pluginId → payload family lookup.

Maps ZAP's numeric ``pluginId`` to a coarse payload family string used
in the Finding fingerprint (docs/04 §0.11).  The family intentionally
drops payload-level details (specific SQLi vector, exact XSS mutation)
so cosmetically different payloads of the same class produce the same
fingerprint and therefore the same Finding.

Phase 0 covers the 20-odd most common baseline/standard rules.  Anything
not here falls back to :data:`_DEFAULT` (``"unknown"``); adding a new
mapping is a one-line change.
"""

from __future__ import annotations

_DEFAULT: str = "unknown"

_PAYLOAD_FAMILIES: dict[str, str] = {
    # ---- Injection ----
    "40018": "sqli-error-based",  # SQL Injection
    "40019": "sqli-error-based",  # SQL Injection - MySQL
    "40020": "sqli-error-based",  # SQL Injection - Hypersonic
    "40021": "sqli-error-based",  # SQL Injection - Oracle
    "40022": "sqli-error-based",  # SQL Injection - PostgreSQL
    "40024": "sqli-error-based",  # SQL Injection - SQLite
    "90018": "sqli-authbypass",  # SQL Injection - Auth Bypass
    "40003": "crlf-injection",  # CRLF Injection
    "40009": "ssi",  # Server Side Include
    # ---- XSS ----
    "40012": "reflected-xss",  # Cross Site Scripting (Reflected)
    "40014": "stored-xss",  # Cross Site Scripting (Persistent)
    "40016": "reflected-xss",  # Cross Site Scripting (Persistent) - Prime
    "40017": "stored-xss",  # Cross Site Scripting (Persistent) - Spider
    # ---- Path traversal / file access ----
    "6": "path-traversal",  # Path Traversal
    "7": "remote-file-inclusion",  # Remote File Inclusion
    # ---- CSRF / same-origin ----
    "10202": "csrf-missing",  # Absence of Anti-CSRF Tokens
    "40008": "param-tampering",  # Parameter Tampering
    # ---- Headers / CSP / HSTS ----
    "10020": "clickjacking-missing",  # X-Frame-Options missing
    "10021": "header-missing",  # X-Content-Type-Options missing
    "10035": "hsts-missing",  # Strict-Transport-Security missing
    "10038": "csp-missing",  # CSP header missing
    "10055": "csp-missing",  # CSP Notices
    "10063": "permissions-policy-missing",  # Permissions Policy Header missing
    # ---- Cookies ----
    "10010": "cookie-missing-httponly",  # Cookie No HttpOnly
    "10011": "cookie-missing-secure",  # Cookie Without Secure
    "10054": "cookie-missing-samesite",  # Cookie Without SameSite
    # ---- Information disclosure ----
    "10015": "info-disclosure",  # Incomplete or No Cache-control
    "10036": "info-disclosure",  # Server Leaks Version Info
    "10037": "info-disclosure",  # X-Powered-By header
    "10049": "info-disclosure",  # Storable and Cacheable Content
    "10062": "info-disclosure",  # PII Disclosure
    "10096": "info-disclosure",  # Timestamp Disclosure
    "10028": "info-disclosure",  # Open Redirect
    # ---- Mixed / transport ----
    "10017": "mixed-content",  # Cross-Domain JavaScript Source File Inclusion
    "10040": "mixed-content",  # Secure Pages Include Mixed Content
}


def family_for(rule_id: str) -> str:
    """Return the payload family for this ZAP plugin id.

    Unknown ids fall back to ``"unknown"`` rather than raising —
    missing a family only means the fingerprint is slightly coarser.
    """
    return _PAYLOAD_FAMILIES.get(rule_id, _DEFAULT)

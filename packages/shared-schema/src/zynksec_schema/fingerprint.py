"""Finding fingerprint — deterministic SHA-256 of a canonical tuple.

Formula (FROZEN — docs/03 §5.1, docs/04 §0.11)::

    sha256(
        project_id || "|" ||
        taxonomy.zynksec_id || "|" ||
        url_normalized(location.url) || "|" ||
        location.method || "|" ||
        (location.parameter or "") || "|" ||
        payload_family
    )

Changing this formula requires bumping ``Finding.schema_version`` and
writing a migration plan.  The module is pure (no I/O) so
``mypy --strict`` sees through every call path.
"""

from __future__ import annotations

import hashlib
import uuid
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}
_TRACKING_PARAM_PREFIXES: tuple[str, ...] = ("utm_",)
_TRACKING_PARAM_EXACT: frozenset[str] = frozenset({"fbclid", "gclid"})


def _is_tracking_param(name: str) -> bool:
    if name in _TRACKING_PARAM_EXACT:
        return True
    return any(name.startswith(prefix) for prefix in _TRACKING_PARAM_PREFIXES)


def normalize_url(url: str) -> str:
    """Return the canonical form used in finding fingerprints.

    - Lowercase ``scheme`` and ``host``.
    - Strip the default port for the scheme (80 for http, 443 for https).
    - Drop the fragment.
    - Drop tracking-only query params (``utm_*``, ``fbclid``, ``gclid``).
    - Sort the remaining query params alphabetically for stable output.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port: int | None = parsed.port
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None

    netloc = host if port is None else f"{host}:{port}"
    # Preserve userinfo if present.  Rare in scan targets, but dropping
    # it silently would make the normalised form non-round-trippable.
    if parsed.username is not None:
        creds = parsed.username
        if parsed.password is not None:
            creds = f"{creds}:{parsed.password}"
        netloc = f"{creds}@{netloc}"

    params: list[tuple[str, str]] = [
        (k, v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if not _is_tracking_param(k)
    ]
    params.sort(key=lambda kv: (kv[0], kv[1]))
    query = urlencode(params, doseq=True)

    return urlunparse((scheme, netloc, parsed.path, parsed.params, query, ""))


def compute_fingerprint(
    project_id: uuid.UUID,
    zynksec_id: str,
    url: str,
    method: str,
    parameter: str | None,
    payload_family: str,
) -> str:
    """Return the SHA-256 hex fingerprint per the formula above."""

    canonical = "|".join(
        [
            str(project_id),
            zynksec_id,
            normalize_url(url),
            method,
            parameter or "",
            payload_family,
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

"""Typed HTTP client for OWASP ZAP's REST API.

This is the **only** place in Zynksec that talks to ZAP's :8090
(CLAUDE.md §5: "No service-to-service HTTP without a typed client").
Every ZAP call is routed through here so upstream API quirks have
exactly one place to fix (docs/04 §0.19 risk table).

TLS verification is NEVER disabled.  We don't pass ``verify=False``
and we don't override ``SSL_CERT_FILE``.  The ZAP daemon speaks plain
HTTP inside the compose network; that's fine because the network is
Docker-internal.
"""

from __future__ import annotations

import logging
import time
from types import TracebackType
from typing import Any

import httpx

_log = logging.getLogger(__name__)

# Retry policy (CLAUDE.md §5: typed service client must carry a retry
# policy).  Three attempts with exponential backoff (0.5s, 1.5s between
# tries) lets us survive the kinds of transient transport blips we saw
# in Phase 0 — ZAP restarting mid-scan, one-off TCP RSTs — without
# masking real failures, which bubble through immediately.
_RETRY_MAX_ATTEMPTS = 3
_RETRY_BASE_DELAY_S = 0.5
_RETRY_EXCEPTIONS: tuple[type[Exception], ...] = (
    httpx.ReadError,
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.RemoteProtocolError,
)


class ZapError(RuntimeError):
    """Raised when ZAP returns an error payload or an HTTP 4xx/5xx."""


class ZapClient:
    """Thin typed wrapper around ``httpx.Client`` for the ZAP JSON API."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout_s: float = 30.0,
    ) -> None:
        self._client: httpx.Client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout_s,
        )
        self._api_key: str = api_key

    # ---- context manager ----
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ZapClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ---- core GET wrapper ----
    def _get(self, path: str, **params: str) -> dict[str, Any]:
        query: dict[str, str] = {"apikey": self._api_key, **params}
        response = self._request_with_retry(path, query)
        if response.status_code >= 400:
            raise ZapError(
                f"ZAP request {path} returned HTTP {response.status_code}: {response.text[:200]}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ZapError(f"ZAP request {path} returned non-JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ZapError(f"ZAP request {path} returned non-object JSON: {type(data).__name__}")
        if data.get("code") in {"illegal_parameter", "no_implementor", "internal_error"}:
            raise ZapError(f"ZAP API error at {path}: {data}")
        return data

    def _request_with_retry(self, path: str, query: dict[str, str]) -> httpx.Response:
        """Issue the GET, retrying only on transient transport errors.

        Non-transient httpx errors (e.g. invalid URL) and any HTTP
        response — even 5xx — fall through to the caller unretried; the
        caller decides how to react based on status code / JSON body.
        ZAP's own API errors are deterministic, so retrying them wastes
        wall-clock budget on a scan that was already going to fail.
        """
        for attempt in range(1, _RETRY_MAX_ATTEMPTS + 1):
            try:
                return self._client.get(path, params=query)
            except _RETRY_EXCEPTIONS as exc:
                _log.warning(
                    "zap_client_retry attempt=%d/%d path=%s error_type=%s error=%s",
                    attempt,
                    _RETRY_MAX_ATTEMPTS,
                    path,
                    type(exc).__name__,
                    exc,
                )
                if attempt >= _RETRY_MAX_ATTEMPTS:
                    raise ZapError(
                        f"ZAP request {path} failed after {_RETRY_MAX_ATTEMPTS} attempts: {exc}"
                    ) from exc
                time.sleep(_RETRY_BASE_DELAY_S * (3 ** (attempt - 1)))
            except httpx.HTTPError as exc:
                raise ZapError(f"ZAP request {path} failed: {exc}") from exc
        raise AssertionError("unreachable: retry loop exited without return or raise")

    # ---- version / health ----
    def version(self) -> str:
        payload = self._get("/JSON/core/view/version/")
        return str(payload.get("version", ""))

    # ---- spider ----
    def spider_scan(self, url: str, *, max_children: int = 30) -> str:
        payload = self._get(
            "/JSON/spider/action/scan/",
            url=url,
            maxChildren=str(max_children),
            recurse="true",
            subtreeOnly="false",
        )
        return str(payload.get("scan", "")) or ""

    def spider_status(self, scan_id: str) -> int:
        payload = self._get("/JSON/spider/view/status/", scanId=scan_id)
        try:
            return int(payload.get("status", "0"))
        except (TypeError, ValueError):
            return 0

    def set_spider_max_duration_mins(self, minutes: int) -> None:
        self._get("/JSON/spider/action/setOptionMaxDuration/", Integer=str(minutes))

    # ---- passive scan ----
    def pscan_records_to_scan(self) -> int:
        """Return the number of requests still queued for passive analysis.

        ZAP runs its passive rules asynchronously as the spider crawls,
        so the plugin must wait for this counter to reach 0 before
        reading alerts — otherwise late-arriving findings are missed.
        """
        payload = self._get("/JSON/pscan/view/recordsToScan/")
        try:
            return int(payload.get("recordsToScan", "0"))
        except (TypeError, ValueError):
            return 0

    # ---- alerts ----
    def alerts(self, baseurl: str) -> list[dict[str, Any]]:
        payload = self._get("/JSON/alert/view/alerts/", baseurl=baseurl)
        alerts_raw = payload.get("alerts", [])
        if not isinstance(alerts_raw, list):
            return []
        return [a for a in alerts_raw if isinstance(a, dict)]

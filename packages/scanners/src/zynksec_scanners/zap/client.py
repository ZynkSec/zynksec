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

from types import TracebackType
from typing import Any

import httpx


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
        try:
            response = self._client.get(path, params=query)
        except httpx.HTTPError as exc:
            raise ZapError(f"ZAP request {path} failed: {exc}") from exc
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

    # ---- active scan ----
    def ascan_scan(self, url: str) -> str:
        payload = self._get(
            "/JSON/ascan/action/scan/",
            url=url,
            recurse="true",
            inScopeOnly="false",
        )
        return str(payload.get("scan", "")) or ""

    def ascan_status(self, scan_id: str) -> int:
        payload = self._get("/JSON/ascan/view/status/", scanId=scan_id)
        try:
            return int(payload.get("status", "0"))
        except (TypeError, ValueError):
            return 0

    def set_ascan_max_duration_mins(self, minutes: int) -> None:
        self._get(
            "/JSON/ascan/action/setOptionMaxScanDurationInMins/",
            Integer=str(minutes),
        )

    # ---- alerts ----
    def alerts(self, baseurl: str) -> list[dict[str, Any]]:
        payload = self._get("/JSON/alert/view/alerts/", baseurl=baseurl)
        alerts_raw = payload.get("alerts", [])
        if not isinstance(alerts_raw, list):
            return []
        return [a for a in alerts_raw if isinstance(a, dict)]

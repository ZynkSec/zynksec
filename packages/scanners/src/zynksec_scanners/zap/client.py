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

import time
from types import TracebackType
from typing import Any

import httpx
import structlog

_log = structlog.get_logger(__name__)

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
                    "zap_client_retry",
                    attempt=attempt,
                    max_attempts=_RETRY_MAX_ATTEMPTS,
                    path=path,
                    error_type=type(exc).__name__,
                    error=str(exc),
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

    # ---- session reset ----
    def new_session(self) -> None:
        """Reset the ZAP session — discards alerts, history, sites tree.

        SAFE_ACTIVE compares finding counts against a baseline PASSIVE
        scan, so each scan must start from a clean slate; otherwise the
        second scan inherits alerts the first one accumulated.
        ``overwrite=true`` drops the in-memory session without writing
        a session file (we don't persist sessions in Phase 0).
        """
        self._get("/JSON/core/action/newSession/", overwrite="true")

    # ---- active scan: policy management ----
    def ascan_scan_policy_names(self) -> list[str]:
        """List currently-defined scan policies."""
        payload = self._get("/JSON/ascan/view/scanPolicyNames/")
        names_raw = payload.get("scanPolicyNames", [])
        if not isinstance(names_raw, list):
            return []
        return [str(n) for n in names_raw]

    def ascan_remove_scan_policy(self, name: str) -> None:
        """Remove a scan policy.  No-op if it doesn't exist (idempotent)."""
        if name not in self.ascan_scan_policy_names():
            return
        self._get("/JSON/ascan/action/removeScanPolicy/", scanPolicyName=name)

    def ascan_add_scan_policy(
        self,
        name: str,
        *,
        attack_strength: str,
        alert_threshold: str,
    ) -> None:
        """Add a scan policy at the given strength + threshold.

        ZAP rejects duplicate policy names with ``already_exists``; the
        plugin's ``_apply_safe_policy`` calls ``ascan_remove_scan_policy``
        first to keep the operation idempotent.
        """
        self._get(
            "/JSON/ascan/action/addScanPolicy/",
            scanPolicyName=name,
            attackStrength=attack_strength,
            alertThreshold=alert_threshold,
        )

    def ascan_disable_scanners(self, ids: list[int], *, scan_policy_name: str) -> None:
        """Disable scanners by id within a named policy.

        Comma-separated id list — ZAP accepts a single batch call so the
        policy reaches its final state in one round-trip rather than N.
        """
        if not ids:
            return
        self._get(
            "/JSON/ascan/action/disableScanners/",
            ids=",".join(str(i) for i in sorted(ids)),
            scanPolicyName=scan_policy_name,
        )

    def ascan_set_option_thread_per_host(self, threads: int) -> None:
        """Cap concurrent active-scan threads per target host (politeness)."""
        self._get("/JSON/ascan/action/setOptionThreadPerHost/", Integer=str(threads))

    def ascan_set_option_delay_in_ms(self, delay_ms: int) -> None:
        """Insert ``delay_ms`` between active-scan requests (politeness)."""
        self._get("/JSON/ascan/action/setOptionDelayInMs/", Integer=str(delay_ms))

    # ---- active scan: lifecycle ----
    def ascan_scan(self, url: str, *, scan_policy_name: str) -> str:
        """Start an active scan against ``url`` with the named policy.

        Returns ZAP's scan id (a string of digits) so the caller can poll
        ``ascan_status``.  ``recurse=true`` re-uses what the spider
        discovered; ``inScopeOnly=false`` because we don't define a
        ZAP scope in Phase 1 — the target URL itself is the scope.
        """
        payload = self._get(
            "/JSON/ascan/action/scan/",
            url=url,
            recurse="true",
            inScopeOnly="false",
            scanPolicyName=scan_policy_name,
        )
        return str(payload.get("scan", "")) or ""

    def ascan_status(self, scan_id: str) -> int:
        payload = self._get("/JSON/ascan/view/status/", scanId=scan_id)
        try:
            return int(payload.get("status", "0"))
        except (TypeError, ValueError):
            return 0

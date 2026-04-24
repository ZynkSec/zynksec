"""OWASP ZAP plugin — the one concrete :class:`ScannerPlugin` in Phase 0.

Phase 0 ships the PASSIVE scan profile only:

    1. spider                          — quick crawl, bounded
    2. passive-scan queue drain        — pscan/view/recordsToScan → 0
    3. alerts view                     — fetch everything ZAP noticed

Active-scan profiles (``SAFE_ACTIVE``, ``AGGRESSIVE``) are declared on
:class:`zynksec_scanners.types.ScanProfile` but not implemented here;
they raise :class:`NotImplementedError` until Glitchtip + structlog
correlation give us the observability to diagnose scan-side failures
live.  The decision is memorialised in the Week-3 post-mortem — active
scanning has unbounded off-heap growth on parameter-rich targets and
we exhausted the cgroup-tuning lever across four iterations.

Each alert becomes zero-or-one Findings via :meth:`normalize`.  CLAUDE.md §5:
only :class:`ZapClient` speaks HTTP to :8090 — this plugin is pure
orchestration + mapping.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any, cast

import structlog
from zynksec_schema import (
    Confidence,
    Evidence,
    Finding,
    Lifecycle,
    Location,
    Severity,
    SeverityLevel,
    Taxonomy,
    compute_fingerprint,
)

from zynksec_scanners.base import ScannerPlugin
from zynksec_scanners.types import (
    HealthStatus,
    RawScanResult,
    ScanContext,
    ScanProfile,
    Target,
)
from zynksec_scanners.zap.client import ZapClient, ZapError
from zynksec_scanners.zap.owasp_mapping import owasp_for_cwe
from zynksec_scanners.zap.payload_families import family_for

_log = structlog.get_logger(__name__)

_RISK_TO_LEVEL: dict[str, SeverityLevel] = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}
_CONFIDENCE_MAP: dict[str, Confidence] = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    # ZAP sometimes uses "User Confirmed" / "Confirmed"; collapse to high.
    "user confirmed": "high",
    "confirmed": "high",
    "false positive": "low",
}


class ZapPlugin(ScannerPlugin):
    """OWASP ZAP Stable — Phase-0 PASSIVE profile."""

    id = "zap"
    display_name = "OWASP ZAP"
    engine_version = "stable"
    supported_target_kinds: set[str] = {"web_app"}
    supported_intensities: set[str] = {ScanProfile.PASSIVE.value}
    required_capabilities: set[str] = set()

    # Phase-0 tuning.  Spider bounds keep the integration test under
    # the 5-minute budget; the passive queue typically drains in under
    # a minute on a Juice-Shop-sized target.  Phase 1 makes these
    # per-scan config.
    _POLL_INTERVAL_S: float = 2.0
    _SPIDER_CEILING_S: float = 120.0
    _PSCAN_DRAIN_CEILING_S: float = 120.0
    _SPIDER_MAX_CHILDREN: int = 25
    _SPIDER_MAX_DURATION_MIN: int = 2
    _RESPONSE_EXCERPT_LIMIT: int = 4096

    def __init__(self, client: ZapClient) -> None:
        self._client = client

    # ---- contract ----
    def supports(self, target: Target) -> bool:
        return target.kind in self.supported_target_kinds

    def prepare(self, target: Target) -> ScanContext:
        # Reachability + version probe.  Raises ZapError if ZAP isn't
        # up; the worker catches and marks the scan failed.
        version = self._client.version()
        self._client.set_spider_max_duration_mins(self._SPIDER_MAX_DURATION_MIN)
        return ScanContext(
            target=target,
            metadata={"engine_version": version},
        )

    def run(self, context: ScanContext) -> RawScanResult:
        profile = context.target.scan_profile
        if profile is not ScanProfile.PASSIVE:
            raise NotImplementedError(
                f"scan profile {profile.value!r} pending Week 4 observability"
            )

        url = context.target.url
        _log.info("zap.run.start", url=url, profile=profile.value)

        spider_id = self._client.spider_scan(
            url,
            max_children=self._SPIDER_MAX_CHILDREN,
        )
        self._poll(
            lambda: self._client.spider_status(spider_id),
            ceiling_s=self._SPIDER_CEILING_S,
            name="spider",
            reached=lambda status: status >= 100,
        )

        # Wait for the passive-scan queue to drain.  ZAP's passive
        # rules run asynchronously during the crawl, so "spider done"
        # doesn't mean "alerts finalised"; we need recordsToScan == 0.
        self._poll(
            lambda: self._client.pscan_records_to_scan(),
            ceiling_s=self._PSCAN_DRAIN_CEILING_S,
            name="pscan",
            reached=lambda remaining: remaining == 0,
        )

        alerts = self._client.alerts(url)
        _log.info("zap.run.complete", url=url, alerts=len(alerts))
        return RawScanResult(
            engine="zap",
            payload={"alerts": alerts, "baseurl": url},
        )

    def normalize(
        self,
        raw: RawScanResult,
        context: ScanContext,
    ) -> Iterator[Finding]:
        alerts_raw = raw.payload.get("alerts", [])
        if not isinstance(alerts_raw, list):
            return iter([])
        alerts: list[dict[str, Any]] = [a for a in alerts_raw if isinstance(a, dict)]
        return self._normalize_alerts(alerts, context)

    def teardown(self, context: ScanContext) -> None:
        # No ZAP context / session artefacts to remove in Phase 0.
        # Week 4 may add /JSON/core/action/newSession/ before each scan
        # so teardown has something to do.
        del context

    def health_check(self) -> HealthStatus:
        try:
            version = self._client.version()
        except ZapError as exc:
            return HealthStatus(ok=False, message=str(exc))
        return HealthStatus(ok=True, engine_version=version)

    # ---- helpers ----
    def _poll(
        self,
        read_status: Any,
        *,
        ceiling_s: float,
        name: str,
        reached: Any,
    ) -> None:
        """Poll ``read_status`` at ``_POLL_INTERVAL_S`` until ``reached``.

        ``reached`` is the predicate that ends the loop — spider uses
        ``status >= 100``; passive-scan drain uses ``remaining == 0``.
        """
        deadline = time.monotonic() + ceiling_s
        last_status: int | None = None
        while time.monotonic() < deadline:
            status = int(read_status())
            if status != last_status:
                _log.info("zap.progress", phase=name, value=status)
                last_status = status
            if reached(status):
                return
            time.sleep(self._POLL_INTERVAL_S)
        raise TimeoutError(
            f"ZAP {name} did not settle within {ceiling_s:.0f}s (last={last_status})"
        )

    def _normalize_alerts(
        self,
        alerts: Iterable[dict[str, Any]],
        context: ScanContext,
    ) -> Iterator[Finding]:
        seen: set[str] = set()
        for alert in alerts:
            finding = self._alert_to_finding(alert, context)
            if finding is None:
                continue
            if finding.fingerprint in seen:
                continue
            seen.add(finding.fingerprint)
            yield finding

    def _alert_to_finding(
        self,
        alert: dict[str, Any],
        context: ScanContext,
    ) -> Finding | None:
        plugin_id = str(alert.get("pluginId") or "").strip()
        if not plugin_id:
            return None
        try:
            ord_value = int(plugin_id)
        except ValueError:
            return None

        family = family_for(plugin_id)
        zynksec_id = f"ZYN-DAST-{family.upper().replace('-', '_')}-{ord_value:05d}"

        risk = (str(alert.get("risk") or "")).strip().lower()
        level: SeverityLevel | None = _RISK_TO_LEVEL.get(risk)
        if level is None:
            _log.debug("zap.alert.unknown_risk", risk=risk, plugin_id=plugin_id)
            return None

        confidence_raw = (str(alert.get("confidence") or "")).strip().lower()
        confidence: Confidence = _CONFIDENCE_MAP.get(confidence_raw, "low")

        cwe = _parse_cwe(alert.get("cweid"))

        url = str(alert.get("url", "") or context.target.url)
        method = (str(alert.get("method", "")) or "GET").upper()
        parameter_raw = alert.get("param")
        parameter = str(parameter_raw) if parameter_raw else None

        now = datetime.now(UTC)
        fingerprint = compute_fingerprint(
            project_id=context.target.project_id,
            zynksec_id=zynksec_id,
            url=url,
            method=method,
            parameter=parameter,
            payload_family=family,
        )

        attack = str(alert.get("attack", "") or "")
        evidence_text = str(alert.get("evidence", "") or "")
        response_excerpt = evidence_text[: self._RESPONSE_EXCERPT_LIMIT]

        return Finding(
            id=uuid.uuid4(),
            fingerprint=fingerprint,
            schema_version=1,
            scan_id=context.target.scan_id,
            taxonomy=Taxonomy(
                zynksec_id=zynksec_id,
                cwe=cwe,
                owasp_top10=owasp_for_cwe(cwe),
            ),
            severity=Severity(level=level, confidence=confidence),
            location=Location(url=url, method=method, parameter=parameter),
            evidence=Evidence(
                engine="zap",
                rule_id=plugin_id,
                request=attack,
                response_excerpt=response_excerpt,
            ),
            lifecycle=Lifecycle(
                status="open",
                first_seen_at=now,
                last_seen_at=now,
            ),
        )


def _parse_cwe(raw: Any) -> int | None:
    if raw is None:
        return None
    try:
        value = int(cast(str, raw))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None

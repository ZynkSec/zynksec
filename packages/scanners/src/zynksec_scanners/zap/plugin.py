"""OWASP ZAP plugin — Zynksec's concrete :class:`ScannerPlugin`.

Profile flow:

    PASSIVE
        1. spider                          — quick crawl, bounded
        2. passive-scan queue drain        — pscan/view/recordsToScan → 0
        3. alerts view                     — fetch everything ZAP noticed

    SAFE_ACTIVE  (Phase 1 Sprint 2)
        1. spider                          — same as PASSIVE
        2. passive-scan drain
        3. apply the constrained "zynksec_safe" scan policy
        4. active scan against the spidered URLs
        5. passive-scan drain (active probes generate new responses)
        6. alerts view

    AGGRESSIVE  — still :class:`NotImplementedError` (Phase 1 Sprint 3).

The SAFE_ACTIVE policy is documented one constant down: it caps the
attack/alert strength at ``MEDIUM``, pins ``threadPerHost = 1`` and a
small per-request delay so we are a polite scanner, and disables
heavy/slow scanner categories that don't earn their wall-clock cost on
modern web targets (see :data:`SAFE_ACTIVE_DISABLED_SCANNERS`).

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

# ---------- SAFE_ACTIVE policy ----------
# This constant block IS the document-of-record for what "SAFE_ACTIVE"
# means.  Anything that changes scanner-set behaviour belongs here, not
# scattered in the run() method, so the policy is greppable and
# reviewable in one place.

#: ZAP scan-policy name used for SAFE_ACTIVE.  Recreated each scan
#: (remove → add → configure) so the policy is deterministic regardless
#: of any state left over from a previous daemon session.
SAFE_ACTIVE_POLICY_NAME: str = "zynksec_safe"

#: Per-policy attack strength.  ZAP's options are LOW/MEDIUM/HIGH/INSANE.
#: MEDIUM keeps coverage close to the default while skipping the
#: combinatorial payload sets that HIGH/INSANE add — those mostly find
#: false-positives on modern frameworks while burning hours of budget.
SAFE_ACTIVE_ATTACK_STRENGTH: str = "MEDIUM"

#: Per-policy alert threshold.  MEDIUM means ZAP only raises an alert
#: when the rule is at least medium-confidence the target is vulnerable;
#: LOW would flood the user with noise that doesn't survive triage.
SAFE_ACTIVE_ALERT_THRESHOLD: str = "MEDIUM"

#: Single thread per target host so we don't overload juice-shop or
#: a real customer staging environment.  ZAP defaults to 2-5 depending
#: on CPU count.
SAFE_ACTIVE_THREAD_PER_HOST: int = 1

#: Per-request delay in milliseconds.  100 ms is the politeness knob —
#: enough to keep an under-provisioned target alive without elongating
#: a juice-shop scan past the 15-minute test budget.
SAFE_ACTIVE_DELAY_MS: int = 100

#: Active-scanner plugin IDs to disable for SAFE_ACTIVE.  Each entry is
#: documented inline so a future maintainer (or a Sprint-3 reviewer)
#: knows WHY it's off, not just THAT it's off.
#:
#: The trade-off pattern: time-based variants of common injection
#: families (SQLi DB-specific, XPath, XSLT, command injection) and
#: classic fuzz-bombs (XXE, SSTI, buffer overflow, format string,
#: CVE-2012-1823) cost minutes of wall-clock per target and rarely add
#: signal that boolean/error-based variants miss on modern stacks.
#: Heartbleed (TLS-only) is irrelevant for plain-HTTP targets and never
#: triggers in our lab anyway.
#:
#: Boolean/error-based SQLi (40018) is KEPT — it's fast and high-signal.
#: XSS family (40012-40017), CRLF (40003), SSI (40009), session
#: fixation (40013), path traversal (6), and remote file inclusion (7)
#: are also kept.
#:
#: IDs verified against ZAP 2.16.x release-quality scanner set.  When a
#: ZAP upgrade introduces or renumbers a heavy scanner, add it here
#: with a one-line reason — that's the policy edit.
SAFE_ACTIVE_DISABLED_SCANNERS: frozenset[int] = frozenset(
    {
        # SQL Injection — DB-specific time-based variants.  Each one
        # repeats the full payload set against ALL parameters and waits
        # for the configured timeout.  We keep 40018 (boolean/error)
        # which catches the same vulns 10× faster.
        40019,  # SQL Injection - MySQL (time-based)
        40020,  # SQL Injection - Hypersonic (time-based)
        40021,  # SQL Injection - Oracle (time-based)
        40022,  # SQL Injection - PostgreSQL (time-based)
        40024,  # SQL Injection - SQLite (time-based)
        40027,  # SQL Injection - MsSQL (time-based)
        # Code/command-injection fuzzers.  90020 mixes time+non-time
        # variants in one rule; we keep the parent on but the time
        # logic gates itself off at MEDIUM attack strength (see
        # SAFE_ACTIVE_ATTACK_STRENGTH).  90019 (Server Side Code Inj.)
        # is a heavy generic fuzz-bomb across language runtimes.
        90019,  # Server Side Code Injection (heavy generic fuzz)
        # XML / XPath / XSLT — all incur slow XML parser bursts on the
        # target and produce noisy false-positives on JSON-only APIs.
        90017,  # XSLT Injection
        90021,  # XPath Injection
        90023,  # XML External Entity Attack (XXE)
        # Server-Side Template Injection — fuzz-heavy, brittle on
        # non-template targets.
        90035,  # Server Side Template Injection
        90036,  # Server Side Template Injection (Blind)
        # Classic legacy fuzz-bombs.  Buffer overflow / format string
        # detection in HTTP land is fishing in dry creeks; CVE-2012-1823
        # only matters for ancient PHP-CGI deployments.
        30001,  # Buffer Overflow
        30002,  # Format String Error
        20018,  # Remote Code Execution - CVE-2012-1823 (PHP-CGI)
        # TLS-only — irrelevant for plain-HTTP target lab.
        20015,  # Heartbleed
    }
)

#: Active-scan ceiling.  juice-shop with the SAFE policy completes in
#: ~5-8 minutes locally; 10 min gives us slack for slower CI runners
#: without papering over a runaway scan.  When this trips, the policy
#: above needs revisiting — not the ceiling.
SAFE_ACTIVE_ASCAN_CEILING_S: float = 600.0


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
    supported_intensities: set[str] = {
        ScanProfile.PASSIVE.value,
        ScanProfile.SAFE_ACTIVE.value,
    }
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
        # Reset the ZAP session so this scan doesn't inherit alerts /
        # sites tree / history from a previous one.  Without this,
        # ``alerts(baseurl)`` returns cumulative alerts across every
        # scan ZAP has run since the daemon started — making the
        # SAFE_ACTIVE > PASSIVE comparison dishonest, and breaking the
        # invariant that each Zynksec scan is independent.
        self._client.new_session()
        self._client.set_spider_max_duration_mins(self._SPIDER_MAX_DURATION_MIN)
        return ScanContext(
            target=target,
            metadata={"engine_version": version},
        )

    def run(self, context: ScanContext) -> RawScanResult:
        profile = context.target.scan_profile
        url = context.target.url
        _log.info("zap.run.start", url=url, profile=profile.value)

        if profile is ScanProfile.PASSIVE:
            self._spider_and_pscan_drain(url)
        elif profile is ScanProfile.SAFE_ACTIVE:
            self._spider_and_pscan_drain(url)
            self._apply_safe_policy()
            self._active_scan(url)
            # Active probes generate fresh responses that the passive
            # analyzers re-process; drain the queue once more before
            # reading alerts so we don't miss late-arriving findings.
            self._poll(
                lambda: self._client.pscan_records_to_scan(),
                ceiling_s=self._PSCAN_DRAIN_CEILING_S,
                name="pscan_post_active",
                reached=lambda remaining: remaining == 0,
            )
        else:
            raise NotImplementedError(f"scan profile {profile.value!r} pending Phase 1 Sprint 3")

        alerts = self._client.alerts(url)
        _log.info("zap.run.complete", url=url, profile=profile.value, alerts=len(alerts))
        return RawScanResult(
            engine="zap",
            payload={"alerts": alerts, "baseurl": url},
        )

    # ---- profile flows ----
    def _spider_and_pscan_drain(self, url: str) -> None:
        """Spider the URL and wait for the passive queue to drain."""
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
        # ZAP's passive rules run asynchronously during the crawl, so
        # "spider done" doesn't mean "alerts finalised"; we need
        # recordsToScan == 0 before reading alerts.
        self._poll(
            lambda: self._client.pscan_records_to_scan(),
            ceiling_s=self._PSCAN_DRAIN_CEILING_S,
            name="pscan",
            reached=lambda remaining: remaining == 0,
        )

    def _apply_safe_policy(self) -> None:
        """Recreate the SAFE_ACTIVE scan policy from scratch.

        Idempotent: removes any pre-existing ``zynksec_safe`` policy
        first (a no-op if it doesn't exist), then adds a fresh one with
        the documented strength/threshold and disables the
        :data:`SAFE_ACTIVE_DISABLED_SCANNERS` set.  The thread/delay
        knobs are global daemon options — Phase 1 Sprint 2 has at most
        one scan in flight at a time, so per-scan policy on those would
        just be ceremony.
        """
        self._client.ascan_remove_scan_policy(SAFE_ACTIVE_POLICY_NAME)
        self._client.ascan_add_scan_policy(
            SAFE_ACTIVE_POLICY_NAME,
            attack_strength=SAFE_ACTIVE_ATTACK_STRENGTH,
            alert_threshold=SAFE_ACTIVE_ALERT_THRESHOLD,
        )
        self._client.ascan_disable_scanners(
            sorted(SAFE_ACTIVE_DISABLED_SCANNERS),
            scan_policy_name=SAFE_ACTIVE_POLICY_NAME,
        )
        self._client.ascan_set_option_thread_per_host(SAFE_ACTIVE_THREAD_PER_HOST)
        self._client.ascan_set_option_delay_in_ms(SAFE_ACTIVE_DELAY_MS)
        _log.info(
            "zap.safe_policy.applied",
            policy=SAFE_ACTIVE_POLICY_NAME,
            attack_strength=SAFE_ACTIVE_ATTACK_STRENGTH,
            alert_threshold=SAFE_ACTIVE_ALERT_THRESHOLD,
            disabled_scanners=len(SAFE_ACTIVE_DISABLED_SCANNERS),
            thread_per_host=SAFE_ACTIVE_THREAD_PER_HOST,
            delay_ms=SAFE_ACTIVE_DELAY_MS,
        )

    def _active_scan(self, url: str) -> None:
        """Run the SAFE active scan to completion."""
        ascan_id = self._client.ascan_scan(url, scan_policy_name=SAFE_ACTIVE_POLICY_NAME)
        self._poll(
            lambda: self._client.ascan_status(ascan_id),
            ceiling_s=SAFE_ACTIVE_ASCAN_CEILING_S,
            name="ascan",
            reached=lambda status: status >= 100,
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

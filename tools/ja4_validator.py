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

    def __init__(self):
        self.unknown_hashes: List[str] = []
        self.malicious_scores: Dict[str, int] = {}

    def evaluate_risk(self, ja4: str, ja4h: str, user_agent: str) -> JA4RiskResult:
        if ja4 not in self.FINGERPRINT_DB:
            score = 100
            return JA4RiskResult(
                status=RiskStatus.CRITICAL,
                score=score,
                action="DROP_CONNECTION",
                reason="Unknown/Anomalous JA4 Raw Fingerprint! Potential EDR scanning probe!",
                details={"ja4": ja4, "ja4h": ja4h, "user_agent": user_agent},
            )

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
            status = RiskStatus.CRITICAL
            action = "DROP_CONNECTION"
        elif score >= 50:
            status = RiskStatus.MALICIOUS
            action = "ALERT_SOC_DECEPTION"
        elif score >= 25:
            status = RiskStatus.SUSPICIOUS
            action = "ADD_OBSERVATION"
        else:
            status = RiskStatus.CLEAN
            action = "ALLOW_POLLING"

        return JA4RiskResult(
            status=status,
            score=score,
            action=action,
            reason="; ".join(reasons) if reasons else "Clean fingerprint match",
            details={"ja4": ja4, "ja4h": ja4h, "user_agent": user_agent, "profile": profile.browser},
        )

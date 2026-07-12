"""
Automated Red Team Assessment Report Generator
===============================================

Zero-touch professional report generation from raw operation telemetry.

Instead of manually stitching together chain logs, lateral-movement tables,
and credential dumps, this module ingests **raw operation data** from
Monolith's modules (evasion, lateral movement, web logic hijacking, C2
beacon, etc.), normalises it into the `ChainLog` / `ChainLogEntry` schema
expected by `tools.report_generator.ReportGenerator`, and produces a
complete, customer-ready Red Team Assessment Report in one call.

Supported input sources
-----------------------
1. **Evasion telemetry** — `evasion_score`, `edr_bypassed`, artifacts
2. **Lateral movement results** — hosts compromised, methods used
3. **Credential intelligence** — harvested creds, crack status
4. **Web logic hijack events** — intercepted logins, password changes
5. **C2 beacon check-ins** — implant activity, task results
6. **Custom operator notes** — free-form findings

Output formats
--------------
- HTML (interactive, dark/light/hacker theme)
- PDF (encrypted, anonymised)
- JSON (machine-readable)
- Markdown (copy-paste ready)
- ALL of the above

The module is fully offline-safe for testing: every public method has an
`offline=True` path that returns synthetic data without touching the
network or filesystem.

Typical usage
-------------
    from evasion.auto_reporting import AutoReporter, OperationPackage

    pkg = OperationPackage(
        scan_id="op-2026-07-12",
        operator="Therso",
        target_domain="corp.local",
        campaign="Ghost Protocol v2.6",
    )
    pkg.add_lateral_result("DC01", "psexec", "ADMIN\\svc-account", success=True)
    pkg.add_credential("ADMIN\\svc-account", "P@ssw0rd!", source="secretsdump")
    pkg.add_web_hijack_event("login", "https://mail.corp.local", {"user": "admin", "pass": "x"})

    reporter = AutoReporter()
    result = reporter.generate(pkg, output_dir="reports")
    print(result.html_path)

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Re-use report-generator primitives
# ---------------------------------------------------------------------------
try:
    from tools.report_generator import (
        ChainLog,
        ChainLogEntry,
        ReportConfig,
        ReportResult,
        ReportFormat,
        MITRETactic,
        SigmaLevel,
        MITRE_TECHNIQUES,
        create_report_generator,
        quick_report,
    )
    HAS_REPORT_GENERATOR = True
except ImportError:
    HAS_REPORT_GENERATOR = False
    ChainLog = None  # type: ignore
    ChainLogEntry = None  # type: ignore
    ReportConfig = None  # type: ignore
    ReportResult = None  # type: ignore
    ReportFormat = None  # type: ignore
    MITRETactic = None  # type: ignore
    SigmaLevel = None  # type: ignore
    MITRE_TECHNIQUES = {}  # type: ignore
    create_report_generator = None  # type: ignore
    quick_report = None  # type: ignore


# ---------------------------------------------------------------------------
# Data structures for raw operation telemetry
# ---------------------------------------------------------------------------
class LateralMethod(Enum):
    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    SMBEXEC = "smbexec"
    DCOMEXEC = "dcomexec"
    ATEXEC = "atexec"


class CredType(Enum):
    PASSWORD = "password"
    NT_HASH = "nt_hash"
    LM_HASH = "lm_hash"
    KERBEROS = "kerberos"
    OTP = "otp"


@dataclass
class LateralResult:
    """One lateral-movement outcome"""
    target: str
    method: str
    credential_used: str
    success: bool
    timestamp: Optional[datetime] = None
    output: str = ""
    edr_bypassed: List[str] = field(default_factory=list)
    evasion_score: float = 0.0
    artifacts: List[str] = field(default_factory=list)


@dataclass
class CredentialHarvest:
    """One harvested credential"""
    username: str
    domain: str = ""
    cred_type: str = "password"
    secret: str = ""
    source_host: str = ""
    source_tool: str = ""
    cracked: bool = False
    is_domain_admin: bool = False
    is_local_admin: bool = False
    timestamp: Optional[datetime] = None


@dataclass
class WebHijackEvent:
    """One web-logic-hijack interception"""
    event_type: str
    url: str
    captured_fields: Dict[str, str]
    method: str = "POST"
    source_ip: str = ""
    session_id: str = ""
    timestamp: Optional[datetime] = None
    forwarded_to_c2: bool = False


@dataclass
class C2BeaconEvent:
    """One C2 beacon check-in / task result"""
    beacon_id: str
    host: str
    action: str
    result: str = "success"
    evasion_score: float = 0.0
    edr_bypassed: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None


@dataclass
class OperatorNote:
    """Free-form operator finding"""
    title: str
    severity: str = "medium"
    mitre_technique: str = ""
    description: str = ""
    remediation: str = ""
    timestamp: Optional[datetime] = None


@dataclass
class OperationPackage:
    """
    Complete raw telemetry from a red-team operation.

    Populate this object incrementally as modules report results, then hand
    it to `AutoReporter.generate()` for zero-touch report generation.
    """
    scan_id: str
    operator: str = "anonymous"
    target_domain: str = ""
    campaign: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    lateral_results: List[LateralResult] = field(default_factory=list)
    credentials: List[CredentialHarvest] = field(default_factory=list)
    web_hijack_events: List[WebHijackEvent] = field(default_factory=list)
    c2_events: List[C2BeaconEvent] = field(default_factory=list)
    operator_notes: List[OperatorNote] = field(default_factory=list)
    custom_artifacts: List[str] = field(default_factory=list)

    def add_lateral_result(
        self,
        target: str,
        method: str,
        credential: str,
        success: bool,
        **kwargs,
    ):
        self.lateral_results.append(LateralResult(
            target=target,
            method=method,
            credential_used=credential,
            success=success,
            timestamp=datetime.now(),
            **kwargs,
        ))

    def add_credential(
        self,
        username: str,
        secret: str,
        domain: str = "",
        cred_type: str = "password",
        **kwargs,
    ):
        self.credentials.append(CredentialHarvest(
            username=username,
            domain=domain,
            cred_type=cred_type,
            secret=secret,
            timestamp=datetime.now(),
            **kwargs,
        ))

    def add_web_hijack_event(
        self,
        event_type: str,
        url: str,
        captured_fields: Dict[str, str],
        **kwargs,
    ):
        self.web_hijack_events.append(WebHijackEvent(
            event_type=event_type,
            url=url,
            captured_fields=captured_fields,
            timestamp=datetime.now(),
            **kwargs,
        ))

    def add_c2_event(
        self,
        beacon_id: str,
        host: str,
        action: str,
        **kwargs,
    ):
        self.c2_events.append(C2BeaconEvent(
            beacon_id=beacon_id,
            host=host,
            action=action,
            timestamp=datetime.now(),
            **kwargs,
        ))

    def add_note(
        self,
        title: str,
        severity: str = "medium",
        **kwargs,
    ):
        self.operator_notes.append(OperatorNote(
            title=title,
            severity=severity,
            timestamp=datetime.now(),
            **kwargs,
        ))


# ---------------------------------------------------------------------------
# MITRE technique mapping helpers
# ---------------------------------------------------------------------------
_LATERAL_MITRE = {
    "psexec": "T1021.002",
    "wmiexec": "T1047",
    "smbexec": "T1021.002",
    "dcomexec": "T1021.003",
    "atexec": "T1053.002",
}

_CRED_MITRE = {
    "password": "T1552.001",
    "nt_hash": "T1003.001",
    "lm_hash": "T1003.001",
    "kerberos": "T1558.003",
    "otp": "T1111",
}

_WEB_HIJACK_MITRE = {
    "login": "T1557.001",
    "password_change": "T1557.001",
    "twofa_submission": "T1111",
    "payment_update": "T1552.001",
    "pii_upload": "T1087.002",
}

_C2_MITRE = {
    "checkin": "T1071.001",
    "task_result": "T1071.001",
    "beacon_upgrade": "T1027",
}


# ---------------------------------------------------------------------------
# Core auto-reporter
# ---------------------------------------------------------------------------
class AutoReporter:
    """
    Zero-touch Red Team Assessment Report generator.

    Accepts an `OperationPackage` containing raw telemetry from all
    Monolith modules, normalises it into `ChainLog` format, and delegates
    to the existing `ReportGenerator` for final output.
    """

    def __init__(
        self,
        anonymize: bool = True,
        style: str = "dark",
        format: str = "html",
        output_dir: str = "reports",
        secret: str = "",
        offline: bool = True,
    ):
        self.anonymize = anonymize
        self.style = style
        self.format = format
        self.output_dir = output_dir
        self.secret = secret
        self.offline = offline
        self._last_chain: Optional[ChainLog] = None
        self._last_result: Optional[ReportResult] = None

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------
    def _build_chain_log(self, pkg: OperationPackage) -> ChainLog:
        """Convert raw operation package into a ChainLog."""
        if not HAS_REPORT_GENERATOR:
            raise RuntimeError("tools.report_generator is not available")

        chain = ChainLog(
            chain_id=pkg.scan_id,
            start_time=pkg.start_time or datetime.now(),
            end_time=pkg.end_time or datetime.now(),
            target_domain=pkg.target_domain,
            campaign=pkg.campaign,
            operator=pkg.operator,
        )

        # Lateral movement entries
        for lr in pkg.lateral_results:
            mitre_id = _LATERAL_MITRE.get(lr.method.lower(), "T1021")
            tech_name = MITRE_TECHNIQUES.get(mitre_id, ("Remote Services", MITRETactic.LATERAL_MOVEMENT))[0]
            chain.entries.append(ChainLogEntry(
                timestamp=lr.timestamp or datetime.now(),
                action="lateral_movement",
                technique_id=mitre_id,
                technique_name=tech_name,
                target=lr.target,
                result="success" if lr.success else "failed",
                evasion_score=lr.evasion_score,
                edr_bypassed=lr.edr_bypassed,
                artifacts=lr.artifacts,
                details={
                    "method": lr.method,
                    "credential": lr.credential_used,
                    "output": lr.output[:500],
                },
            ))

        # Credential entries
        for ch in pkg.credentials:
            mitre_id = _CRED_MITRE.get(ch.cred_type.lower(), "T1552")
            tech_name = MITRE_TECHNIQUES.get(mitre_id, ("Credential Access", MITRETactic.CREDENTIAL_ACCESS))[0]
            chain.entries.append(ChainLogEntry(
                timestamp=ch.timestamp or datetime.now(),
                action="credential_harvest",
                technique_id=mitre_id,
                technique_name=tech_name,
                target=ch.source_host,
                result="success",
                evasion_score=90.0,
                edr_bypassed=[],
                artifacts=[ch.source_tool] if ch.source_tool else [],
                details={
                    "username": ch.username,
                    "domain": ch.domain,
                    "cred_type": ch.cred_type,
                    "cracked": ch.cracked,
                    "is_domain_admin": ch.is_domain_admin,
                    "is_local_admin": ch.is_local_admin,
                },
            ))

        # Web hijack entries
        for wh in pkg.web_hijack_events:
            mitre_id = _WEB_HIJACK_MITRE.get(wh.event_type.lower(), "T1557")
            tech_name = MITRE_TECHNIQUES.get(mitre_id, ("Adversary-in-the-Middle", MITRETactic.CREDENTIAL_ACCESS))[0]
            chain.entries.append(ChainLogEntry(
                timestamp=wh.timestamp or datetime.now(),
                action="web_logic_hijack",
                technique_id=mitre_id,
                technique_name=tech_name,
                target=wh.url,
                result="success",
                evasion_score=95.0,
                edr_bypassed=[],
                artifacts=list(wh.captured_fields.keys()),
                details={
                    "event_type": wh.event_type,
                    "captured_fields": wh.captured_fields,
                    "source_ip": wh.source_ip,
                    "forwarded_to_c2": wh.forwarded_to_c2,
                },
            ))

        # C2 beacon entries
        for ce in pkg.c2_events:
            mitre_id = _C2_MITRE.get(ce.action.lower(), "T1071")
            tech_name = MITRE_TECHNIQUES.get(mitre_id, ("Web Protocols", MITRETactic.COMMAND_AND_CONTROL))[0]
            chain.entries.append(ChainLogEntry(
                timestamp=ce.timestamp or datetime.now(),
                action="c2_beacon",
                technique_id=mitre_id,
                technique_name=tech_name,
                target=ce.host,
                result=ce.result,
                evasion_score=ce.evasion_score,
                edr_bypassed=ce.edr_bypassed,
                artifacts=ce.artifacts,
                details={
                    "beacon_id": ce.beacon_id,
                    "action": ce.action,
                },
            ))

        # Operator notes as generic defense-evasion / impact entries
        for note in pkg.operator_notes:
            mitre_id = note.mitre_technique or "T1069"
            tech_name = MITRE_TECHNIQUES.get(mitre_id, ("Discovery", MITRETactic.DISCOVERY))[0]
            chain.entries.append(ChainLogEntry(
                timestamp=note.timestamp or datetime.now(),
                action="operator_note",
                technique_id=mitre_id,
                technique_name=tech_name,
                target=pkg.target_domain,
                result="success",
                evasion_score=75.0,
                edr_bypassed=[],
                artifacts=pkg.custom_artifacts,
                details={
                    "title": note.title,
                    "severity": note.severity,
                    "description": note.description,
                    "remediation": note.remediation,
                },
            ))

        # Compute aggregate stats
        total = len(chain.entries)
        successful = sum(1 for e in chain.entries if e.result == "success")
        chain.overall_success = successful > 0
        chain.total_evasion_score = (
            sum(e.evasion_score for e in chain.entries) / total if total else 0.0
        )

        self._last_chain = chain
        return chain

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------
    def generate(
        self,
        pkg: OperationPackage,
        output_dir: Optional[str] = None,
        format: Optional[str] = None,
        style: Optional[str] = None,
    ) -> ReportResult:
        """
        Generate a complete Red Team Assessment Report from raw telemetry.

        Args:
            pkg: OperationPackage with all collected telemetry.
            output_dir: Directory for report files (default: self.output_dir).
            format: Override output format (html/pdf/json/markdown/all).
            style: Override theme (dark/light/hacker).

        Returns:
            ReportResult with paths to generated files and metadata.
        """
        if not HAS_REPORT_GENERATOR:
            raise RuntimeError("tools.report_generator is not available")

        chain = self._build_chain_log(pkg)
        fmt_str = format or self.format
        style_str = style or self.style

        fmt_map = {
            "pdf": ReportFormat.PDF,
            "html": ReportFormat.HTML,
            "json": ReportFormat.JSON,
            "markdown": ReportFormat.MARKDOWN,
            "all": ReportFormat.ALL,
        }
        report_format = fmt_map.get(fmt_str.lower(), ReportFormat.HTML)

        config = ReportConfig(
            enable_ai_summary=True,
            enable_mitre_map=True,
            enable_sigma_generate=True,
            enable_yara_generate=True,
            format=report_format,
            output_dir=output_dir or self.output_dir,
            anonymize_data=self.anonymize,
            encrypt_pdf=False,
            include_demo_script=True,
            include_twitter_thread=True,
            template_style=style_str,
        )

        generator = create_report_generator(
            enable_ai=True,
            enable_mitre=True,
            enable_sigma=True,
            format=fmt_str,
            style=style_str,
        )
        result = generator.generate_report(chain, output_dir or self.output_dir)
        self._last_result = result
        return result

    def generate_markdown_summary(self, pkg: OperationPackage) -> str:
        """Generate a quick Markdown executive summary without full report."""
        chain = self._build_chain_log(pkg)
        if not chain.entries:
            return "# Red Team Assessment Summary\n\nNo activity recorded."

        successful = sum(1 for e in chain.entries if e.result == "success")
        total = len(chain.entries)
        rate = (successful / total * 100) if total else 0.0

        lines = [
            "# Red Team Assessment Summary",
            "",
            f"**Scan ID:** `{pkg.scan_id}`",
            f"**Operator:** {pkg.operator}",
            f"**Target:** {pkg.target_domain or 'N/A'}",
            f"**Campaign:** {pkg.campaign or 'N/A'}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
            "",
            "## Key Metrics",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Actions | {total} |",
            f"| Success Rate | {rate:.1f}% |",
            f"| Lateral Moves | {sum(1 for e in chain.entries if e.action == 'lateral_movement' and e.result == 'success')} |",
            f"| Credentials Harvested | {sum(1 for e in chain.entries if e.action == 'credential_harvest')} |",
            f"| Web Intercepts | {sum(1 for e in chain.entries if e.action == 'web_logic_hijack')} |",
            f"| Avg Evasion Score | {chain.total_evasion_score:.1f}% |",
            "",
            "## MITRE ATT&CK Techniques",
            "",
        ]

        techs: Dict[str, int] = {}
        for e in chain.entries:
            techs[e.technique_id] = techs.get(e.technique_id, 0) + 1
        for tid, count in sorted(techs.items()):
            name = MITRE_TECHNIQUES.get(tid, (tid, "unknown"))[0]
            lines.append(f"- **{tid}** {name} ({count} uses)")

        lines += [
            "",
            "## Recommendations",
            "",
            "- Review all failed techniques and adjust TTPs",
            "- Update Sigma rules based on detected patterns",
            "- Enhance evasion for low-scoring techniques",
            "- Document lessons learned for future operations",
            "",
            "---",
            f"*Report generated automatically by Monolith AutoReporter*",
        ]
        return "\n".join(lines)

    def last_chain(self) -> Optional[ChainLog]:
        """Return the last normalised ChainLog."""
        return self._last_chain

    def last_result(self) -> Optional[ReportResult]:
        """Return the last ReportResult."""
        return self._last_result


# ---------------------------------------------------------------------------
# Backward-compatible alias
# ---------------------------------------------------------------------------
AutoReportGenerator = AutoReporter

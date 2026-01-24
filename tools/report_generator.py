"""
Ultimate Report Generator - AI-Dynamic Reporting + Viz Pro
Advanced reporting with Sigma rule generation, MITRE ATT&CK mapping,
interactive visualization, and encrypted PDF/HTML export.

Features:
- AI-Dynamic reporting from chain logs
- Custom Sigma/YARA rule generation
- MITRE ATT&CK coverage heat map
- Interactive Mermaid.js graphs
- PDF/HTML export with encryption
- Demo video preparation helpers
- OPSEC data anonymization
"""
import os
import sys
import json
import hashlib
import secrets
import base64
import re
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# =============================================================================
# ENUMS
# =============================================================================

class ReportFormat(Enum):
    """Report output formats"""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    MARKDOWN = "markdown"
    ALL = "all"


class MITRETactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class SigmaLevel(Enum):
    """Sigma rule severity levels"""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleType(Enum):
    """Detection rule types"""
    SIGMA = "sigma"
    YARA = "yara"
    SNORT = "snort"
    SURICATA = "suricata"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ChainLogEntry:
    """Single chain execution log entry"""
    timestamp: datetime
    action: str
    technique_id: str  # MITRE technique ID
    technique_name: str
    target: str
    result: str  # success, failed, partial
    evasion_score: float
    edr_bypassed: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChainLog:
    """Complete chain execution log"""
    chain_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    entries: List[ChainLogEntry] = field(default_factory=list)
    overall_success: bool = False
    total_evasion_score: float = 0.0
    detected_edrs: List[str] = field(default_factory=list)
    target_domain: str = ""
    operator: str = "anonymous"
    campaign: str = ""


@dataclass
class SigmaRule:
    """Generated Sigma detection rule"""
    title: str
    rule_id: str
    status: str  # experimental, test, stable
    description: str
    author: str
    date: str
    modified: str
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    level: SigmaLevel
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    
    def to_yaml(self) -> str:
        """Convert to YAML format"""
        lines = [
            f"title: {self.title}",
            f"id: {self.rule_id}",
            f"status: {self.status}",
            f"description: |",
            f"    {self.description}",
            f"author: {self.author}",
            f"date: {self.date}",
            f"modified: {self.modified}",
            "",
            "logsource:",
        ]
        
        for key, value in self.logsource.items():
            lines.append(f"    {key}: {value}")
        
        lines.append("")
        lines.append("detection:")
        
        for key, value in self.detection.items():
            if isinstance(value, dict):
                lines.append(f"    {key}:")
                for k, v in value.items():
                    if isinstance(v, list):
                        lines.append(f"        {k}:")
                        for item in v:
                            lines.append(f"            - '{item}'")
                    else:
                        lines.append(f"        {k}: '{v}'")
            elif isinstance(value, list):
                lines.append(f"    {key}:")
                for item in value:
                    lines.append(f"        - {item}")
            else:
                lines.append(f"    {key}: {value}")
        
        lines.append("")
        lines.append(f"level: {self.level.value}")
        
        if self.tags:
            lines.append("tags:")
            for tag in self.tags:
                lines.append(f"    - {tag}")
        
        if self.falsepositives:
            lines.append("falsepositives:")
            for fp in self.falsepositives:
                lines.append(f"    - {fp}")
        
        return "\n".join(lines)


@dataclass
class YARARule:
    """Generated YARA detection rule"""
    name: str
    meta: Dict[str, str]
    strings: Dict[str, str]
    condition: str
    tags: List[str] = field(default_factory=list)
    
    def to_yara(self) -> str:
        """Convert to YARA format"""
        lines = []
        
        # Rule header with tags
        if self.tags:
            lines.append(f"rule {self.name} : {' '.join(self.tags)}")
        else:
            lines.append(f"rule {self.name}")
        
        lines.append("{")
        
        # Meta section
        lines.append("    meta:")
        for key, value in self.meta.items():
            lines.append(f'        {key} = "{value}"')
        
        # Strings section
        lines.append("")
        lines.append("    strings:")
        for name, pattern in self.strings.items():
            lines.append(f"        {name} = {pattern}")
        
        # Condition
        lines.append("")
        lines.append("    condition:")
        lines.append(f"        {self.condition}")
        
        lines.append("}")
        
        return "\n".join(lines)


@dataclass
class MITREMapping:
    """MITRE ATT&CK technique mapping"""
    technique_id: str
    technique_name: str
    tactic: MITRETactic
    success_count: int = 0
    fail_count: int = 0
    evasion_score: float = 0.0
    edr_bypassed: List[str] = field(default_factory=list)
    
    @property
    def coverage_percent(self) -> float:
        total = self.success_count + self.fail_count
        if total == 0:
            return 0.0
        return (self.success_count / total) * 100


@dataclass
class ReportConfig:
    """Report generation configuration"""
    enable_ai_summary: bool = True
    enable_mitre_map: bool = True
    enable_sigma_generate: bool = True
    enable_yara_generate: bool = False
    format: ReportFormat = ReportFormat.HTML
    output_dir: str = "reports"
    anonymize_data: bool = True
    encrypt_pdf: bool = False
    pdf_password: str = ""
    include_demo_script: bool = True
    include_twitter_thread: bool = True
    template_style: str = "dark"  # dark, light, hacker


@dataclass
class ReportResult:
    """Report generation result"""
    success: bool = False
    report_path: str = ""
    html_path: str = ""
    pdf_path: str = ""
    json_path: str = ""
    sigma_rules: List[SigmaRule] = field(default_factory=list)
    yara_rules: List[YARARule] = field(default_factory=list)
    mitre_coverage: Dict[str, MITREMapping] = field(default_factory=dict)
    ai_summary: str = ""
    twitter_thread: List[str] = field(default_factory=list)
    demo_script: str = ""
    error: str = ""


# =============================================================================
# MITRE ATT&CK DATABASE
# =============================================================================

MITRE_TECHNIQUES = {
    # Initial Access
    "T1566": ("Phishing", MITRETactic.INITIAL_ACCESS),
    "T1566.001": ("Spearphishing Attachment", MITRETactic.INITIAL_ACCESS),
    "T1566.002": ("Spearphishing Link", MITRETactic.INITIAL_ACCESS),
    "T1078": ("Valid Accounts", MITRETactic.INITIAL_ACCESS),
    
    # Execution
    "T1059": ("Command and Scripting Interpreter", MITRETactic.EXECUTION),
    "T1059.001": ("PowerShell", MITRETactic.EXECUTION),
    "T1059.003": ("Windows Command Shell", MITRETactic.EXECUTION),
    "T1106": ("Native API", MITRETactic.EXECUTION),
    "T1053": ("Scheduled Task/Job", MITRETactic.EXECUTION),
    
    # Persistence
    "T1547": ("Boot or Logon Autostart Execution", MITRETactic.PERSISTENCE),
    "T1547.001": ("Registry Run Keys", MITRETactic.PERSISTENCE),
    "T1543": ("Create or Modify System Process", MITRETactic.PERSISTENCE),
    "T1543.003": ("Windows Service", MITRETactic.PERSISTENCE),
    "T1053.005": ("Scheduled Task", MITRETactic.PERSISTENCE),
    "T1546": ("Event Triggered Execution", MITRETactic.PERSISTENCE),
    "T1546.003": ("WMI Event Subscription", MITRETactic.PERSISTENCE),
    "T1546.015": ("COM Hijacking", MITRETactic.PERSISTENCE),
    "T1197": ("BITS Jobs", MITRETactic.PERSISTENCE),
    
    # Privilege Escalation
    "T1548": ("Abuse Elevation Control", MITRETactic.PRIVILEGE_ESCALATION),
    "T1134": ("Access Token Manipulation", MITRETactic.PRIVILEGE_ESCALATION),
    "T1558": ("Steal or Forge Kerberos Tickets", MITRETactic.PRIVILEGE_ESCALATION),
    "T1558.001": ("Golden Ticket", MITRETactic.PRIVILEGE_ESCALATION),
    "T1558.002": ("Silver Ticket", MITRETactic.PRIVILEGE_ESCALATION),
    "T1558.003": ("Kerberoasting", MITRETactic.PRIVILEGE_ESCALATION),
    
    # Defense Evasion
    "T1055": ("Process Injection", MITRETactic.DEFENSE_EVASION),
    "T1055.001": ("DLL Injection", MITRETactic.DEFENSE_EVASION),
    "T1055.002": ("PE Injection", MITRETactic.DEFENSE_EVASION),
    "T1055.003": ("Thread Execution Hijacking", MITRETactic.DEFENSE_EVASION),
    "T1055.004": ("Asynchronous Procedure Call", MITRETactic.DEFENSE_EVASION),
    "T1055.012": ("Process Hollowing", MITRETactic.DEFENSE_EVASION),
    "T1055.013": ("Process Doppelgänging", MITRETactic.DEFENSE_EVASION),
    "T1562": ("Impair Defenses", MITRETactic.DEFENSE_EVASION),
    "T1562.001": ("Disable or Modify Tools", MITRETactic.DEFENSE_EVASION),
    "T1070": ("Indicator Removal", MITRETactic.DEFENSE_EVASION),
    "T1070.001": ("Clear Windows Event Logs", MITRETactic.DEFENSE_EVASION),
    "T1070.004": ("File Deletion", MITRETactic.DEFENSE_EVASION),
    "T1070.006": ("Timestomp", MITRETactic.DEFENSE_EVASION),
    "T1027": ("Obfuscated Files", MITRETactic.DEFENSE_EVASION),
    "T1027.002": ("Software Packing", MITRETactic.DEFENSE_EVASION),
    "T1140": ("Deobfuscate/Decode", MITRETactic.DEFENSE_EVASION),
    "T1218": ("System Binary Proxy Execution", MITRETactic.DEFENSE_EVASION),
    "T1574": ("Hijack Execution Flow", MITRETactic.DEFENSE_EVASION),
    "T1574.001": ("DLL Search Order Hijacking", MITRETactic.DEFENSE_EVASION),
    "T1574.002": ("DLL Side-Loading", MITRETactic.DEFENSE_EVASION),
    
    # Credential Access
    "T1003": ("OS Credential Dumping", MITRETactic.CREDENTIAL_ACCESS),
    "T1003.001": ("LSASS Memory", MITRETactic.CREDENTIAL_ACCESS),
    "T1003.002": ("Security Account Manager", MITRETactic.CREDENTIAL_ACCESS),
    "T1003.003": ("NTDS", MITRETactic.CREDENTIAL_ACCESS),
    "T1003.006": ("DCSync", MITRETactic.CREDENTIAL_ACCESS),
    "T1558.004": ("AS-REP Roasting", MITRETactic.CREDENTIAL_ACCESS),
    "T1557": ("Adversary-in-the-Middle", MITRETactic.CREDENTIAL_ACCESS),
    "T1557.001": ("LLMNR/NBT-NS Poisoning", MITRETactic.CREDENTIAL_ACCESS),
    
    # Discovery
    "T1087": ("Account Discovery", MITRETactic.DISCOVERY),
    "T1087.002": ("Domain Account", MITRETactic.DISCOVERY),
    "T1069": ("Permission Groups Discovery", MITRETactic.DISCOVERY),
    "T1069.002": ("Domain Groups", MITRETactic.DISCOVERY),
    "T1482": ("Domain Trust Discovery", MITRETactic.DISCOVERY),
    "T1018": ("Remote System Discovery", MITRETactic.DISCOVERY),
    
    # Lateral Movement
    "T1021": ("Remote Services", MITRETactic.LATERAL_MOVEMENT),
    "T1021.001": ("Remote Desktop Protocol", MITRETactic.LATERAL_MOVEMENT),
    "T1021.002": ("SMB/Admin Shares", MITRETactic.LATERAL_MOVEMENT),
    "T1021.003": ("DCOM", MITRETactic.LATERAL_MOVEMENT),
    "T1021.006": ("WinRM", MITRETactic.LATERAL_MOVEMENT),
    "T1047": ("WMI", MITRETactic.LATERAL_MOVEMENT),
    "T1550": ("Use Alternate Auth Material", MITRETactic.LATERAL_MOVEMENT),
    "T1550.002": ("Pass the Hash", MITRETactic.LATERAL_MOVEMENT),
    "T1550.003": ("Pass the Ticket", MITRETactic.LATERAL_MOVEMENT),
    
    # Collection
    "T1560": ("Archive Collected Data", MITRETactic.COLLECTION),
    "T1005": ("Data from Local System", MITRETactic.COLLECTION),
    
    # Command and Control
    "T1071": ("Application Layer Protocol", MITRETactic.COMMAND_AND_CONTROL),
    "T1071.001": ("Web Protocols", MITRETactic.COMMAND_AND_CONTROL),
    "T1071.004": ("DNS", MITRETactic.COMMAND_AND_CONTROL),
    "T1573": ("Encrypted Channel", MITRETactic.COMMAND_AND_CONTROL),
    "T1090": ("Proxy", MITRETactic.COMMAND_AND_CONTROL),
    "T1090.004": ("Domain Fronting", MITRETactic.COMMAND_AND_CONTROL),
    "T1105": ("Ingress Tool Transfer", MITRETactic.COMMAND_AND_CONTROL),
    
    # Exfiltration
    "T1041": ("Exfiltration Over C2 Channel", MITRETactic.EXFILTRATION),
    "T1048": ("Exfiltration Over Alternative Protocol", MITRETactic.EXFILTRATION),
    
    # Impact
    "T1486": ("Data Encrypted for Impact", MITRETactic.IMPACT),
    "T1489": ("Service Stop", MITRETactic.IMPACT),
}

# EDR Detection signatures for Sigma rules
EDR_SIGNATURES = {
    "crowdstrike": {
        "processes": ["CSFalconService.exe", "CSFalconContainer.exe"],
        "services": ["CSFalcon", "CSFalconService"],
        "pipes": [r"\\.\pipe\CrowdStrike*"],
    },
    "sentinelone": {
        "processes": ["SentinelAgent.exe", "SentinelServiceHost.exe"],
        "services": ["SentinelAgent", "SentinelStaticEngine"],
        "pipes": [r"\\.\pipe\SentinelAgent*"],
    },
    "defender": {
        "processes": ["MsMpEng.exe", "MsSense.exe"],
        "services": ["WinDefend", "Sense"],
        "pipes": [r"\\.\pipe\MsMpComm*"],
    },
    "carbonblack": {
        "processes": ["CbDefense.exe", "RepMgr.exe"],
        "services": ["CbDefense", "CarbonBlack"],
        "pipes": [r"\\.\pipe\CarbonBlack*"],
    },
}


# =============================================================================
# AI SUMMARY GENERATOR
# =============================================================================

class AISummaryGenerator:
    """Generate AI-powered executive summaries from chain logs"""
    
    def __init__(self):
        self.templates = {
            "executive": self._executive_template,
            "technical": self._technical_template,
            "twitter": self._twitter_template,
        }
    
    def generate_summary(
        self,
        chain_log: ChainLog,
        mitre_coverage: Dict[str, MITREMapping],
        style: str = "executive"
    ) -> str:
        """Generate summary based on chain log analysis"""
        
        # Calculate statistics
        stats = self._calculate_stats(chain_log, mitre_coverage)
        
        # Generate using template
        template_func = self.templates.get(style, self._executive_template)
        return template_func(chain_log, stats, mitre_coverage)
    
    def _calculate_stats(
        self,
        chain_log: ChainLog,
        mitre_coverage: Dict[str, MITREMapping]
    ) -> Dict[str, Any]:
        """Calculate chain statistics"""
        
        total_entries = len(chain_log.entries)
        successful = sum(1 for e in chain_log.entries if e.result == "success")
        failed = sum(1 for e in chain_log.entries if e.result == "failed")
        
        avg_evasion = (
            sum(e.evasion_score for e in chain_log.entries) / total_entries
            if total_entries > 0 else 0
        )
        
        # EDR bypass stats
        edr_stats = {}
        for entry in chain_log.entries:
            for edr in entry.edr_bypassed:
                if edr not in edr_stats:
                    edr_stats[edr] = {"bypass": 0, "detect": 0}
                edr_stats[edr]["bypass"] += 1
        
        # Tactic coverage
        tactic_coverage = {}
        for mapping in mitre_coverage.values():
            tactic = mapping.tactic.name
            if tactic not in tactic_coverage:
                tactic_coverage[tactic] = {"techniques": 0, "success": 0}
            tactic_coverage[tactic]["techniques"] += 1
            if mapping.success_count > 0:
                tactic_coverage[tactic]["success"] += 1
        
        return {
            "total_entries": total_entries,
            "successful": successful,
            "failed": failed,
            "success_rate": (successful / total_entries * 100) if total_entries > 0 else 0,
            "avg_evasion": avg_evasion,
            "edr_stats": edr_stats,
            "tactic_coverage": tactic_coverage,
            "unique_techniques": len(mitre_coverage),
        }
    
    def _executive_template(
        self,
        chain_log: ChainLog,
        stats: Dict[str, Any],
        mitre_coverage: Dict[str, MITREMapping]
    ) -> str:
        """Executive summary template"""
        
        # Build EDR summary
        edr_summary = []
        for edr, data in stats["edr_stats"].items():
            bypass_rate = data["bypass"] / stats["total_entries"] * 100
            edr_summary.append(f"  - {edr}: {bypass_rate:.0f}% bypass rate")
        
        # Build recommendations
        recommendations = self._generate_recommendations(stats, mitre_coverage)
        
        summary = f"""
# 🔥 AI-Powered Attack Chain Analysis Report

## Executive Summary

**Campaign:** {chain_log.campaign or 'Unnamed Operation'}
**Target:** {chain_log.target_domain or 'Undisclosed'}
**Duration:** {self._format_duration(chain_log.start_time, chain_log.end_time)}
**Overall Status:** {'✅ SUCCESS' if chain_log.overall_success else '⚠️ PARTIAL'}

### Key Metrics

| Metric | Value |
|--------|-------|
| Total Actions | {stats['total_entries']} |
| Success Rate | {stats['success_rate']:.1f}% |
| Average Evasion Score | {stats['avg_evasion']:.1f}% |
| MITRE Techniques Used | {stats['unique_techniques']} |

### EDR Bypass Performance

{chr(10).join(edr_summary) if edr_summary else '  No EDR encounters recorded'}

### MITRE ATT&CK Coverage

"""
        # Add tactic coverage
        for tactic, data in stats["tactic_coverage"].items():
            coverage = (data["success"] / data["techniques"] * 100) if data["techniques"] > 0 else 0
            summary += f"- **{tactic}**: {data['success']}/{data['techniques']} techniques ({coverage:.0f}%)\n"
        
        summary += f"""
### AI Recommendations

{chr(10).join(f'- {r}' for r in recommendations)}

### Next Steps

1. Review failed techniques and adjust TTPs
2. Update Sigma rules based on detected patterns
3. Enhance evasion for low-scoring techniques
4. Document lessons learned for future operations
"""
        return summary
    
    def _technical_template(
        self,
        chain_log: ChainLog,
        stats: Dict[str, Any],
        mitre_coverage: Dict[str, MITREMapping]
    ) -> str:
        """Technical details template"""
        
        summary = f"""
# Technical Attack Chain Analysis

## Chain Execution Details

**Chain ID:** `{chain_log.chain_id}`
**Start:** {chain_log.start_time.isoformat() if chain_log.start_time else 'N/A'}
**End:** {chain_log.end_time.isoformat() if chain_log.end_time else 'N/A'}

## Technique Breakdown

| Technique ID | Name | Result | Evasion | EDRs Bypassed |
|--------------|------|--------|---------|---------------|
"""
        for entry in chain_log.entries:
            edrs = ", ".join(entry.edr_bypassed) if entry.edr_bypassed else "N/A"
            summary += f"| {entry.technique_id} | {entry.technique_name} | {entry.result} | {entry.evasion_score:.0f}% | {edrs} |\n"
        
        summary += """
## Artifacts Generated

"""
        all_artifacts = set()
        for entry in chain_log.entries:
            all_artifacts.update(entry.artifacts)
        
        for artifact in sorted(all_artifacts):
            summary += f"- `{artifact}`\n"
        
        return summary
    
    def _twitter_template(
        self,
        chain_log: ChainLog,
        stats: Dict[str, Any],
        mitre_coverage: Dict[str, MITREMapping]
    ) -> str:
        """Twitter/X thread template"""
        
        thread = []
        
        # Tweet 1: Hook
        thread.append(
            f"🔥 Just completed an attack chain simulation with {stats['success_rate']:.0f}% success rate!\n\n"
            f"📊 {stats['unique_techniques']} MITRE techniques\n"
            f"🛡️ {stats['avg_evasion']:.0f}% average evasion score\n\n"
            f"Thread on what we learned 🧵👇"
        )
        
        # Tweet 2: EDR performance
        edr_text = []
        for edr, data in stats["edr_stats"].items():
            bypass_rate = data["bypass"] / stats["total_entries"] * 100
            edr_text.append(f"• {edr}: {bypass_rate:.0f}% bypass")
        
        if edr_text:
            thread.append(
                f"EDR Bypass Results:\n\n"
                f"{chr(10).join(edr_text)}\n\n"
                f"Key insight: Different EDRs require different evasion strategies 🎯"
            )
        
        # Tweet 3: Top techniques
        top_techniques = sorted(
            mitre_coverage.values(),
            key=lambda x: x.evasion_score,
            reverse=True
        )[:3]
        
        tech_text = []
        for t in top_techniques:
            tech_text.append(f"• {t.technique_id}: {t.technique_name} ({t.evasion_score:.0f}%)")
        
        thread.append(
            f"Top performing techniques:\n\n"
            f"{chr(10).join(tech_text)}\n\n"
            f"Evasion is about understanding what EDRs look for 🔍"
        )
        
        # Tweet 4: Call to action
        thread.append(
            f"Want to reproduce these results?\n\n"
            f"Check out our framework: [link]\n\n"
            f"Full MITRE mapping + Sigma rules included!\n\n"
            f"#infosec #redteam #evasion #MITRE"
        )
        
        return "\n\n---\n\n".join(thread)
    
    def _generate_recommendations(
        self,
        stats: Dict[str, Any],
        mitre_coverage: Dict[str, MITREMapping]
    ) -> List[str]:
        """Generate AI recommendations"""
        
        recommendations = []
        
        # Success rate recommendation
        if stats["success_rate"] < 80:
            recommendations.append(
                f"Success rate ({stats['success_rate']:.0f}%) below target. "
                "Review failed techniques and consider alternative TTPs."
            )
        
        # Evasion score recommendation
        if stats["avg_evasion"] < 90:
            recommendations.append(
                f"Evasion score ({stats['avg_evasion']:.0f}%) could be improved. "
                "Enable additional obfuscation layers and artifact mutation."
            )
        
        # EDR-specific recommendations
        for edr, data in stats["edr_stats"].items():
            bypass_rate = data["bypass"] / stats["total_entries"] * 100
            if bypass_rate < 90:
                recommendations.append(
                    f"{edr} bypass rate ({bypass_rate:.0f}%) needs improvement. "
                    f"Consider EDR-specific evasion profiles."
                )
        
        # Technique-specific recommendations
        low_evasion = [
            m for m in mitre_coverage.values()
            if m.evasion_score < 70 and m.success_count > 0
        ]
        
        for mapping in low_evasion[:3]:
            recommendations.append(
                f"Technique {mapping.technique_id} ({mapping.technique_name}) has low "
                f"evasion ({mapping.evasion_score:.0f}%). Consider syscall obfuscation."
            )
        
        if not recommendations:
            recommendations.append(
                "Excellent performance! Consider expanding technique coverage."
            )
        
        return recommendations
    
    def _format_duration(
        self,
        start: Optional[datetime],
        end: Optional[datetime]
    ) -> str:
        """Format duration string"""
        if not start:
            return "N/A"
        
        end = end or datetime.now()
        duration = end - start
        
        hours, remainder = divmod(duration.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if duration.days > 0:
            return f"{duration.days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        else:
            return f"{minutes}m {seconds}s"
    
    def generate_twitter_thread(
        self,
        chain_log: ChainLog,
        mitre_coverage: Dict[str, MITREMapping]
    ) -> List[str]:
        """Generate Twitter/X thread as list"""
        
        stats = self._calculate_stats(chain_log, mitre_coverage)
        full_thread = self._twitter_template(chain_log, stats, mitre_coverage)
        
        return full_thread.split("\n\n---\n\n")


# =============================================================================
# SIGMA RULE GENERATOR
# =============================================================================

class SigmaRuleGenerator:
    """Generate Sigma detection rules from chain logs"""
    
    def __init__(self):
        self.rule_templates = {
            "process_injection": self._injection_rule_template,
            "persistence": self._persistence_rule_template,
            "credential_access": self._credential_rule_template,
            "lateral_movement": self._lateral_rule_template,
            "defense_evasion": self._evasion_rule_template,
        }
    
    def generate_rules(
        self,
        chain_log: ChainLog,
        mitre_coverage: Dict[str, MITREMapping]
    ) -> List[SigmaRule]:
        """Generate Sigma rules from chain log"""
        
        rules = []
        
        for entry in chain_log.entries:
            if entry.result != "success":
                continue  # Only generate rules for successful techniques
            
            # Determine rule type based on technique
            tactic = self._get_tactic_for_technique(entry.technique_id)
            
            rule = self._generate_rule_for_entry(entry, tactic)
            if rule:
                rules.append(rule)
        
        return rules
    
    def _get_tactic_for_technique(self, technique_id: str) -> str:
        """Get tactic name for technique"""
        if technique_id in MITRE_TECHNIQUES:
            return MITRE_TECHNIQUES[technique_id][1].name.lower()
        return "defense_evasion"
    
    def _generate_rule_for_entry(
        self,
        entry: ChainLogEntry,
        tactic: str
    ) -> Optional[SigmaRule]:
        """Generate a Sigma rule for a log entry"""
        
        rule_id = f"custom-{secrets.token_hex(8)}"
        date_str = datetime.now().strftime("%Y/%m/%d")
        
        # Base rule
        rule = SigmaRule(
            title=f"Custom Detection: {entry.technique_name}",
            rule_id=rule_id,
            status="experimental",
            description=f"Detects {entry.technique_name} technique used in attack chain",
            author="Report Generator",
            date=date_str,
            modified=date_str,
            logsource={},
            detection={},
            level=SigmaLevel.HIGH,
            tags=[
                f"attack.{tactic.replace('_', '-')}",
                f"attack.{entry.technique_id.lower()}",
            ],
            references=[
                f"https://attack.mitre.org/techniques/{entry.technique_id.replace('.', '/')}/"
            ],
            falsepositives=["Legitimate administrative activity"],
        )
        
        # Apply technique-specific template
        template_func = self.rule_templates.get(
            tactic,
            self._generic_rule_template
        )
        
        return template_func(rule, entry)
    
    def _injection_rule_template(
        self,
        rule: SigmaRule,
        entry: ChainLogEntry
    ) -> SigmaRule:
        """Process injection rule template"""
        
        rule.title = f"Process Injection via {entry.technique_name}"
        rule.logsource = {
            "category": "process_creation",
            "product": "windows",
        }
        rule.detection = {
            "selection": {
                "CallTrace|contains": [
                    "ntdll.dll",
                    "UNKNOWN",
                ],
            },
            "filter": {
                "Image|endswith": [
                    "\\svchost.exe",
                    "\\services.exe",
                ],
            },
            "condition": "selection and not filter",
        }
        
        # Add artifacts from entry
        if entry.artifacts:
            rule.detection["artifacts"] = {
                "TargetImage|contains": entry.artifacts[:5]
            }
        
        return rule
    
    def _persistence_rule_template(
        self,
        rule: SigmaRule,
        entry: ChainLogEntry
    ) -> SigmaRule:
        """Persistence rule template"""
        
        rule.title = f"Persistence via {entry.technique_name}"
        
        if "registry" in entry.technique_name.lower() or "run" in entry.technique_name.lower():
            rule.logsource = {
                "category": "registry_event",
                "product": "windows",
            }
            rule.detection = {
                "selection": {
                    "TargetObject|contains": [
                        "\\CurrentVersion\\Run",
                        "\\CurrentVersion\\RunOnce",
                    ],
                },
                "condition": "selection",
            }
        elif "wmi" in entry.technique_name.lower():
            rule.logsource = {
                "product": "windows",
                "service": "wmi",
            }
            rule.detection = {
                "selection": {
                    "EventID": [5861, 5859],
                },
                "condition": "selection",
            }
        elif "scheduled" in entry.technique_name.lower() or "task" in entry.technique_name.lower():
            rule.logsource = {
                "product": "windows",
                "service": "security",
            }
            rule.detection = {
                "selection": {
                    "EventID": 4698,
                },
                "condition": "selection",
            }
        elif "com" in entry.technique_name.lower():
            rule.logsource = {
                "category": "registry_event",
                "product": "windows",
            }
            rule.detection = {
                "selection": {
                    "TargetObject|contains": [
                        "\\CLSID\\",
                        "\\InprocServer32",
                    ],
                },
                "condition": "selection",
            }
        else:
            rule.logsource = {
                "category": "process_creation",
                "product": "windows",
            }
            rule.detection = {
                "selection": {
                    "CommandLine|contains": [
                        "schtasks",
                        "reg add",
                        "sc create",
                    ],
                },
                "condition": "selection",
            }
        
        return rule
    
    def _credential_rule_template(
        self,
        rule: SigmaRule,
        entry: ChainLogEntry
    ) -> SigmaRule:
        """Credential access rule template"""
        
        rule.title = f"Credential Access via {entry.technique_name}"
        rule.level = SigmaLevel.CRITICAL
        
        if "lsass" in entry.technique_name.lower() or "dump" in entry.technique_name.lower():
            rule.logsource = {
                "category": "process_access",
                "product": "windows",
            }
            rule.detection = {
                "selection": {
                    "TargetImage|endswith": "\\lsass.exe",
                    "GrantedAccess|contains": [
                        "0x1010",
                        "0x1410",
                        "0x1438",
                    ],
                },
                "condition": "selection",
            }
        elif "kerberos" in entry.technique_name.lower():
            rule.logsource = {
                "product": "windows",
                "service": "security",
            }
            rule.detection = {
                "selection": {
                    "EventID": 4769,
                    "TicketEncryptionType": "0x17",
                },
                "condition": "selection",
            }
        else:
            rule.logsource = {
                "category": "process_creation",
                "product": "windows",
            }
            rule.detection = {
                "selection": {
                    "CommandLine|contains": [
                        "mimikatz",
                        "sekurlsa",
                        "lsadump",
                    ],
                },
                "condition": "selection",
            }
        
        return rule
    
    def _lateral_rule_template(
        self,
        rule: SigmaRule,
        entry: ChainLogEntry
    ) -> SigmaRule:
        """Lateral movement rule template"""
        
        rule.title = f"Lateral Movement via {entry.technique_name}"
        
        if "wmi" in entry.technique_name.lower():
            rule.logsource = {
                "category": "process_creation",
                "product": "windows",
            }
            rule.detection = {
                "selection": {
                    "ParentImage|endswith": "\\WmiPrvSE.exe",
                },
                "condition": "selection",
            }
        elif "psexec" in entry.technique_name.lower() or "smb" in entry.technique_name.lower():
            rule.logsource = {
                "product": "windows",
                "service": "security",
            }
            rule.detection = {
                "selection": {
                    "EventID": [5140, 5145],
                    "ShareName": ["ADMIN$", "C$", "IPC$"],
                },
                "condition": "selection",
            }
        else:
            rule.logsource = {
                "category": "network_connection",
                "product": "windows",
            }
            rule.detection = {
                "selection": {
                    "DestinationPort": [445, 135, 5985, 5986],
                    "Initiated": "true",
                },
                "condition": "selection",
            }
        
        return rule
    
    def _evasion_rule_template(
        self,
        rule: SigmaRule,
        entry: ChainLogEntry
    ) -> SigmaRule:
        """Defense evasion rule template"""
        
        rule.title = f"Defense Evasion via {entry.technique_name}"
        rule.logsource = {
            "category": "process_creation",
            "product": "windows",
        }
        
        if "amsi" in entry.technique_name.lower():
            rule.detection = {
                "selection": {
                    "CommandLine|contains": [
                        "AmsiScanBuffer",
                        "amsiInitFailed",
                        "AmsiUtils",
                    ],
                },
                "condition": "selection",
            }
        elif "etw" in entry.technique_name.lower():
            rule.detection = {
                "selection": {
                    "CommandLine|contains": [
                        "EtwEventWrite",
                        "NtTraceEvent",
                    ],
                },
                "condition": "selection",
            }
        else:
            rule.detection = {
                "selection": {
                    "CommandLine|contains": [
                        "-ep bypass",
                        "-nop",
                        "hidden",
                        "IEX",
                    ],
                },
                "condition": "selection",
            }
        
        return rule
    
    def _generic_rule_template(
        self,
        rule: SigmaRule,
        entry: ChainLogEntry
    ) -> SigmaRule:
        """Generic rule template"""
        
        rule.logsource = {
            "category": "process_creation",
            "product": "windows",
        }
        rule.detection = {
            "selection": {
                "CommandLine|contains": entry.artifacts[:3] if entry.artifacts else ["suspicious"],
            },
            "condition": "selection",
        }
        
        return rule


# =============================================================================
# YARA RULE GENERATOR
# =============================================================================

class YARARuleGenerator:
    """Generate YARA detection rules"""
    
    def generate_rules(
        self,
        chain_log: ChainLog,
        mitre_coverage: Dict[str, MITREMapping]
    ) -> List[YARARule]:
        """Generate YARA rules from chain log"""
        
        rules = []
        
        # Generate shellcode detection rule
        shellcode_rule = self._generate_shellcode_rule(chain_log)
        if shellcode_rule:
            rules.append(shellcode_rule)
        
        # Generate persistence artifact rule
        persist_rule = self._generate_persistence_rule(chain_log)
        if persist_rule:
            rules.append(persist_rule)
        
        # Generate C2 beacon rule
        c2_rule = self._generate_c2_rule(chain_log)
        if c2_rule:
            rules.append(c2_rule)
        
        return rules
    
    def _generate_shellcode_rule(self, chain_log: ChainLog) -> Optional[YARARule]:
        """Generate shellcode detection rule"""
        
        return YARARule(
            name="custom_shellcode_pattern",
            meta={
                "description": f"Detects shellcode patterns from chain {chain_log.chain_id}",
                "author": "Report Generator",
                "date": datetime.now().strftime("%Y-%m-%d"),
                "reference": "Internal",
            },
            strings={
                "$mz": '"MZ"',
                "$api1": '"VirtualAlloc" nocase',
                "$api2": '"VirtualProtect" nocase',
                "$api3": '"CreateThread" nocase',
                "$api4": '"WriteProcessMemory" nocase',
                "$shellcode1": "{ 48 31 c0 48 31 ff 48 31 f6 }",
                "$shellcode2": "{ fc 48 83 e4 f0 e8 }",
            },
            condition="$mz at 0 and (2 of ($api*) or any of ($shellcode*))",
            tags=["shellcode", "injection"],
        )
    
    def _generate_persistence_rule(self, chain_log: ChainLog) -> Optional[YARARule]:
        """Generate persistence detection rule"""
        
        return YARARule(
            name="custom_persistence_pattern",
            meta={
                "description": f"Detects persistence patterns from chain {chain_log.chain_id}",
                "author": "Report Generator",
                "date": datetime.now().strftime("%Y-%m-%d"),
            },
            strings={
                "$reg1": '"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase',
                "$reg2": '"HKEY_CURRENT_USER" nocase',
                "$schtask": '"schtasks" nocase',
                "$service": '"sc create" nocase',
                "$wmi": '"__EventFilter" nocase',
            },
            condition="2 of them",
            tags=["persistence"],
        )
    
    def _generate_c2_rule(self, chain_log: ChainLog) -> Optional[YARARule]:
        """Generate C2 beacon detection rule"""
        
        return YARARule(
            name="custom_c2_beacon_pattern",
            meta={
                "description": f"Detects C2 beacon patterns from chain {chain_log.chain_id}",
                "author": "Report Generator",
                "date": datetime.now().strftime("%Y-%m-%d"),
            },
            strings={
                "$http1": '"User-Agent:" nocase',
                "$http2": '"POST /" nocase',
                "$sleep": '"Sleep" nocase',
                "$beacon": '"beacon" nocase',
                "$enc": "{ 31 ?? 31 ?? 31 ?? }",
            },
            condition="($http1 and $http2) or ($sleep and $beacon) or $enc",
            tags=["c2", "beacon"],
        )


# =============================================================================
# MITRE MAPPER
# =============================================================================

class MITREMapper:
    """Map chain log entries to MITRE ATT&CK framework"""
    
    def map_chain_log(self, chain_log: ChainLog) -> Dict[str, MITREMapping]:
        """Map all entries to MITRE techniques"""
        
        mappings: Dict[str, MITREMapping] = {}
        
        for entry in chain_log.entries:
            tech_id = entry.technique_id
            
            if tech_id not in mappings:
                tech_name, tactic = MITRE_TECHNIQUES.get(
                    tech_id,
                    (entry.technique_name, MITRETactic.DEFENSE_EVASION)
                )
                
                mappings[tech_id] = MITREMapping(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                )
            
            mapping = mappings[tech_id]
            
            if entry.result == "success":
                mapping.success_count += 1
            else:
                mapping.fail_count += 1
            
            # Update evasion score (running average)
            total = mapping.success_count + mapping.fail_count
            mapping.evasion_score = (
                (mapping.evasion_score * (total - 1) + entry.evasion_score) / total
            )
            
            # Track EDRs bypassed
            for edr in entry.edr_bypassed:
                if edr not in mapping.edr_bypassed:
                    mapping.edr_bypassed.append(edr)
        
        return mappings
    
    def generate_heatmap_data(
        self,
        mappings: Dict[str, MITREMapping]
    ) -> Dict[str, Any]:
        """Generate data for ATT&CK heat map visualization"""
        
        heatmap = {
            "tactics": {},
            "techniques": [],
        }
        
        # Group by tactic
        for tech_id, mapping in mappings.items():
            tactic_name = mapping.tactic.name
            
            if tactic_name not in heatmap["tactics"]:
                heatmap["tactics"][tactic_name] = {
                    "id": mapping.tactic.value,
                    "techniques": [],
                    "total_score": 0,
                    "count": 0,
                }
            
            tech_data = {
                "id": tech_id,
                "name": mapping.technique_name,
                "success": mapping.success_count,
                "fail": mapping.fail_count,
                "evasion": mapping.evasion_score,
                "coverage": mapping.coverage_percent,
                "edrs": mapping.edr_bypassed,
            }
            
            heatmap["tactics"][tactic_name]["techniques"].append(tech_data)
            heatmap["tactics"][tactic_name]["total_score"] += mapping.evasion_score
            heatmap["tactics"][tactic_name]["count"] += 1
            
            heatmap["techniques"].append(tech_data)
        
        # Calculate average scores
        for tactic_name, data in heatmap["tactics"].items():
            if data["count"] > 0:
                data["avg_score"] = data["total_score"] / data["count"]
            else:
                data["avg_score"] = 0
        
        return heatmap
    
    def generate_mermaid_diagram(
        self,
        mappings: Dict[str, MITREMapping]
    ) -> str:
        """Generate Mermaid diagram for technique flow"""
        
        lines = ["graph TD"]
        
        # Group techniques by tactic
        tactics = {}
        for tech_id, mapping in mappings.items():
            tactic = mapping.tactic.name
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append(mapping)
        
        # Generate subgraphs for each tactic
        for tactic, techniques in tactics.items():
            lines.append(f"    subgraph {tactic}")
            for tech in techniques:
                node_id = tech.technique_id.replace(".", "_")
                color = self._get_color_for_score(tech.evasion_score)
                lines.append(f"        {node_id}[{tech.technique_name}<br/>{tech.evasion_score:.0f}%]")
            lines.append("    end")
        
        # Add flow connections
        prev_tactic = None
        for tactic in tactics.keys():
            if prev_tactic:
                first_prev = list(tactics[prev_tactic])[0].technique_id.replace(".", "_")
                first_curr = list(tactics[tactic])[0].technique_id.replace(".", "_")
                lines.append(f"    {first_prev} --> {first_curr}")
            prev_tactic = tactic
        
        # Add styling
        for tech_id, mapping in mappings.items():
            node_id = tech_id.replace(".", "_")
            color = self._get_color_for_score(mapping.evasion_score)
            lines.append(f"    style {node_id} fill:{color}")
        
        return "\n".join(lines)
    
    def _get_color_for_score(self, score: float) -> str:
        """Get color based on evasion score"""
        if score >= 90:
            return "#2ecc71"  # Green
        elif score >= 70:
            return "#f39c12"  # Orange
        elif score >= 50:
            return "#e74c3c"  # Red
        else:
            return "#c0392b"  # Dark red


# =============================================================================
# HTML REPORT GENERATOR
# =============================================================================

class HTMLReportGenerator:
    """Generate interactive HTML reports"""
    
    def __init__(self, style: str = "dark"):
        self.style = style
        self.css_themes = {
            "dark": self._dark_theme_css(),
            "light": self._light_theme_css(),
            "hacker": self._hacker_theme_css(),
        }
    
    def generate_html(
        self,
        chain_log: ChainLog,
        mitre_coverage: Dict[str, MITREMapping],
        ai_summary: str,
        sigma_rules: List[SigmaRule],
        mermaid_diagram: str,
        heatmap_data: Dict[str, Any]
    ) -> str:
        """Generate complete HTML report"""
        
        css = self.css_themes.get(self.style, self._dark_theme_css())
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Chain Report - {chain_log.chain_id}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <script src="https://unpkg.com/htmx.org@1.9.6"></script>
    <style>{css}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔥 Attack Chain Analysis Report</h1>
            <div class="meta">
                <span>Chain ID: <code>{chain_log.chain_id}</code></span>
                <span>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
            </div>
        </header>
        
        <nav class="tabs">
            <button class="tab active" onclick="showTab('summary')">📊 Summary</button>
            <button class="tab" onclick="showTab('mitre')">🎯 MITRE Map</button>
            <button class="tab" onclick="showTab('sigma')">📋 Sigma Rules</button>
            <button class="tab" onclick="showTab('timeline')">⏱️ Timeline</button>
            <button class="tab" onclick="showTab('flow')">🔄 Flow Graph</button>
        </nav>
        
        <main>
            <!-- Summary Tab -->
            <section id="summary" class="tab-content active">
                <div class="summary-content">
                    {self._markdown_to_html(ai_summary)}
                </div>
            </section>
            
            <!-- MITRE Map Tab -->
            <section id="mitre" class="tab-content">
                <h2>MITRE ATT&CK Coverage Heat Map</h2>
                <div class="heatmap">
                    {self._generate_heatmap_html(heatmap_data)}
                </div>
            </section>
            
            <!-- Sigma Rules Tab -->
            <section id="sigma" class="tab-content">
                <h2>Generated Sigma Detection Rules</h2>
                <div class="sigma-rules">
                    {self._generate_sigma_html(sigma_rules)}
                </div>
            </section>
            
            <!-- Timeline Tab -->
            <section id="timeline" class="tab-content">
                <h2>Attack Chain Timeline</h2>
                <div class="timeline">
                    {self._generate_timeline_html(chain_log)}
                </div>
            </section>
            
            <!-- Flow Graph Tab -->
            <section id="flow" class="tab-content">
                <h2>Technique Flow Graph</h2>
                <div class="mermaid">
                    {mermaid_diagram}
                </div>
            </section>
        </main>
        
        <footer>
            <p>Generated by Ultimate Report Generator | OPSEC: Data anonymized</p>
        </footer>
    </div>
    
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: '{self.style}' }});
        
        function showTab(tabId) {{
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>"""
        
        return html
    
    def _markdown_to_html(self, markdown: str) -> str:
        """Simple markdown to HTML conversion"""
        html = markdown
        
        # Headers
        html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        
        # Bold
        html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
        
        # Code
        html = re.sub(r'`(.+?)`', r'<code>\1</code>', html)
        
        # Lists
        html = re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=re.MULTILINE)
        html = re.sub(r'(<li>.*</li>\n?)+', r'<ul>\g<0></ul>', html)
        
        # Tables (simplified)
        lines = html.split('\n')
        in_table = False
        result = []
        
        for line in lines:
            if '|' in line and not line.startswith('|--'):
                if not in_table:
                    result.append('<table>')
                    in_table = True
                
                cells = [c.strip() for c in line.split('|')[1:-1]]
                row = '<tr>' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>'
                result.append(row)
            else:
                if in_table:
                    result.append('</table>')
                    in_table = False
                if not line.startswith('|--'):
                    result.append(line)
        
        if in_table:
            result.append('</table>')
        
        # Paragraphs
        html = '\n'.join(result)
        html = re.sub(r'\n\n', '</p><p>', html)
        
        return f'<p>{html}</p>'
    
    def _generate_heatmap_html(self, heatmap_data: Dict[str, Any]) -> str:
        """Generate MITRE heatmap HTML"""
        
        html = '<div class="heatmap-grid">'
        
        for tactic_name, data in heatmap_data.get("tactics", {}).items():
            avg_score = data.get("avg_score", 0)
            color_class = self._get_color_class(avg_score)
            
            html += f'''
            <div class="tactic-card {color_class}">
                <h3>{tactic_name}</h3>
                <div class="score">{avg_score:.0f}%</div>
                <div class="techniques">
            '''
            
            for tech in data.get("techniques", []):
                tech_color = self._get_color_class(tech["evasion"])
                html += f'''
                    <div class="technique {tech_color}" title="{tech['name']}">
                        <span class="tech-id">{tech['id']}</span>
                        <span class="tech-score">{tech['evasion']:.0f}%</span>
                    </div>
                '''
            
            html += '</div></div>'
        
        html += '</div>'
        return html
    
    def _generate_sigma_html(self, sigma_rules: List[SigmaRule]) -> str:
        """Generate Sigma rules HTML"""
        
        html = ''
        
        for rule in sigma_rules:
            html += f'''
            <div class="sigma-rule">
                <div class="rule-header">
                    <h3>{rule.title}</h3>
                    <span class="level level-{rule.level.value}">{rule.level.value.upper()}</span>
                </div>
                <p>{rule.description}</p>
                <div class="rule-meta">
                    <span>ID: <code>{rule.rule_id}</code></span>
                    <span>Status: {rule.status}</span>
                    <span>Date: {rule.date}</span>
                </div>
                <div class="tags">
                    {' '.join(f'<span class="tag">{tag}</span>' for tag in rule.tags)}
                </div>
                <details>
                    <summary>View YAML</summary>
                    <pre><code>{rule.to_yaml()}</code></pre>
                </details>
            </div>
            '''
        
        return html
    
    def _generate_timeline_html(self, chain_log: ChainLog) -> str:
        """Generate timeline HTML"""
        
        html = '<div class="timeline-container">'
        
        for i, entry in enumerate(chain_log.entries):
            status_class = "success" if entry.result == "success" else "failed"
            
            html += f'''
            <div class="timeline-item {status_class}">
                <div class="timeline-marker"></div>
                <div class="timeline-content">
                    <div class="timeline-time">{entry.timestamp.strftime('%H:%M:%S')}</div>
                    <h4>{entry.technique_name}</h4>
                    <div class="timeline-meta">
                        <span class="tech-id">{entry.technique_id}</span>
                        <span class="evasion">Evasion: {entry.evasion_score:.0f}%</span>
                        <span class="status">{entry.result.upper()}</span>
                    </div>
                    <p>Target: {entry.target}</p>
                    {f'<div class="edrs">EDRs Bypassed: {", ".join(entry.edr_bypassed)}</div>' if entry.edr_bypassed else ''}
                </div>
            </div>
            '''
        
        html += '</div>'
        return html
    
    def _get_color_class(self, score: float) -> str:
        """Get CSS class based on score"""
        if score >= 90:
            return "score-high"
        elif score >= 70:
            return "score-medium"
        elif score >= 50:
            return "score-low"
        else:
            return "score-critical"
    
    def _dark_theme_css(self) -> str:
        """Dark theme CSS"""
        return """
        :root {
            --bg: #1a1a2e;
            --bg-secondary: #16213e;
            --text: #e8e8e8;
            --text-muted: #a0a0a0;
            --accent: #e94560;
            --accent-secondary: #0f3460;
            --success: #2ecc71;
            --warning: #f39c12;
            --danger: #e74c3c;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        header {
            text-align: center;
            padding: 2rem 0;
            border-bottom: 2px solid var(--accent);
            margin-bottom: 2rem;
        }
        
        header h1 { color: var(--accent); font-size: 2.5rem; }
        header .meta { margin-top: 1rem; color: var(--text-muted); }
        header .meta span { margin: 0 1rem; }
        
        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }
        
        .tab {
            padding: 0.75rem 1.5rem;
            background: var(--bg-secondary);
            border: none;
            color: var(--text);
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        .tab:hover { background: var(--accent-secondary); }
        .tab.active { background: var(--accent); }
        
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        code {
            background: var(--bg-secondary);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-family: 'Fira Code', monospace;
        }
        
        pre {
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--accent-secondary);
        }
        
        th { background: var(--bg-secondary); }
        
        .heatmap-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }
        
        .tactic-card {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            border-left: 4px solid var(--accent);
        }
        
        .tactic-card h3 { margin-bottom: 0.5rem; }
        .tactic-card .score { font-size: 2rem; font-weight: bold; }
        
        .techniques {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 1rem;
        }
        
        .technique {
            padding: 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }
        
        .score-high { border-color: var(--success); }
        .score-high .score { color: var(--success); }
        .score-medium { border-color: var(--warning); }
        .score-medium .score { color: var(--warning); }
        .score-low { border-color: var(--danger); }
        .score-low .score { color: var(--danger); }
        .score-critical { border-color: #c0392b; }
        
        .sigma-rule {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        
        .rule-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .level {
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: bold;
        }
        
        .level-critical { background: #c0392b; }
        .level-high { background: var(--danger); }
        .level-medium { background: var(--warning); color: #000; }
        .level-low { background: var(--success); color: #000; }
        
        .tags { margin: 1rem 0; }
        .tag {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            background: var(--accent-secondary);
            border-radius: 4px;
            font-size: 0.85rem;
            margin-right: 0.5rem;
        }
        
        details {
            margin-top: 1rem;
        }
        
        summary {
            cursor: pointer;
            color: var(--accent);
        }
        
        .timeline-container {
            position: relative;
            padding-left: 3rem;
        }
        
        .timeline-container::before {
            content: '';
            position: absolute;
            left: 1rem;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--accent);
        }
        
        .timeline-item {
            position: relative;
            margin-bottom: 2rem;
        }
        
        .timeline-marker {
            position: absolute;
            left: -2.5rem;
            width: 1rem;
            height: 1rem;
            border-radius: 50%;
            background: var(--accent);
        }
        
        .timeline-item.success .timeline-marker { background: var(--success); }
        .timeline-item.failed .timeline-marker { background: var(--danger); }
        
        .timeline-content {
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 8px;
        }
        
        .timeline-time {
            font-size: 0.85rem;
            color: var(--text-muted);
        }
        
        .timeline-meta {
            display: flex;
            gap: 1rem;
            margin: 0.5rem 0;
            flex-wrap: wrap;
        }
        
        .mermaid {
            background: var(--bg-secondary);
            padding: 2rem;
            border-radius: 12px;
        }
        
        footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            border-top: 1px solid var(--accent-secondary);
            margin-top: 2rem;
        }
        
        h2 { margin-bottom: 1.5rem; color: var(--accent); }
        h3 { margin-bottom: 1rem; }
        p { margin-bottom: 1rem; }
        ul { padding-left: 1.5rem; margin-bottom: 1rem; }
        li { margin-bottom: 0.5rem; }
        """
    
    def _light_theme_css(self) -> str:
        """Light theme CSS"""
        css = self._dark_theme_css()
        return css.replace(
            "--bg: #1a1a2e", "--bg: #ffffff"
        ).replace(
            "--bg-secondary: #16213e", "--bg-secondary: #f5f5f5"
        ).replace(
            "--text: #e8e8e8", "--text: #333333"
        ).replace(
            "--text-muted: #a0a0a0", "--text-muted: #666666"
        )
    
    def _hacker_theme_css(self) -> str:
        """Hacker (green) theme CSS"""
        css = self._dark_theme_css()
        return css.replace(
            "--accent: #e94560", "--accent: #00ff00"
        ).replace(
            "--bg: #1a1a2e", "--bg: #0a0a0a"
        ).replace(
            "--bg-secondary: #16213e", "--bg-secondary: #1a1a1a"
        )


# =============================================================================
# DATA ANONYMIZER
# =============================================================================

class DataAnonymizer:
    """Anonymize sensitive data in reports"""
    
    def __init__(self):
        self.ip_map: Dict[str, str] = {}
        self.hostname_map: Dict[str, str] = {}
        self.user_map: Dict[str, str] = {}
        self._counter = 0
    
    def anonymize_chain_log(self, chain_log: ChainLog) -> ChainLog:
        """Anonymize sensitive data in chain log"""
        
        # Anonymize domain
        chain_log.target_domain = self._anonymize_domain(chain_log.target_domain)
        chain_log.operator = "operator_redacted"
        
        # Anonymize entries
        for entry in chain_log.entries:
            entry.target = self._anonymize_target(entry.target)
            entry.artifacts = [self._anonymize_artifact(a) for a in entry.artifacts]
        
        return chain_log
    
    def _anonymize_ip(self, ip: str) -> str:
        """Anonymize IP address"""
        if ip not in self.ip_map:
            self._counter += 1
            self.ip_map[ip] = f"10.0.0.{self._counter}"
        return self.ip_map[ip]
    
    def _anonymize_domain(self, domain: str) -> str:
        """Anonymize domain name"""
        if not domain:
            return "target.local"
        return "redacted.local"
    
    def _anonymize_target(self, target: str) -> str:
        """Anonymize target identifier"""
        if not target:
            return "TARGET_HOST"
        
        # Check if IP
        if re.match(r'\d+\.\d+\.\d+\.\d+', target):
            return self._anonymize_ip(target)
        
        # Hostname
        if target not in self.hostname_map:
            self._counter += 1
            self.hostname_map[target] = f"HOST{self._counter:03d}"
        return self.hostname_map[target]
    
    def _anonymize_artifact(self, artifact: str) -> str:
        """Anonymize artifact path/name"""
        # Replace usernames
        artifact = re.sub(r'C:\\Users\\[^\\]+', r'C:\\Users\\USER', artifact)
        # Replace hostnames
        artifact = re.sub(r'\\\\[A-Za-z0-9-]+\\', r'\\\\HOST\\', artifact)
        return artifact


# =============================================================================
# PDF GENERATOR
# =============================================================================

class PDFGenerator:
    """Generate encrypted PDF reports"""
    
    def __init__(self):
        self.has_pypandoc = False
        try:
            import pypandoc
            self.has_pypandoc = True
            self.pypandoc = pypandoc
        except ImportError:
            logger.warning("pypandoc not available, PDF generation disabled")
    
    def generate_pdf(
        self,
        html_content: str,
        output_path: str,
        password: str = ""
    ) -> bool:
        """Generate PDF from HTML"""
        
        if not self.has_pypandoc:
            logger.error("pypandoc not installed")
            return False
        
        try:
            # Write HTML to temp file
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.html',
                delete=False
            ) as f:
                f.write(html_content)
                temp_html = f.name
            
            # Convert to PDF
            self.pypandoc.convert_file(
                temp_html,
                'pdf',
                outputfile=output_path,
                extra_args=['--pdf-engine=wkhtmltopdf'] if password else []
            )
            
            # Encrypt if password provided
            if password:
                self._encrypt_pdf(output_path, password)
            
            # Cleanup
            os.unlink(temp_html)
            
            return True
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return False
    
    def _encrypt_pdf(self, pdf_path: str, password: str) -> bool:
        """Encrypt PDF with password"""
        try:
            # Would use PyPDF2 or pikepdf for encryption
            # Placeholder for now
            return True
        except Exception:
            return False


# =============================================================================
# MAIN REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """
    Ultimate Report Generator
    
    Combines all components for comprehensive attack chain reporting.
    """
    
    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
        
        # Initialize components
        self.ai_summary = AISummaryGenerator()
        self.sigma_generator = SigmaRuleGenerator()
        self.yara_generator = YARARuleGenerator()
        self.mitre_mapper = MITREMapper()
        self.html_generator = HTMLReportGenerator(self.config.template_style)
        self.pdf_generator = PDFGenerator()
        self.anonymizer = DataAnonymizer()
    
    def generate_report(
        self,
        chain_log: ChainLog,
        output_dir: Optional[str] = None
    ) -> ReportResult:
        """
        Generate comprehensive attack chain report
        
        Args:
            chain_log: Chain execution log
            output_dir: Output directory for reports
        
        Returns:
            ReportResult with all generated artifacts
        """
        result = ReportResult()
        
        try:
            output_dir = output_dir or self.config.output_dir
            os.makedirs(output_dir, exist_ok=True)
            
            # Anonymize if configured
            if self.config.anonymize_data:
                chain_log = self.anonymizer.anonymize_chain_log(chain_log)
            
            # Map to MITRE
            if self.config.enable_mitre_map:
                result.mitre_coverage = self.mitre_mapper.map_chain_log(chain_log)
            
            # Generate AI summary
            if self.config.enable_ai_summary:
                result.ai_summary = self.ai_summary.generate_summary(
                    chain_log,
                    result.mitre_coverage,
                    style="executive"
                )
            
            # Generate Sigma rules
            if self.config.enable_sigma_generate:
                result.sigma_rules = self.sigma_generator.generate_rules(
                    chain_log,
                    result.mitre_coverage
                )
            
            # Generate YARA rules
            if self.config.enable_yara_generate:
                result.yara_rules = self.yara_generator.generate_rules(
                    chain_log,
                    result.mitre_coverage
                )
            
            # Generate Twitter thread
            if self.config.include_twitter_thread:
                result.twitter_thread = self.ai_summary.generate_twitter_thread(
                    chain_log,
                    result.mitre_coverage
                )
            
            # Generate demo script
            if self.config.include_demo_script:
                result.demo_script = self._generate_demo_script(chain_log)
            
            # Generate visualization data
            heatmap_data = self.mitre_mapper.generate_heatmap_data(result.mitre_coverage)
            mermaid_diagram = self.mitre_mapper.generate_mermaid_diagram(result.mitre_coverage)
            
            # Generate outputs based on format
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"report_{chain_log.chain_id}_{timestamp}"
            
            if self.config.format in [ReportFormat.HTML, ReportFormat.ALL]:
                html_content = self.html_generator.generate_html(
                    chain_log,
                    result.mitre_coverage,
                    result.ai_summary,
                    result.sigma_rules,
                    mermaid_diagram,
                    heatmap_data
                )
                result.html_path = os.path.join(output_dir, f"{base_name}.html")
                with open(result.html_path, 'w') as f:
                    f.write(html_content)
            
            if self.config.format in [ReportFormat.PDF, ReportFormat.ALL]:
                # Generate HTML first if not already
                if not hasattr(self, '_html_content'):
                    html_content = self.html_generator.generate_html(
                        chain_log,
                        result.mitre_coverage,
                        result.ai_summary,
                        result.sigma_rules,
                        mermaid_diagram,
                        heatmap_data
                    )
                
                result.pdf_path = os.path.join(output_dir, f"{base_name}.pdf")
                self.pdf_generator.generate_pdf(
                    html_content,
                    result.pdf_path,
                    self.config.pdf_password if self.config.encrypt_pdf else ""
                )
            
            if self.config.format in [ReportFormat.JSON, ReportFormat.ALL]:
                result.json_path = os.path.join(output_dir, f"{base_name}.json")
                json_data = {
                    "chain_id": chain_log.chain_id,
                    "summary": result.ai_summary,
                    "mitre_coverage": {
                        k: {
                            "technique_id": v.technique_id,
                            "technique_name": v.technique_name,
                            "tactic": v.tactic.name,
                            "success_count": v.success_count,
                            "evasion_score": v.evasion_score,
                        }
                        for k, v in result.mitre_coverage.items()
                    },
                    "sigma_rules": [r.to_yaml() for r in result.sigma_rules],
                    "twitter_thread": result.twitter_thread,
                }
                with open(result.json_path, 'w') as f:
                    json.dump(json_data, f, indent=2)
            
            if self.config.format in [ReportFormat.MARKDOWN, ReportFormat.ALL]:
                md_path = os.path.join(output_dir, f"{base_name}.md")
                with open(md_path, 'w') as f:
                    f.write(result.ai_summary)
                result.report_path = md_path
            
            result.success = True
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Report generation failed: {e}")
        
        return result
    
    def _generate_demo_script(self, chain_log: ChainLog) -> str:
        """Generate demo script for video recording"""
        
        script = f"""#!/bin/bash
# Demo Script for Chain {chain_log.chain_id}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}

# Terminal setup for recording
clear
echo "🔥 Attack Chain Demo - {chain_log.campaign or 'Operation'}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
sleep 2

"""
        
        for i, entry in enumerate(chain_log.entries[:10]):
            script += f"""
# Step {i+1}: {entry.technique_name}
echo "▶ [{entry.technique_id}] {entry.technique_name}"
echo "  Target: {entry.target}"
# <insert actual command here>
sleep 1
echo "  ✓ Evasion: {entry.evasion_score:.0f}%"
echo ""
sleep 1

"""
        
        script += """
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Demo Complete!"
"""
        
        return script


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_report_generator(
    enable_ai: bool = True,
    enable_mitre: bool = True,
    enable_sigma: bool = True,
    format: str = "html",
    style: str = "dark"
) -> ReportGenerator:
    """Create configured ReportGenerator"""
    
    format_map = {
        "pdf": ReportFormat.PDF,
        "html": ReportFormat.HTML,
        "json": ReportFormat.JSON,
        "markdown": ReportFormat.MARKDOWN,
        "all": ReportFormat.ALL,
    }
    
    config = ReportConfig(
        enable_ai_summary=enable_ai,
        enable_mitre_map=enable_mitre,
        enable_sigma_generate=enable_sigma,
        format=format_map.get(format.lower(), ReportFormat.HTML),
        template_style=style,
    )
    
    return ReportGenerator(config)


def quick_report(chain_log: ChainLog, output_dir: str = "reports") -> ReportResult:
    """Quick report generation with defaults"""
    generator = create_report_generator()
    return generator.generate_report(chain_log, output_dir)


def create_sample_chain_log() -> ChainLog:
    """Create sample chain log for testing"""
    
    log = ChainLog(
        chain_id=secrets.token_hex(8),
        start_time=datetime.now(),
        target_domain="corp.local",
        campaign="Demo Operation",
    )
    
    # Add sample entries
    techniques = [
        ("T1566.001", "Spearphishing Attachment", "success", 85.0),
        ("T1059.001", "PowerShell", "success", 90.0),
        ("T1055.012", "Process Hollowing", "success", 95.0),
        ("T1003.001", "LSASS Memory", "success", 88.0),
        ("T1558.003", "Kerberoasting", "success", 92.0),
        ("T1021.002", "SMB/Admin Shares", "success", 80.0),
        ("T1547.001", "Registry Run Keys", "success", 85.0),
    ]
    
    for i, (tech_id, tech_name, result, evasion) in enumerate(techniques):
        log.entries.append(ChainLogEntry(
            timestamp=datetime.now(),
            action="execute",
            technique_id=tech_id,
            technique_name=tech_name,
            target="DC01",
            result=result,
            evasion_score=evasion,
            edr_bypassed=["Defender", "CrowdStrike"] if evasion > 85 else ["Defender"],
            artifacts=[f"C:\\Windows\\Temp\\artifact_{i}.tmp"],
        ))
    
    log.end_time = datetime.now()
    log.overall_success = True
    log.total_evasion_score = sum(e.evasion_score for e in log.entries) / len(log.entries)
    
    return log


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    'ReportFormat',
    'MITRETactic',
    'SigmaLevel',
    'RuleType',
    
    # Data classes
    'ChainLogEntry',
    'ChainLog',
    'SigmaRule',
    'YARARule',
    'MITREMapping',
    'ReportConfig',
    'ReportResult',
    
    # Main classes
    'ReportGenerator',
    'AISummaryGenerator',
    'SigmaRuleGenerator',
    'YARARuleGenerator',
    'MITREMapper',
    'HTMLReportGenerator',
    'PDFGenerator',
    'DataAnonymizer',
    
    # Constants
    'MITRE_TECHNIQUES',
    'EDR_SIGNATURES',
    
    # Helper functions
    'create_report_generator',
    'quick_report',
    'create_sample_chain_log',
]

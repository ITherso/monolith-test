"""
Automated ATT&CK Mapping
Maps scan findings, attack modules, and artifacts to MITRE ATT&CK framework.

Supports:
- Technique mapping from module names and findings
- Tactic grouping (Reconnaissance, Initial Access, Execution, Persistence, etc.)
- Technique coverage stats
- JSON and Markdown export
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class Tactic(str, Enum):
    RECON = "reconnaissance"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# Lightweight ATT&CK technique catalog for mapping
TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1046": {"name": "Network Service Scanning", "tactic": Tactic.RECON},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": Tactic.EXECUTION},
    "T1059.001": {"name": "PowerShell", "tactic": Tactic.EXECUTION},
    "T1059.003": {"name": "Windows Command Shell", "tactic": Tactic.EXECUTION},
    "T1059.004": {"name": "Unix Shell", "tactic": Tactic.EXECUTION},
    "T1078": {"name": "Valid Accounts", "tactic": Tactic.DEFENSE_EVASION},
    "T1078.002": {"name": "Domain Accounts", "tactic": Tactic.DEFENSE_EVASION},
    "T1087": {"name": "Account Discovery", "tactic": Tactic.DISCOVERY},
    "T1087.002": {"name": "Domain Account Discovery", "tactic": Tactic.DISCOVERY},
    "T1098": {"name": "Account Manipulation", "tactic": Tactic.PERSISTENCE},
    "T1110": {"name": "Brute Force", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1135": {"name": "Network Share Discovery", "tactic": Tactic.DISCOVERY},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": Tactic.INITIAL_ACCESS},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": Tactic.DEFENSE_EVASION},
    "T1218.011": {"name": "Mshta", "tactic": Tactic.DEFENSE_EVASION},
    "T1218.004": {"name": "Runas", "tactic": Tactic.DEFENSE_EVASION},
    "T1218.005": {"name": "Msiexec", "tactic": Tactic.DEFENSE_EVASION},
    "T1218.009": {"name": "Regsvr32", "tactic": Tactic.DEFENSE_EVASION},
    "T1218.010": {"name": "InstallUtil", "tactic": Tactic.DEFENSE_EVASION},
    "T1218.007": {"name": "Msbuild", "tactic": Tactic.DEFENSE_EVASION},
    "T1222": {"name": "File and Directory Permissions Modification", "tactic": Tactic.DEFENSE_EVASION},
    "T1250": {"name": "Unsecured Credentials", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1003": {"name": "OS Credential Dumping", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1003.001": {"name": "LSASS Memory", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1003.002": {"name": "Security Account Manager", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1003.003": {"name": "NTDS", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": Tactic.DISCOVERY},
    "T1018": {"name": "Remote System Discovery", "tactic": Tactic.DISCOVERY},
    "T1021": {"name": "Remote Services", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1021.003": {"name": "Distributed Component Object Model", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1021.004": {"name": "SSH", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1021.006": {"name": "Windows Remote Management", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": Tactic.DEFENSE_EVASION},
    "T1027.001": {"name": "Binary Padding", "tactic": Tactic.DEFENSE_EVASION},
    "T1027.002": {"name": "Software Packing", "tactic": Tactic.DEFENSE_EVASION},
    "T1027.003": {"name": "Steganography", "tactic": Tactic.DEFENSE_EVASION},
    "T1027.004": {"name": "Compile After Delivery", "tactic": Tactic.DEFENSE_EVASION},
    "T1027.005": {"name": "Indicator Removal from Tools", "tactic": Tactic.DEFENSE_EVASION},
    "T1033": {"name": "System Owner/User Discovery", "tactic": Tactic.DISCOVERY},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": Tactic.EXECUTION},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": Tactic.EXFILTRATION},
    "T1048.003": {"name": "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol", "tactic": Tactic.EXFILTRATION},
    "T1052": {"name": "Exfiltration Over USB", "tactic": Tactic.EXFILTRATION},
    "T1053": {"name": "Scheduled Task/Job", "tactic": Tactic.EXECUTION},
    "T1053.005": {"name": "Scheduled Task", "tactic": Tactic.PERSISTENCE},
    "T1053.003": {"name": "Windows Service", "tactic": Tactic.PERSISTENCE},
    "T1055": {"name": "Process Injection", "tactic": Tactic.DEFENSE_EVASION},
    "T1056": {"name": "Input Capture", "tactic": Tactic.COLLECTION},
    "T1056.001": {"name": "Keylogging", "tactic": Tactic.COLLECTION},
    "T1069": {"name": "Permission Group Discovery", "tactic": Tactic.DISCOVERY},
    "T1071": {"name": "Application Layer Protocol", "tactic": Tactic.COMMAND_CONTROL},
    "T1071.001": {"name": "Web Protocols", "tactic": Tactic.COMMAND_CONTROL},
    "T1071.004": {"name": "DNS", "tactic": Tactic.COMMAND_CONTROL},
    "T1072": {"name": "Software Deployment Tools", "tactic": Tactic.EXECUTION},
    "T1078": {"name": "Valid Accounts", "tactic": Tactic.DEFENSE_EVASION},
    "T1078.002": {"name": "Domain Accounts", "tactic": Tactic.DEFENSE_EVASION},
    "T1083": {"name": "File and Directory Discovery", "tactic": Tactic.DISCOVERY},
    "T1086": {"name": "PowerShell", "tactic": Tactic.EXECUTION},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": Tactic.COMMAND_CONTROL},
    "T1097": {"name": "Pass the Ticket", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1099": {"name": "Timestomp", "tactic": Tactic.DEFENSE_EVASION},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": Tactic.COMMAND_CONTROL},
    "T1106": {"name": "Native API", "tactic": Tactic.DEFENSE_EVASION},
    "T1110": {"name": "Brute Force", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1112": {"name": "Modify Registry", "tactic": Tactic.DEFENSE_EVASION},
    "T1113": {"name": "Screen Capture", "tactic": Tactic.COLLECTION},
    "T1123": {"name": "Audio Capture", "tactic": Tactic.COLLECTION},
    "T1127": {"name": "Trusted Developer Utilities Proxy Execution", "tactic": Tactic.DEFENSE_EVASION},
    "T1127.001": {"name": "MSBuild", "tactic": Tactic.DEFENSE_EVASION},
    "T1132": {"name": "Data Encoding", "tactic": Tactic.COMMAND_CONTROL},
    "T1133": {"name": "External Remote Services", "tactic": Tactic.PERSISTENCE},
    "T1134": {"name": "Access Token Manipulation", "tactic": Tactic.PRIVILEGE_ESCALATION},
    "T1136": {"name": "Create Account", "tactic": Tactic.PERSISTENCE},
    "T1137": {"name": "Office Application Startup", "tactic": Tactic.PERSISTENCE},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": Tactic.DEFENSE_EVASION},
    "T1158": {"name": "Stored Data Manipulation", "tactic": Tactic.IMPACT},
    "T1176": {"name": "Browser Extensions", "tactic": Tactic.PERSISTENCE},
    "T1185": {"name": "Browser Session Hijacking", "tactic": Tactic.COLLECTION},
    "T1204": {"name": "User Execution", "tactic": Tactic.EXECUTION},
    "T1204.002": {"name": "Malicious File", "tactic": Tactic.EXECUTION},
    "T1204.001": {"name": "Malicious Link", "tactic": Tactic.EXECUTION},
    "T1207": {"name": "Rogue Domain Controller", "tactic": Tactic.DEFENSE_EVASION},
    "T1213": {"name": "Data from Information Repositories", "tactic": Tactic.COLLECTION},
    "T1216": {"name": "System Script Proxy Execution", "tactic": Tactic.DEFENSE_EVASION},
    "T1216.001": {"name": "PubPrn", "tactic": Tactic.DEFENSE_EVASION},
    "T1217": {"name": "Browser Bookmark Discovery", "tactic": Tactic.DISCOVERY},
    "T1219": {"name": "Remote Access Tools", "tactic": Tactic.COMMAND_CONTROL},
    "T1220": {"name": "XSL Script Processing", "tactic": Tactic.EXECUTION},
    "T1221": {"name": "Template Injection", "tactic": Tactic.EXECUTION},
    "T1222": {"name": "File and Directory Permissions Modification", "tactic": Tactic.DEFENSE_EVASION},
    "T1482": {"name": "Domain Trust Discovery", "tactic": Tactic.DISCOVERY},
    "T1484": {"name": "Group Policy Modification", "tactic": Tactic.DEFENSE_EVASION},
    "T1484.001": {"name": "Group Policy Modification", "tactic": Tactic.DEFENSE_EVASION},
    "T1485": {"name": "Data Destruction", "tactic": Tactic.IMPACT},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": Tactic.IMPACT},
    "T1490": {"name": "Inhibit System Recovery", "tactic": Tactic.IMPACT},
    "T1496": {"name": "Data Manipulation", "tactic": Tactic.IMPACT},
    "T1497": {"name": "Virtualization/Sandbox Evasion", "tactic": Tactic.DISCOVERY},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": Tactic.IMPACT},
    "T1505": {"name": "Server Software Component", "tactic": Tactic.PERSISTENCE},
    "T1505.003": {"name": "Web Shell", "tactic": Tactic.PERSISTENCE},
    "T1518": {"name": "Software Discovery", "tactic": Tactic.DISCOVERY},
    "T1526": {"name": "Cloud Service Discovery", "tactic": Tactic.DISCOVERY},
    "T1530": {"name": "Data from Cloud Storage", "tactic": Tactic.COLLECTION},
    "T1531": {"name": "Account Access Removal", "tactic": Tactic.IMPACT},
    "T1542": {"name": "Pre-OS Boot", "tactic": Tactic.PERSISTENCE},
    "T1543": {"name": "Create or Modify System Process", "tactic": Tactic.PERSISTENCE},
    "T1543.003": {"name": "Windows Service", "tactic": Tactic.PERSISTENCE},
    "T1546": {"name": "Event Triggered Execution", "tactic": Tactic.EXECUTION},
    "T1546.003": {"name": "Windows Management Instrumentation Event Subscription", "tactic": Tactic.PERSISTENCE},
    "T1546.004": {"name": "Unix Shell Configuration Modification", "tactic": Tactic.PERSISTENCE},
    "T1546.008": {"name": "Accessibility Features", "tactic": Tactic.PERSISTENCE},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": Tactic.PERSISTENCE},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": Tactic.PERSISTENCE},
    "T1547.006": {"name": "Web Shell", "tactic": Tactic.PERSISTENCE},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": Tactic.PRIVILEGE_ESCALATION},
    "T1548.002": {"name": "Bypass User Account Control", "tactic": Tactic.PRIVILEGE_ESCALATION},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1552": {"name": "Unsecured Credentials", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1552.001": {"name": "Credentials in Files", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1552.004": {"name": "Credentials in Registry", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1552.005": {"name": "Cached Domain Credentials", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1553": {"name": "Subvert Trust Controls", "tactic": Tactic.DEFENSE_EVASION},
    "T1555": {"name": "Credentials from Password Stores", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1559": {"name": "Inter-Process Communication", "tactic": Tactic.EXECUTION},
    "T1560": {"name": "Archive Collected Data", "tactic": Tactic.COLLECTION},
    "T1562": {"name": "Impair Defenses", "tactic": Tactic.DEFENSE_EVASION},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": Tactic.DEFENSE_EVASION},
    "T1562.006": {"name": "Indirect Command Execution", "tactic": Tactic.DEFENSE_EVASION},
    "T1566": {"name": "Phishing", "tactic": Tactic.INITIAL_ACCESS},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": Tactic.INITIAL_ACCESS},
    "T1566.002": {"name": "Spearphishing Link", "tactic": Tactic.INITIAL_ACCESS},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": Tactic.EXFILTRATION},
    "T1569": {"name": "System Services", "tactic": Tactic.EXECUTION},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1571": {"name": "Non-Standard Port", "tactic": Tactic.COMMAND_CONTROL},
    "T1572": {"name": "Protocol Tunneling", "tactic": Tactic.COMMAND_CONTROL},
    "T1573": {"name": "Encrypted Channel", "tactic": Tactic.COMMAND_CONTROL},
    "T1574": {"name": "Hijack Execution Flow", "tactic": Tactic.PERSISTENCE},
    "T1574.001": {"name": "DLL Search Order Hijacking", "tactic": Tactic.PERSISTENCE},
    "T1574.002": {"name": "DLL Side-Loading", "tactic": Tactic.PERSISTENCE},
    "T1574.005": {"name": "XSL Script Processing", "tactic": Tactic.EXECUTION},
    "T1574.006": {"name": "Dynamic Linker Hijacking", "tactic": Tactic.PERSISTENCE},
    "T1574.007": {"name": "Path Interception by PATH Environment Variable", "tactic": Tactic.PERSISTENCE},
    "T1574.008": {"name": "Path Interception by Search Order Hijacking", "tactic": Tactic.PERSISTENCE},
    "T1574.009": {"name": "Path Interception by Unquoted Paths", "tactic": Tactic.PERSISTENCE},
    "T1574.010": {"name": "Services File Permissions Weakness", "tactic": Tactic.PERSISTENCE},
    "T1574.011": {"name": "Services Registry Permissions Weakness", "tactic": Tactic.PERSISTENCE},
    "T1574.012": {"name": "COR_PROFILER", "tactic": Tactic.PERSISTENCE},
    "T1583": {"name": "Acquire Infrastructure", "tactic": Tactic.RECON},
    "T1584": {"name": "Compromise Infrastructure", "tactic": Tactic.RECON},
    "T1587": {"name": "Develop Capabilities", "tactic": Tactic.RECON},
    "T1588": {"name": "Obtain Capabilities", "tactic": Tactic.RECON},
    "T1606": {"name": "Forge Web Credentials", "tactic": Tactic.DEFENSE_EVASION},
    "T1606.001": {"name": "Web Cookies", "tactic": Tactic.DEFENSE_EVASION},
    "T1606.002": {"name": "SAML Tokens", "tactic": Tactic.DEFENSE_EVASION},
    "T1606.003": {"name": "Kerberos Tickets", "tactic": Tactic.DEFENSE_EVASION},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1558.001": {"name": "Golden Ticket", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1558.002": {"name": "Silver Ticket", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1558.003": {"name": "Kerberoasting", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1558.004": {"name": "AS-REP Roasting", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1559": {"name": "Inter-Process Communication", "tactic": Tactic.EXECUTION},
    "T1560": {"name": "Archive Collected Data", "tactic": Tactic.COLLECTION},
    "T1561": {"name": "Disk Wipe", "tactic": Tactic.IMPACT},
    "T1562": {"name": "Impair Defenses", "tactic": Tactic.DEFENSE_EVASION},
    "T1564": {"name": "Hide Artifacts", "tactic": Tactic.DEFENSE_EVASION},
    "T1564.001": {"name": "Hidden Files and Directories", "tactic": Tactic.DEFENSE_EVASION},
    "T1564.003": {"name": "Hidden Window", "tactic": Tactic.DEFENSE_EVASION},
    "T1566": {"name": "Phishing", "tactic": Tactic.INITIAL_ACCESS},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": Tactic.EXFILTRATION},
    "T1568": {"name": "Dynamic Resolution", "tactic": Tactic.COMMAND_CONTROL},
    "T1569": {"name": "System Services", "tactic": Tactic.EXECUTION},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": Tactic.LATERAL_MOVEMENT},
    "T1571": {"name": "Non-Standard Port", "tactic": Tactic.COMMAND_CONTROL},
    "T1572": {"name": "Protocol Tunneling", "tactic": Tactic.COMMAND_CONTROL},
    "T1573": {"name": "Encrypted Channel", "tactic": Tactic.COMMAND_CONTROL},
    "T1574": {"name": "Hijack Execution Flow", "tactic": Tactic.PERSISTENCE},
    "T1583": {"name": "Acquire Infrastructure", "tactic": Tactic.RECON},
    "T1584": {"name": "Compromise Infrastructure", "tactic": Tactic.RECON},
    "T1587": {"name": "Develop Capabilities", "tactic": Tactic.RECON},
    "T1588": {"name": "Obtain Capabilities", "tactic": Tactic.RECON},
    "T1606": {"name": "Forge Web Credentials", "tactic": Tactic.DEFENSE_EVASION},
}

MODULE_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "nmap": ["T1046", "T1016", "T1018"],
    "nuclei": ["T1190", "T1210"],
    "gobuster": ["T1083", "T1087"],
    "sql_injection": ["T1190", "T1210"],
    "xss": ["T1059"],
    "ssrf": ["T1190", "T1210"],
    "kerberos": ["T1558.001", "T1558.002", "T1558.003", "T1558.004", "T1550.003"],
    "ntlm_relay": ["T1003", "T1078.002", "T1550.002"],
    "dcsync": ["T1003.003", "T1558.003"],
    "dcshadow": ["T1207", "T1484"],
    "wmiexec": ["T1047", "T1021.002"],
    "smb": ["T1021.002"],
    "rdp": ["T1021.001"],
    "impacket": ["T1021", "T1047", "T1003"],
    "wmi_persistence": ["T1546.003", "T1547"],
    "com_hijack": ["T1547.001"],
    "bits_job": ["T1197"],
    "dll_sideload": ["T1574.002"],
    "registry_persistence": ["T1547.001"],
    "amsi_bypass": ["T1562.001"],
    "etw_bypass": ["T1562.001"],
    "process_injection": ["T1055"],
    "sleep_masking": ["T1497"],
    "behavioral_mimicry": ["T1497"],
    "ml_evasion": ["T1027.005", "T1497"],
    "edr_poison": ["T1562.001"],
    "cloud_pivot": ["T1526", "T1550"],
    "blockchain_c2": ["T1071.001", "T1568"],
    "telegram_c2": ["T1071.001"],
    "doh_c2": ["T1071.004"],
    "steganography_c2": ["T1027.003"],
    "exfiltration": ["T1048", "T1048.003", "T1567"],
    "report": ["T1082", "T1083", "T1127"],
}

TACTIC_COLORS = {
    Tactic.RECON: "#00C853",
    Tactic.INITIAL_ACCESS: "#FF6D00",
    Tactic.EXECUTION: "#FFD600",
    Tactic.PERSISTENCE: "#00B8D4",
    Tactic.PRIVILEGE_ESCALATION: "#6200EA",
    Tactic.DEFENSE_EVASION: "#D50000",
    Tactic.CREDENTIAL_ACCESS: "#AA00FF",
    Tactic.DISCOVERY: "#0091EA",
    Tactic.LATERAL_MOVEMENT: "#304FFE",
    Tactic.COLLECTION: "#64DD17",
    Tactic.COMMAND_CONTROL: "#AEEA00",
    Tactic.EXFILTRATION: "#FF6D00",
    Tactic.IMPACT: "#D50000",
}


class AttackMapper:
    """Map findings/modules to MITRE ATT&CK techniques."""

    def __init__(self):
        self.mapped: Set[str] = set()

    def map_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        mapped: Dict[str, List[Dict[str, Any]]] = {}
        for finding in findings:
            module = finding.get("module", "unknown")
            techniques = self._resolve_module(module)
            for tech_id in techniques:
                if tech_id not in mapped:
                    mapped[tech_id] = []
                mapped[tech_id].append({
                    "module": module,
                    "finding": finding.get("finding", ""),
                    "severity": finding.get("severity", "INFO")
                })
                self.mapped.add(tech_id)
        return {
            "techniques": mapped,
            "tactic_summary": self._tactic_summary(mapped),
            "coverage": len(self.mapped)
        }

    def map_modules(self, modules: List[str]) -> Dict[str, Any]:
        mapped: Dict[str, List[str]] = {}
        for module in modules:
            techniques = self._resolve_module(module)
            mapped[module] = techniques
            self.mapped.update(techniques)
        return {
            "modules": mapped,
            "tactic_summary": self._tactic_summary(mapped),
            "coverage": len(self.mapped)
        }

    def _resolve_module(self, module_name: str) -> List[str]:
        name = module_name.lower()
        for key, techniques in MODULE_TECHNIQUE_MAP.items():
            if key in name:
                return techniques
        return []

    def _tactic_summary(self, mapped: Dict[str, Any]) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        if isinstance(list(mapped.values())[0], list) and mapped and isinstance(list(mapped.values())[0][0], str):
            tech_ids = {t for techs in mapped.values() for t in techs}
        else:
            tech_ids = {t for techs in mapped.values() for t in (techs if isinstance(techs, list) else [])}
        for tech_id in tech_ids:
            info = TECHNIQUES.get(tech_id)
            if info:
                tactic = info["tactic"].value if isinstance(info["tactic"], Tactic) else info["tactic"]
                summary[tactic] = summary.get(tactic, 0) + 1
        return summary

    def export_json(self, result: Dict[str, Any]) -> str:
        return json.dumps(result, indent=2)

    def export_markdown(self, result: Dict[str, Any]) -> str:
        lines = ["# MITRE ATT&CK Mapping Report", ""]
        lines.append("## Coverage Summary")
        lines.append(f"- **Techniques Covered:** {result.get('coverage', 0)}")
        lines.append("")
        tactics = result.get("tactic_summary", {})
        if tactics:
            lines.append("| Tactic | Techniques |")
            lines.append("|--------|-----------|")
            for tactic, count in tactics.items():
                lines.append(f"| {tactic} | {count} |")
            lines.append("")
        techniques = result.get("techniques", {})
        if techniques:
            lines.append("## Techniques")
            for tech_id, entries in techniques.items():
                info = TECHNIQUES.get(tech_id, {})
                name = info.get("name", tech_id)
                lines.append(f"### {tech_id} - {name}")
                for entry in entries:
                    lines.append(f"- {entry.get('module')}: {entry.get('finding')} ({entry.get('severity')})")
                lines.append("")
        return "\\n".join(lines)

    def heatmap_data(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Return data formatted for a simple HTML heatmap."""
        tactics = result.get("tactic_summary", {})
        return {
            "tactics": [
                {"name": t, "count": c, "color": TACTIC_COLORS.get(Tactic(t), "#757575")}
                for t, c in tactics.items()
            ],
            "techniques": [
                {
                    "id": tech_id,
                    "name": TECHNIQUES.get(tech_id, {}).get("name", tech_id),
                    "count": len(entries)
                }
                for tech_id, entries in result.get("techniques", {}).items()
            ]
        }

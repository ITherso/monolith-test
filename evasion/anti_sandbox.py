"""
Anti-Sandbox Detection Module
Detect analysis environments and evade sandbox execution
"""
import os
import sys
import time
import random
import socket
import platform
import subprocess
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib


@dataclass
class SandboxIndicator:
    """Sandbox detection indicator"""
    name: str
    detected: bool
    confidence: float  # 0.0 - 1.0
    details: str


class SandboxDetector:
    """
    Comprehensive sandbox and analysis environment detection.
    
    Detection categories:
    - Hardware fingerprinting
    - User activity simulation checks
    - Known VM/sandbox artifacts
    - Timing-based detection
    - Network environment checks
    - Process/service enumeration
    """
    
    def __init__(self, paranoid_mode: bool = False):
        """
        Initialize detector.
        
        Args:
            paranoid_mode: Extra aggressive detection (may have false positives)
        """
        self.paranoid_mode = paranoid_mode
        self.indicators: List[SandboxIndicator] = []
        
    def run_all_checks(self) -> Tuple[bool, float, List[SandboxIndicator]]:
        """
        Run all sandbox detection checks.
        
        Returns:
            Tuple of (is_sandbox, confidence_score, indicators)
        """
        self.indicators = []
        
        # Run all detection methods
        self._check_hardware()
        self._check_user_activity()
        self._check_vm_artifacts()
        self._check_timing()
        self._check_network()
        self._check_processes()
        self._check_files()
        self._check_registry_windows()
        
        # Calculate overall confidence
        if not self.indicators:
            return False, 0.0, []
        
        detected_count = sum(1 for i in self.indicators if i.detected)
        avg_confidence = sum(i.confidence for i in self.indicators if i.detected) / max(detected_count, 1)
        
        # Threshold for sandbox determination
        is_sandbox = detected_count >= 3 or avg_confidence > 0.7
        
        return is_sandbox, avg_confidence, self.indicators
    
    def _add_indicator(self, name: str, detected: bool, confidence: float, details: str):
        """Add detection indicator"""
        self.indicators.append(SandboxIndicator(
            name=name,
            detected=detected,
            confidence=confidence,
            details=details
        ))
    
    def _check_hardware(self):
        """Check hardware indicators"""
        # CPU cores check (sandboxes often have 1-2 cores)
        try:
            cpu_count = os.cpu_count() or 1
            self._add_indicator(
                "cpu_cores",
                cpu_count <= 2,
                0.6 if cpu_count == 1 else 0.4,
                f"CPU cores: {cpu_count}"
            )
        except Exception:
            pass
        
        # RAM check (sandboxes often have limited RAM)
        try:
            if platform.system() == 'Linux':
                with open('/proc/meminfo') as f:
                    meminfo = f.read()
                    mem_kb = int(meminfo.split()[1])
                    mem_gb = mem_kb / 1024 / 1024
                    self._add_indicator(
                        "low_ram",
                        mem_gb < 4,
                        0.5,
                        f"RAM: {mem_gb:.1f} GB"
                    )
            elif platform.system() == 'Windows':
                import ctypes
                kernel32 = ctypes.windll.kernel32
                c_ulong = ctypes.c_ulong
                class MEMORYSTATUS(ctypes.Structure):
                    _fields_ = [
                        ('dwLength', c_ulong),
                        ('dwMemoryLoad', c_ulong),
                        ('dwTotalPhys', c_ulong),
                        ('dwAvailPhys', c_ulong),
                        ('dwTotalPageFile', c_ulong),
                        ('dwAvailPageFile', c_ulong),
                        ('dwTotalVirtual', c_ulong),
                        ('dwAvailVirtual', c_ulong)
                    ]
                mem_stat = MEMORYSTATUS()
                mem_stat.dwLength = ctypes.sizeof(MEMORYSTATUS)
                kernel32.GlobalMemoryStatus(ctypes.byref(mem_stat))
                mem_gb = mem_stat.dwTotalPhys / 1024 / 1024 / 1024
                self._add_indicator(
                    "low_ram",
                    mem_gb < 4,
                    0.5,
                    f"RAM: {mem_gb:.1f} GB"
                )
        except Exception:
            pass
        
        # Disk size check
        try:
            if platform.system() != 'Windows':
                stat = os.statvfs('/')
                disk_gb = (stat.f_blocks * stat.f_frsize) / 1024 / 1024 / 1024
                self._add_indicator(
                    "small_disk",
                    disk_gb < 60,
                    0.5,
                    f"Disk: {disk_gb:.1f} GB"
                )
        except Exception:
            pass
    
    def _check_user_activity(self):
        """Check for signs of real user activity"""
        # Recent files check
        try:
            recent_dirs = []
            if platform.system() == 'Linux':
                recent_dirs = [
                    os.path.expanduser('~/.local/share/recently-used.xbel'),
                    os.path.expanduser('~/Downloads'),
                    os.path.expanduser('~/.bash_history')
                ]
            elif platform.system() == 'Windows':
                recent_dirs = [
                    os.path.expandvars('%APPDATA%\\Microsoft\\Windows\\Recent'),
                    os.path.expandvars('%USERPROFILE%\\Downloads'),
                ]
            
            recent_count = 0
            for path in recent_dirs:
                if os.path.exists(path):
                    if os.path.isdir(path):
                        recent_count += len(os.listdir(path))
                    else:
                        recent_count += 1
            
            self._add_indicator(
                "no_recent_activity",
                recent_count < 10,
                0.6,
                f"Recent items: {recent_count}"
            )
        except Exception:
            pass
        
        # Check for typical user directories
        try:
            user_dirs = ['Documents', 'Pictures', 'Music', 'Videos']
            existing = 0
            for d in user_dirs:
                if os.path.exists(os.path.expanduser(f'~/{d}')):
                    existing += 1
            
            self._add_indicator(
                "missing_user_dirs",
                existing < 2,
                0.4,
                f"User directories: {existing}/4"
            )
        except Exception:
            pass
    
    def _check_vm_artifacts(self):
        """Check for VM-specific artifacts"""
        vm_indicators = {
            'VirtualBox': [
                'VBoxService', 'VBoxTray', 'vboxguest', 'vboxsf',
                '/dev/vboxguest', '/dev/vboxuser'
            ],
            'VMware': [
                'vmtoolsd', 'vmwaretray', 'vmware-vmx', 'vmhgfs',
                '/dev/vmci', 'vmw_balloon'
            ],
            'Hyper-V': [
                'vmicheartbeat', 'vmicvss', 'vmicshutdown', 'vmicexchange'
            ],
            'QEMU/KVM': [
                'qemu-ga', '/dev/kvm', 'virtio', 'kvm-clock'
            ],
            'Xen': [
                'xenservice', 'xensvc', '/proc/xen'
            ]
        }
        
        detected_vms = []
        
        # Check processes
        try:
            if platform.system() == 'Linux':
                ps_output = subprocess.getoutput('ps aux 2>/dev/null')
            elif platform.system() == 'Windows':
                ps_output = subprocess.getoutput('tasklist 2>nul')
            else:
                ps_output = ""
            
            for vm_name, indicators in vm_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in ps_output.lower():
                        detected_vms.append(vm_name)
                        break
        except Exception:
            pass
        
        # Check device files (Linux)
        try:
            for vm_name, indicators in vm_indicators.items():
                for indicator in indicators:
                    if indicator.startswith('/') and os.path.exists(indicator):
                        if vm_name not in detected_vms:
                            detected_vms.append(vm_name)
        except Exception:
            pass
        
        self._add_indicator(
            "vm_artifacts",
            len(detected_vms) > 0,
            0.9 if detected_vms else 0.0,
            f"VMs detected: {', '.join(detected_vms) if detected_vms else 'None'}"
        )
        
        # Check MAC address for VM prefixes
        try:
            # Common VM MAC prefixes
            vm_mac_prefixes = [
                '00:0c:29', '00:50:56',  # VMware
                '08:00:27', '0a:00:27',  # VirtualBox
                '00:15:5d',              # Hyper-V
                '52:54:00',              # QEMU/KVM
                '00:16:3e',              # Xen
            ]
            
            if platform.system() == 'Linux':
                mac_output = subprocess.getoutput("ip link 2>/dev/null | grep ether | awk '{print $2}'")
            else:
                mac_output = ""
            
            vm_mac_found = any(prefix in mac_output.lower() for prefix in vm_mac_prefixes)
            self._add_indicator(
                "vm_mac_address",
                vm_mac_found,
                0.8,
                f"VM MAC prefix detected: {vm_mac_found}"
            )
        except Exception:
            pass
    
    def _check_timing(self):
        """Timing-based sandbox detection"""
        # Sleep acceleration detection
        try:
            start = time.time()
            time.sleep(1)
            elapsed = time.time() - start
            
            # If sleep was accelerated (sandbox fast-forward)
            accelerated = elapsed < 0.9
            
            self._add_indicator(
                "sleep_acceleration",
                accelerated,
                0.9,
                f"1s sleep took {elapsed:.2f}s"
            )
        except Exception:
            pass
        
        # RDTSC timing (CPU instruction timing)
        try:
            # Multiple timing checks
            timings = []
            for _ in range(10):
                start = time.perf_counter_ns()
                _ = sum(range(1000))
                end = time.perf_counter_ns()
                timings.append(end - start)
            
            avg_timing = sum(timings) / len(timings)
            variance = sum((t - avg_timing) ** 2 for t in timings) / len(timings)
            
            # High variance might indicate sandbox
            high_variance = variance > avg_timing * 10
            
            self._add_indicator(
                "timing_variance",
                high_variance,
                0.6,
                f"Timing variance: {variance:.0f}"
            )
        except Exception:
            pass
    
    def _check_network(self):
        """Network environment checks"""
        # Hostname check
        try:
            hostname = socket.gethostname().lower()
            sandbox_hostnames = [
                'sandbox', 'malware', 'virus', 'sample', 'test',
                'analysis', 'cuckoo', 'joe', 'any.run', 'hybrid'
            ]
            suspicious_hostname = any(s in hostname for s in sandbox_hostnames)
            
            self._add_indicator(
                "suspicious_hostname",
                suspicious_hostname,
                0.8,
                f"Hostname: {hostname}"
            )
        except Exception:
            pass
        
        # IP address check
        try:
            ip = socket.gethostbyname(socket.gethostname())
            # Check for common sandbox IP ranges
            sandbox_ips = ['192.168.56.', '10.0.2.', '172.16.']
            suspicious_ip = any(ip.startswith(prefix) for prefix in sandbox_ips)
            
            self._add_indicator(
                "sandbox_ip_range",
                suspicious_ip,
                0.5,
                f"IP: {ip}"
            )
        except Exception:
            pass
    
    def _check_processes(self):
        """Check for analysis tools and processes"""
        analysis_tools = [
            # Debuggers
            'x64dbg', 'x32dbg', 'ollydbg', 'windbg', 'ida', 'ida64',
            'immunity', 'gdb', 'radare2', 'r2',
            # Sandboxes
            'cuckoo', 'vboxservice', 'vmtoolsd', 'sandboxie',
            # Monitoring
            'procmon', 'procexp', 'wireshark', 'fiddler', 'burp',
            'apimonitor', 'processhacker', 'pestudio',
            # AV/EDR
            'mbam', 'avp', 'avgui', 'avguard', 'msmpeng',
            'carbonblack', 'crowdstrike', 'sentinel'
        ]
        
        try:
            if platform.system() == 'Linux':
                ps_output = subprocess.getoutput('ps aux 2>/dev/null').lower()
            else:
                ps_output = subprocess.getoutput('tasklist 2>nul').lower()
            
            found_tools = [tool for tool in analysis_tools if tool in ps_output]
            
            self._add_indicator(
                "analysis_tools",
                len(found_tools) > 0,
                0.95 if found_tools else 0.0,
                f"Analysis tools: {', '.join(found_tools) if found_tools else 'None'}"
            )
        except Exception:
            pass
    
    def _check_files(self):
        """Check for sandbox-specific files"""
        sandbox_files = [
            # Cuckoo
            '/tmp/cuckoo-tmp', '/tmp/vmhgfs', 'C:\\cuckoo',
            # VirtualBox
            '/usr/share/virtualbox', 'C:\\Program Files\\Oracle\\VirtualBox',
            # VMware
            '/usr/lib/vmware-tools', 'C:\\Program Files\\VMware',
            # Analysis
            '/tmp/analysis', 'C:\\analysis', 'C:\\sample',
            # Common sandbox paths
            'C:\\Users\\sandbox', 'C:\\Users\\virus', 'C:\\Users\\malware'
        ]
        
        found_files = []
        for path in sandbox_files:
            if os.path.exists(path):
                found_files.append(path)
        
        self._add_indicator(
            "sandbox_files",
            len(found_files) > 0,
            0.85 if found_files else 0.0,
            f"Sandbox files: {', '.join(found_files) if found_files else 'None'}"
        )
    
    def _check_registry_windows(self):
        """Check Windows registry for VM indicators"""
        if platform.system() != 'Windows':
            return
        
        try:
            import winreg
            
            vm_registry_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\VMware, Inc.\VMware Tools'),
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Oracle\VirtualBox Guest Additions'),
                (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\VBoxGuest'),
                (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\vmtools'),
            ]
            
            found_keys = []
            for hkey, path in vm_registry_keys:
                try:
                    key = winreg.OpenKey(hkey, path)
                    winreg.CloseKey(key)
                    found_keys.append(path)
                except FileNotFoundError:
                    pass
            
            self._add_indicator(
                "vm_registry_keys",
                len(found_keys) > 0,
                0.9 if found_keys else 0.0,
                f"VM registry keys: {len(found_keys)}"
            )
        except Exception:
            pass
    
    def wait_for_user_activity(self, timeout: int = 300) -> bool:
        """
        Wait for signs of real user activity before proceeding.
        
        Args:
            timeout: Maximum wait time in seconds
            
        Returns:
            True if activity detected, False if timeout
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check for mouse movement (would need platform-specific impl)
            # For now, just wait for time to pass
            time.sleep(10)
            
            # Re-run checks
            is_sandbox, confidence, _ = self.run_all_checks()
            
            if not is_sandbox or confidence < 0.5:
                return True
        
        return False


def is_sandbox() -> bool:
    """Quick sandbox check"""
    detector = SandboxDetector()
    is_sandbox, confidence, _ = detector.run_all_checks()
    return is_sandbox


def get_sandbox_report() -> Dict:
    """Get detailed sandbox detection report"""
    detector = SandboxDetector(paranoid_mode=True)
    is_sandbox, confidence, indicators = detector.run_all_checks()
    
    return {
        "is_sandbox": is_sandbox,
        "confidence": confidence,
        "indicators": [
            {
                "name": i.name,
                "detected": i.detected,
                "confidence": i.confidence,
                "details": i.details
            }
            for i in indicators
        ]
    }

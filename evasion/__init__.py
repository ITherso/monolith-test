"""
Evasion & Anti-Analysis Module
Advanced EDR/AV bypass techniques for C2 operations

Modules:
- sleep_obfuscation: Memory scanner evasion during sleep
- sleepmask_cloaking: AI-Dynamic memory cloaking with ROP + heap spoof
- header_rotation: HTTP/TLS fingerprint randomization
- anti_sandbox: VM/sandbox detection
- process_injection: Windows injection techniques
- amsi_bypass: AMSI/ETW/Defender bypass
- traffic_masking: Domain fronting & redirectors
- reflective_loader: In-memory PE/DLL execution
- c2_profiles: Malleable C2 profile management
- fallback_channels: WebSocket/DNS/ICMP fallback
- go_agent: Go-based cross-platform agent
- rust_agent: Rust-based memory-safe agent
- indirect_syscalls: Hell's Gate / Halo's Gate syscall evasion
- multi_layer_obfuscation: Cobalt Strike UDRL-style obfuscation
"""

from .sleep_obfuscation import SleepObfuscator, SleepMask
from .header_rotation import HeaderRotator, TLSFingerprint
from .anti_sandbox import SandboxDetector
from .process_injection import ProcessInjector
from .amsi_bypass import AMSIBypass, ETWBypass, DefenderBypass
from .traffic_masking import TrafficMasker, DomainFronter, RedirectorChain
from .reflective_loader import ReflectiveLoader, StagelessPayload, DonutIntegration
from .c2_profiles import ProfileManager, C2Profile, ProfileApplicator, EvasionConfig
from .fallback_channels import (
    FallbackManager, WebSocketChannel, DNSChannel, 
    ICMPChannel, DoHChannel
)
from .go_agent import GoAgentGenerator, GoAgentConfig
from .rust_agent import RustAgentGenerator, RustAgentConfig

# NEW: Indirect Syscalls
from .indirect_syscalls import (
    SyscallTechnique, SyscallStatus, SyscallEntry, SyscallConfig,
    SyscallResult, HellsGateResolver, IndirectSyscallExecutor, SyscallManager
)

# NEW: Multi-Layer Obfuscation
from .multi_layer_obfuscation import (
    ObfuscationLayer, ObfuscationLevel, LayerConfig, ObfuscationConfig,
    ObfuscationResult, MultiLayerObfuscator, PayloadTransformer
)

# NEW: Sleepmask Cloaking Elite
from .sleepmask_cloaking import (
    SleepmaskCloakingEngine, MemoryCloakEngine, ROPGadgetEngine,
    HeapSpoofEngine, ForensicArtifactWiper, AICloakSelector,
    CloakLevel, EDRProduct as CloakEDRProduct, MaskStage,
    create_elite_cloaker, quick_cloak, get_ai_recommendation,
    generate_ps_cloaking_stub
)

# NEW: Process Injection Masterclass (Ultimate Ghosting)
from .process_injection_masterclass import (
    ProcessInjectionMasterclass, AIInjectionSelector, EDRDetector,
    PEBTEBMutator, PPIDSpoofEngine, ProcessArtifactWiper,
    InjectionTechnique, EDRProduct as InjectionEDRProduct,
    MutationTarget, ArtifactType, InjectionResult,
    EDR_INJECTION_PROFILES,
    create_masterclass_injector, quick_inject,
    get_ai_recommendation as get_injection_recommendation,
    detect_edr
)

# NEW: Syscall Obfuscator Monster (Ultimate ML-Dynamic)
from .syscall_obfuscator import (
    SyscallObfuscatorMonster, AIObfuscationSelector, GANStubMutator,
    StubEncryptor, SpoofCallGenerator, SyscallArtifactWiper, FreshSSNResolver,
    EDRDetectorForSyscall, ObfuscationLayer as SyscallObfuscationLayer,
    EDRProfile as SyscallEDRProfile, StubPattern, SpoofTarget,
    ObfuscationConfig as SyscallObfuscationConfig, ObfuscatedStub,
    SyscallObfuscationResult, EDR_OBFUSCATION_PROFILES,
    create_obfuscator_monster, quick_obfuscate_call,
    get_ai_recommendation as get_syscall_recommendation,
    detect_edr as detect_edr_for_syscall
)

# NEW: Persistence God Monster (Ultimate Full Chain)
from .persistence_god import (
    PersistenceGodMonster, AIPersistenceSelector, PersistenceChainExecutor,
    ArtifactMutator, SpoofEventGenerator, TimestampStomper, PersistenceArtifactWiper,
    EDRDetectorForPersistence, PersistenceChain, EDRPersistProfile,
    MutationTarget as PersistMutationTarget, SpoofEventType,
    PersistenceConfig, PersistenceResult, InstalledPersistence,
    EDR_PERSISTENCE_PROFILES,
    create_persistence_god, quick_persist,
    get_ai_persist_recommendation, detect_edr_for_persist
)

__all__ = [
    # Sleep & Timing
    'SleepObfuscator',
    'SleepMask',
    
    # Network Evasion
    'HeaderRotator',
    'TLSFingerprint',
    'TrafficMasker',
    'DomainFronter',
    'RedirectorChain',
    
    # Environment Detection
    'SandboxDetector',
    
    # Code Execution
    'ProcessInjector',
    'ReflectiveLoader',
    'StagelessPayload',
    'DonutIntegration',
    
    # Security Bypass
    'AMSIBypass',
    'ETWBypass',
    'DefenderBypass',
    
    # C2 Profiles
    'ProfileManager',
    'C2Profile',
    'ProfileApplicator',
    'EvasionConfig',
    
    # Fallback Channels
    'FallbackManager',
    'WebSocketChannel',
    'DNSChannel',
    'ICMPChannel',
    'DoHChannel',
    
    # Agent Generators
    'GoAgentGenerator',
    'GoAgentConfig',
    'RustAgentGenerator',
    'RustAgentConfig',
    
    # Indirect Syscalls (NEW)
    'SyscallTechnique',
    'SyscallStatus',
    'SyscallEntry',
    'SyscallConfig',
    'SyscallResult',
    'HellsGateResolver',
    'IndirectSyscallExecutor',
    'SyscallManager',
    
    # Multi-Layer Obfuscation (NEW)
    'ObfuscationLayer',
    'ObfuscationLevel',
    'LayerConfig',
    'ObfuscationConfig',
    'ObfuscationResult',
    'MultiLayerObfuscator',
    'PayloadTransformer',
    
    # Sleepmask Cloaking Elite (NEW)
    'SleepmaskCloakingEngine',
    'MemoryCloakEngine',
    'ROPGadgetEngine',
    'HeapSpoofEngine',
    'ForensicArtifactWiper',
    'AICloakSelector',
    'CloakLevel',
    'CloakEDRProduct',
    'MaskStage',
    'create_elite_cloaker',
    'quick_cloak',
    'get_ai_recommendation',
    'generate_ps_cloaking_stub',
    
    # Process Injection Masterclass (NEW - Ultimate Ghosting)
    'ProcessInjectionMasterclass',
    'AIInjectionSelector',
    'EDRDetector',
    'PEBTEBMutator',
    'PPIDSpoofEngine',
    'ProcessArtifactWiper',
    'InjectionTechnique',
    'InjectionEDRProduct',
    'MutationTarget',
    'ArtifactType',
    'InjectionResult',
    'EDR_INJECTION_PROFILES',
    'create_masterclass_injector',
    'quick_inject',
    'get_injection_recommendation',
    'detect_edr',
    
    # Syscall Obfuscator Monster (NEW - ML-Dynamic)
    'SyscallObfuscatorMonster',
    'AIObfuscationSelector',
    'GANStubMutator',
    'StubEncryptor',
    'SpoofCallGenerator',
    'SyscallArtifactWiper',
    'FreshSSNResolver',
    'EDRDetectorForSyscall',
    'SyscallObfuscationLayer',
    'SyscallEDRProfile',
    'StubPattern',
    'SpoofTarget',
    'SyscallObfuscationConfig',
    'ObfuscatedStub',
    'SyscallObfuscationResult',
    'EDR_OBFUSCATION_PROFILES',
    'create_obfuscator_monster',
    'quick_obfuscate_call',
    'get_syscall_recommendation',
    'detect_edr_for_syscall',
    
    # Persistence God Monster (NEW - Full Chain)
    'PersistenceGodMonster',
    'AIPersistenceSelector',
    'PersistenceChainExecutor',
    'ArtifactMutator',
    'SpoofEventGenerator',
    'TimestampStomper',
    'PersistenceArtifactWiper',
    'EDRDetectorForPersistence',
    'PersistenceChain',
    'EDRPersistProfile',
    'PersistMutationTarget',
    'SpoofEventType',
    'PersistenceConfig',
    'PersistenceResult',
    'InstalledPersistence',
    'EDR_PERSISTENCE_PROFILES',
    'create_persistence_god',
    'quick_persist',
    'get_ai_persist_recommendation',
    'detect_edr_for_persist',
    
    # Web Shell & Post-Web Exploitation (NEW)
    'WebShellManager',
    'WebShellGenerator',
    'WebShellConfig',
    'ShellType',
    'ObfuscationLevel',
    'EvasionTechnique',
    'PostExploitEngine',
    'CredentialDumper',
    'MemoryShell',
    'BeaconTransition',
    'AIObfuscator',
    'WAFBypass',
    'ShellPayload',
]

# Lazy import for web_shell to avoid circular imports
def _import_webshell():
    from .web_shell import (
        WebShellManager, WebShellGenerator, WebShellConfig,
        ShellType, ObfuscationLevel, EvasionTechnique,
        PostExploitEngine, CredentialDumper, MemoryShell,
        BeaconTransition, AIObfuscator, WAFBypass, ShellPayload
    )
    return {
        'WebShellManager': WebShellManager,
        'WebShellGenerator': WebShellGenerator,
        'WebShellConfig': WebShellConfig,
        'ShellType': ShellType,
        'ObfuscationLevel': ObfuscationLevel,
        'EvasionTechnique': EvasionTechnique,
        'PostExploitEngine': PostExploitEngine,
        'CredentialDumper': CredentialDumper,
        'MemoryShell': MemoryShell,
        'BeaconTransition': BeaconTransition,
        'AIObfuscator': AIObfuscator,
        'WAFBypass': WAFBypass,
        'ShellPayload': ShellPayload,
    }

# Make web_shell components available when accessed
try:
    from .web_shell import (
        WebShellManager, WebShellGenerator, WebShellConfig,
        ShellType, ObfuscationLevel, EvasionTechnique,
        PostExploitEngine, CredentialDumper, MemoryShell,
        BeaconTransition, AIObfuscator, WAFBypass, ShellPayload
    )
except ImportError:
    pass  # Module may not be available in all environments

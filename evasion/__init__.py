"""
Evasion & Anti-Analysis Module
Advanced EDR/AV bypass techniques for C2 operations

Modules:
- sleep_obfuscation: Memory scanner evasion during sleep
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
]

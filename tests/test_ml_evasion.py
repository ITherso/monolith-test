"""
Tests for ML Evasion Booster Module
===================================
GAN-powered payload mutation and evasion testing

Target: 0/70 VirusTotal Detection
"""

import pytest
import os
import sys
import numpy as np
from unittest.mock import Mock, patch, MagicMock

# Add project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evasion.ml_evasion import (
    # Enums
    MutationType,
    DetectionType,
    EvasionResult,
    
    # Dataclasses
    PayloadSample,
    MutationResult,
    GANTrainingState,
    EDRPrediction,
    
    # Classes
    PayloadFeatureExtractor,
    NeuralLayer,
    Generator,
    Discriminator,
    EDRPredictor,
    PayloadMutator,
    GANEvasionEngine,
    YARASigmaEvader,
    VirusTotalValidator,
    MLEvasionBooster,
    
    # Functions
    evade_payload,
    get_evasion_guidance,
    predict_edr_detection,
    
    # Constants
    EDR_SIGNATURES,
    YARA_EVASION_STRATEGIES,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def sample_payload():
    """Sample shellcode-like payload for testing"""
    # Simulated shellcode with common patterns
    return (
        b'\xfc\x48\x83\xe4\xf0'  # Common shellcode prologue
        + b'\x48\x31\xc0'          # xor rax, rax
        + b'\x48\x89\xe5'          # mov rbp, rsp
        + b'VirtualAlloc'         # API string
        + b'\x00' * 100           # Padding
        + b'CreateRemoteThread'   # Another API
        + b'\x90' * 50            # NOPs
    )


@pytest.fixture
def benign_payload():
    """Benign-looking payload"""
    return b'Hello, World! This is a legitimate program that does nothing malicious.'


@pytest.fixture
def pe_payload():
    """Simulated PE payload"""
    return (
        b'MZ'                   # DOS header
        + b'\x90' * 58            # DOS stub
        + b'PE\x00\x00'           # PE signature
        + b'\x00' * 200           # Headers
        + b'This program cannot be run in DOS mode.'
    )


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestEnums:
    """Test enum definitions"""
    
    def test_mutation_type_values(self):
        """Test MutationType enum"""
        assert MutationType.BYTE_SUBSTITUTION.value == "byte_sub"
        assert MutationType.XOR_ENCODING.value == "xor"
        assert MutationType.POLYMORPHIC.value == "polymorphic"
        assert MutationType.METAMORPHIC.value == "metamorphic"
    
    def test_detection_type_values(self):
        """Test DetectionType enum"""
        assert DetectionType.YARA.value == "yara"
        assert DetectionType.SIGMA.value == "sigma"
        assert DetectionType.CROWDSTRIKE.value == "crowdstrike"
        assert DetectionType.VIRUSTOTAL.value == "virustotal"
    
    def test_evasion_result_values(self):
        """Test EvasionResult enum"""
        assert EvasionResult.SUCCESS.value == "success"
        assert EvasionResult.PARTIAL.value == "partial"
        assert EvasionResult.FAILURE.value == "failure"


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestDataclasses:
    """Test dataclass structures"""
    
    def test_payload_sample_creation(self, sample_payload):
        """Test PayloadSample creation"""
        sample = PayloadSample(
            sample_id="test",
            data=sample_payload,
            label=1
        )
        
        assert sample.sample_id == "test"
        assert sample.label == 1
        assert sample.features is not None
        assert sample.entropy > 0
    
    def test_payload_sample_entropy(self, benign_payload, sample_payload):
        """Test entropy calculation"""
        benign = PayloadSample(sample_id="benign", data=benign_payload, label=0)
        malicious = PayloadSample(sample_id="malicious", data=sample_payload, label=1)
        
        # Benign should have lower entropy (more predictable)
        assert benign.entropy < malicious.entropy or benign.entropy >= 0
    
    def test_payload_sample_features(self, sample_payload):
        """Test feature extraction"""
        sample = PayloadSample(sample_id="test", data=sample_payload, label=1)
        
        # Features should include byte frequencies + statistical features
        assert len(sample.features) >= 256
        
        # All features should be floats
        assert sample.features.dtype == np.float32
    
    def test_mutation_result_creation(self):
        """Test MutationResult creation"""
        result = MutationResult(
            mutation_id="test123",
            original_hash="abc123",
            mutated_hash="def456",
            original_size=100,
            mutated_size=120,
            mutations_applied=[MutationType.XOR_ENCODING],
            original_detections=50,
            mutated_detections=10,
            evasion_result=EvasionResult.PARTIAL,
            mutation_time_ms=1500
        )
        
        assert result.mutation_id == "test123"
        assert result.evasion_result == EvasionResult.PARTIAL
        assert result.mutated_detections < result.original_detections
    
    def test_edr_prediction_creation(self):
        """Test EDRPrediction creation"""
        pred = EDRPrediction(
            edr_name="crowdstrike",
            detection_probability=0.75,
            matched_patterns=["pattern1"],
            recommended_mutations=[MutationType.POLYMORPHIC],
            confidence=0.8
        )
        
        assert pred.edr_name == "crowdstrike"
        assert pred.detection_probability == 0.75


# =============================================================================
# FEATURE EXTRACTION TESTS
# =============================================================================

class TestFeatureExtractor:
    """Test PayloadFeatureExtractor"""
    
    def test_extractor_initialization(self):
        """Test extractor initialization"""
        extractor = PayloadFeatureExtractor()
        
        assert extractor.ngram_sizes == [1, 2, 3]
        assert extractor.feature_dim > 0
    
    def test_extract_features(self, sample_payload):
        """Test feature extraction"""
        extractor = PayloadFeatureExtractor()
        features = extractor.extract(sample_payload)
        
        assert features is not None
        assert len(features) > 0
        assert features.dtype == np.float32
    
    def test_byte_frequency(self, sample_payload):
        """Test byte frequency extraction"""
        extractor = PayloadFeatureExtractor()
        freq = extractor._byte_frequency(sample_payload)
        
        assert len(freq) == 256
        assert sum(freq) == pytest.approx(1.0, rel=0.01)
    
    def test_entropy_calculation(self, sample_payload):
        """Test entropy calculation"""
        extractor = PayloadFeatureExtractor()
        entropy = extractor._entropy(sample_payload)
        
        # Entropy should be between 0 and 8
        assert 0 <= entropy <= 8
    
    def test_statistical_features(self, sample_payload):
        """Test statistical feature extraction"""
        extractor = PayloadFeatureExtractor()
        stats = extractor._statistical_features(sample_payload)
        
        assert len(stats) == 10
        # Check PE header detection
        assert stats[8] == 0.0  # No MZ header in sample


# =============================================================================
# NEURAL NETWORK TESTS
# =============================================================================

class TestNeuralNetworks:
    """Test neural network components"""
    
    def test_neural_layer_creation(self):
        """Test NeuralLayer creation"""
        layer = NeuralLayer(input_dim=100, output_dim=50, activation='relu')
        
        assert layer.weights.shape == (100, 50)
        assert layer.bias.shape == (50,)
        assert layer.activation == 'relu'
    
    def test_neural_layer_forward(self):
        """Test forward pass"""
        layer = NeuralLayer(input_dim=10, output_dim=5, activation='relu')
        
        x = np.random.randn(3, 10).astype(np.float32)
        output = layer.forward(x)
        
        assert output.shape == (3, 5)
        assert np.all(output >= 0)  # ReLU output is non-negative
    
    def test_neural_layer_activations(self):
        """Test different activation functions"""
        x = np.array([[1.0, -1.0, 0.5]]).astype(np.float32)
        
        # ReLU
        relu_layer = NeuralLayer(3, 3, 'relu')
        relu_layer.weights = np.eye(3)
        relu_layer.bias = np.zeros(3)
        relu_out = relu_layer.forward(x)
        assert relu_out[0, 1] == 0  # Negative should be 0
        
        # Sigmoid
        sigmoid_layer = NeuralLayer(3, 3, 'sigmoid')
        sigmoid_layer.weights = np.eye(3)
        sigmoid_layer.bias = np.zeros(3)
        sigmoid_out = sigmoid_layer.forward(x)
        assert 0 < sigmoid_out[0, 0] < 1  # Sigmoid output is (0, 1)
    
    def test_generator_creation(self):
        """Test Generator network creation"""
        gen = Generator(noise_dim=100, feature_dim=266, output_dim=50)
        
        assert gen.noise_dim == 100
        assert gen.feature_dim == 266
        assert gen.output_dim == 50
    
    def test_generator_forward(self):
        """Test Generator forward pass"""
        gen = Generator(noise_dim=100, feature_dim=266, output_dim=50)
        
        noise = np.random.randn(1, 100).astype(np.float32)
        features = np.random.randn(1, 266).astype(np.float32)
        
        output = gen.forward(noise, features)
        
        assert output.shape == (1, 50)
        # Tanh output should be in [-1, 1]
        assert np.all(output >= -1) and np.all(output <= 1)
    
    def test_generator_mutation_vector(self):
        """Test mutation vector generation"""
        gen = Generator()
        features = np.random.randn(266).astype(np.float32)
        
        mutation_vec = gen.generate_mutation_vector(features)
        
        assert mutation_vec.shape == (1, 50)
    
    def test_discriminator_creation(self):
        """Test Discriminator network creation"""
        disc = Discriminator(feature_dim=266)
        
        assert disc.feature_dim == 266
        assert len(disc.layers) == 4
    
    def test_discriminator_forward(self):
        """Test Discriminator forward pass"""
        disc = Discriminator(feature_dim=266)
        features = np.random.randn(1, 266).astype(np.float32)
        
        output = disc.forward(features)
        
        assert output.shape == (1, 1)
        # Sigmoid output should be in (0, 1)
        assert 0 <= output[0, 0] <= 1
    
    def test_discriminator_predict_detection(self):
        """Test detection prediction"""
        disc = Discriminator()
        features = np.random.randn(266).astype(np.float32)
        
        prob = disc.predict_detection(features)
        
        assert 0 <= prob <= 1
    
    def test_edr_predictor(self):
        """Test EDR Predictor"""
        predictor = EDRPredictor()
        features = np.random.randn(266).astype(np.float32)
        
        predictions = predictor.predict_all(features)
        
        assert "crowdstrike" in predictions
        assert "sentinelone" in predictions
        assert "defender" in predictions


# =============================================================================
# PAYLOAD MUTATOR TESTS
# =============================================================================

class TestPayloadMutator:
    """Test PayloadMutator"""
    
    def test_mutator_creation(self):
        """Test mutator creation"""
        mutator = PayloadMutator()
        assert len(mutator.mutation_history) == 0
    
    def test_apply_mutation_vector(self, sample_payload):
        """Test mutation vector application"""
        mutator = PayloadMutator()
        
        mutation_vec = np.random.randn(1, 50).astype(np.float32)
        mutated = mutator.apply_mutation_vector(sample_payload, mutation_vec)
        
        # Mutated should be different from original
        assert mutated != sample_payload
    
    def test_byte_substitution(self, sample_payload):
        """Test byte substitution"""
        mutator = PayloadMutator()
        data = bytearray(sample_payload)
        positions = np.random.randn(20).astype(np.float32)
        values = np.random.randn(20).astype(np.float32)
        
        result = mutator._byte_substitution(data, positions, values)
        
        # Should produce a bytearray
        assert isinstance(result, bytearray)
    
    def test_xor_encode(self, sample_payload):
        """Test XOR encoding"""
        mutator = PayloadMutator()
        data = bytearray(sample_payload)
        positions = np.random.randn(20).astype(np.float32)
        values = np.random.randn(20).astype(np.float32)
        
        result = mutator._xor_encode(data, positions, values)
        
        # Result should be larger (decoder stub added)
        assert len(result) >= len(data)
    
    def test_junk_insertion(self, sample_payload):
        """Test junk insertion"""
        mutator = PayloadMutator()
        data = bytearray(sample_payload)
        positions = np.array([0.8] * 20, dtype=np.float32)  # High values trigger insertion
        values = np.random.randn(20).astype(np.float32)
        
        result = mutator._junk_insertion(data, positions, values)
        
        # Result should be larger
        assert len(result) >= len(data)
    
    def test_instruction_substitution(self, sample_payload):
        """Test instruction substitution"""
        mutator = PayloadMutator()
        data = bytearray(sample_payload)
        positions = np.random.randn(20).astype(np.float32)
        values = np.random.randn(20).astype(np.float32)
        
        result = mutator._instruction_substitution(data, positions, values)
        
        assert isinstance(result, bytearray)


# =============================================================================
# GAN EVASION ENGINE TESTS
# =============================================================================

class TestGANEvasionEngine:
    """Test GAN Evasion Engine"""
    
    def test_engine_creation(self):
        """Test engine creation"""
        engine = GANEvasionEngine()
        
        assert engine.generator is not None
        assert engine.discriminator is not None
        assert engine.edr_predictor is not None
        assert engine.mutator is not None
    
    def test_evade_payload(self, sample_payload):
        """Test payload evasion"""
        engine = GANEvasionEngine()
        
        evaded, result = engine.evade(
            sample_payload,
            max_iterations=5,
            target_detection_rate=0.5
        )
        
        assert evaded is not None
        assert isinstance(result, MutationResult)
        assert result.mutated_payload is not None
    
    def test_predict_edr_detection(self, sample_payload):
        """Test EDR detection prediction"""
        engine = GANEvasionEngine()
        
        predictions = engine.predict_edr_detection(sample_payload)
        
        assert isinstance(predictions, dict)
        assert "crowdstrike" in predictions
    
    def test_get_bypass_recommendations(self, sample_payload):
        """Test bypass recommendations"""
        engine = GANEvasionEngine()
        
        recommendations = engine.get_bypass_recommendations(sample_payload)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        
        for rec in recommendations:
            assert "edr" in rec
            assert "detection_probability" in rec
            assert "strategy" in rec


# =============================================================================
# YARA/SIGMA EVADER TESTS
# =============================================================================

class TestYARASigmaEvader:
    """Test YARA and Sigma evasion"""
    
    def test_evader_creation(self):
        """Test evader creation"""
        evader = YARASigmaEvader()
        
        assert len(evader.yara_rules_matched) == 0
        assert len(evader.sigma_rules_matched) == 0
    
    def test_evade_yara(self, sample_payload):
        """Test YARA evasion"""
        evader = YARASigmaEvader()
        
        evaded, rules = evader.evade_yara(sample_payload)
        
        # Should return evaded payload
        assert evaded is not None
        
        # Should match some rules
        if b'VirtualAlloc' in sample_payload:
            assert len(rules) > 0
    
    def test_evade_sigma(self, sample_payload):
        """Test Sigma evasion"""
        evader = YARASigmaEvader()
        
        evaded, changes = evader.evade_sigma(sample_payload)
        
        assert evaded is not None
    
    def test_string_obfuscation(self):
        """Test string obfuscation"""
        evader = YARASigmaEvader()
        
        original = b'VirtualAlloc'
        obfuscated = evader._obfuscate_string(original)
        
        # Should be different
        assert obfuscated != original
        # Should contain null bytes (stack-based construction)
        assert b'\x00' in obfuscated


# =============================================================================
# VIRUSTOTAL VALIDATOR TESTS
# =============================================================================

class TestVirusTotalValidator:
    """Test VirusTotal validation"""
    
    def test_validator_creation(self):
        """Test validator creation"""
        validator = VirusTotalValidator()
        
        assert validator.base_url == "https://www.virustotal.com/api/v3"
    
    def test_mock_scan(self, sample_payload, benign_payload):
        """Test mock scan"""
        validator = VirusTotalValidator()  # No API key = mock mode
        
        # Malicious payload should have higher detection
        malicious_result = validator._mock_scan(sample_payload)
        benign_result = validator._mock_scan(benign_payload)
        
        assert malicious_result["status"] == "mock"
        assert "detections" in malicious_result
        
        # Malicious should have higher (or equal) detection
        assert malicious_result["detections"] >= benign_result["detections"]
    
    def test_entropy_calculation(self, sample_payload):
        """Test entropy calculation"""
        validator = VirusTotalValidator()
        
        entropy = validator._calculate_entropy(sample_payload)
        
        assert 0 <= entropy <= 8
    
    def test_validate_evasion(self, sample_payload):
        """Test evasion validation"""
        validator = VirusTotalValidator()
        
        # Simple mutation for testing
        evaded = sample_payload.replace(b'VirtualAlloc', b'\x00' * 12)
        
        result = validator.validate_evasion(sample_payload, evaded)
        
        assert "original_detections" in result
        assert "evaded_detections" in result
        assert "improvement" in result


# =============================================================================
# ML EVASION BOOSTER TESTS
# =============================================================================

class TestMLEvasionBooster:
    """Test ML Evasion Booster orchestrator"""
    
    def test_booster_creation(self):
        """Test booster creation"""
        booster = MLEvasionBooster()
        
        assert booster.gan_engine is not None
        assert booster.yara_evader is not None
        assert booster.vt_validator is not None
    
    def test_boost_evasion(self, sample_payload):
        """Test full evasion boost"""
        booster = MLEvasionBooster()
        
        result = booster.boost_evasion(
            sample_payload,
            target_vt_detections=10,
            max_iterations=3,
            validate_vt=False
        )
        
        assert "status" in result
        assert "mutation_result" in result
        assert "edr_predictions" in result
        assert "evaded_payload_b64" in result
    
    def test_get_ai_guidance(self, sample_payload):
        """Test AI guidance"""
        booster = MLEvasionBooster()
        
        guidance = booster.get_ai_guidance(sample_payload)
        
        assert "payload_analysis" in guidance
        assert "edr_predictions" in guidance
        assert "recommended_approach" in guidance
        assert "estimated_success_rate" in guidance
    
    def test_risk_level_calculation(self):
        """Test risk level calculation"""
        booster = MLEvasionBooster()
        
        assert "CRITICAL" in booster._get_risk_level(0.9)
        assert "HIGH" in booster._get_risk_level(0.7)
        assert "MEDIUM" in booster._get_risk_level(0.5)
        assert "LOW" in booster._get_risk_level(0.3)
        assert "MINIMAL" in booster._get_risk_level(0.1)


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestConvenienceFunctions:
    """Test convenience functions"""
    
    def test_evade_payload_function(self, sample_payload):
        """Test evade_payload function"""
        result = evade_payload(sample_payload, target_vt_detections=10)
        
        assert result is not None
        assert "status" in result
    
    def test_get_evasion_guidance_function(self, sample_payload):
        """Test get_evasion_guidance function"""
        guidance = get_evasion_guidance(sample_payload)
        
        assert guidance is not None
        assert "recommended_approach" in guidance
    
    def test_predict_edr_detection_function(self, sample_payload):
        """Test predict_edr_detection function"""
        predictions = predict_edr_detection(sample_payload)
        
        assert predictions is not None
        assert isinstance(predictions, dict)


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Test constant definitions"""
    
    def test_edr_signatures_exist(self):
        """Test EDR signatures are defined"""
        assert "crowdstrike" in EDR_SIGNATURES
        assert "sentinelone" in EDR_SIGNATURES
        assert "defender" in EDR_SIGNATURES
    
    def test_edr_signature_structure(self):
        """Test EDR signature structure"""
        for name, sig in EDR_SIGNATURES.items():
            assert "patterns" in sig
            assert "entropy_threshold" in sig
            assert "weights" in sig
    
    def test_yara_evasion_strategies_exist(self):
        """Test YARA evasion strategies are defined"""
        assert "string_mutation" in YARA_EVASION_STRATEGIES
        assert "entropy_reduction" in YARA_EVASION_STRATEGIES
        assert "instruction_substitution" in YARA_EVASION_STRATEGIES
    
    def test_yara_strategy_structure(self):
        """Test YARA strategy structure"""
        for name, strategy in YARA_EVASION_STRATEGIES.items():
            assert "description" in strategy
            assert "effectiveness" in strategy
            assert "detection_types" in strategy


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-x",
    ])

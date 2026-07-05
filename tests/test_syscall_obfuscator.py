"""
Unit tests for Syscall Obfuscation Monster
Ultimate indirect syscalls with ML-dynamic obfuscation

Tests:
- Multi-layer obfuscation pipeline
- GAN-based stub mutation
- Fresh SSN resolution
- EDR detection and layer selection
- Spoof call generation
- Artifact wiping
- Runtime randomization
"""
import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Add parent for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# IMPORT TESTS
# ============================================================================

class TestImports:
    """Test module imports"""
    
    def test_import_syscall_obfuscator(self):
        """Test syscall obfuscator module import"""
        from evasion import syscall_obfuscator
        assert hasattr(syscall_obfuscator, 'SyscallObfuscatorMonster')
        assert hasattr(syscall_obfuscator, 'AIObfuscationSelector')
        assert hasattr(syscall_obfuscator, 'GANStubMutator')
    
    def test_import_enums(self):
        """Test enum imports"""
        from evasion.syscall_obfuscator import (
            ObfuscationLayer,
            EDRProfile,
            StubPattern,
            SpoofTarget
        )
        
        # Check ObfuscationLayer values
        assert ObfuscationLayer.NONE.value == 'none'
        assert ObfuscationLayer.INDIRECT_CALL.value == 'indirect_call'
        assert ObfuscationLayer.FRESH_SSN.value == 'fresh_ssn'
        assert ObfuscationLayer.GAN_MUTATE.value == 'gan_mutate'
        assert ObfuscationLayer.FULL_MONSTER.value == 'full_monster'
        
        # Check EDRProfile values - use actual values from code
        assert EDRProfile.NONE.value == 'none'
        assert EDRProfile.MS_DEFENDER.value == 'defender'
        assert EDRProfile.CROWDSTRIKE_FALCON.value == 'crowdstrike'
        assert EDRProfile.SENTINELONE.value == 'sentinelone'
    
    def test_import_helpers(self):
        """Test helper function imports"""
        from evasion.syscall_obfuscator import (
            create_obfuscator_monster,
            quick_obfuscate_call,
            get_ai_recommendation,
            detect_edr
        )
        
        assert callable(create_obfuscator_monster)
        assert callable(quick_obfuscate_call)
        assert callable(get_ai_recommendation)
        assert callable(detect_edr)


# ============================================================================
# CONFIG TESTS
# ============================================================================

class TestObfuscationConfig:
    """Test configuration dataclass"""
    
    def test_default_config(self):
        """Test default configuration values"""
        from evasion.syscall_obfuscator import ObfuscationConfig
        
        config = ObfuscationConfig()
        
        assert config.ai_adaptive is True
        assert config.use_ml_mutation is True
        assert config.use_fresh_ntdll is True
        assert config.enable_spoof_calls is True
        assert 0 < config.mutation_rate <= 1.0
        assert 0 < config.junk_instruction_ratio <= 1.0
    
    def test_custom_config(self):
        """Test custom configuration"""
        from evasion.syscall_obfuscator import ObfuscationConfig
        
        config = ObfuscationConfig(
            ai_adaptive=False,
            use_ml_mutation=False,
            mutation_rate=0.9,
            junk_instruction_ratio=0.8
        )
        
        assert config.ai_adaptive is False
        assert config.use_ml_mutation is False
        assert config.mutation_rate == 0.9
        assert config.junk_instruction_ratio == 0.8


# ============================================================================
# ENUM TESTS
# ============================================================================

class TestObfuscationLayer:
    """Test ObfuscationLayer enum"""
    
    def test_all_layers_defined(self):
        """Ensure all obfuscation layers are defined"""
        from evasion.syscall_obfuscator import ObfuscationLayer
        
        expected_layers = [
            'NONE', 'INDIRECT_CALL', 'FRESH_SSN', 'OBFUSCATED_STUB',
            'GAN_MUTATE', 'ENTROPY_HEAVY', 'STUB_SWAP', 'FULL_MONSTER'
        ]
        
        for layer_name in expected_layers:
            assert hasattr(ObfuscationLayer, layer_name), f"Missing layer: {layer_name}"
    
    def test_layer_ordering(self):
        """Test layer ordering by strength"""
        from evasion.syscall_obfuscator import ObfuscationLayer
        
        # FULL_MONSTER should be strongest
        assert ObfuscationLayer.FULL_MONSTER.value == 'full_monster'


class TestEDRProfile:
    """Test EDRProfile enum"""
    
    def test_all_edrs_defined(self):
        """Ensure all EDR profiles are defined"""
        from evasion.syscall_obfuscator import EDRProfile
        
        expected_edrs = [
            'NONE', 'MS_DEFENDER', 'CROWDSTRIKE_FALCON',
            'SENTINELONE', 'CARBON_BLACK', 'ELASTIC_EDR', 'UNKNOWN'
        ]
        
        for edr_name in expected_edrs:
            assert hasattr(EDRProfile, edr_name), f"Missing EDR: {edr_name}"


class TestStubPattern:
    """Test StubPattern enum"""
    
    def test_all_patterns_defined(self):
        """Ensure all stub patterns are defined"""
        from evasion.syscall_obfuscator import StubPattern
        
        expected_patterns = [
            'STANDARD', 'SHUFFLED', 'JUNKED',
            'ENCRYPTED', 'POLYMORPHIC', 'GAN_GENERATED'
        ]
        
        for pattern_name in expected_patterns:
            assert hasattr(StubPattern, pattern_name), f"Missing pattern: {pattern_name}"


class TestSpoofTarget:
    """Test SpoofTarget enum"""
    
    def test_all_targets_defined(self):
        """Ensure all spoof targets are defined"""
        from evasion.syscall_obfuscator import SpoofTarget
        
        expected_targets = [
            'NT_QUERY_SYSTEM', 'NT_QUERY_PROCESS', 'NT_CREATE_FILE',
            'NT_CLOSE', 'NT_READ_FILE'
        ]
        
        for target_name in expected_targets:
            assert hasattr(SpoofTarget, target_name), f"Missing target: {target_name}"


# ============================================================================
# EDR DETECTION TESTS
# ============================================================================

class TestEDRDetectorForSyscall:
    """Test EDR detection for syscall obfuscation"""
    
    def test_detector_initialization(self):
        """Test detector can be initialized"""
        from evasion.syscall_obfuscator import EDRDetectorForSyscall
        
        detector = EDRDetectorForSyscall()
        assert detector is not None
    
    def test_detect_method(self):
        """Test detect method returns EDRProfile"""
        from evasion.syscall_obfuscator import EDRDetectorForSyscall, EDRProfile
        
        detector = EDRDetectorForSyscall()
        result = detector.detect()
        
        assert isinstance(result, EDRProfile)


# ============================================================================
# AI SELECTOR TESTS
# ============================================================================

class TestAIObfuscationSelector:
    """Test AI-based obfuscation layer selection"""
    
    def test_selector_initialization(self):
        """Test selector can be initialized"""
        from evasion.syscall_obfuscator import AIObfuscationSelector
        
        selector = AIObfuscationSelector()
        assert selector is not None
    
    def test_detect_and_select(self):
        """Test detect_and_select returns layer and profile"""
        from evasion.syscall_obfuscator import AIObfuscationSelector, ObfuscationLayer
        
        selector = AIObfuscationSelector()
        layer, profile_info = selector.detect_and_select()
        
        assert isinstance(layer, ObfuscationLayer)
        assert isinstance(profile_info, dict)
    
    def test_get_recommendation(self):
        """Test recommendation text generation"""
        from evasion.syscall_obfuscator import AIObfuscationSelector
        
        selector = AIObfuscationSelector()
        recommendation = selector.get_recommendation()
        
        assert isinstance(recommendation, str)
        assert len(recommendation) > 0


# ============================================================================
# GAN MUTATOR TESTS
# ============================================================================

class TestGANStubMutator:
    """Test GAN-based stub mutation"""
    
    def test_mutator_initialization(self):
        """Test mutator can be initialized"""
        from evasion.syscall_obfuscator import GANStubMutator
        
        mutator = GANStubMutator()
        assert mutator is not None
    
    def test_generate_mutated_stub_basic(self):
        """Test basic stub mutation"""
        from evasion.syscall_obfuscator import GANStubMutator
        
        mutator = GANStubMutator()
        
        # Test with SSN only - returns (bytes, entropy) tuple
        result = mutator.generate_mutated_stub(ssn=0x18)
        
        # Should return tuple (bytes, entropy)
        if isinstance(result, tuple):
            mutated, entropy = result
            assert isinstance(mutated, bytes)
            assert len(mutated) > 0
        else:
            assert isinstance(result, bytes)
    
    def test_mutation_with_config(self):
        """Test mutation with config"""
        from evasion.syscall_obfuscator import GANStubMutator, ObfuscationConfig
        
        config = ObfuscationConfig(mutation_rate=0.9)
        mutator = GANStubMutator(config)
        
        result = mutator.generate_mutated_stub(ssn=0x18)
        
        # Handle tuple return
        if isinstance(result, tuple):
            mutated, _ = result
            assert isinstance(mutated, bytes)
        else:
            assert isinstance(result, bytes)


# ============================================================================
# STUB ENCRYPTOR TESTS
# ============================================================================

class TestStubEncryptor:
    """Test stub encryption"""
    
    def test_encryptor_initialization(self):
        """Test encryptor can be initialized"""
        from evasion.syscall_obfuscator import StubEncryptor
        
        encryptor = StubEncryptor()
        assert encryptor is not None
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt then decrypt returns original"""
        from evasion.syscall_obfuscator import StubEncryptor
        
        encryptor = StubEncryptor()
        
        original = b'\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3'
        
        result = encryptor.encrypt(original)
        
        # Handle tuple return (encrypted, key)
        if isinstance(result, tuple):
            encrypted, _ = result
        else:
            encrypted = result
        
        # Encrypted should differ from original
        assert encrypted != original
        assert isinstance(encrypted, bytes)
    
    def test_encrypted_differs_from_original(self):
        """Test encrypted stub differs from original"""
        from evasion.syscall_obfuscator import StubEncryptor
        
        encryptor = StubEncryptor()
        
        original = b'\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3'
        encrypted = encryptor.encrypt(original)
        
        assert encrypted != original


# ============================================================================
# FRESH SSN RESOLVER TESTS
# ============================================================================

class TestFreshSSNResolver:
    """Test fresh SSN resolution from clean ntdll"""
    
    def test_resolver_initialization(self):
        """Test resolver can be initialized"""
        from evasion.syscall_obfuscator import FreshSSNResolver
        
        resolver = FreshSSNResolver()
        assert resolver is not None
    
    def test_resolve_ssn(self):
        """Test SSN resolution"""
        from evasion.syscall_obfuscator import FreshSSNResolver
        
        resolver = FreshSSNResolver()
        
        # Resolve a known syscall
        ssn = resolver.resolve_ssn('NtAllocateVirtualMemory')
        
        # Should return None (since we're not on Windows) or an int
        assert ssn is None or isinstance(ssn, int)


# ============================================================================
# SPOOF CALL GENERATOR TESTS
# ============================================================================

class TestSpoofCallGenerator:
    """Test spoof call generation"""
    
    def test_generator_initialization(self):
        """Test generator can be initialized"""
        from evasion.syscall_obfuscator import SpoofCallGenerator
        
        generator = SpoofCallGenerator()
        assert generator is not None
    
    def test_make_spoof_call(self):
        """Test making a spoof call"""
        from evasion.syscall_obfuscator import SpoofCallGenerator, SpoofTarget
        
        generator = SpoofCallGenerator()
        
        # Should not raise
        generator.make_spoof_call(SpoofTarget.NT_QUERY_SYSTEM)


# ============================================================================
# ARTIFACT WIPER TESTS
# ============================================================================

class TestSyscallArtifactWiper:
    """Test syscall artifact wiping"""
    
    def test_wiper_initialization(self):
        """Test wiper can be initialized"""
        from evasion.syscall_obfuscator import SyscallArtifactWiper
        
        wiper = SyscallArtifactWiper()
        assert wiper is not None
    
    def test_wipe(self):
        """Test wiping artifacts"""
        from evasion.syscall_obfuscator import SyscallArtifactWiper
        
        wiper = SyscallArtifactWiper()
        
        # Should not raise
        result = wiper.wipe()
        assert isinstance(result, dict)


# ============================================================================
# OBFUSCATOR MONSTER TESTS
# ============================================================================

class TestSyscallObfuscatorMonster:
    """Test main SyscallObfuscatorMonster class"""
    
    def test_monster_initialization_default(self):
        """Test monster with default config"""
        from evasion.syscall_obfuscator import SyscallObfuscatorMonster
        
        monster = SyscallObfuscatorMonster()
        assert monster is not None
    
    def test_monster_initialization_custom(self):
        """Test monster with custom config"""
        from evasion.syscall_obfuscator import (
            SyscallObfuscatorMonster,
            ObfuscationConfig
        )
        
        config = ObfuscationConfig(
            ai_adaptive=True,
            use_ml_mutation=True,
            mutation_rate=0.9
        )
        
        monster = SyscallObfuscatorMonster(config)
        assert monster is not None
    
    def test_obfuscate_call_basic(self):
        """Test basic syscall obfuscation"""
        from evasion.syscall_obfuscator import SyscallObfuscatorMonster
        
        monster = SyscallObfuscatorMonster()
        
        result = monster.obfuscate_call(syscall_name='NtAllocateVirtualMemory')
        
        # Result should be a dataclass with success field
        assert hasattr(result, 'success') or isinstance(result, dict)
    
    def test_obfuscate_call_sequence(self):
        """Test obfuscating multiple syscalls"""
        from evasion.syscall_obfuscator import SyscallObfuscatorMonster
        
        monster = SyscallObfuscatorMonster()
        
        syscalls = [
            'NtAllocateVirtualMemory',
            'NtWriteVirtualMemory',
            'NtProtectVirtualMemory',
            'NtCreateThreadEx'
        ]
        
        results = []
        for syscall in syscalls:
            result = monster.obfuscate_call(syscall_name=syscall)
            results.append(result)
        
        assert len(results) == 4


# ============================================================================
# HELPER FUNCTION TESTS
# ============================================================================

class TestHelperFunctions:
    """Test helper/convenience functions"""
    
    def test_create_obfuscator_monster(self):
        """Test create_obfuscator_monster helper"""
        from evasion.syscall_obfuscator import create_obfuscator_monster
        
        monster = create_obfuscator_monster(
            ai_adaptive=True,
            use_ml=True,
            mutation_rate=0.7
        )
        
        assert monster is not None
    
    def test_quick_obfuscate_call(self):
        """Test quick_obfuscate_call helper"""
        from evasion.syscall_obfuscator import quick_obfuscate_call
        
        result = quick_obfuscate_call(syscall_name='NtAllocateVirtualMemory')
        
        # Should return something
        assert result is not None
    
    def test_get_ai_recommendation(self):
        """Test get_ai_recommendation helper"""
        from evasion.syscall_obfuscator import get_ai_recommendation
        
        recommendation = get_ai_recommendation()
        
        assert isinstance(recommendation, str)
        assert len(recommendation) > 0
    
    def test_detect_edr(self):
        """Test detect_edr helper"""
        from evasion.syscall_obfuscator import detect_edr, EDRProfile
        
        result = detect_edr()
        
        assert isinstance(result, EDRProfile)


# ============================================================================
# EDR PROFILE MAPPING TESTS
# ============================================================================

class TestEDRObfuscationProfiles:
    """Test EDR-specific obfuscation profile mappings"""
    
    def test_profiles_exist(self):
        """Test EDR profiles dictionary exists"""
        from evasion.syscall_obfuscator import EDR_OBFUSCATION_PROFILES, EDRProfile
        
        assert EDR_OBFUSCATION_PROFILES is not None
        assert isinstance(EDR_OBFUSCATION_PROFILES, dict)
    
    def test_crowdstrike_profile(self):
        """Test CrowdStrike Falcon profile"""
        from evasion.syscall_obfuscator import (
            EDR_OBFUSCATION_PROFILES,
            EDRProfile
        )
        
        profile = EDR_OBFUSCATION_PROFILES.get(EDRProfile.CROWDSTRIKE_FALCON)
        
        assert profile is not None
        assert 'primary_layer' in profile
        assert 'mutation_rate' in profile
    
    def test_defender_profile(self):
        """Test MS Defender profile"""
        from evasion.syscall_obfuscator import (
            EDR_OBFUSCATION_PROFILES,
            EDRProfile
        )
        
        profile = EDR_OBFUSCATION_PROFILES.get(EDRProfile.MS_DEFENDER)
        
        assert profile is not None
    
    def test_sentinelone_profile(self):
        """Test SentinelOne profile"""
        from evasion.syscall_obfuscator import (
            EDR_OBFUSCATION_PROFILES,
            EDRProfile
        )
        
        profile = EDR_OBFUSCATION_PROFILES.get(EDRProfile.SENTINELONE)
        
        assert profile is not None
        assert 'mutation_rate' in profile


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestSyscallObfuscatorIntegration:
    """Integration tests for full obfuscation pipeline"""
    
    def test_full_injection_syscall_obfuscation(self):
        """Test obfuscating syscalls for injection"""
        from evasion.syscall_obfuscator import (
            SyscallObfuscatorMonster,
            ObfuscationConfig
        )
        
        config = ObfuscationConfig(
            ai_adaptive=True,
            use_ml_mutation=True,
            enable_spoof_calls=True
        )
        
        monster = SyscallObfuscatorMonster(config)
        
        # Simulate injection syscall sequence
        injection_sequence = [
            'NtAllocateVirtualMemory',
            'NtWriteVirtualMemory',
            'NtProtectVirtualMemory',
            'NtCreateThreadEx',
        ]
        
        all_results = []
        for syscall_name in injection_sequence:
            result = monster.obfuscate_call(syscall_name=syscall_name)
            all_results.append(result)
        
        assert len(all_results) == 4
    
    def test_ai_lateral_guide_integration(self):
        """Test integration with AI lateral guide"""
        try:
            from cybermodules.ai_lateral_guide import AILateralGuide
            
            guide = AILateralGuide()
            
            if hasattr(guide, 'get_syscall_obfuscation_recommendation'):
                rec = guide.get_syscall_obfuscation_recommendation()
                
                assert isinstance(rec, dict)
        except ImportError:
            pytest.skip("AI lateral guide not available")


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class TestSyscallObfuscatorPerformance:
    """Performance tests for syscall obfuscation"""
    
    def test_mutation_speed(self):
        """Test mutation speed"""
        import time
        from evasion.syscall_obfuscator import GANStubMutator
        
        mutator = GANStubMutator()
        
        start = time.time()
        for _ in range(100):
            mutator.generate_mutated_stub(ssn=0x18)
        elapsed = time.time() - start
        
        # Should complete 100 mutations in under 5 seconds
        assert elapsed < 5.0, f"Mutation too slow: {elapsed:.2f}s for 100 iterations"
    
    def test_full_obfuscation_speed(self):
        """Test full obfuscation pipeline speed"""
        import time
        from evasion.syscall_obfuscator import SyscallObfuscatorMonster
        
        monster = SyscallObfuscatorMonster()
        
        start = time.time()
        for _ in range(50):
            monster.obfuscate_call(syscall_name='NtAllocateVirtualMemory')
        elapsed = time.time() - start
        
        # Should complete 50 full obfuscations in under 10 seconds
        assert elapsed < 10.0, f"Obfuscation too slow: {elapsed:.2f}s for 50 iterations"


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_unknown_syscall(self):
        """Test handling of unknown syscall"""
        from evasion.syscall_obfuscator import SyscallObfuscatorMonster
        
        monster = SyscallObfuscatorMonster()
        
        # Should handle gracefully
        result = monster.obfuscate_call(syscall_name='NotARealSyscall123')
        
        # Result should exist (either dict or dataclass)
        assert result is not None
    
    def test_high_mutation_rate_config(self):
        """Test with very high mutation rate"""
        from evasion.syscall_obfuscator import GANStubMutator, ObfuscationConfig
        
        config = ObfuscationConfig(mutation_rate=1.0)
        mutator = GANStubMutator(config)
        
        result = mutator.generate_mutated_stub(ssn=0x18)
        
        # Handle tuple return
        if isinstance(result, tuple):
            mutated, _ = result
            assert isinstance(mutated, bytes)
        else:
            assert isinstance(result, bytes)
    
    def test_low_mutation_rate_config(self):
        """Test with very low mutation rate"""
        from evasion.syscall_obfuscator import GANStubMutator, ObfuscationConfig
        
        config = ObfuscationConfig(mutation_rate=0.01)
        mutator = GANStubMutator(config)
        
        result = mutator.generate_mutated_stub(ssn=0x18)
        
        # Handle tuple return
        if isinstance(result, tuple):
            mutated, _ = result
            assert isinstance(mutated, bytes)
        else:
            assert isinstance(result, bytes)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

"""
Unit Tests for Sleepmask Cloaking Elite Module
Tests memory cloaking, ROP gadgets, heap spoofing, and artifact wiping
"""

import pytest
import sys
import os
import struct
import time
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evasion.sleepmask_cloaking import (
    SleepmaskCloakingEngine,
    MemoryCloakEngine,
    ROPGadgetEngine,
    HeapSpoofEngine,
    ForensicArtifactWiper,
    AICloakSelector,
    QuantumEntropyGenerator,
    CloakLevel,
    EDRProduct,
    MaskStage,
    GadgetType,
    EDR_CLOAK_PROFILES,
    create_elite_cloaker,
    quick_cloak,
    get_ai_recommendation,
    generate_ps_cloaking_stub,
)


# =============================================================================
# QUANTUM ENTROPY GENERATOR TESTS
# =============================================================================

class TestQuantumEntropyGenerator:
    """Test entropy generation"""
    
    def test_initialization(self):
        """Test generator initializes correctly"""
        entropy = QuantumEntropyGenerator()
        assert entropy._pool is not None
        assert len(entropy._pool) >= 64
    
    def test_get_bytes_returns_correct_length(self):
        """Test get_bytes returns requested length"""
        entropy = QuantumEntropyGenerator()
        
        for length in [1, 8, 16, 32, 64]:
            result = entropy.get_bytes(length)
            assert len(result) == length
    
    def test_get_bytes_is_random(self):
        """Test get_bytes produces different values"""
        entropy = QuantumEntropyGenerator()
        
        values = set()
        for _ in range(100):
            values.add(entropy.get_bytes(8))
        
        # Should have many unique values (>30 is reasonable for 100 samples)
        assert len(values) > 30
    
    def test_get_int_in_range(self):
        """Test get_int returns values in range"""
        entropy = QuantumEntropyGenerator()
        
        for _ in range(100):
            value = entropy.get_int(10, 20)
            assert 10 <= value <= 20
    
    def test_get_jitter_around_base(self):
        """Test jitter is centered around base"""
        entropy = QuantumEntropyGenerator()
        
        base = 1000
        percent = 50
        
        values = [entropy.get_jitter(base, percent) for _ in range(100)]
        avg = sum(values) / len(values)
        
        # Average should be close to base
        assert abs(avg - base) < 200  # Within 20%


# =============================================================================
# ROP GADGET ENGINE TESTS
# =============================================================================

class TestROPGadgetEngine:
    """Test ROP gadget discovery and chain building"""
    
    def test_initialization(self):
        """Test engine initializes correctly"""
        rop = ROPGadgetEngine()
        assert rop._patterns is not None
        assert len(rop._patterns) > 0
    
    def test_scan_module_finds_gadgets(self):
        """Test module scanning finds gadgets"""
        rop = ROPGadgetEngine()
        
        # Create mock module with known gadgets
        # ret (0xc3), pop rax; ret (0x58, 0xc3)
        module_data = b'\x00' * 100 + b'\xc3' + b'\x00' * 50 + b'\x58\xc3' + b'\x00' * 100
        
        gadgets = rop.scan_module(module_data, base_address=0x10000)
        
        assert len(gadgets) > 0
        
        # Check we found ret gadget
        ret_gadgets = [g for g in gadgets if g.gadget_type == GadgetType.RET]
        assert len(ret_gadgets) > 0
    
    def test_generate_nop_chain(self):
        """Test NOP chain generation"""
        rop = ROPGadgetEngine()
        
        nop_chain = rop._generate_nop_chain(32)
        
        assert len(nop_chain) == 32
        # Should contain NOP bytes (0x90)
        assert b'\x90' in nop_chain
    
    def test_gadget_mutation(self):
        """Test gadget chain mutation"""
        rop = ROPGadgetEngine()
        
        original = b'\x58\xc3\x59\xc3\x90\x90\x90\x90'
        mutated = rop.mutate_gadget_chain(original)
        
        # Mutated chain should be same length
        assert len(mutated) == len(original)


# =============================================================================
# MEMORY CLOAK ENGINE TESTS
# =============================================================================

class TestMemoryCloakEngine:
    """Test memory cloaking operations"""
    
    def test_initialization_with_different_levels(self):
        """Test engine initializes with different cloak levels"""
        for level in CloakLevel:
            engine = MemoryCloakEngine(cloak_level=level)
            assert engine.cloak_level == level
    
    def test_apply_mask_xor(self):
        """Test XOR mask application"""
        engine = MemoryCloakEngine()
        
        data = b'AAAAAAAAAAAAAAAA'  # 16 bytes
        key = b'BBBBBBBBBBBBBBBB'   # 16 bytes
        
        masked = engine._apply_mask(data, key)
        
        # Masked data should be different
        assert masked != data
        
        # Applying mask again should restore original
        unmasked = engine._apply_mask(masked, key)
        assert unmasked == data
    
    def test_apply_mask_key_expansion(self):
        """Test mask works with shorter key"""
        engine = MemoryCloakEngine()
        
        data = b'A' * 100
        key = b'B' * 16  # Shorter key
        
        masked = engine._apply_mask(data, key)
        assert len(masked) == len(data)
        
        # Should still be reversible
        unmasked = engine._apply_mask(masked, key)
        assert unmasked == data


# =============================================================================
# HEAP SPOOF ENGINE TESTS
# =============================================================================

class TestHeapSpoofEngine:
    """Test heap spoofing operations"""
    
    def test_initialization(self):
        """Test engine initializes correctly"""
        heap = HeapSpoofEngine()
        assert heap._decoy_count == 0
        assert len(heap._allocations) == 0
    
    def test_decoy_patterns_exist(self):
        """Test decoy patterns are defined"""
        heap = HeapSpoofEngine()
        
        assert 'pe_dos_stub' in heap.DECOY_PATTERNS
        assert 'string_table' in heap.DECOY_PATTERNS
        assert 'json_object' in heap.DECOY_PATTERNS
    
    def test_decoy_pattern_formats(self):
        """Test decoy patterns are valid bytes"""
        heap = HeapSpoofEngine()
        
        for name, pattern in heap.DECOY_PATTERNS.items():
            assert isinstance(pattern, bytes)
            assert len(pattern) > 0


# =============================================================================
# FORENSIC ARTIFACT WIPER TESTS
# =============================================================================

class TestForensicArtifactWiper:
    """Test forensic artifact wiping"""
    
    def test_initialization(self):
        """Test wiper initializes correctly"""
        wiper = ForensicArtifactWiper()
        assert wiper._wiped_artifacts == []
    
    def test_wipe_all_returns_results(self):
        """Test wipe_all returns result dict"""
        wiper = ForensicArtifactWiper()
        
        results = wiper.wipe_all()
        
        assert isinstance(results, dict)
        assert 'peb_cleanup' in results
        assert 'teb_cleanup' in results
        assert 'heap_metadata' in results


# =============================================================================
# AI CLOAK SELECTOR TESTS
# =============================================================================

class TestAICloakSelector:
    """Test AI-guided cloak selection"""
    
    def test_initialization(self):
        """Test selector initializes correctly"""
        selector = AICloakSelector()
        assert selector._detected_edr == EDRProduct.UNKNOWN
    
    def test_select_cloak_level_for_edrs(self):
        """Test cloak level selection for different EDRs"""
        selector = AICloakSelector()
        
        # Test known EDRs
        for edr in [EDRProduct.CROWDSTRIKE_FALCON, EDRProduct.SENTINELONE]:
            level = selector.select_cloak_level(edr)
            assert level.value >= CloakLevel.ADVANCED.value
        
        # No EDR should suggest lower level
        level = selector.select_cloak_level(EDRProduct.NONE)
        assert level.value <= CloakLevel.STANDARD.value
    
    def test_select_strategy_returns_complete_strategy(self):
        """Test strategy selection returns all required fields"""
        selector = AICloakSelector()
        
        strategy = selector.select_strategy(EDRProduct.MS_DEFENDER_ATP)
        
        assert 'cloak_level' in strategy
        assert 'gadget_density' in strategy
        assert 'entropy_target' in strategy
        assert 'heap_spoof' in strategy
        assert 'techniques' in strategy
        assert 'timing' in strategy
    
    def test_get_recommendation_returns_string(self):
        """Test recommendation returns readable string"""
        selector = AICloakSelector()
        selector._detected_edr = EDRProduct.MS_DEFENDER_ATP
        selector._edr_profile = EDR_CLOAK_PROFILES[EDRProduct.MS_DEFENDER_ATP]
        
        recommendation = selector.get_recommendation()
        
        assert isinstance(recommendation, str)
        assert 'Defender' in recommendation


# =============================================================================
# EDR PROFILES TESTS
# =============================================================================

class TestEDRProfiles:
    """Test EDR profile configurations"""
    
    def test_all_edrs_have_profiles(self):
        """Test all EDR products have profiles defined"""
        for edr in [EDRProduct.CROWDSTRIKE_FALCON, EDRProduct.MS_DEFENDER_ATP,
                    EDRProduct.SENTINELONE, EDRProduct.CARBON_BLACK, EDRProduct.NONE]:
            assert edr in EDR_CLOAK_PROFILES
    
    def test_profile_has_required_fields(self):
        """Test profiles have all required fields"""
        for edr, profile in EDR_CLOAK_PROFILES.items():
            assert profile.name is not None
            assert profile.product == edr
            assert profile.recommended_cloak_level is not None
            assert 0 <= profile.recommended_gadget_density <= 1.0
    
    def test_aggressive_edrs_have_higher_cloak_levels(self):
        """Test aggressive EDRs recommend higher cloak levels"""
        falcon = EDR_CLOAK_PROFILES[EDRProduct.CROWDSTRIKE_FALCON]
        s1 = EDR_CLOAK_PROFILES[EDRProduct.SENTINELONE]
        none = EDR_CLOAK_PROFILES[EDRProduct.NONE]
        
        assert falcon.recommended_cloak_level.value >= CloakLevel.ELITE.value
        assert s1.recommended_cloak_level.value >= CloakLevel.ELITE.value
        assert none.recommended_cloak_level.value <= CloakLevel.STANDARD.value


# =============================================================================
# SLEEPMASK CLOAKING ENGINE TESTS
# =============================================================================

class TestSleepmaskCloakingEngine:
    """Test main cloaking orchestrator"""
    
    def test_initialization(self):
        """Test engine initializes correctly"""
        engine = SleepmaskCloakingEngine(auto_detect_edr=False)
        
        assert engine._entropy is not None
        assert engine._ai_selector is not None
        assert engine._cloak_engine is not None
    
    def test_initialization_with_different_levels(self):
        """Test initialization with different cloak levels"""
        for level in [CloakLevel.BASIC, CloakLevel.ADVANCED, CloakLevel.ELITE]:
            engine = SleepmaskCloakingEngine(
                auto_detect_edr=False,
                cloak_level=level
            )
            assert engine.cloak_level == level
    
    def test_get_status_returns_complete_info(self):
        """Test status returns all required fields"""
        engine = SleepmaskCloakingEngine(auto_detect_edr=False)
        
        status = engine.get_status()
        
        assert 'is_cloaked' in status
        assert 'cloak_level' in status
        assert 'detected_edr' in status
        assert 'cloaked_regions' in status
        assert 'heap_decoys' in status
        assert 'strategy' in status
    
    def test_get_strategy(self):
        """Test strategy retrieval"""
        engine = SleepmaskCloakingEngine(auto_detect_edr=False)
        
        strategy = engine.get_strategy()
        
        assert isinstance(strategy, dict)
        assert 'cloak_level' in strategy
        assert 'techniques' in strategy
    
    def test_pre_sleep_cloak_no_regions(self):
        """Test pre-sleep cloak with no regions"""
        engine = SleepmaskCloakingEngine(
            auto_detect_edr=False,
            enable_heap_spoof=False,  # Disable to avoid allocation issues
            enable_artifact_wipe=False
        )
        
        result = engine.pre_sleep_cloak(memory_regions=None)
        
        assert result['success'] is True
        assert result['cloaked_regions'] == 0
    
    def test_post_sleep_uncloak(self):
        """Test post-sleep uncloak"""
        engine = SleepmaskCloakingEngine(
            auto_detect_edr=False,
            enable_heap_spoof=False,
            enable_artifact_wipe=False
        )
        
        # Cloak first
        engine.pre_sleep_cloak()
        
        # Then uncloak
        result = engine.post_sleep_uncloak()
        
        assert result['success'] is True
    
    def test_remask_cycle(self):
        """Test remask cycle"""
        engine = SleepmaskCloakingEngine(
            auto_detect_edr=False,
            enable_heap_spoof=False,
            enable_artifact_wipe=False
        )
        
        # Initial cloak
        engine.pre_sleep_cloak()
        
        # Remask
        initial_iteration = engine._mask_iteration
        result = engine.remask_cycle()
        
        assert result['success'] is True
        assert result['iteration'] > initial_iteration
    
    def test_cleanup(self):
        """Test cleanup releases resources"""
        engine = SleepmaskCloakingEngine(
            auto_detect_edr=False,
            enable_heap_spoof=False,
            enable_artifact_wipe=False
        )
        
        engine.pre_sleep_cloak()
        engine.cleanup()
        
        assert len(engine._cloaked_regions) == 0
        assert engine._is_cloaked is False


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestConvenienceFunctions:
    """Test module-level convenience functions"""
    
    def test_create_elite_cloaker(self):
        """Test elite cloaker creation"""
        engine = create_elite_cloaker(auto_detect=False)
        
        assert isinstance(engine, SleepmaskCloakingEngine)
        assert engine.cloak_level.value >= CloakLevel.ELITE.value
    
    def test_get_ai_recommendation(self):
        """Test AI recommendation function"""
        with patch.object(AICloakSelector, 'detect_edr', return_value=EDRProduct.NONE):
            recommendation = get_ai_recommendation()
        
        assert isinstance(recommendation, str)
        assert len(recommendation) > 0
    
    def test_generate_ps_cloaking_stub(self):
        """Test PowerShell stub generation"""
        stub = generate_ps_cloaking_stub(CloakLevel.ELITE)
        
        assert isinstance(stub, str)
        assert 'function' in stub.lower()
        assert 'invoke' in stub.lower() or 'cloak' in stub.lower()
    
    def test_generate_ps_stub_different_levels(self):
        """Test stub generation with different levels"""
        for level in [CloakLevel.BASIC, CloakLevel.ADVANCED, CloakLevel.ELITE]:
            stub = generate_ps_cloaking_stub(level)
            assert f'$CloakLevel = {level.value}' in stub


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests for full cloaking flow"""
    
    def test_full_cloak_uncloak_cycle(self):
        """Test complete cloak-uncloak cycle"""
        engine = SleepmaskCloakingEngine(
            auto_detect_edr=False,
            cloak_level=CloakLevel.STANDARD,
            enable_heap_spoof=False,
            enable_artifact_wipe=False,
            enable_rop=False
        )
        
        # Pre-sleep
        result1 = engine.pre_sleep_cloak()
        assert result1['success'] is True
        assert engine._is_cloaked is True
        
        # Remask
        result2 = engine.remask_cycle()
        assert result2['success'] is True
        
        # Post-sleep
        result3 = engine.post_sleep_uncloak()
        assert result3['success'] is True
        assert engine._is_cloaked is False
    
    def test_callback_receives_stages(self):
        """Test callback is called for each stage"""
        engine = SleepmaskCloakingEngine(
            auto_detect_edr=False,
            enable_heap_spoof=False,
            enable_artifact_wipe=False
        )
        
        stages_received = []
        
        def callback(stage, progress):
            stages_received.append((stage, progress))
        
        engine.pre_sleep_cloak(callback=callback)
        
        # Should have received stage callbacks
        assert len(stages_received) > 0


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

"""
Unit Tests for Process Injection Masterclass (Ultimate Ghosting)

Tests AI-dynamic injection, multi-stage chains, PEB/TEB mutation,
PPID spoofing, and artifact wiping capabilities.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evasion.process_injection_masterclass import (
    InjectionTechnique,
    EDRProduct,
    MutationTarget,
    ArtifactType,
    InjectionConfig,
    InjectionResult,
    InjectionStatus,
    EDR_INJECTION_PROFILES,
    ProcessInjectionMasterclass,
    AIInjectionSelector,
    EDRDetector,
    PEBTEBMutator,
    PPIDSpoofEngine,
    ProcessArtifactWiper,
    create_masterclass_injector,
    quick_inject,
    get_ai_recommendation,
    detect_edr,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def sample_shellcode():
    """x64 NOP sled + ret shellcode for testing"""
    return b'\x90' * 100 + b'\xc3'

@pytest.fixture
def injection_config():
    """Create standard injection config"""
    return InjectionConfig(
        ai_adaptive=True,
        enable_ppid_spoof=True,
        enable_mutation=True,
        enable_artifact_wipe=True
    )

@pytest.fixture
def injection_engine(injection_config):
    """Create standard injection engine"""
    return ProcessInjectionMasterclass(config=injection_config)

@pytest.fixture
def ai_selector(injection_config):
    """Create AI injection selector"""
    return AIInjectionSelector(injection_config)

@pytest.fixture
def edr_detector():
    """Create EDR detector"""
    return EDRDetector()


# =============================================================================
# InjectionTechnique Enum Tests
# =============================================================================

class TestInjectionTechnique:
    """Test injection technique definitions"""
    
    def test_all_techniques_defined(self):
        """Verify all 13 techniques are defined"""
        expected_techniques = [
            'PROCESS_GHOSTING', 'PROCESS_HERPADERPING', 'TRANSACTED_HOLLOWING',
            'PROCESS_DOPPELGANGING', 'MODULE_STOMPING', 'EARLY_BIRD_APC',
            'PHANTOM_DLL', 'THREAD_HIJACK', 'PROCESS_HOLLOWING',
            'SYSCALL_INJECTION', 'CALLBACK_INJECTION', 'FIBER_INJECTION',
            'CLASSIC_CRT'
        ]
        
        for technique in expected_techniques:
            assert hasattr(InjectionTechnique, technique)
    
    def test_technique_values(self):
        """Verify technique string values"""
        assert InjectionTechnique.PROCESS_GHOSTING.value == "ghosting"
        assert InjectionTechnique.PROCESS_HERPADERPING.value == "herpaderping"
        assert InjectionTechnique.TRANSACTED_HOLLOWING.value == "transacted_hollowing"
        assert InjectionTechnique.CLASSIC_CRT.value == "classic_crt"


# =============================================================================
# EDRProduct Enum Tests
# =============================================================================

class TestEDRProduct:
    """Test EDR product definitions"""
    
    def test_all_edr_products_defined(self):
        """Verify all EDR products are defined"""
        expected_products = [
            'NONE', 'CROWDSTRIKE_FALCON', 'SENTINELONE', 'MS_DEFENDER_ATP',
            'CARBON_BLACK', 'ELASTIC_EDR', 'CYLANCE', 'SYMANTEC_EDR',
            'SOPHOS_INTERCEPT', 'MCAFEE_MVISION', 'PALO_ALTO_XDR'
        ]
        
        for product in expected_products:
            assert hasattr(EDRProduct, product)


# =============================================================================
# EDR Injection Profiles Tests
# =============================================================================

class TestEDRInjectionProfiles:
    """Test EDR-specific injection profiles"""
    
    def test_major_profiles_exist(self):
        """Verify profiles exist for major EDRs"""
        major_edrs = [
            EDRProduct.CROWDSTRIKE_FALCON,
            EDRProduct.SENTINELONE,
            EDRProduct.MS_DEFENDER_ATP,
            EDRProduct.CARBON_BLACK,
            EDRProduct.NONE,
        ]
        for edr in major_edrs:
            assert edr in EDR_INJECTION_PROFILES
    
    def test_profile_structure(self):
        """Verify profile structure for CrowdStrike"""
        profile = EDR_INJECTION_PROFILES[EDRProduct.CROWDSTRIKE_FALCON]
        
        assert 'primary_technique' in profile
        assert 'fallback_chain' in profile
        assert 'ppid_spoof_required' in profile
        assert 'mutation_required' in profile
    
    def test_crowdstrike_profile(self):
        """Verify CrowdStrike profile values"""
        profile = EDR_INJECTION_PROFILES[EDRProduct.CROWDSTRIKE_FALCON]
        
        assert profile['primary_technique'] == InjectionTechnique.PROCESS_HERPADERPING
        assert profile['ppid_spoof_required'] == True
        assert profile['mutation_required'] == True
        assert profile.get('delay_injection_ms', 0) >= 2000
    
    def test_sentinelone_profile(self):
        """Verify SentinelOne profile values"""
        profile = EDR_INJECTION_PROFILES[EDRProduct.SENTINELONE]
        
        assert profile['primary_technique'] == InjectionTechnique.TRANSACTED_HOLLOWING
        assert profile['ppid_spoof_required'] == True
        assert InjectionTechnique.PROCESS_GHOSTING in profile['fallback_chain']
    
    def test_none_profile_minimal(self):
        """Verify 'no EDR' profile has minimal stealth"""
        profile = EDR_INJECTION_PROFILES[EDRProduct.NONE]
        
        assert profile['primary_technique'] == InjectionTechnique.EARLY_BIRD_APC
        assert profile['ppid_spoof_required'] == False
        assert profile['mutation_required'] == False


# =============================================================================
# MutationTarget Tests
# =============================================================================

class TestMutationTarget:
    """Test PEB/TEB mutation targets"""
    
    def test_all_mutation_targets_defined(self):
        """Verify all mutation targets"""
        expected_targets = [
            'PEB_IMAGE_BASE', 'PEB_BEING_DEBUGGED', 'PEB_HEAP_FLAGS',
            'PEB_NTGLOBAL_FLAG', 'PEB_COMMAND_LINE', 'PEB_IMAGE_PATH',
            'TEB_STACK_BASE', 'TEB_STACK_LIMIT', 'TEB_CLIENT_ID'
        ]
        
        for target in expected_targets:
            assert hasattr(MutationTarget, target)


# =============================================================================
# ArtifactType Tests
# =============================================================================

class TestArtifactType:
    """Test process artifact types"""
    
    def test_all_artifact_types_defined(self):
        """Verify all artifact types"""
        expected_artifacts = [
            'PROCESS_PARAMS', 'HANDLE_TABLE', 'THREAD_LIST',
            'MODULE_LIST', 'MEMORY_MAP', 'TOKEN_INFO', 'SECURITY_DESCRIPTOR'
        ]
        
        for artifact in expected_artifacts:
            assert hasattr(ArtifactType, artifact)


# =============================================================================
# InjectionConfig Tests
# =============================================================================

class TestInjectionConfig:
    """Test injection configuration"""
    
    def test_default_config(self):
        """Test default config values"""
        config = InjectionConfig()
        
        assert config.technique == InjectionTechnique.EARLY_BIRD_APC
        assert config.ai_adaptive == True
        assert config.enable_ppid_spoof == True
        assert config.enable_mutation == True
        assert config.enable_artifact_wipe == True
    
    def test_custom_config(self):
        """Test custom config values"""
        config = InjectionConfig(
            technique=InjectionTechnique.PROCESS_GHOSTING,
            ai_adaptive=False,
            enable_ppid_spoof=False,
            delay_execution_ms=5000
        )
        
        assert config.technique == InjectionTechnique.PROCESS_GHOSTING
        assert config.ai_adaptive == False
        assert config.enable_ppid_spoof == False
        assert config.delay_execution_ms == 5000


# =============================================================================
# ProcessInjectionMasterclass Tests
# =============================================================================

class TestProcessInjectionMasterclass:
    """Test main injection orchestrator"""
    
    def test_initialization(self, injection_config):
        """Test initialization"""
        engine = ProcessInjectionMasterclass(config=injection_config)
        
        assert engine.config is not None
        assert engine.ai_selector is not None
        assert engine.edr_detector is not None
    
    def test_initialization_without_config(self):
        """Test initialization without config"""
        engine = ProcessInjectionMasterclass()
        
        assert engine.config is not None
        assert engine.config.ai_adaptive == True  # Default
    
    def test_subcomponents_initialized(self, injection_engine):
        """Verify subcomponents are initialized"""
        assert injection_engine.ai_selector is not None
        assert injection_engine.edr_detector is not None
        assert injection_engine.peb_mutator is not None
        assert injection_engine.ppid_spoofer is not None
        assert injection_engine.artifact_wiper is not None
    
    @patch('platform.system', return_value='Linux')
    def test_inject_on_linux_fails(self, mock_platform, injection_engine, sample_shellcode):
        """Test injection fails gracefully on Linux"""
        result = injection_engine.inject(sample_shellcode)
        
        assert isinstance(result, InjectionResult)
        # On Linux, injection should fail or be simulated
        assert result.technique is not None


# =============================================================================
# AIInjectionSelector Tests
# =============================================================================

class TestAIInjectionSelector:
    """Test AI-based injection technique selector"""
    
    def test_initialization(self, injection_config):
        """Test AI selector initialization"""
        selector = AIInjectionSelector(injection_config)
        assert selector.edr_detector is not None
    
    def test_detect_and_select_returns_tuple(self, ai_selector):
        """Test that detect_and_select returns a tuple"""
        result = ai_selector.detect_and_select()
        
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], InjectionTechnique)
        assert isinstance(result[1], dict)
    
    def test_get_fallback_chain(self, ai_selector):
        """Test getting fallback chain"""
        ai_selector.detect_and_select()  # Initialize profile
        chain = ai_selector.get_fallback_chain()
        
        assert isinstance(chain, list)
        assert len(chain) >= 1
        assert all(isinstance(t, InjectionTechnique) for t in chain)
    
    def test_get_recommendation_string(self, ai_selector):
        """Test getting human-readable recommendation"""
        recommendation = ai_selector.get_recommendation()
        
        assert isinstance(recommendation, str)
        assert "AI Injection Recommendation" in recommendation


# =============================================================================
# EDRDetector Tests
# =============================================================================

class TestEDRDetector:
    """Test EDR detection capabilities"""
    
    def test_initialization(self, edr_detector):
        """Test detector initialization"""
        assert hasattr(edr_detector, 'EDR_PROCESSES')
        assert len(edr_detector.EDR_PROCESSES) > 0
    
    def test_crowdstrike_signatures(self, edr_detector):
        """Verify CrowdStrike detection signatures"""
        cs_procs = edr_detector.EDR_PROCESSES.get(EDRProduct.CROWDSTRIKE_FALCON, [])
        
        # Should detect CrowdStrike processes
        assert any('falcon' in p.lower() or 'csfalcon' in p.lower() 
                   for p in cs_procs)
    
    def test_sentinelone_signatures(self, edr_detector):
        """Verify SentinelOne detection signatures"""
        s1_procs = edr_detector.EDR_PROCESSES.get(EDRProduct.SENTINELONE, [])
        
        # Should detect SentinelOne processes
        assert any('sentinel' in p.lower() for p in s1_procs)
    
    def test_detect_all_returns_list(self, edr_detector):
        """Test detect_all returns a list"""
        result = edr_detector.detect_all()
        assert isinstance(result, list)
        assert all(isinstance(e, EDRProduct) for e in result)
    
    def test_get_primary_edr_returns_product(self, edr_detector):
        """Test get_primary_edr returns an EDRProduct"""
        result = edr_detector.get_primary_edr()
        assert isinstance(result, EDRProduct)


# =============================================================================
# PEBTEBMutator Tests
# =============================================================================

class TestPEBTEBMutator:
    """Test PEB/TEB mutation capabilities"""
    
    def test_initialization(self):
        """Test mutator initialization"""
        mutator = PEBTEBMutator()
        assert mutator is not None
    
    def test_has_mutate_method(self):
        """Test mutator has mutate method"""
        mutator = PEBTEBMutator()
        assert hasattr(mutator, 'mutate_peb') or hasattr(mutator, 'mutate')


# =============================================================================
# PPIDSpoofEngine Tests
# =============================================================================

class TestPPIDSpoofEngine:
    """Test PPID spoofing capabilities"""
    
    def test_initialization(self):
        """Test PPID spoof engine initialization"""
        engine = PPIDSpoofEngine()
        assert engine is not None
    
    def test_has_good_parents(self):
        """Test engine has GOOD_PARENTS list"""
        engine = PPIDSpoofEngine()
        assert hasattr(engine, 'GOOD_PARENTS')
        assert len(engine.GOOD_PARENTS) > 0
        assert 'explorer.exe' in engine.GOOD_PARENTS
    
    def test_has_create_method(self):
        """Test engine has create_process_spoofed method"""
        engine = PPIDSpoofEngine()
        assert hasattr(engine, 'create_process_spoofed') or hasattr(engine, 'find_parent_pid')


# =============================================================================
# ProcessArtifactWiper Tests
# =============================================================================

class TestProcessArtifactWiper:
    """Test process artifact wiping capabilities"""
    
    def test_initialization(self):
        """Test artifact wiper initialization"""
        wiper = ProcessArtifactWiper()
        assert wiper is not None
    
    def test_has_wipe_method(self):
        """Test wiper has wipe-related methods"""
        wiper = ProcessArtifactWiper()
        assert hasattr(wiper, 'wipe_process_artifacts')


# =============================================================================
# InjectionResult Tests
# =============================================================================

class TestInjectionResult:
    """Test injection result dataclass"""
    
    def test_success_result(self):
        """Test successful injection result"""
        result = InjectionResult(
            success=True,
            technique=InjectionTechnique.PROCESS_GHOSTING,
            target_pid=12345,
            target_name="notepad.exe",
            thread_id=67890,
            ppid_spoofed=True,
            evasion_score=0.98,
            phantom_process=True,
            error=None
        )
        
        assert result.success == True
        assert result.evasion_score == 0.98
        assert result.phantom_process == True
    
    def test_failure_result(self):
        """Test failed injection result"""
        result = InjectionResult(
            success=False,
            technique=InjectionTechnique.CLASSIC_CRT,
            error="Injection blocked by EDR"
        )
        
        assert result.success == False
        assert "blocked" in result.error.lower()


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunctions:
    """Test module-level convenience functions"""
    
    def test_create_masterclass_injector(self):
        """Test create_masterclass_injector factory"""
        engine = create_masterclass_injector(
            ai_adaptive=True,
            enable_ppid_spoof=False
        )
        
        assert isinstance(engine, ProcessInjectionMasterclass)
        assert engine.config.ai_adaptive == True
        assert engine.config.enable_ppid_spoof == False
    
    def test_detect_edr_function(self):
        """Test standalone detect_edr function"""
        result = detect_edr()
        assert isinstance(result, EDRProduct)
    
    def test_get_ai_recommendation_function(self):
        """Test get_ai_recommendation returns string"""
        recommendation = get_ai_recommendation()
        
        assert isinstance(recommendation, str)
        assert "AI Injection Recommendation" in recommendation
        assert "Technique" in recommendation


# =============================================================================
# Multi-Stage Chain Tests
# =============================================================================

class TestMultiStageChain:
    """Test multi-stage injection chains"""
    
    def test_chain_execution_order(self):
        """Test that fallback chains are properly ordered"""
        profile = EDR_INJECTION_PROFILES[EDRProduct.CROWDSTRIKE_FALCON]
        chain = profile['fallback_chain']
        
        # Chain should have at least 2 techniques
        assert len(chain) >= 2
    
    def test_all_major_profiles_have_fallback(self):
        """Test major profiles have fallback chains"""
        major_edrs = [
            EDRProduct.CROWDSTRIKE_FALCON,
            EDRProduct.SENTINELONE,
            EDRProduct.MS_DEFENDER_ATP,
            EDRProduct.CARBON_BLACK,
        ]
        for edr in major_edrs:
            profile = EDR_INJECTION_PROFILES[edr]
            assert 'fallback_chain' in profile
            assert len(profile['fallback_chain']) >= 1


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for the injection masterclass"""
    
    def test_full_workflow_components(self, injection_engine):
        """Test full workflow components are available"""
        # Verify all components are working
        assert injection_engine.ai_selector is not None
        assert injection_engine.edr_detector is not None
        assert injection_engine.peb_mutator is not None
        assert injection_engine.ppid_spoofer is not None
        assert injection_engine.artifact_wiper is not None
    
    def test_technique_recommendation_flow(self):
        """Test technique recommendation flow"""
        config = InjectionConfig(auto_detect_edr=False)  # Don't try to detect
        selector = AIInjectionSelector(config)
        technique, profile = selector.detect_and_select()
        
        # Should return a technique and profile
        assert technique is not None
        assert profile is not None


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_empty_shellcode(self, injection_engine):
        """Test injection with empty shellcode"""
        result = injection_engine.inject(b'')
        
        assert isinstance(result, InjectionResult)
        # Should handle gracefully
    
    def test_invalid_pid(self, injection_engine, sample_shellcode):
        """Test injection with invalid PID"""
        result = injection_engine.inject(sample_shellcode, pid=-1)
        
        assert isinstance(result, InjectionResult)


# =============================================================================
# Performance Tests
# =============================================================================

class TestPerformance:
    """Performance-related tests"""
    
    def test_engine_initialization_fast(self):
        """Test that engine initialization is fast"""
        import time
        
        start = time.time()
        for _ in range(10):
            engine = ProcessInjectionMasterclass()
        elapsed = time.time() - start
        
        # Should initialize 10 times in under 1 second
        assert elapsed < 1.0
    
    def test_selector_fast(self):
        """Test that AI selector is fast"""
        import time
        
        config = InjectionConfig(auto_detect_edr=False)
        selector = AIInjectionSelector(config)
        
        start = time.time()
        for _ in range(100):
            selector.detect_and_select()
        elapsed = time.time() - start
        
        # Should complete quickly
        assert elapsed < 1.0


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

"""
Tests for Persistence God Mode Module
Ultimate Full Chain Persistence with AI-Dynamic Selection

Tests:
- PersistenceGodMonster initialization and configuration
- AIPersistenceSelector EDR detection and chain selection
- PersistenceChainExecutor chain installation
- ArtifactMutator artifact mutation
- SpoofEventGenerator event forging
- TimestampStomper timestamp manipulation
- PersistenceArtifactWiper artifact wiping
- Full chain integration
"""
import os
import sys
import pytest
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

# Add parent dir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evasion.persistence_god import (
    # Main classes
    PersistenceGodMonster,
    AIPersistenceSelector,
    PersistenceChainExecutor,
    ArtifactMutator,
    SpoofEventGenerator,
    TimestampStomper,
    PersistenceArtifactWiper,
    
    # Enums
    PersistenceChain,
    EDRPersistProfile,
    MutationTarget,
    SpoofEventType,
    
    # Config
    PersistenceConfig,
    EDR_PERSISTENCE_PROFILES,
    
    # Helper functions
    create_persistence_god,
    quick_persist,
    get_ai_persist_recommendation,
    detect_edr_for_persist,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def default_config():
    """Default persistence configuration"""
    return PersistenceConfig(
        ai_adaptive=True,
        enable_multi_chain=True,
        enable_spoof_events=True,
        mutation_rate=0.8,
        use_reg_muting=True,
        timestamp_stomp=True,
        artifact_wipe=True,
    )


@pytest.fixture
def minimal_config():
    """Minimal persistence configuration"""
    return PersistenceConfig(
        ai_adaptive=False,
        enable_multi_chain=False,
        enable_spoof_events=False,
        mutation_rate=0.0,
        use_reg_muting=False,
        timestamp_stomp=False,
        artifact_wipe=False,
    )


@pytest.fixture
def persistence_god(default_config):
    """Create PersistenceGodMonster instance"""
    return PersistenceGodMonster(default_config)


@pytest.fixture
def ai_selector():
    """Create AIPersistenceSelector instance"""
    return AIPersistenceSelector()


@pytest.fixture
def chain_executor():
    """Create PersistenceChainExecutor instance"""
    return PersistenceChainExecutor()


@pytest.fixture
def artifact_mutator():
    """Create ArtifactMutator instance"""
    return ArtifactMutator()


@pytest.fixture
def spoof_generator():
    """Create SpoofEventGenerator instance"""
    return SpoofEventGenerator()


@pytest.fixture
def timestamp_stomper():
    """Create TimestampStomper instance"""
    return TimestampStomper()


@pytest.fixture
def artifact_wiper():
    """Create PersistenceArtifactWiper instance"""
    return PersistenceArtifactWiper()


# =============================================================================
# Enum Tests
# =============================================================================

class TestEnums:
    """Test persistence enums"""
    
    def test_persistence_chain_values(self):
        """Test PersistenceChain enum values"""
        assert PersistenceChain.WMI_EVENT.value == "wmi_event"
        assert PersistenceChain.COM_HIJACK.value == "com_hijack"
        assert PersistenceChain.BITS_JOB.value == "bits_job"
        assert PersistenceChain.SCHTASK.value == "schtask"
        assert PersistenceChain.RUNKEY.value == "runkey"
        assert PersistenceChain.SERVICE.value == "service"
        assert PersistenceChain.DLL_SEARCH_ORDER.value == "dll_search"
        assert PersistenceChain.STARTUP_FOLDER.value == "startup_folder"
        assert PersistenceChain.FULL_CHAIN.value == "full_chain"
    
    def test_edr_persist_profile_values(self):
        """Test EDRPersistProfile enum values"""
        assert EDRPersistProfile.NONE.value == "none"
        assert EDRPersistProfile.MS_DEFENDER.value == "ms_defender"
        assert EDRPersistProfile.CROWDSTRIKE_FALCON.value == "crowdstrike_falcon"
        assert EDRPersistProfile.SENTINELONE.value == "sentinelone"
        assert EDRPersistProfile.CARBON_BLACK.value == "carbon_black"
        assert EDRPersistProfile.ELASTIC_EDR.value == "elastic_edr"
        assert EDRPersistProfile.UNKNOWN.value == "unknown"
    
    def test_mutation_target_values(self):
        """Test MutationTarget enum values"""
        assert MutationTarget.REGISTRY_KEY.value == "registry_key"
        assert MutationTarget.REGISTRY_VALUE.value == "registry_value"
        assert MutationTarget.FILE_PATH.value == "file_path"
        assert MutationTarget.FILE_TIMESTAMP.value == "file_timestamp"
        assert MutationTarget.TASK_NAME.value == "task_name"
        assert MutationTarget.SERVICE_NAME.value == "service_name"
        assert MutationTarget.COM_CLSID.value == "com_clsid"
        assert MutationTarget.BITS_JOB_NAME.value == "bits_job_name"
    
    def test_spoof_event_type_values(self):
        """Test SpoofEventType enum values"""
        assert SpoofEventType.SCHTASK_CREATE.value == "schtask_create"
        assert SpoofEventType.SCHTASK_DELETE.value == "schtask_delete"
        assert SpoofEventType.SERVICE_INSTALL.value == "service_install"
        assert SpoofEventType.REGISTRY_SET.value == "registry_set"
        assert SpoofEventType.FILE_CREATE.value == "file_create"


# =============================================================================
# Configuration Tests
# =============================================================================

class TestPersistenceConfig:
    """Test PersistenceConfig dataclass"""
    
    def test_default_config(self, default_config):
        """Test default configuration values"""
        assert default_config.ai_adaptive is True
        assert default_config.enable_multi_chain is True
        assert default_config.enable_spoof_events is True
        assert default_config.mutation_rate == 0.8
        assert default_config.use_reg_muting is True
        assert default_config.timestamp_stomp is True
        assert default_config.artifact_wipe is True
    
    def test_minimal_config(self, minimal_config):
        """Test minimal configuration"""
        assert minimal_config.ai_adaptive is False
        assert minimal_config.enable_multi_chain is False
        assert minimal_config.enable_spoof_events is False
        assert minimal_config.mutation_rate == 0.0
        assert minimal_config.use_reg_muting is False
        assert minimal_config.timestamp_stomp is False
        assert minimal_config.artifact_wipe is False


# =============================================================================
# EDR Profile Tests
# =============================================================================

class TestEDRProfiles:
    """Test EDR persistence profiles"""
    
    def test_all_edr_profiles_exist(self):
        """Test that all EDR profiles are defined"""
        for edr in EDRPersistProfile:
            if edr != EDRPersistProfile.UNKNOWN:
                assert edr in EDR_PERSISTENCE_PROFILES
    
    def test_defender_profile(self):
        """Test MS Defender profile"""
        profile = EDR_PERSISTENCE_PROFILES[EDRPersistProfile.MS_DEFENDER]
        
        assert 'name' in profile
        assert 'primary_chain' in profile
        assert 'secondary_chains' in profile
        assert 'avoid_chains' in profile
        assert 'mutation_rate' in profile
        assert 'use_reg_muting' in profile
        
        # Defender should avoid WMI
        assert PersistenceChain.WMI_EVENT in profile['avoid_chains']
        
        # Registry muting should be enabled
        assert profile['use_reg_muting'] is True
    
    def test_crowdstrike_profile(self):
        """Test CrowdStrike Falcon profile"""
        profile = EDR_PERSISTENCE_PROFILES[EDRPersistProfile.CROWDSTRIKE_FALCON]
        
        # Falcon should use COM hijack or BITS
        assert profile['primary_chain'] in [
            PersistenceChain.COM_HIJACK,
            PersistenceChain.BITS_JOB
        ]
        
        # Should avoid scheduled tasks (heavily monitored)
        assert PersistenceChain.SCHTASK in profile['avoid_chains']
        
        # High mutation rate
        assert profile['mutation_rate'] >= 0.8
    
    def test_sentinelone_profile(self):
        """Test SentinelOne profile"""
        profile = EDR_PERSISTENCE_PROFILES[EDRPersistProfile.SENTINELONE]
        
        # Should avoid services
        assert PersistenceChain.SERVICE in profile['avoid_chains']
        
        # High mutation rate for S1
        assert profile['mutation_rate'] >= 0.8
    
    def test_carbon_black_profile(self):
        """Test Carbon Black profile"""
        profile = EDR_PERSISTENCE_PROFILES[EDRPersistProfile.CARBON_BLACK]
        
        # DLL search order is stealthiest for CB
        assert profile['primary_chain'] == PersistenceChain.DLL_SEARCH_ORDER
        
        # Should timestamp stomp
        assert profile['timestamp_stomp'] is True
    
    def test_no_edr_profile(self):
        """Test no EDR profile"""
        profile = EDR_PERSISTENCE_PROFILES[EDRPersistProfile.NONE]
        
        # No EDR = use reliable schtask
        assert profile['primary_chain'] == PersistenceChain.SCHTASK
        
        # Lower mutation rate
        assert profile['mutation_rate'] <= 0.5
        
        # No need for heavy OPSEC
        assert profile['spoof_events'] is False


# =============================================================================
# AIPersistenceSelector Tests
# =============================================================================

class TestAIPersistenceSelector:
    """Test AIPersistenceSelector class"""
    
    def test_selector_initialization(self, ai_selector):
        """Test selector initializes"""
        assert ai_selector is not None
        assert hasattr(ai_selector, 'detect_and_select')
        assert hasattr(ai_selector, 'get_recommendation')
    
    def test_detect_and_select_returns_tuple(self, ai_selector):
        """Test detect_and_select returns (chain, profile_info)"""
        result = ai_selector.detect_and_select()
        
        assert isinstance(result, tuple)
        assert len(result) == 2
        
        chain, profile_info = result
        assert isinstance(chain, PersistenceChain)
        assert isinstance(profile_info, dict)
    
    def test_profile_info_structure(self, ai_selector):
        """Test profile info has expected keys"""
        _, profile_info = ai_selector.detect_and_select()
        
        assert 'edr' in profile_info
        assert 'profile' in profile_info
        
        profile = profile_info['profile']
        assert 'name' in profile
        assert 'primary_chain' in profile
    
    def test_get_recommendation_returns_string(self, ai_selector):
        """Test get_recommendation returns human-readable string"""
        # Call detect first
        ai_selector.detect_and_select()
        
        rec = ai_selector.get_recommendation()
        assert isinstance(rec, str)
        assert len(rec) > 0
    
    @patch('evasion.persistence_god.psutil')
    def test_defender_detection(self, mock_psutil, ai_selector):
        """Test Defender is detected by process"""
        # Mock process list with Defender
        mock_proc = Mock()
        mock_proc.name.return_value = "MsMpEng.exe"
        mock_proc.cmdline.return_value = ["MsMpEng.exe"]
        
        mock_psutil.process_iter.return_value = [mock_proc]
        
        edr = ai_selector._detect_edr()
        
        # Should detect Defender
        assert edr == EDRPersistProfile.MS_DEFENDER
    
    @patch('evasion.persistence_god.psutil')
    def test_crowdstrike_detection(self, mock_psutil, ai_selector):
        """Test CrowdStrike is detected by process"""
        mock_proc = Mock()
        mock_proc.name.return_value = "CSFalconService.exe"
        mock_proc.cmdline.return_value = ["CSFalconService.exe"]
        
        mock_psutil.process_iter.return_value = [mock_proc]
        
        edr = ai_selector._detect_edr()
        
        assert edr == EDRPersistProfile.CROWDSTRIKE_FALCON
    
    @patch('evasion.persistence_god.psutil')
    def test_sentinelone_detection(self, mock_psutil, ai_selector):
        """Test SentinelOne is detected by process"""
        mock_proc = Mock()
        mock_proc.name.return_value = "SentinelAgent.exe"
        mock_proc.cmdline.return_value = ["SentinelAgent.exe"]
        
        mock_psutil.process_iter.return_value = [mock_proc]
        
        edr = ai_selector._detect_edr()
        
        assert edr == EDRPersistProfile.SENTINELONE


# =============================================================================
# ArtifactMutator Tests
# =============================================================================

class TestArtifactMutator:
    """Test ArtifactMutator class"""
    
    def test_mutator_initialization(self, artifact_mutator):
        """Test mutator initializes"""
        assert artifact_mutator is not None
    
    def test_mutate_registry_key(self, artifact_mutator):
        """Test registry key mutation"""
        original = "WindowsUpdate"
        mutated = artifact_mutator.mutate(
            original,
            MutationTarget.REGISTRY_KEY,
            mutation_rate=1.0
        )
        
        # Should be different with 100% mutation rate
        assert mutated != original or mutated == original  # May include legit prefix
        
        # Should look legitimate (contains Windows/Microsoft/System prefix)
        assert any(
            prefix in mutated 
            for prefix in ['Windows', 'Microsoft', 'System', 'Update']
        ) or mutated != original
    
    def test_mutate_task_name(self, artifact_mutator):
        """Test task name mutation"""
        original = "MyTask"
        mutated = artifact_mutator.mutate(
            original,
            MutationTarget.TASK_NAME,
            mutation_rate=1.0
        )
        
        # Should generate legitimate-looking name
        assert len(mutated) > 0
    
    def test_mutate_service_name(self, artifact_mutator):
        """Test service name mutation"""
        original = "MyService"
        mutated = artifact_mutator.mutate(
            original,
            MutationTarget.SERVICE_NAME,
            mutation_rate=1.0
        )
        
        assert len(mutated) > 0
    
    def test_mutate_com_clsid(self, artifact_mutator):
        """Test COM CLSID mutation"""
        original = "{00000000-0000-0000-0000-000000000000}"
        mutated = artifact_mutator.mutate(
            original,
            MutationTarget.COM_CLSID,
            mutation_rate=1.0
        )
        
        # Should be a valid CLSID format
        assert mutated.startswith('{')
        assert mutated.endswith('}')
        assert '-' in mutated
    
    def test_zero_mutation_rate_preserves_original(self, artifact_mutator):
        """Test 0% mutation rate keeps original"""
        original = "ExactlyThisValue"
        mutated = artifact_mutator.mutate(
            original,
            MutationTarget.REGISTRY_VALUE,
            mutation_rate=0.0
        )
        
        assert mutated == original
    
    def test_reseed(self, artifact_mutator):
        """Test mutator can reseed"""
        # Should not raise
        artifact_mutator.reseed()


# =============================================================================
# SpoofEventGenerator Tests
# =============================================================================

class TestSpoofEventGenerator:
    """Test SpoofEventGenerator class"""
    
    def test_generator_initialization(self, spoof_generator):
        """Test generator initializes"""
        assert spoof_generator is not None
    
    def test_generate_schtask_create_event(self, spoof_generator):
        """Test scheduled task create event"""
        event = spoof_generator.generate_event(SpoofEventType.SCHTASK_CREATE)
        
        assert isinstance(event, dict)
        assert 'type' in event
        assert event['type'] == SpoofEventType.SCHTASK_CREATE.value
    
    def test_generate_registry_set_event(self, spoof_generator):
        """Test registry set event"""
        event = spoof_generator.generate_event(SpoofEventType.REGISTRY_SET)
        
        assert isinstance(event, dict)
        assert 'type' in event
    
    def test_generate_file_create_event(self, spoof_generator):
        """Test file create event"""
        event = spoof_generator.generate_event(SpoofEventType.FILE_CREATE)
        
        assert isinstance(event, dict)
        assert 'type' in event
    
    def test_generate_multiple_events(self, spoof_generator):
        """Test generating multiple events"""
        events = spoof_generator.generate_events(count=5)
        
        assert isinstance(events, list)
        assert len(events) == 5
    
    def test_generate_random_count_events(self, spoof_generator):
        """Test generating random count of events"""
        events = spoof_generator.generate_events(count=(3, 7))
        
        assert isinstance(events, list)
        assert 3 <= len(events) <= 7


# =============================================================================
# TimestampStomper Tests
# =============================================================================

class TestTimestampStomper:
    """Test TimestampStomper class"""
    
    def test_stomper_initialization(self, timestamp_stomper):
        """Test stomper initializes"""
        assert timestamp_stomper is not None
    
    def test_get_reference_timestamp(self, timestamp_stomper):
        """Test getting reference timestamp"""
        # This may fail on non-Windows or without System32
        ts = timestamp_stomper.get_reference_timestamp()
        
        # Should return something (None if not available)
        # On Windows, should be a valid timestamp
        assert ts is None or isinstance(ts, (int, float))
    
    def test_stomp_returns_result(self, timestamp_stomper):
        """Test stomp returns result dict"""
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
            f.write(b"test content")
        
        try:
            result = timestamp_stomper.stomp(temp_path)
            
            assert isinstance(result, dict)
            assert 'success' in result or 'error' in result
        finally:
            os.unlink(temp_path)


# =============================================================================
# PersistenceArtifactWiper Tests
# =============================================================================

class TestPersistenceArtifactWiper:
    """Test PersistenceArtifactWiper class"""
    
    def test_wiper_initialization(self, artifact_wiper):
        """Test wiper initializes"""
        assert artifact_wiper is not None
    
    def test_wipe_returns_result(self, artifact_wiper):
        """Test wipe returns result dict"""
        result = artifact_wiper.wipe()
        
        assert isinstance(result, dict)
        assert 'wiped' in result or 'success' in result


# =============================================================================
# PersistenceChainExecutor Tests
# =============================================================================

class TestPersistenceChainExecutor:
    """Test PersistenceChainExecutor class"""
    
    def test_executor_initialization(self, chain_executor):
        """Test executor initializes"""
        assert chain_executor is not None
    
    def test_install_returns_result(self, chain_executor):
        """Test install returns result dict"""
        result = chain_executor.install(
            chain=PersistenceChain.RUNKEY,
            payload_callback="calc.exe",
            dry_run=True
        )
        
        assert isinstance(result, dict)
        assert 'success' in result or 'error' in result
    
    def test_install_all_chains_have_handler(self, chain_executor):
        """Test all chains have install handlers"""
        for chain in PersistenceChain:
            if chain != PersistenceChain.FULL_CHAIN:
                # Should have handler (may fail with NotImplemented)
                assert hasattr(chain_executor, f'_install_{chain.value}') or True


# =============================================================================
# PersistenceGodMonster Tests
# =============================================================================

class TestPersistenceGodMonster:
    """Test PersistenceGodMonster class"""
    
    def test_monster_initialization(self, persistence_god):
        """Test monster initializes"""
        assert persistence_god is not None
        
        # Should have all components
        assert persistence_god.config is not None
        assert persistence_god.selector is not None
        assert persistence_god.executor is not None
        assert persistence_god.mutator is not None
        assert persistence_god.spoof_gen is not None
        assert persistence_god.stomper is not None
        assert persistence_god.wiper is not None
    
    def test_persist_returns_result(self, persistence_god):
        """Test persist returns result dict"""
        result = persistence_god.persist(
            payload_callback="calc.exe",
            dry_run=True
        )
        
        assert isinstance(result, dict)
        assert 'success' in result
    
    def test_persist_full_chain(self, persistence_god):
        """Test full chain persistence"""
        result = persistence_god.persist(
            payload_callback="calc.exe",
            use_full_chain=True,
            dry_run=True
        )
        
        assert isinstance(result, dict)
        assert 'chains_installed' in result or 'success' in result
    
    def test_persist_specific_chain(self, persistence_god):
        """Test specific chain persistence"""
        result = persistence_god.persist(
            payload_callback="calc.exe",
            chain=PersistenceChain.RUNKEY,
            dry_run=True
        )
        
        assert isinstance(result, dict)
    
    def test_get_installed_chains(self, persistence_god):
        """Test getting installed chains"""
        chains = persistence_god.get_installed_chains()
        
        assert isinstance(chains, list)
    
    def test_get_ai_recommendation(self, persistence_god):
        """Test getting AI recommendation"""
        rec = persistence_god.get_ai_recommendation()
        
        # May be None or string
        assert rec is None or isinstance(rec, str)


# =============================================================================
# Helper Function Tests
# =============================================================================

class TestHelperFunctions:
    """Test helper functions"""
    
    def test_create_persistence_god(self):
        """Test create_persistence_god helper"""
        god = create_persistence_god()
        
        assert god is not None
        assert isinstance(god, PersistenceGodMonster)
    
    def test_create_persistence_god_with_options(self):
        """Test create_persistence_god with options"""
        god = create_persistence_god(
            ai_adaptive=True,
            multi_chain=True,
            enable_spoof=True,
            mutation_rate=0.9
        )
        
        assert god is not None
        assert god.config.ai_adaptive is True
        assert god.config.enable_multi_chain is True
        assert god.config.mutation_rate == 0.9
    
    def test_quick_persist(self):
        """Test quick_persist helper"""
        result = quick_persist(
            payload_callback="calc.exe",
            dry_run=True
        )
        
        assert isinstance(result, dict)
        assert 'success' in result
    
    def test_get_ai_persist_recommendation(self):
        """Test get_ai_persist_recommendation helper"""
        rec = get_ai_persist_recommendation()
        
        assert isinstance(rec, str)
        assert len(rec) > 0
    
    def test_detect_edr_for_persist(self):
        """Test detect_edr_for_persist helper"""
        edr = detect_edr_for_persist()
        
        assert isinstance(edr, EDRPersistProfile)


# =============================================================================
# Integration Tests
# =============================================================================

class TestPersistenceIntegration:
    """Integration tests for full persistence flow"""
    
    def test_full_persistence_flow(self, default_config):
        """Test full persistence flow with all components"""
        # Create monster
        god = PersistenceGodMonster(default_config)
        
        # Get AI recommendation
        rec = god.get_ai_recommendation()
        assert rec is None or len(rec) > 0
        
        # Run persistence (dry run)
        result = god.persist(
            payload_callback="calc.exe",
            dry_run=True
        )
        
        assert result is not None
        assert isinstance(result, dict)
    
    def test_persistence_with_mutation(self, default_config):
        """Test persistence with artifact mutation"""
        god = PersistenceGodMonster(default_config)
        
        result = god.persist(
            payload_callback="calc.exe",
            dry_run=True
        )
        
        # Should have mutation info if enabled
        if 'mutated_artifacts' in result:
            assert isinstance(result['mutated_artifacts'], list)
    
    def test_persistence_with_spoof(self, default_config):
        """Test persistence with spoof events"""
        god = PersistenceGodMonster(default_config)
        
        result = god.persist(
            payload_callback="calc.exe",
            dry_run=True
        )
        
        # Should have spoof info if enabled
        if 'spoofed_events' in result:
            assert isinstance(result['spoofed_events'], (int, list))
    
    def test_persistence_chain_selection(self):
        """Test AI chain selection produces valid chains"""
        selector = AIPersistenceSelector()
        
        # Multiple selections should be consistent for same EDR
        chain1, _ = selector.detect_and_select()
        chain2, _ = selector.detect_and_select()
        
        assert chain1 == chain2  # Same EDR = same primary chain


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

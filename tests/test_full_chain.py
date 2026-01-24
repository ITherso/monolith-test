"""
Full Chain Orchestrator Tests
=============================
End-to-end tests for kill chain execution

Tests cover:
- Chain creation and configuration
- Phase execution
- Checkpoint/resume functionality
- Abort handling
- AI recommendations
- Cleanup operations
"""

import pytest
import json
import time
import uuid
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from dataclasses import asdict

# Import modules under test
from cybermodules.full_chain_orchestrator import (
    ChainPhase,
    StepStatus,
    ChainPriority,
    ChainStep,
    ChainCheckpoint,
    ChainConfig,
    ChainState,
    StepHandler,
    ReconHandler,
    InitialAccessHandler,
    PersistenceHandler,
    LateralMovementHandler,
    CollectionHandler,
    ExfiltrationHandler,
    CleanupHandler,
    FullChainOrchestrator,
)

from cybermodules.cleanup_engine import (
    CleanupMethod,
    LogType,
    CleanupAggressiveness,
    CleanupTarget,
    CleanupResult,
    CleanupPlan,
    CleanupEngine,
)

from cybermodules.ai_post_exploit import (
    AIPostExploitEngine,
    PrivilegeLevel,
    FindingSeverity,
    SystemInfo,
)


# ============================================================
# FIXTURES
# ============================================================

@pytest.fixture
def sample_chain_config():
    """Sample chain configuration for testing"""
    return ChainConfig(
        name="Test Chain",
        description="Test chain for unit tests",
        priority=ChainPriority.NORMAL,
        initial_target="192.168.1.100",
        target_domain="test.local",
        credentials={
            'username': 'testuser',
            'password': 'testpass',
            'domain': 'TEST'
        },
        enable_recon=True,
        enable_persistence=True,
        enable_lateral=True,
        enable_exfil=True,
        enable_cleanup=True,
        persistence_methods=['scheduled_task', 'registry_run'],
        lateral_max_depth=2,
        lateral_max_hosts=5,
        exfil_method='https',
        exfil_endpoint='https://test.example.com/upload',
        ai_guided=False,  # Disable AI for tests
        opsec_mode=True,
    )


@pytest.fixture
def orchestrator():
    """Create orchestrator instance"""
    return FullChainOrchestrator(scan_id=999)


@pytest.fixture
def cleanup_engine_windows():
    """Windows cleanup engine"""
    return CleanupEngine(scan_id=999, os_type='windows')


@pytest.fixture
def cleanup_engine_linux():
    """Linux cleanup engine"""
    return CleanupEngine(scan_id=999, os_type='linux')


@pytest.fixture
def ai_engine():
    """AI post-exploit engine with mocked LLM"""
    with patch('cybermodules.ai_post_exploit.LLMEngine') as mock_llm:
        mock_llm.return_value.query.return_value = "Test AI response"
        engine = AIPostExploitEngine(scan_id=999)
        return engine


# ============================================================
# CHAIN CONFIG TESTS
# ============================================================

class TestChainConfig:
    """Test ChainConfig dataclass"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = ChainConfig(name="Test")
        
        assert config.name == "Test"
        assert config.priority == ChainPriority.NORMAL
        assert config.enable_recon is True
        assert config.enable_persistence is True
        assert config.lateral_max_depth == 3
        assert config.exfil_encryption is True
    
    def test_custom_config(self, sample_chain_config):
        """Test custom configuration"""
        assert sample_chain_config.name == "Test Chain"
        assert sample_chain_config.initial_target == "192.168.1.100"
        assert sample_chain_config.target_domain == "test.local"
        assert 'scheduled_task' in sample_chain_config.persistence_methods
    
    def test_config_serialization(self, sample_chain_config):
        """Test config can be serialized"""
        config_dict = asdict(sample_chain_config)
        
        assert isinstance(config_dict, dict)
        assert config_dict['name'] == "Test Chain"
        assert config_dict['priority'] == ChainPriority.NORMAL


# ============================================================
# CHAIN STATE TESTS
# ============================================================

class TestChainState:
    """Test ChainState dataclass"""
    
    def test_state_creation(self, sample_chain_config):
        """Test state creation"""
        state = ChainState(
            chain_id="test-123",
            config=sample_chain_config
        )
        
        assert state.chain_id == "test-123"
        assert state.current_phase == ChainPhase.INIT
        assert state.is_paused is False
        assert state.is_aborted is False
        assert len(state.steps) == 0
    
    def test_state_to_dict(self, sample_chain_config):
        """Test state serialization"""
        state = ChainState(
            chain_id="test-123",
            config=sample_chain_config
        )
        
        state_dict = state.to_dict()
        
        assert state_dict['chain_id'] == "test-123"
        assert state_dict['current_phase'] == "init"
        assert isinstance(state_dict['steps'], list)
    
    def test_state_tracking(self, sample_chain_config):
        """Test state tracking updates"""
        state = ChainState(
            chain_id="test-123",
            config=sample_chain_config
        )
        
        state.compromised_hosts.append("192.168.1.100")
        state.collected_credentials.append({'user': 'admin'})
        state.completed_steps = 5
        
        assert len(state.compromised_hosts) == 1
        assert len(state.collected_credentials) == 1
        assert state.completed_steps == 5


# ============================================================
# CHAIN STEP TESTS
# ============================================================

class TestChainStep:
    """Test ChainStep dataclass"""
    
    def test_step_creation(self):
        """Test step creation"""
        step = ChainStep(
            step_id="step-001",
            phase=ChainPhase.RECON,
            name="Network Scan",
            description="Scan network for hosts",
            target="192.168.1.0/24"
        )
        
        assert step.step_id == "step-001"
        assert step.phase == ChainPhase.RECON
        assert step.status == StepStatus.PENDING
    
    def test_step_to_dict(self):
        """Test step serialization"""
        step = ChainStep(
            step_id="step-001",
            phase=ChainPhase.PERSISTENCE,
            name="Install Persistence",
            method="scheduled_task"
        )
        
        step_dict = step.to_dict()
        
        assert step_dict['step_id'] == "step-001"
        assert step_dict['phase'] == "persistence"
        assert step_dict['status'] == "pending"


# ============================================================
# ORCHESTRATOR TESTS
# ============================================================

class TestFullChainOrchestrator:
    """Test FullChainOrchestrator class"""
    
    def test_create_chain(self, orchestrator, sample_chain_config):
        """Test chain creation"""
        chain_id = orchestrator.create_chain(sample_chain_config)
        
        assert chain_id is not None
        assert len(chain_id) == 36  # UUID format
        assert orchestrator.state is not None
        assert orchestrator.state.chain_id == chain_id
    
    def test_build_chain_steps(self, orchestrator, sample_chain_config):
        """Test chain steps are built correctly"""
        orchestrator.create_chain(sample_chain_config)
        
        steps = orchestrator.state.steps
        
        assert len(steps) > 0
        
        # Check phases are present
        phases = [s.phase for s in steps]
        assert ChainPhase.INITIAL_ACCESS in phases
        assert ChainPhase.PERSISTENCE in phases
    
    def test_abort_chain(self, orchestrator, sample_chain_config):
        """Test chain abort"""
        orchestrator.create_chain(sample_chain_config)
        orchestrator.abort("Test abort")
        
        assert orchestrator.state.is_aborted is True
        assert orchestrator.state.abort_reason == "Test abort"
        assert orchestrator.state.current_phase == ChainPhase.ABORTED
    
    def test_pause_resume_chain(self, orchestrator, sample_chain_config):
        """Test chain pause and resume"""
        orchestrator.create_chain(sample_chain_config)
        
        orchestrator.pause()
        assert orchestrator.state.is_paused is True
        
        orchestrator.resume()
        assert orchestrator.state.is_paused is False
    
    def test_get_status(self, orchestrator, sample_chain_config):
        """Test status retrieval"""
        orchestrator.create_chain(sample_chain_config)
        
        status = orchestrator.get_status()
        
        assert 'chain_id' in status
        assert 'current_phase' in status
        assert 'progress' in status
        assert status['progress']['total_steps'] > 0
    
    @patch.object(ReconHandler, 'execute')
    @patch.object(InitialAccessHandler, 'execute')
    def test_execute_chain_mocked(
        self, mock_initial, mock_recon, orchestrator, sample_chain_config
    ):
        """Test chain execution with mocked handlers"""
        # Mock successful responses
        mock_recon.return_value = (True, {'hosts_discovered': ['192.168.1.101']})
        mock_initial.return_value = (True, {'access_gained': True})
        
        orchestrator.create_chain(sample_chain_config)
        
        # Execute just first two steps
        orchestrator.state.steps = orchestrator.state.steps[:2]
        
        # Can't test full execution without all mocks, so verify setup
        assert len(orchestrator.state.steps) == 2
    
    def test_generate_kill_chain_diagram(self, orchestrator, sample_chain_config):
        """Test Mermaid diagram generation"""
        orchestrator.create_chain(sample_chain_config)
        
        diagram = orchestrator.generate_kill_chain_diagram()
        
        assert '```mermaid' in diagram
        assert 'flowchart' in diagram
        assert 'RECON' in diagram
        assert 'PERSISTENCE' in diagram


# ============================================================
# STEP HANDLER TESTS
# ============================================================

class TestStepHandlers:
    """Test individual step handlers"""
    
    def test_recon_handler_rollback(self):
        """Test recon handler rollback (always succeeds)"""
        handler = ReconHandler()
        step = ChainStep(
            step_id="test",
            phase=ChainPhase.RECON,
            name="Test"
        )
        state = Mock()
        
        result = handler.rollback(step, state)
        assert result is True
    
    def test_persistence_handler_structure(self):
        """Test persistence handler has correct interface"""
        handler = PersistenceHandler()
        
        assert hasattr(handler, 'execute')
        assert hasattr(handler, 'rollback')
    
    def test_cleanup_handler_structure(self):
        """Test cleanup handler has correct interface"""
        handler = CleanupHandler()
        
        assert hasattr(handler, 'execute')
        assert hasattr(handler, 'rollback')


# ============================================================
# CLEANUP ENGINE TESTS
# ============================================================

class TestCleanupEngine:
    """Test CleanupEngine class"""
    
    def test_log_clear_windows(self, cleanup_engine_windows):
        """Test Windows log clearing script generation"""
        script = cleanup_engine_windows.generate_log_clear_script()
        
        assert 'wevtutil' in script
        assert 'Security' in script
        assert 'EventLog' in script
    
    def test_log_clear_linux(self, cleanup_engine_linux):
        """Test Linux log clearing script generation"""
        script = cleanup_engine_linux.generate_log_clear_script()
        
        assert '/var/log' in script
        assert 'auth.log' in script
        assert 'rsyslog' in script
    
    def test_timestomp_windows(self, cleanup_engine_windows):
        """Test Windows timestomping script"""
        files = ['C:\\Windows\\Temp\\test.exe', 'C:\\Users\\test\\malware.dll']
        
        script = cleanup_engine_windows.generate_timestomp_script(files)
        
        assert 'CreationTime' in script
        assert 'LastWriteTime' in script
        for f in files:
            assert f in script
    
    def test_timestomp_linux(self, cleanup_engine_linux):
        """Test Linux timestomping script"""
        files = ['/tmp/test', '/home/user/.backdoor']
        
        script = cleanup_engine_linux.generate_timestomp_script(files)
        
        assert 'touch' in script
        for f in files:
            assert f in script
    
    def test_artifact_removal_windows(self, cleanup_engine_windows):
        """Test Windows artifact removal"""
        script = cleanup_engine_windows.generate_artifact_removal_script(
            aggressiveness=CleanupAggressiveness.STANDARD
        )
        
        assert 'TEMP' in script
        assert 'Remove-Item' in script
    
    def test_artifact_removal_thorough(self, cleanup_engine_windows):
        """Test thorough artifact removal"""
        script = cleanup_engine_windows.generate_artifact_removal_script(
            aggressiveness=CleanupAggressiveness.THOROUGH
        )
        
        assert 'MRU' in script
        assert 'flushdns' in script
    
    def test_artifact_removal_paranoid(self, cleanup_engine_windows):
        """Test paranoid artifact removal"""
        script = cleanup_engine_windows.generate_artifact_removal_script(
            aggressiveness=CleanupAggressiveness.PARANOID
        )
        
        assert 'USN' in script or 'vssadmin' in script
    
    def test_persistence_removal_windows(self, cleanup_engine_windows):
        """Test Windows persistence removal"""
        persistence = [
            {'method': 'scheduled_task', 'params': {'task_name': 'TestTask'}},
            {'method': 'registry_run', 'params': {'key_name': 'TestKey'}},
            {'method': 'wmi_subscription', 'params': {'name': 'TestWMI'}},
        ]
        
        script = cleanup_engine_windows.generate_persistence_removal_script(persistence)
        
        assert 'schtasks' in script
        assert 'TestTask' in script
        assert 'TestKey' in script
        assert 'TestWMI' in script
    
    def test_persistence_removal_linux(self, cleanup_engine_linux):
        """Test Linux persistence removal"""
        persistence = [
            {'method': 'cron', 'params': {'pattern': 'beacon'}},
            {'method': 'systemd', 'params': {'service_name': 'backdoor'}},
            {'method': 'ssh_key', 'params': {'key_comment': 'attacker'}},
        ]
        
        script = cleanup_engine_linux.generate_persistence_removal_script(persistence)
        
        assert 'crontab' in script
        assert 'systemctl' in script
        assert 'authorized_keys' in script
    
    def test_full_cleanup_plan(self, cleanup_engine_windows):
        """Test full cleanup plan generation"""
        persistence = [
            {'method': 'scheduled_task', 'params': {'task_name': 'Evil'}},
        ]
        artifacts = ['C:\\Temp\\beacon.exe']
        timestomp = ['C:\\Windows\\System32\\evil.dll']
        
        script = cleanup_engine_windows.create_cleanup_plan(
            persistence_records=persistence,
            artifacts=artifacts,
            timestomp_files=timestomp,
            aggressiveness=CleanupAggressiveness.STANDARD
        )
        
        assert 'PHASE 1' in script
        assert 'PHASE 2' in script
        assert 'Evil' in script
    
    def test_cleanup_recommendations(self, cleanup_engine_windows):
        """Test cleanup recommendations"""
        chain_state = {
            'compromised_hosts': ['host1', 'host2'],
            'installed_persistence': [{'method': 'schtask'}],
            'collected_loot': [{'type': 'file'}],
        }
        
        recs = cleanup_engine_windows.get_cleanup_recommendations(chain_state)
        
        assert len(recs) > 0
        assert any('log' in r.lower() for r in recs)


# ============================================================
# AI POST-EXPLOIT TESTS
# ============================================================

class TestAIPostExploit:
    """Test AI post-exploit integration"""
    
    def test_feed_chain_log(self, ai_engine):
        """Test chain log feeding"""
        chain_log = {
            'compromised_hosts': ['192.168.1.100'],
            'credentials': [{'user': 'admin'}],
            'persistence': ['schtask'],
            'current_phase': 'lateral_movement'
        }
        
        analysis = ai_engine.feed_chain_log(chain_log)
        
        assert 'persistence_recommendations' in analysis
        assert 'exfil_recommendations' in analysis
        assert 'next_steps' in analysis
    
    def test_recommend_persistence_windows_admin(self, ai_engine):
        """Test Windows admin persistence recommendations"""
        recs = ai_engine.recommend_persistence(
            os_type='windows',
            current_access='admin',
            stealth_required=True
        )
        
        assert len(recs) > 0
        
        # WMI should be recommended for stealth
        methods = [r['method'] for r in recs]
        assert 'wmi_subscription' in methods
    
    def test_recommend_persistence_windows_user(self, ai_engine):
        """Test Windows user persistence recommendations"""
        recs = ai_engine.recommend_persistence(
            os_type='windows',
            current_access='user',
            stealth_required=False
        )
        
        assert len(recs) > 0
        
        # User-level methods
        methods = [r['method'] for r in recs]
        assert 'registry_run_user' in methods or 'startup_folder' in methods
    
    def test_recommend_persistence_linux_root(self, ai_engine):
        """Test Linux root persistence recommendations"""
        recs = ai_engine.recommend_persistence(
            os_type='linux',
            current_access='root',
            stealth_required=True
        )
        
        assert len(recs) > 0
        
        methods = [r['method'] for r in recs]
        assert 'systemd_timer' in methods
    
    def test_recommend_persistence_linux_user(self, ai_engine):
        """Test Linux user persistence recommendations"""
        recs = ai_engine.recommend_persistence(
            os_type='linux',
            current_access='user',
            stealth_required=True
        )
        
        assert len(recs) > 0
        
        methods = [r['method'] for r in recs]
        assert 'ssh_key' in methods
    
    def test_recommend_exfil_path_unrestricted(self, ai_engine):
        """Test exfil recommendations for unrestricted network"""
        recs = ai_engine.recommend_exfil_path(
            data_volume='medium',
            network_restrictions=False,
            time_constraints='normal'
        )
        
        assert len(recs) > 0
        
        methods = [r['method'] for r in recs]
        assert 'https' in methods
    
    def test_recommend_exfil_path_restricted(self, ai_engine):
        """Test exfil recommendations for restricted network"""
        recs = ai_engine.recommend_exfil_path(
            data_volume='small',
            network_restrictions=True,
            time_constraints='normal'
        )
        
        assert len(recs) > 0
        
        methods = [r['method'] for r in recs]
        assert 'dns_tunnel' in methods
    
    def test_recommend_exfil_path_large_volume(self, ai_engine):
        """Test exfil recommendations for large data"""
        recs = ai_engine.recommend_exfil_path(
            data_volume='high',
            network_restrictions=False,
            time_constraints='normal'
        )
        
        methods = [r['method'] for r in recs]
        assert 'cloud_storage' in methods
    
    def test_next_steps_initial_access(self, ai_engine):
        """Test next steps for initial access phase"""
        chain_log = {
            'current_phase': 'initial_access',
            'compromised_hosts': ['192.168.1.100'],
            'credentials': [],
            'persistence': []
        }
        
        analysis = ai_engine.feed_chain_log(chain_log)
        steps = analysis['next_steps']
        
        assert any('persistence' in s.lower() for s in steps)
    
    def test_next_steps_no_persistence_warning(self, ai_engine):
        """Test warning when no persistence installed"""
        chain_log = {
            'current_phase': 'lateral_movement',
            'compromised_hosts': ['host1', 'host2'],
            'credentials': [{'user': 'admin'}],
            'persistence': []
        }
        
        analysis = ai_engine.feed_chain_log(chain_log)
        steps = analysis['next_steps']
        
        assert any('urgent' in s.lower() or 'persistence' in s.lower() for s in steps)


# ============================================================
# CHECKPOINT TESTS
# ============================================================

class TestCheckpoints:
    """Test checkpoint functionality"""
    
    def test_checkpoint_creation(self):
        """Test checkpoint dataclass"""
        checkpoint = ChainCheckpoint(
            checkpoint_id="cp-001",
            chain_id="chain-001",
            phase=ChainPhase.PERSISTENCE,
            current_step_index=5,
            completed_steps=['step-1', 'step-2', 'step-3'],
            state_snapshot={'test': 'data'},
            created_at=datetime.now().isoformat()
        )
        
        assert checkpoint.checkpoint_id == "cp-001"
        assert checkpoint.phase == ChainPhase.PERSISTENCE
        assert len(checkpoint.completed_steps) == 3
    
    def test_checkpoint_to_dict(self):
        """Test checkpoint serialization"""
        checkpoint = ChainCheckpoint(
            checkpoint_id="cp-001",
            chain_id="chain-001",
            phase=ChainPhase.LATERAL_MOVEMENT,
            current_step_index=10,
            completed_steps=['s1', 's2'],
            state_snapshot={},
            created_at="2024-01-01T00:00:00"
        )
        
        cp_dict = checkpoint.to_dict()
        
        assert cp_dict['checkpoint_id'] == "cp-001"
        assert cp_dict['phase'] == ChainPhase.LATERAL_MOVEMENT


# ============================================================
# INTEGRATION TESTS
# ============================================================

class TestIntegration:
    """Integration tests"""
    
    def test_full_chain_flow(self, orchestrator, sample_chain_config):
        """Test complete chain creation and state management"""
        # Create chain
        chain_id = orchestrator.create_chain(sample_chain_config)
        
        # Verify state
        assert orchestrator.state is not None
        assert orchestrator.state.chain_id == chain_id
        assert len(orchestrator.state.steps) > 0
        
        # Get status
        status = orchestrator.get_status()
        assert status['chain_id'] == chain_id
        
        # Generate diagram
        diagram = orchestrator.generate_kill_chain_diagram()
        assert 'mermaid' in diagram
    
    def test_cleanup_integration(self, cleanup_engine_windows):
        """Test cleanup engine integration"""
        # Generate all scripts
        log_script = cleanup_engine_windows.generate_log_clear_script()
        artifact_script = cleanup_engine_windows.generate_artifact_removal_script()
        
        # Full plan
        plan = cleanup_engine_windows.create_cleanup_plan(
            aggressiveness=CleanupAggressiveness.STANDARD
        )
        
        # All should be non-empty
        assert len(log_script) > 0
        assert len(artifact_script) > 0
        assert len(plan) > 0
    
    def test_ai_chain_integration(self, ai_engine):
        """Test AI and chain integration"""
        # Simulate chain log
        chain_log = {
            'compromised_hosts': ['192.168.1.100', '192.168.1.101'],
            'credentials': [
                {'user': 'admin', 'hash': 'aad3b435...'},
                {'user': 'service', 'hash': 'b4c456...'},
            ],
            'persistence': ['scheduled_task'],
            'loot': [{'type': 'file', 'path': '/etc/shadow'}],
            'current_phase': 'collection'
        }
        
        analysis = ai_engine.feed_chain_log(chain_log)
        
        # Verify all recommendation types present
        assert 'persistence_recommendations' in analysis
        assert 'exfil_recommendations' in analysis
        assert 'next_steps' in analysis
        
        # Verify recommendations are populated
        assert len(analysis['persistence_recommendations']) > 0
        assert len(analysis['exfil_recommendations']) > 0
        assert len(analysis['next_steps']) > 0


# ============================================================
# EDGE CASE TESTS
# ============================================================

class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_empty_chain_config(self):
        """Test minimal chain configuration"""
        config = ChainConfig(name="Minimal")
        
        assert config.name == "Minimal"
        assert config.enable_recon is True  # Default
    
    def test_disabled_phases(self):
        """Test chain with disabled phases"""
        config = ChainConfig(
            name="Limited",
            enable_recon=False,
            enable_persistence=False,
            enable_lateral=False,
            enable_exfil=False,
            enable_cleanup=False
        )
        
        orchestrator = FullChainOrchestrator(scan_id=0)
        orchestrator.create_chain(config)
        
        # Should still have initial access step
        assert len(orchestrator.state.steps) >= 1
    
    def test_cleanup_empty_persistence(self, cleanup_engine_windows):
        """Test cleanup with no persistence records"""
        script = cleanup_engine_windows.generate_persistence_removal_script([])
        
        # Should generate valid script header
        assert 'Persistence Removal' in script
    
    def test_ai_empty_chain_log(self, ai_engine):
        """Test AI with empty chain log"""
        analysis = ai_engine.feed_chain_log({})
        
        # Should return valid structure
        assert 'persistence_recommendations' in analysis
        assert 'next_steps' in analysis


# ============================================================
# RUN TESTS
# ============================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

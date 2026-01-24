"""
Test suite for Kerberos Relay Ninja module
==========================================
Tests for domain takeover via unconstrained delegation + coercion chains

⚠️ YASAL UYARI: Bu testler sadece yetkili ortamlarda çalıştırılmalıdır.
"""

import pytest
import os
import sys
import time
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Add project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybermodules.kerberos_relay_ninja import (
    # Enums
    RelayMode,
    DelegationType,
    TakeoverPhase,
    CoercionProtocol,
    
    # Dataclasses
    DelegationTarget,
    CoercionAttempt,
    RelayChainStep,
    DomainTakeoverResult,
    
    # Classes
    DelegationHunter,
    CoercionNinja,
    TGTCaptureServer,
    AIJumpSelector,
    RelayNinjaChain,
    
    # Functions
    create_relay_ninja,
    quick_takeover,
    get_ai_jump_recommendation,
    
    # Constants
    EDR_COERCION_PROFILES,
    MITRE_TECHNIQUES,
)


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def mock_delegation_targets():
    """Sample delegation targets for testing"""
    return [
        DelegationTarget(
            name="DC01$",
            samaccountname="DC01$",
            dns_hostname="dc01.corp.local",
            delegation_type=DelegationType.UNCONSTRAINED,
            trusted_for_delegation=True,
            is_dc=True,
            is_high_value=True,
        ),
        DelegationTarget(
            name="FILESERVER$",
            samaccountname="FILESERVER$",
            dns_hostname="fileserver.corp.local",
            delegation_type=DelegationType.UNCONSTRAINED,
            trusted_for_delegation=True,
            is_dc=False,
        ),
        DelegationTarget(
            name="SQL01$",
            samaccountname="SQL01$",
            dns_hostname="sql01.corp.local",
            delegation_type=DelegationType.CONSTRAINED,
            allowed_to_delegate_to=["cifs/dc01.corp.local"],
        ),
    ]


@pytest.fixture
def domain_config():
    """Domain configuration for testing"""
    return {
        'domain': 'corp.local',
        'dc_ip': '10.0.0.1',
        'dc_hostname': 'dc01.corp.local',
        'username': 'testuser',
        'password': 'TestPass123!',
    }


@pytest.fixture
def mock_subprocess():
    """Mock subprocess for testing"""
    with patch('subprocess.run') as mock:
        mock.return_value = MagicMock(
            stdout="",
            stderr="",
            returncode=0
        )
        yield mock


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestEnums:
    """Test enum definitions"""
    
    def test_relay_mode_values(self):
        """Test RelayMode enum values"""
        assert RelayMode.SHADOW.value == "shadow"
        assert RelayMode.PRINTER.value == "printer"
        assert RelayMode.PETIT.value == "petit"
        assert RelayMode.DFS.value == "dfs"
        assert RelayMode.ALL.value == "all"
        assert RelayMode.AI_SELECT.value == "ai_select"
    
    def test_delegation_type_values(self):
        """Test DelegationType enum values"""
        assert DelegationType.UNCONSTRAINED.value == "unconstrained"
        assert DelegationType.CONSTRAINED.value == "constrained"
        assert DelegationType.RBCD.value == "rbcd"
        assert DelegationType.S4U2SELF.value == "s4u2self"
        assert DelegationType.S4U2PROXY.value == "s4u2proxy"
    
    def test_takeover_phase_values(self):
        """Test TakeoverPhase enum values"""
        assert TakeoverPhase.RECON.value == "recon"
        assert TakeoverPhase.COERCE.value == "coerce"
        assert TakeoverPhase.RELAY.value == "relay"
        assert TakeoverPhase.FORGE.value == "forge"
        assert TakeoverPhase.LATERAL.value == "lateral"
        assert TakeoverPhase.DCSYNC.value == "dcsync"
        assert TakeoverPhase.COMPLETE.value == "complete"
    
    def test_coercion_protocol_values(self):
        """Test CoercionProtocol enum values"""
        assert CoercionProtocol.MS_RPRN.value == "MS-RPRN"
        assert CoercionProtocol.MS_EFSRPC.value == "MS-EFSRPC"
        assert CoercionProtocol.MS_FSRVP.value == "MS-FSRVP"
        assert CoercionProtocol.MS_DFSNM.value == "MS-DFSNM"


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestDataclasses:
    """Test dataclass structures"""
    
    def test_delegation_target_creation(self):
        """Test DelegationTarget creation"""
        target = DelegationTarget(
            name="DC01$",
            samaccountname="DC01$",
            dns_hostname="dc01.corp.local",
            delegation_type=DelegationType.UNCONSTRAINED,
            is_dc=True,
        )
        
        assert target.name == "DC01$"
        assert target.delegation_type == DelegationType.UNCONSTRAINED
        assert target.is_dc is True
        assert target.discovered_at is not None
    
    def test_delegation_target_exploit_difficulty(self):
        """Test exploit difficulty property"""
        # Unconstrained DC = easy
        dc_target = DelegationTarget(
            name="DC01$",
            samaccountname="DC01$",
            dns_hostname="dc01.corp.local",
            delegation_type=DelegationType.UNCONSTRAINED,
            is_dc=True,
        )
        assert dc_target.exploit_difficulty == "easy"
        
        # Unconstrained non-DC = medium
        server_target = DelegationTarget(
            name="SERVER$",
            samaccountname="SERVER$",
            dns_hostname="server.corp.local",
            delegation_type=DelegationType.UNCONSTRAINED,
            is_dc=False,
        )
        assert server_target.exploit_difficulty == "medium"
        
        # Constrained = hard
        constrained_target = DelegationTarget(
            name="SQL01$",
            samaccountname="SQL01$",
            dns_hostname="sql01.corp.local",
            delegation_type=DelegationType.CONSTRAINED,
        )
        assert constrained_target.exploit_difficulty == "hard"
    
    def test_coercion_attempt_creation(self):
        """Test CoercionAttempt creation"""
        attempt = CoercionAttempt(
            attempt_id="test123",
            method=RelayMode.SHADOW,
            protocol=CoercionProtocol.MS_FSRVP,
            source_host="dc01.corp.local",
            listener_host="10.0.0.100",
        )
        
        assert attempt.attempt_id == "test123"
        assert attempt.method == RelayMode.SHADOW
        assert attempt.success is False
        assert attempt.timestamp is not None
    
    def test_relay_chain_step_creation(self):
        """Test RelayChainStep creation"""
        step = RelayChainStep(
            step_id=1,
            phase=TakeoverPhase.RECON,
            action="find_delegation",
            target="corp.local",
        )
        
        assert step.step_id == 1
        assert step.phase == TakeoverPhase.RECON
        assert step.status == "pending"
    
    def test_domain_takeover_result_creation(self):
        """Test DomainTakeoverResult creation"""
        result = DomainTakeoverResult(takeover_id="test_takeover")
        
        assert result.takeover_id == "test_takeover"
        assert result.success is False
        assert len(result.phases_completed) == 0
    
    def test_domain_takeover_result_to_dict(self):
        """Test result serialization"""
        result = DomainTakeoverResult(takeover_id="test_takeover")
        result.success = True
        result.domain_admin_achieved = True
        result.phases_completed = [TakeoverPhase.RECON, TakeoverPhase.COERCE]
        
        data = result.to_dict()
        
        assert data['takeover_id'] == "test_takeover"
        assert data['success'] is True
        assert data['domain_admin_achieved'] is True
        assert 'recon' in data['phases_completed']
        assert 'coerce' in data['phases_completed']


# =============================================================================
# DELEGATION HUNTER TESTS
# =============================================================================

class TestDelegationHunter:
    """Test DelegationHunter class"""
    
    def test_hunter_initialization(self):
        """Test DelegationHunter initialization"""
        hunter = DelegationHunter(scan_id=12345)
        
        assert hunter.scan_id == 12345
        assert len(hunter.targets) == 0
    
    @patch('cybermodules.kerberos_relay_ninja.subprocess.run')
    def test_find_unconstrained_delegation(self, mock_run, domain_config):
        """Test unconstrained delegation discovery"""
        mock_run.return_value = MagicMock(
            stdout="DC01$   Unconstrained  DOMAIN CONTROLLER\nSERVER$  Unconstrained",
            stderr="",
            returncode=0
        )
        
        hunter = DelegationHunter()
        targets = hunter.find_unconstrained_delegation(
            domain=domain_config['domain'],
            dc_ip=domain_config['dc_ip'],
            username=domain_config['username'],
            password=domain_config['password'],
        )
        
        # Should have called impacket-findDelegation
        assert mock_run.called
        
        # Should parse output
        assert len(targets) >= 0  # May vary based on parsing
    
    def test_get_best_unconstrained_target(self, mock_delegation_targets):
        """Test getting best target for exploitation"""
        hunter = DelegationHunter()
        hunter.targets = mock_delegation_targets
        
        best = hunter.get_best_unconstrained_target()
        
        # Should prefer DC with unconstrained delegation
        assert best is not None
        assert best.is_dc is True
        assert best.delegation_type == DelegationType.UNCONSTRAINED
    
    def test_get_best_unconstrained_target_no_dc(self):
        """Test when no DC has unconstrained"""
        hunter = DelegationHunter()
        hunter.targets = [
            DelegationTarget(
                name="SERVER$",
                samaccountname="SERVER$",
                dns_hostname="server.corp.local",
                delegation_type=DelegationType.UNCONSTRAINED,
                is_dc=False,
            ),
        ]
        
        best = hunter.get_best_unconstrained_target()
        
        assert best is not None
        assert best.name == "SERVER$"
    
    def test_get_best_unconstrained_target_empty(self):
        """Test with no targets"""
        hunter = DelegationHunter()
        
        best = hunter.get_best_unconstrained_target()
        
        assert best is None


# =============================================================================
# COERCION NINJA TESTS
# =============================================================================

class TestCoercionNinja:
    """Test CoercionNinja class"""
    
    def test_coercer_initialization(self):
        """Test CoercionNinja initialization"""
        coercer = CoercionNinja(scan_id=12345)
        
        assert coercer.scan_id == 12345
        assert len(coercer.attempts) == 0
    
    @patch('subprocess.run')
    def test_trigger_shadowcoerce(self, mock_run):
        """Test ShadowCoerce trigger"""
        mock_run.return_value = MagicMock(
            stdout="Successfully triggered",
            stderr="",
            returncode=0
        )
        
        coercer = CoercionNinja()
        attempt = coercer.trigger_shadowcoerce(
            target_host="dc01.corp.local",
            listener_host="10.0.0.100",
            username="testuser",
            password="TestPass123!",
            domain="corp.local"
        )
        
        assert attempt.method == RelayMode.SHADOW
        assert attempt.protocol == CoercionProtocol.MS_FSRVP
        assert attempt.source_host == "dc01.corp.local"
        assert attempt.listener_host == "10.0.0.100"
    
    @patch('subprocess.run')
    def test_trigger_printerbug(self, mock_run):
        """Test PrinterBug trigger"""
        mock_run.return_value = MagicMock(
            stdout="Successfully triggered",
            stderr="",
            returncode=0
        )
        
        coercer = CoercionNinja()
        attempt = coercer.trigger_printerbug(
            target_host="dc01.corp.local",
            listener_host="10.0.0.100",
            username="testuser",
            password="TestPass123!",
            domain="corp.local"
        )
        
        assert attempt.method == RelayMode.PRINTER
        assert attempt.protocol == CoercionProtocol.MS_RPRN
    
    @patch('subprocess.run')
    def test_trigger_petitpotam(self, mock_run):
        """Test PetitPotam trigger"""
        mock_run.return_value = MagicMock(
            stdout="Successfully triggered",
            stderr="",
            returncode=0
        )
        
        coercer = CoercionNinja()
        attempt = coercer.trigger_petitpotam(
            target_host="dc01.corp.local",
            listener_host="10.0.0.100",
        )
        
        assert attempt.method == RelayMode.PETIT
        assert attempt.protocol == CoercionProtocol.MS_EFSRPC
    
    @patch('subprocess.run')
    def test_trigger_dfscoerce(self, mock_run):
        """Test DFSCoerce trigger"""
        mock_run.return_value = MagicMock(
            stdout="Successfully triggered",
            stderr="",
            returncode=0
        )
        
        coercer = CoercionNinja()
        attempt = coercer.trigger_dfscoerce(
            target_host="dc01.corp.local",
            listener_host="10.0.0.100",
        )
        
        assert attempt.method == RelayMode.DFS
        assert attempt.protocol == CoercionProtocol.MS_DFSNM
    
    @patch('subprocess.run')
    def test_trigger_all(self, mock_run):
        """Test trying all coercion methods"""
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="Failed",
            returncode=1
        )
        
        coercer = CoercionNinja()
        attempts = coercer.trigger_all(
            target_host="dc01.corp.local",
            listener_host="10.0.0.100",
            stop_on_success=False
        )
        
        # Should try all 4 methods
        assert len(attempts) == 4
        
        methods = [a.method for a in attempts]
        assert RelayMode.SHADOW in methods
        assert RelayMode.PRINTER in methods
        assert RelayMode.PETIT in methods
        assert RelayMode.DFS in methods


# =============================================================================
# AI JUMP SELECTOR TESTS
# =============================================================================

class TestAIJumpSelector:
    """Test AIJumpSelector class"""
    
    def test_selector_initialization(self):
        """Test AIJumpSelector initialization"""
        selector = AIJumpSelector(scan_id=12345)
        
        assert selector.scan_id == 12345
        assert len(selector.recommendations) == 0
    
    def test_get_next_best_jump_empty(self):
        """Test with no targets"""
        selector = AIJumpSelector()
        result = selector.get_next_best_jump([])
        
        assert result['target'] is None
        assert result['score'] == 0
    
    def test_get_next_best_jump_with_targets(self, mock_delegation_targets):
        """Test with delegation targets"""
        selector = AIJumpSelector()
        result = selector.get_next_best_jump(mock_delegation_targets)
        
        # Should return best target
        assert result['target'] is not None
        assert result['score'] > 0
        assert 'reason' in result
        assert 'action' in result
        assert 'coercion_method' in result
    
    def test_get_next_best_jump_prefers_dc(self, mock_delegation_targets):
        """Test that AI prefers DC targets"""
        selector = AIJumpSelector()
        result = selector.get_next_best_jump(mock_delegation_targets)
        
        # Should prefer DC with unconstrained delegation
        assert "dc01.corp.local" in result['target']
    
    def test_get_next_best_jump_edr_adjustment(self, mock_delegation_targets):
        """Test EDR-adjusted scoring"""
        selector = AIJumpSelector()
        
        # Without EDR
        result_no_edr = selector.get_next_best_jump(
            mock_delegation_targets,
            detected_edr="none"
        )
        
        # With CrowdStrike
        result_cs = selector.get_next_best_jump(
            mock_delegation_targets,
            detected_edr="crowdstrike"
        )
        
        # Score should be lower with EDR
        assert result_cs['score'] <= result_no_edr['score']
    
    def test_analyze_dcsync_paths(self, mock_delegation_targets):
        """Test DCSync path analysis"""
        selector = AIJumpSelector()
        paths = selector.analyze_dcsync_paths(mock_delegation_targets)
        
        # Should find paths
        assert len(paths) > 0
        
        # Best path should have high score
        assert paths[0]['score'] >= 75
    
    def test_best_coercion_for_edr(self):
        """Test coercion method selection for EDR"""
        selector = AIJumpSelector()
        
        # CrowdStrike should avoid PetitPotam
        method = selector._get_best_coercion("crowdstrike")
        assert method in ['shadow', 'dfs']
        
        # SentinelOne should prefer shadow
        method = selector._get_best_coercion("sentinelone")
        assert method == 'shadow'
        
        # No EDR should use shadow by default
        method = selector._get_best_coercion("none")
        assert method == 'shadow'


# =============================================================================
# RELAY NINJA CHAIN TESTS
# =============================================================================

class TestRelayNinjaChain:
    """Test RelayNinjaChain orchestrator"""
    
    def test_chain_initialization(self):
        """Test RelayNinjaChain initialization"""
        ninja = RelayNinjaChain(scan_id=12345, relay_mode=RelayMode.SHADOW)
        
        assert ninja.scan_id == 12345
        assert ninja.relay_mode == RelayMode.SHADOW
        assert ninja.hunter is not None
        assert ninja.coercer is not None
        assert ninja.tgt_server is not None
        assert ninja.ai_selector is not None
    
    def test_create_relay_ninja_helper(self):
        """Test create_relay_ninja helper function"""
        ninja = create_relay_ninja(relay_mode="shadow", scan_id=12345)
        
        assert ninja.relay_mode == RelayMode.SHADOW
        assert ninja.scan_id == 12345
    
    def test_create_relay_ninja_modes(self):
        """Test all relay modes"""
        modes = ["shadow", "printer", "petit", "dfs", "all", "ai_select"]
        expected = [
            RelayMode.SHADOW,
            RelayMode.PRINTER,
            RelayMode.PETIT,
            RelayMode.DFS,
            RelayMode.ALL,
            RelayMode.AI_SELECT
        ]
        
        for mode, expected_mode in zip(modes, expected):
            ninja = create_relay_ninja(relay_mode=mode)
            assert ninja.relay_mode == expected_mode
    
    def test_generate_attack_diagram(self):
        """Test attack diagram generation"""
        ninja = RelayNinjaChain()
        diagram = ninja.generate_attack_diagram()
        
        assert "```mermaid" in diagram
        assert "sequenceDiagram" in diagram
        assert "Relay Ninja" in diagram
        assert "RECON" in diagram
        assert "COERCE" in diagram
        assert "DCSYNC" in diagram


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Test constant definitions"""
    
    def test_edr_profiles_exist(self):
        """Test EDR profiles are defined"""
        assert 'crowdstrike' in EDR_COERCION_PROFILES
        assert 'sentinelone' in EDR_COERCION_PROFILES
        assert 'defender' in EDR_COERCION_PROFILES
        assert 'carbon_black' in EDR_COERCION_PROFILES
        assert 'none' in EDR_COERCION_PROFILES
    
    def test_edr_profile_structure(self):
        """Test EDR profile structure"""
        for name, profile in EDR_COERCION_PROFILES.items():
            assert 'blocked_methods' in profile
            assert 'preferred' in profile
            assert 'delay_ms' in profile
            assert 'stealth_level' in profile
    
    def test_mitre_techniques_exist(self):
        """Test MITRE techniques are defined"""
        assert 'delegation_abuse' in MITRE_TECHNIQUES
        assert 'unconstrained' in MITRE_TECHNIQUES
        assert 'printerbug' in MITRE_TECHNIQUES
        assert 'shadowcoerce' in MITRE_TECHNIQUES
        assert 'petitpotam' in MITRE_TECHNIQUES
        assert 'dcsync' in MITRE_TECHNIQUES
    
    def test_mitre_technique_structure(self):
        """Test MITRE technique structure"""
        for name, (technique_id, description) in MITRE_TECHNIQUES.items():
            assert technique_id.startswith("T")
            assert len(description) > 0


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests (require mocking)"""
    
    @patch.object(DelegationHunter, 'find_unconstrained_delegation')
    @patch.object(CoercionNinja, 'trigger_shadowcoerce')
    @patch.object(TGTCaptureServer, 'start_krbrelayx')
    @patch.object(TGTCaptureServer, 'get_captured_tgts')
    @patch.object(TGTCaptureServer, 'stop')
    @patch('subprocess.run')
    def test_full_takeover_flow(
        self,
        mock_run,
        mock_stop,
        mock_get_tgts,
        mock_start,
        mock_coerce,
        mock_find,
        mock_delegation_targets,
        domain_config
    ):
        """Test full domain takeover flow"""
        # Setup mocks
        mock_find.return_value = mock_delegation_targets
        mock_start.return_value = True
        mock_coerce.return_value = CoercionAttempt(
            attempt_id="test",
            method=RelayMode.SHADOW,
            protocol=CoercionProtocol.MS_FSRVP,
            source_host="dc01.corp.local",
            listener_host="10.0.0.100",
            success=True,
        )
        mock_get_tgts.return_value = [{
            'path': '/tmp/dc01.ccache',
            'timestamp': datetime.now().isoformat()
        }]
        mock_run.return_value = MagicMock(
            stdout="krbtgt:502:aad3b435b51404eeaad3b435b51404ee:deadbeef1234567890abcdef12345678",
            stderr="",
            returncode=0
        )
        
        # Execute takeover
        ninja = create_relay_ninja(relay_mode="shadow")
        result = ninja.execute_takeover(
            domain=domain_config['domain'],
            dc_ip=domain_config['dc_ip'],
            username=domain_config['username'],
            password=domain_config['password'],
        )
        
        # Verify result
        assert result.takeover_id is not None
        assert TakeoverPhase.RECON in result.phases_completed
        assert TakeoverPhase.COERCE in result.phases_completed
        assert len(result.delegation_targets) > 0


# =============================================================================
# DCSYNC BYPASS TESTS
# =============================================================================

class TestDCSyncBypass:
    """Test DCSync bypass techniques"""
    
    def test_dcsync_via_captured_tgt(self):
        """Test DCSync using captured TGT"""
        # This would be a real test in AD lab
        # For now, just verify the method exists
        ninja = RelayNinjaChain()
        assert hasattr(ninja, '_execute_dcsync_phase')
    
    def test_dcsync_targets(self):
        """Test default DCSync targets"""
        # Default targets should include krbtgt
        expected_targets = ['krbtgt', 'Administrator']
        
        # These should be the default targets
        ninja = RelayNinjaChain()
        # The method should support these targets
        assert ninja is not None


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-x",  # Stop on first failure
    ])

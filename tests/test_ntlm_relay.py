"""
Tests for NTLM Relay Module
===========================
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import subprocess

from cybermodules.ntlm_relay import (
    CoercionMethod,
    RelayTarget,
    RelayAttack,
    CoercionStatus,
    CoercionAttempt,
    RelaySession,
    NTLMRelayResult,
    NTLMRelayServer,
    NTLMCoercer,
    NTLMRelayChain,
)


# ============================================================
# ENUM TESTS
# ============================================================

class TestEnums:
    """Tests for NTLM relay enums"""
    
    def test_coercion_methods(self):
        """Test CoercionMethod enum"""
        assert CoercionMethod.PETITPOTAM.value == "petitpotam"
        assert CoercionMethod.PRINTERBUG.value == "printerbug"
        assert CoercionMethod.DFSCOERCE.value == "dfscoerce"
        assert CoercionMethod.SHADOWCOERCE.value == "shadowcoerce"
    
    def test_relay_targets(self):
        """Test RelayTarget enum"""
        assert RelayTarget.LDAP.value == "ldap"
        assert RelayTarget.SMB.value == "smb"
        assert RelayTarget.ADCS.value == "adcs"
    
    def test_relay_attacks(self):
        """Test RelayAttack enum"""
        assert RelayAttack.RBCD.value == "rbcd"
        assert RelayAttack.SHADOW_CREDENTIALS.value == "shadow_creds"
        assert RelayAttack.ADCS_ESC8.value == "adcs_esc8"
    
    def test_coercion_status(self):
        """Test CoercionStatus enum"""
        assert CoercionStatus.TRIGGERED.value == "triggered"
        assert CoercionStatus.RELAYED.value == "relayed"
        assert CoercionStatus.BLOCKED.value == "blocked"


# ============================================================
# DATACLASS TESTS
# ============================================================

class TestCoercionAttempt:
    """Tests for CoercionAttempt dataclass"""
    
    def test_attempt_creation(self):
        """Test CoercionAttempt creation"""
        attempt = CoercionAttempt(
            coercion_id="abc123",
            method=CoercionMethod.PETITPOTAM,
            target_host="dc01.corp.local",
            listener_host="192.168.1.100"
        )
        
        assert attempt.coercion_id == "abc123"
        assert attempt.method == CoercionMethod.PETITPOTAM
        assert attempt.status == CoercionStatus.PENDING
    
    def test_attempt_with_captured_hash(self):
        """Test attempt with captured credentials"""
        attempt = CoercionAttempt(
            coercion_id="def456",
            method=CoercionMethod.PRINTERBUG,
            target_host="dc01.corp.local",
            listener_host="192.168.1.100",
            status=CoercionStatus.SUCCESS,
            captured_hash="Administrator::CORP:abc123",
            captured_user="Administrator"
        )
        
        assert attempt.captured_user == "Administrator"
        assert attempt.status == CoercionStatus.SUCCESS


class TestRelaySession:
    """Tests for RelaySession dataclass"""
    
    def test_session_creation(self):
        """Test RelaySession creation"""
        session = RelaySession(
            session_id="sess123",
            source_host="192.168.1.10",
            source_user="CORP\\DC01$",
            target_host="dc01.corp.local",
            target_protocol=RelayTarget.LDAP,
            attack_type=RelayAttack.RBCD
        )
        
        assert session.source_user == "CORP\\DC01$"
        assert session.attack_type == RelayAttack.RBCD


class TestNTLMRelayResult:
    """Tests for NTLMRelayResult dataclass"""
    
    def test_result_creation(self):
        """Test NTLMRelayResult creation"""
        result = NTLMRelayResult(
            relay_id="relay123",
            success=True
        )
        
        assert result.success is True
        assert result.coercion_attempts == []
        assert result.captured_hashes == []
    
    def test_result_to_dict(self):
        """Test result serialization"""
        result = NTLMRelayResult(
            relay_id="relay456",
            success=True,
            compromised_hosts=["host1", "host2"]
        )
        
        data = result.to_dict()
        
        assert data['relay_id'] == "relay456"
        assert data['success'] is True
        assert data['compromised_hosts'] == ["host1", "host2"]


# ============================================================
# NTLM RELAY SERVER TESTS
# ============================================================

class TestNTLMRelayServer:
    """Tests for NTLMRelayServer class"""
    
    def test_server_initialization(self):
        """Test relay server initialization"""
        server = NTLMRelayServer(scan_id=123)
        
        assert server.scan_id == 123
        assert server.relay_process is None
        assert server.running is False
        assert server.sessions == []
        assert server.captured == []
    
    @patch('subprocess.Popen')
    def test_start_ldap_relay(self, mock_popen):
        """Test starting LDAP relay"""
        mock_process = Mock()
        mock_process.stdout = iter([])
        mock_popen.return_value = mock_process
        
        server = NTLMRelayServer()
        success = server.start_relay_to_ldap(
            target_dc="dc01.corp.local",
            attack=RelayAttack.RBCD,
            delegate_to="EVILPC$"
        )
        
        assert success is True
        assert server.running is True
    
    @patch('subprocess.Popen')
    def test_start_smb_relay(self, mock_popen):
        """Test starting SMB relay"""
        mock_process = Mock()
        mock_process.stdout = iter([])
        mock_popen.return_value = mock_process
        
        server = NTLMRelayServer()
        success = server.start_relay_to_smb(
            targets=["192.168.1.10", "192.168.1.11"],
            command="whoami"
        )
        
        assert success is True
    
    @patch('subprocess.Popen')
    def test_start_adcs_relay(self, mock_popen):
        """Test starting AD CS relay"""
        mock_process = Mock()
        mock_process.stdout = iter([])
        mock_popen.return_value = mock_process
        
        server = NTLMRelayServer()
        success = server.start_relay_to_adcs(
            ca_host="ca01.corp.local",
            template="Machine"
        )
        
        assert success is True
    
    def test_stop_server(self):
        """Test stopping relay server"""
        server = NTLMRelayServer()
        server.relay_process = Mock()
        server.running = True
        
        server.stop()
        
        server.relay_process.terminate.assert_called_once()
        assert server.running is False
    
    def test_get_captured_hashes(self):
        """Test getting captured hashes"""
        server = NTLMRelayServer()
        server.captured = [
            {'hash': 'user1::CORP:abc', 'timestamp': '2024-01-01'},
            {'hash': 'user2::CORP:def', 'timestamp': '2024-01-02'}
        ]
        
        hashes = server.get_captured_hashes()
        
        assert len(hashes) == 2
        assert hashes[0]['hash'] == 'user1::CORP:abc'


# ============================================================
# NTLM COERCER TESTS
# ============================================================

class TestNTLMCoercer:
    """Tests for NTLMCoercer class"""
    
    def test_coercer_initialization(self):
        """Test coercer initialization"""
        coercer = NTLMCoercer(scan_id=456)
        
        assert coercer.scan_id == 456
        assert coercer.attempts == []
    
    @patch('subprocess.run')
    def test_petitpotam_success(self, mock_run):
        """Test successful PetitPotam attack"""
        mock_run.return_value = Mock(
            stdout="Attack worked!",
            stderr="",
            returncode=0
        )
        
        coercer = NTLMCoercer()
        attempt = coercer.petitpotam(
            target="dc01.corp.local",
            listener="192.168.1.100"
        )
        
        assert attempt.method == CoercionMethod.PETITPOTAM
        assert attempt.status == CoercionStatus.TRIGGERED
    
    @patch('subprocess.run')
    def test_petitpotam_blocked(self, mock_run):
        """Test blocked PetitPotam attack"""
        mock_run.return_value = Mock(
            stdout="Access denied",
            stderr="",
            returncode=1
        )
        
        coercer = NTLMCoercer()
        attempt = coercer.petitpotam(
            target="dc01.corp.local",
            listener="192.168.1.100"
        )
        
        assert attempt.status == CoercionStatus.BLOCKED
    
    @patch('subprocess.run')
    def test_dfscoerce(self, mock_run):
        """Test DFSCoerce attack"""
        mock_run.return_value = Mock(
            stdout="DFSCoerce triggered!",
            stderr="",
            returncode=0
        )
        
        coercer = NTLMCoercer()
        attempt = coercer.dfscoerce(
            target="dc01.corp.local",
            listener="192.168.1.100"
        )
        
        assert attempt.method == CoercionMethod.DFSCOERCE
    
    @patch('subprocess.run')
    def test_shadowcoerce(self, mock_run):
        """Test ShadowCoerce attack"""
        mock_run.return_value = Mock(
            stdout="ShadowCoerce triggered!",
            stderr="",
            returncode=0
        )
        
        coercer = NTLMCoercer()
        attempt = coercer.shadowcoerce(
            target="dc01.corp.local",
            listener="192.168.1.100"
        )
        
        assert attempt.method == CoercionMethod.SHADOWCOERCE
    
    @patch.object(NTLMCoercer, 'petitpotam')
    @patch.object(NTLMCoercer, 'dfscoerce')
    @patch.object(NTLMCoercer, 'shadowcoerce')
    def test_check_all_methods(self, mock_shadow, mock_dfs, mock_petit):
        """Test checking all coercion methods"""
        mock_petit.return_value = CoercionAttempt(
            coercion_id="1",
            method=CoercionMethod.PETITPOTAM,
            target_host="dc01",
            listener_host="192.168.1.100",
            status=CoercionStatus.TRIGGERED
        )
        mock_dfs.return_value = CoercionAttempt(
            coercion_id="2",
            method=CoercionMethod.DFSCOERCE,
            target_host="dc01",
            listener_host="192.168.1.100",
            status=CoercionStatus.BLOCKED
        )
        mock_shadow.return_value = CoercionAttempt(
            coercion_id="3",
            method=CoercionMethod.SHADOWCOERCE,
            target_host="dc01",
            listener_host="192.168.1.100",
            status=CoercionStatus.FAILED
        )
        
        coercer = NTLMCoercer()
        results = coercer.check_all_methods(
            target="dc01.corp.local",
            listener="192.168.1.100"
        )
        
        assert len(results) == 3
        triggered = [r for r in results if r.status == CoercionStatus.TRIGGERED]
        assert len(triggered) == 1


# ============================================================
# NTLM RELAY CHAIN TESTS
# ============================================================

class TestNTLMRelayChain:
    """Tests for NTLMRelayChain class"""
    
    def test_chain_initialization(self):
        """Test relay chain initialization"""
        chain = NTLMRelayChain(scan_id=789)
        
        assert chain.scan_id == 789
        assert chain.relay_id is not None
        assert chain.relay_server is not None
        assert chain.coercer is not None
    
    def test_generate_attack_diagram(self):
        """Test attack diagram generation"""
        chain = NTLMRelayChain()
        diagram = chain.generate_attack_diagram()
        
        assert "mermaid" in diagram
        assert "Attacker" in diagram
        assert "Relay" in diagram
        assert "NTLM" in diagram
    
    @patch.object(NTLMRelayServer, 'start_relay_to_ldap')
    @patch.object(NTLMCoercer, 'petitpotam')
    @patch.object(NTLMRelayServer, 'get_captured_hashes')
    @patch.object(NTLMRelayServer, 'stop')
    @patch('time.sleep')
    def test_execute_rbcd_attack(self, mock_sleep, mock_stop, mock_hashes, mock_coerce, mock_relay):
        """Test RBCD attack execution"""
        mock_relay.return_value = True
        mock_coerce.return_value = CoercionAttempt(
            coercion_id="1",
            method=CoercionMethod.PETITPOTAM,
            target_host="dc01",
            listener_host="192.168.1.100",
            status=CoercionStatus.TRIGGERED
        )
        mock_hashes.return_value = []
        
        chain = NTLMRelayChain()
        result = chain.execute_rbcd_attack(
            coerce_target="dc01.corp.local",
            dc_target="dc01.corp.local",
            delegate_to="EVILPC$",
            listener_ip="192.168.1.100"
        )
        
        assert result.relay_id is not None
        assert len(result.coercion_attempts) == 1
    
    @patch.object(NTLMRelayServer, 'start_relay_to_adcs')
    @patch.object(NTLMCoercer, 'petitpotam')
    @patch.object(NTLMRelayServer, 'get_captured_hashes')
    @patch.object(NTLMRelayServer, 'stop')
    @patch('time.sleep')
    def test_execute_adcs_relay(self, mock_sleep, mock_stop, mock_hashes, mock_coerce, mock_adcs):
        """Test AD CS relay attack"""
        mock_adcs.return_value = True
        mock_coerce.return_value = CoercionAttempt(
            coercion_id="1",
            method=CoercionMethod.PETITPOTAM,
            target_host="dc01",
            listener_host="192.168.1.100",
            status=CoercionStatus.TRIGGERED
        )
        mock_hashes.return_value = []
        
        chain = NTLMRelayChain()
        result = chain.execute_adcs_relay(
            coerce_target="dc01.corp.local",
            ca_host="ca01.corp.local",
            listener_ip="192.168.1.100"
        )
        
        assert result.relay_id is not None


# ============================================================
# INTEGRATION TESTS
# ============================================================

class TestRelayIntegration:
    """Integration tests for relay module"""
    
    def test_full_workflow(self):
        """Test full relay workflow (mocked)"""
        # This would test the full workflow in an integration environment
        chain = NTLMRelayChain()
        
        # Verify all components are properly connected
        assert chain.relay_server.scan_id == chain.scan_id
        assert chain.coercer.scan_id == chain.scan_id
    
    def test_result_aggregation(self):
        """Test result aggregation"""
        result = NTLMRelayResult(
            relay_id="test",
            success=True
        )
        
        # Add various results
        result.coercion_attempts.append(
            CoercionAttempt(
                coercion_id="1",
                method=CoercionMethod.PETITPOTAM,
                target_host="dc01",
                listener_host="192.168.1.100"
            )
        )
        result.captured_hashes.append({'hash': 'test::hash'})
        result.compromised_hosts.append("dc01.corp.local")
        
        data = result.to_dict()
        
        assert data['coercion_attempts'] == 1
        assert data['captured_hashes'] == 1
        assert "dc01.corp.local" in data['compromised_hosts']

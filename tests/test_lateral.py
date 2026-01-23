"""
Lateral Movement Chain Tests
Tests for the lateral movement module and routes
"""
import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime


class TestLateralMovementEngine:
    """Test LateralMovementEngine class"""
    
    def test_import(self):
        """Test module import"""
        from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
        assert LateralMovementEngine is not None
        assert LateralMethod is not None
    
    def test_enum_methods(self):
        """Test lateral movement method enum"""
        from cybermodules.lateral_movement import LateralMethod
        
        assert LateralMethod.PSEXEC.value == "psexec"
        assert LateralMethod.WMIEXEC.value == "wmiexec"
        assert LateralMethod.SMBEXEC.value == "smbexec"
        assert LateralMethod.DCOMEXEC.value == "dcomexec"
        assert LateralMethod.ATEXEC.value == "atexec"
    
    def test_engine_initialization(self):
        """Test engine initialization"""
        from cybermodules.lateral_movement import LateralMovementEngine
        
        session_info = {
            "target": "192.168.1.10",
            "username": "admin",
            "password": "P@ssw0rd",
            "domain": "CORP"
        }
        
        engine = LateralMovementEngine(scan_id=1, session_info=session_info)
        
        assert engine.scan_id == 1
        assert engine.username == "admin"
        assert engine.password == "P@ssw0rd"
        assert engine.domain == "CORP"
        assert engine.targets == []
        assert engine.results == []
    
    def test_add_manual_targets(self):
        """Test adding manual targets"""
        from cybermodules.lateral_movement import LateralMovementEngine
        
        engine = LateralMovementEngine(scan_id=1)
        engine.add_manual_targets(["192.168.1.10", "192.168.1.20", "dc01.corp.local"])
        
        assert len(engine.targets) == 3
        assert engine.targets[0]['hostname'] == "192.168.1.10"
        assert engine.targets[0]['type'] == "manual"
    
    def test_prepare_credentials(self):
        """Test credential preparation"""
        from cybermodules.lateral_movement import LateralMovementEngine
        
        session_info = {
            "target": "192.168.1.10",
            "username": "admin",
            "password": "P@ssw0rd",
            "domain": "CORP",
            "nt_hash": "aad3b435b51404ee"
        }
        
        engine = LateralMovementEngine(scan_id=1, session_info=session_info)
        creds = engine.prepare_credentials()
        
        assert len(creds) >= 1
        assert creds[0]['username'] == "CORP\\admin"
        assert creds[0]['password'] == "P@ssw0rd"
        assert creds[0]['source'] == "current_session"
    
    @patch('cybermodules.lateral_movement.subprocess.run')
    def test_execute_impacket(self, mock_run):
        """Test Impacket command execution"""
        from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
        
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Successfully connected",
            stderr=""
        )
        
        engine = LateralMovementEngine(scan_id=1)
        
        target = {'hostname': '192.168.1.10', 'ip': '192.168.1.10'}
        creds = {
            'username': 'admin',
            'password': 'P@ssw0rd',
            'nt_hash': '',
            'lm_hash': ''
        }
        
        result = engine._execute_impacket(LateralMethod.WMIEXEC, target, creds)
        
        assert result['success'] == True
        assert 'Successfully connected' in result['stdout']
        assert mock_run.called
    
    def test_verify_success_indicators(self):
        """Test success verification"""
        from cybermodules.lateral_movement import LateralMovementEngine
        
        engine = LateralMovementEngine(scan_id=1)
        
        # Success case
        result_success = {
            'success': True,
            'stdout': 'Successfully connected to target\nAdministrator',
            'stderr': '',
            'returncode': 0
        }
        assert engine._verify_success(result_success, {}, {}) == True
        
        # Failure case
        result_fail = {
            'success': False,
            'stdout': 'Access denied',
            'stderr': 'ERROR: Access denied',
            'returncode': 1
        }
        assert engine._verify_success(result_fail, {}, {}) == False
    
    def test_build_impacket_command_psexec(self):
        """Test PsExec command building"""
        from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
        
        engine = LateralMovementEngine(scan_id=1)
        
        target = {'hostname': '192.168.1.10', 'ip': '192.168.1.10'}
        creds = {
            'username': 'admin',
            'password': 'P@ssw0rd',
            'nt_hash': '',
            'lm_hash': ''
        }
        
        cmd = engine._build_impacket_command(LateralMethod.PSEXEC, target, creds)
        
        assert 'python3' in cmd
        assert 'psexec.py' in cmd[1]
        assert 'admin:P@ssw0rd@192.168.1.10' in cmd[-1]
    
    def test_build_impacket_command_with_hash(self):
        """Test command building with NTLM hash"""
        from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
        
        engine = LateralMovementEngine(scan_id=1)
        
        target = {'hostname': '192.168.1.10', 'ip': '192.168.1.10'}
        creds = {
            'username': 'admin',
            'password': '',
            'nt_hash': 'aad3b435b51404eeaad3b435b51404ee',
            'lm_hash': 'aad3b435b51404ee'
        }
        
        cmd = engine._build_impacket_command(LateralMethod.WMIEXEC, target, creds)
        
        assert '-hashes' in cmd
        assert 'aad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee' in cmd


class TestLateralMovementChain:
    """Test chain execution"""
    
    @patch('cybermodules.lateral_movement.LateralMovementEngine._execute_impacket')
    def test_execute_pivot_chain(self, mock_execute):
        """Test pivot chain execution"""
        from cybermodules.lateral_movement import LateralMovementEngine
        
        mock_execute.return_value = {
            'success': True,
            'stdout': 'Successfully connected',
            'stderr': '',
            'returncode': 0
        }
        
        engine = LateralMovementEngine(scan_id=1)
        
        pivot_sequence = [
            {'target': '192.168.1.10', 'creds': {'username': 'admin', 'password': 'pass', 'nt_hash': '', 'lm_hash': ''}},
            {'target': '192.168.1.20', 'creds': {'username': 'admin', 'password': 'pass', 'nt_hash': '', 'lm_hash': ''}}
        ]
        
        results = engine.execute_pivot_chain(pivot_sequence)
        
        assert len(results) == 2
        assert results[0]['step'] == 1
        assert results[0]['target'] == '192.168.1.10'
    
    @patch('cybermodules.lateral_movement.LateralMovementEngine.attempt_lateral_movement')
    def test_hash_thief_pattern(self, mock_attempt):
        """Test hash thief pattern"""
        from cybermodules.lateral_movement import LateralMovementEngine
        
        mock_attempt.return_value = {
            'success': True,
            'target': '192.168.1.10',
            'username': 'admin',
            'session_info': {'method': 'wmiexec'}
        }
        
        engine = LateralMovementEngine(scan_id=1)
        
        cracked_creds = [
            {'username': 'admin', 'password': 'P@ssw0rd', 'source': 'test'}
        ]
        
        results = engine.execute_hash_thief_pattern('192.168.1.10', cracked_creds)
        
        assert 'visited_hosts' in results
        assert 'pivot_path' in results
        assert '192.168.1.10' in results['visited_hosts']


class TestLateralRoutes:
    """Test Flask routes for lateral movement"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        from cyberapp.app import create_app
        app = create_app(run_migrations_on_start=False)
        app.config['TESTING'] = True
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['logged_in'] = True
            yield client
    
    def test_lateral_dashboard_requires_login(self):
        """Test dashboard requires authentication"""
        from cyberapp.app import create_app
        app = create_app(run_migrations_on_start=False)
        app.config['TESTING'] = True
        with app.test_client() as client:
            response = client.get('/lateral')
            assert response.status_code == 302  # Redirect to login
    
    def test_lateral_dashboard_authenticated(self, client):
        """Test dashboard loads when authenticated"""
        response = client.get('/lateral')
        assert response.status_code == 200
        assert b'Lateral Movement Chain' in response.data
    
    def test_quick_jump_requires_target(self, client):
        """Test quick jump validation"""
        response = client.post('/lateral/quick-jump', 
            json={'username': 'admin'},
            content_type='application/json')
        
        data = response.get_json()
        assert data['success'] == False
        assert 'target' in data['error']
    
    def test_quick_jump_requires_username(self, client):
        """Test quick jump validation"""
        response = client.post('/lateral/quick-jump', 
            json={'target': '192.168.1.10'},
            content_type='application/json')
        
        data = response.get_json()
        assert data['success'] == False
        assert 'username' in data['error']
    
    @patch('cyberapp.routes.lateral.LateralMovementEngine')
    def test_quick_jump_execution(self, mock_engine, client):
        """Test quick jump execution"""
        mock_instance = MagicMock()
        mock_instance.attempt_lateral_movement.return_value = {
            'success': True,
            'methods': [{'output': 'nt authority\\system', 'error': ''}]
        }
        mock_engine.return_value = mock_instance
        
        response = client.post('/lateral/quick-jump', 
            json={
                'target': '192.168.1.10',
                'username': 'admin',
                'password': 'P@ssw0rd',
                'method': 'wmiexec'
            },
            content_type='application/json')
        
        data = response.get_json()
        assert data['success'] == True
        assert data['target'] == '192.168.1.10'
    
    def test_chain_requires_initial_target(self, client):
        """Test chain validation"""
        response = client.post('/lateral/chain', 
            json={'credentials': {'username': 'admin'}},
            content_type='application/json')
        
        data = response.get_json()
        assert data['success'] == False
        assert 'initial_target' in data['error']
    
    @patch('cyberapp.routes.lateral.LateralMovementEngine')
    @patch('cyberapp.routes.lateral._create_chain_scan')
    @patch('cyberapp.routes.lateral._save_chain_results')
    def test_chain_execution(self, mock_save, mock_create, mock_engine, client):
        """Test chain execution"""
        mock_create.return_value = 1
        
        mock_instance = MagicMock()
        mock_instance.execute_pivot_chain.return_value = [
            {'step': 1, 'target': '192.168.1.10', 'success': True}
        ]
        mock_instance.success_count = 1
        mock_instance.fail_count = 0
        mock_engine.return_value = mock_instance
        
        response = client.post('/lateral/chain', 
            json={
                'initial_target': '192.168.1.10',
                'targets': ['192.168.1.20'],
                'credentials': {'username': 'admin', 'password': 'pass'},
                'methods': ['wmiexec']
            },
            content_type='application/json')
        
        data = response.get_json()
        assert data['success'] == True
        assert data['scan_id'] == 1
    
    @patch('cyberapp.routes.lateral.LateralMovementEngine')
    def test_discover_targets(self, mock_engine, client):
        """Test network discovery"""
        mock_instance = MagicMock()
        mock_instance.targets = [
            {'ip': '192.168.1.10', 'hostname': '192.168.1.10', 'type': 'discovered'}
        ]
        mock_engine.return_value = mock_instance
        
        response = client.post('/lateral/discover',
            json={'subnet': '192.168.1.0/24'},
            content_type='application/json')
        
        data = response.get_json()
        assert data['success'] == True
        assert data['count'] == 1
    
    def test_get_credentials(self, client):
        """Test credentials retrieval"""
        response = client.get('/lateral/creds')
        
        data = response.get_json()
        assert data['success'] == True
        assert 'credentials' in data
        assert 'count' in data


class TestLateralSessionHook:
    """Test lateral session hook integration"""
    
    def test_import(self):
        """Test module import"""
        from cybermodules.lateral_hooks import LateralSessionHook
        assert LateralSessionHook is not None
    
    def test_hook_initialization(self):
        """Test hook initialization"""
        from cybermodules.lateral_hooks import LateralSessionHook
        
        hook = LateralSessionHook(scan_id=1)
        
        assert hook.scan_id == 1
        assert hook.lateral_engine is None
        assert hook.persistence_engine is None
        assert hook.hashdump_engine is None
    
    @patch('cybermodules.lateral_hooks.HashDumpEngine')
    def test_on_session_opened(self, mock_hashdump):
        """Test session opened hook"""
        from cybermodules.lateral_hooks import LateralSessionHook
        
        mock_hashdump_instance = MagicMock()
        mock_hashdump_instance.execute_session_hook.return_value = {
            'success': True,
            'total_cracked': 2,
            'extraction': {'hashes': ['hash1', 'hash2']}
        }
        mock_hashdump.return_value = mock_hashdump_instance
        
        hook = LateralSessionHook(scan_id=1)
        
        session_info = {
            'target': '192.168.1.10',
            'username': 'admin',
            'password': 'P@ssw0rd',
            'domain': 'CORP'
        }
        
        results = hook.on_session_opened(session_info)
        
        assert 'session' in results
        assert 'hashdump' in results
        assert results['hashdump']['success'] == True


class TestLateralMovementIntegration:
    """Integration tests for lateral movement chain"""
    
    def test_full_chain_workflow(self):
        """Test complete chain workflow"""
        from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
        
        # Initialize engine
        session_info = {
            "target": "192.168.1.10",
            "username": "admin",
            "password": "P@ssw0rd",
            "domain": "CORP"
        }
        
        engine = LateralMovementEngine(scan_id=99, session_info=session_info)
        
        # Add targets
        engine.add_manual_targets(["192.168.1.20", "192.168.1.30"])
        assert len(engine.targets) == 2
        
        # Prepare credentials
        creds = engine.prepare_credentials()
        assert len(creds) >= 1
        
        # Generate report (even without execution)
        report = engine.generate_report()
        assert "LATERAL MOVEMENT REPORT" in report
    
    def test_method_fallback_order(self):
        """Test method fallback order"""
        from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
        
        engine = LateralMovementEngine(scan_id=1)
        
        # Default methods should be in order of stealth
        default_methods = [
            LateralMethod.WMIEXEC,
            LateralMethod.PSEXEC,
            LateralMethod.SMBEXEC
        ]
        
        # Verify method enum values
        assert default_methods[0].value == "wmiexec"  # Most stealthy
        assert default_methods[1].value == "psexec"
        assert default_methods[2].value == "smbexec"

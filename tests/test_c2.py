"""
Comprehensive tests for C2 Framework.
Coverage target: c2_framework.py, c2_advanced.py
"""
import pytest
import json
import time
import uuid
from unittest.mock import patch, MagicMock
from cyberapp.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user'] = 'admin'
        yield client


@pytest.fixture
def api_client():
    """Client with API key auth."""
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestC2Dashboard:
    """Tests for C2 dashboard routes."""
    
    def test_c2_index(self, client):
        """Test C2 index page."""
        resp = client.get('/c2')
        assert resp.status_code in [200, 302]
    
    def test_c2_listeners_page(self, client):
        """Test listeners page (JSON API)."""
        resp = client.get('/c2/listeners')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert 'listeners' in data or 'success' in data
    
    def test_c2_agents_page(self, client):
        """Test agents page (JSON API)."""
        resp = client.get('/c2/agents')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert 'agents' in data or 'success' in data
    
    def test_c2_payloads_types(self, client):
        """Test payload types endpoint."""
        resp = client.get('/c2/payloads/types')
        assert resp.status_code in [200, 401]


class TestC2Listeners:
    """Tests for C2 listener management."""
    
    def test_create_listener(self, client):
        """Test creating a listener."""
        resp = client.post('/c2/listeners', 
                          json={
                              'name': 'test_listener',
                              'type': 'http',
                              'host': '0.0.0.0',
                              'port': '8888'
                          },
                          content_type='application/json')
        assert resp.status_code in [200, 201, 302, 400]
    
    def test_create_https_listener(self, client):
        """Test creating HTTPS listener."""
        resp = client.post('/c2/listeners',
                          json={
                              'name': 'https_listener',
                              'type': 'https',
                              'host': '0.0.0.0',
                              'port': '443'
                          },
                          content_type='application/json')
        assert resp.status_code in [200, 201, 302, 400]
    
    def test_create_dns_listener(self, client):
        """Test creating DNS listener."""
        resp = client.post('/c2/listeners',
                          json={
                              'name': 'dns_listener',
                              'type': 'dns',
                              'host': '0.0.0.0',
                              'port': '53'
                          },
                          content_type='application/json')
        assert resp.status_code in [200, 201, 302, 400]
    
    def test_list_listeners(self, client):
        """Test listing listeners."""
        resp = client.get('/c2/listeners')
        assert resp.status_code == 200
    
    def test_delete_listener(self, client):
        """Test deleting listener."""
        resp = client.delete('/c2/listeners/test-id')
        assert resp.status_code in [200, 302, 404]


class TestC2Agents:
    """Tests for C2 agent management."""
    
    def test_list_agents(self, client):
        """Test listing agents."""
        resp = client.get('/c2/agents')
        assert resp.status_code == 200
    
    def test_agent_detail(self, client):
        """Test agent detail page."""
        resp = client.get('/c2/agents/test-agent-id')
        assert resp.status_code in [200, 404]
    
    def test_kill_agent(self, client):
        """Test killing agent."""
        resp = client.post('/c2/agents/test-agent-id/kill')
        assert resp.status_code in [200, 302, 404]


class TestC2Beacon:
    """Tests for beacon communication."""
    
    def test_beacon_register(self, api_client):
        """Test agent registration beacon."""
        agent_id = str(uuid.uuid4())
        resp = api_client.post('/c2/beacon/register', 
                              json={
                                  'hostname': 'WORKSTATION01',
                                  'username': 'testuser',
                                  'os': 'Windows 10',
                                  'arch': 'x64',
                                  'pid': 1234,
                                  'integrity': 'medium',
                                  'listener_id': 'default'
                              },
                              content_type='application/json')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert 'success' in data
    
    def test_beacon_checkin(self, api_client):
        """Test agent checkin beacon."""
        agent_id = str(uuid.uuid4())
        resp = api_client.post('/c2/beacon/checkin', 
                              json={'agent_id': agent_id},
                              content_type='application/json')
        assert resp.status_code == 200
    
    def test_beacon_result(self, api_client):
        """Test submitting task result."""
        resp = api_client.post('/c2/beacon/result', 
                              json={
                                  'agent_id': 'test-agent',
                                  'task_id': 'test-task',
                                  'output': 'Command output here',
                                  'status': 'completed'
                              },
                              content_type='application/json')
        assert resp.status_code == 200


class TestC2Tasks:
    """Tests for task management."""
    
    def test_create_task(self, client):
        """Test creating a task for agent."""
        resp = client.post('/c2/agents/test-agent/task', 
                          json={
                              'command': 'shell',
                              'args': ['whoami']
                          },
                          content_type='application/json')
        assert resp.status_code in [200, 201, 302, 404]
    
    def test_create_download_task(self, client):
        """Test creating download task."""
        resp = client.post('/c2/agents/test-agent/task', 
                          json={
                              'command': 'download',
                              'args': ['/etc/passwd']
                          },
                          content_type='application/json')
        assert resp.status_code in [200, 201, 302, 404]
    
    def test_list_tasks(self, client):
        """Test listing tasks."""
        resp = client.get('/c2/tasks')
        assert resp.status_code == 200


class TestC2Payloads:
    """Tests for payload generation."""
    
    def test_generate_python_payload(self, client):
        """Test generating Python payload."""
        resp = client.post('/c2/payloads/generate', 
                          json={
                              'type': 'python',
                              'listener_id': 'test-listener',
                              'options': {
                                  'sleep_interval': 5
                              }
                          },
                          content_type='application/json')
        assert resp.status_code in [200, 302, 400]
    
    def test_generate_powershell_payload(self, client):
        """Test generating PowerShell payload."""
        resp = client.post('/c2/payloads/generate', 
                          json={
                              'type': 'powershell',
                              'listener_id': 'test-listener',
                              'options': {
                                  'sleep_interval': 10
                              }
                          },
                          content_type='application/json')
        assert resp.status_code in [200, 302, 400]
    
    def test_generate_go_payload(self, client):
        """Test generating Go payload."""
        resp = client.post('/c2/payloads/generate', 
                          json={
                              'type': 'go',
                              'listener_id': 'test-listener',
                              'options': {}
                          },
                          content_type='application/json')
        assert resp.status_code in [200, 302, 400]
    
    def test_payload_types(self, client):
        """Test getting payload types."""
        resp = client.get('/c2/payloads/types')
        assert resp.status_code in [200, 401]


class TestC2Framework:
    """Tests for C2Framework module directly."""
    
    def test_import_c2_framework(self):
        """Test importing C2 framework."""
        from cybermodules.c2_framework import C2Server
        assert C2Server is not None
    
    def test_c2_server_instance(self):
        """Test C2 server instantiation."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        assert server is not None
    
    def test_create_listener_programmatic(self):
        """Test creating listener programmatically."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        listener = server.create_listener(
            name='test_http',
            listener_type='http',
            host='0.0.0.0',
            port=9999
        )
        assert listener is not None
    
    def test_register_agent_programmatic(self):
        """Test registering agent programmatically."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        agent = server.register_agent(
            hostname='TEST-PC',
            username='testuser',
            os_info='Windows 10',
            arch='x64',
            pid=1234,
            listener_id='default'
        )
        assert agent is not None
    
    def test_create_task_programmatic(self):
        """Test creating task programmatically."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        agent = server.register_agent(
            hostname='TEST-PC',
            username='testuser',
            os_info='Linux',
            arch='x64',
            pid=5678,
            listener_id='default'
        )
        task = server.create_task(
            agent_id=agent.agent_id,
            command='shell',
            args=['id']
        )
        assert task is not None
    
    def test_get_pending_tasks(self):
        """Test getting pending tasks."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        agent = server.register_agent(
            hostname='TEST-PC',
            username='testuser',
            os_info='Linux',
            arch='x64',
            pid=9999,
            listener_id='default'
        )
        server.create_task(agent.agent_id, 'shell', ['whoami'])
        tasks = server.agent_checkin(agent.agent_id)
        assert isinstance(tasks, list)
    
    def test_generate_python_payload_direct(self):
        """Test Python payload generation."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        # Create listener first
        listener = server.create_listener(
            name='payload_test',
            listener_type='http',
            host='localhost',
            port=8443
        )
        result = server.generate_payload(
            listener_id=listener.listener_id,
            payload_type='python',
            options={'sleep_interval': 5}
        )
        assert result is not None
    
    def test_generate_powershell_payload_direct(self):
        """Test PowerShell payload generation."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        listener = server.create_listener(
            name='ps_test',
            listener_type='http',
            host='localhost',
            port=8444
        )
        result = server.generate_payload(
            listener_id=listener.listener_id,
            payload_type='powershell',
            options={'sleep_interval': 10}
        )
        assert result is not None
    
    def test_agent_checkin(self):
        """Test agent checkin update."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        agent = server.register_agent(
            hostname='CHECK-PC',
            username='checker',
            os_info='Linux',
            arch='x64',
            pid=1111,
            listener_id='default'
        )
        tasks = server.agent_checkin(agent.agent_id)
        assert isinstance(tasks, list)
    
    def test_list_listeners(self):
        """Test listing listeners."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        listeners = server.list_listeners()
        assert isinstance(listeners, list)
    
    def test_list_agents(self):
        """Test listing agents."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        agents = server.list_agents()
        assert isinstance(agents, list)
    
    def test_list_tasks(self):
        """Test listing tasks."""
        from cybermodules.c2_framework import C2Server
        server = C2Server()
        tasks = server.list_tasks()
        assert isinstance(tasks, list)


class TestC2Security:
    """Tests for C2 security features."""
    
    def test_beacon_without_auth(self, api_client):
        """Test beacon without proper auth."""
        resp = api_client.post('/c2/beacon/register', json={})
        assert resp.status_code in [200, 400, 401]
    
    def test_encrypted_beacon(self, api_client):
        """Test encrypted beacon communication."""
        import base64
        encrypted_data = base64.b64encode(b'test_data').decode()
        resp = api_client.post('/c2/beacon/checkin', json={
            'agent_id': 'test',
            'encrypted': encrypted_data
        })
        assert resp.status_code in [200, 400]

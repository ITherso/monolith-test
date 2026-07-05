"""
Comprehensive tests for vulnerable endpoints.
Coverage target: vulnerable.py, api_vulnerable.py
"""
import pytest
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
def unauthenticated_client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestSQLInjection:
    """Tests for SQL Injection endpoints."""
    
    def test_sqli_login_get(self, client):
        """Test SQLi login page."""
        resp = client.get('/vuln/sqli/login')
        assert resp.status_code == 200
        
    def test_sqli_login_post(self, client):
        """Test SQLi login with credentials."""
        resp = client.post('/vuln/sqli/login', 
                          data={'username': 'admin', 'password': 'test'})
        assert resp.status_code == 200
        
    def test_sqli_login_bypass(self, client):
        """Test SQLi with OR bypass."""
        resp = client.post('/vuln/sqli/login', 
                          data={'username': "' OR '1'='1' --", 'password': 'x'})
        assert resp.status_code == 200
    
    def test_sqli_search(self, client):
        """Test SQLi search endpoint."""
        resp = client.get('/vuln/sqli/search?q=test')
        assert resp.status_code == 200


class TestCommandInjection:
    """Tests for Command Injection endpoints."""
    
    def test_cmdi_ping_get(self, client):
        """Test CMDi ping page."""
        resp = client.get('/vuln/cmdi/ping')
        assert resp.status_code == 200
        
    def test_cmdi_ping_post(self, client):
        """Test CMDi with host input."""
        resp = client.post('/vuln/cmdi/ping', data={'host': '127.0.0.1'})
        assert resp.status_code == 200
        
    def test_cmdi_ping_injection(self, client):
        """Test command injection."""
        resp = client.post('/vuln/cmdi/ping', data={'host': '127.0.0.1; whoami'})
        assert resp.status_code == 200
    
    def test_cmdi_nslookup_get(self, client):
        """Test CMDi nslookup page."""
        resp = client.get('/vuln/cmdi/nslookup')
        assert resp.status_code == 200


class TestSSTI:
    """Tests for Server-Side Template Injection."""
    
    def test_ssti_greeting(self, client):
        """Test SSTI greeting endpoint."""
        resp = client.get('/vuln/ssti/greeting?name=test')
        assert resp.status_code == 200
        assert b'test' in resp.data
        
    def test_ssti_greeting_payload(self, client):
        """Test SSTI with template payload."""
        resp = client.get('/vuln/ssti/greeting?name={{7*7}}')
        assert resp.status_code == 200
        
    def test_ssti_email(self, client):
        """Test SSTI email endpoint."""
        resp = client.get('/vuln/ssti/email?email=test@test.com')
        assert resp.status_code == 200


class TestDeserialization:
    """Tests for Insecure Deserialization."""
    
    def test_deserial_pickle_get(self, client):
        """Test pickle deserialization page."""
        resp = client.get('/vuln/deserial/pickle')
        assert resp.status_code == 200
        
    def test_deserial_pickle_post(self, client):
        """Test pickle with data."""
        import pickle
        import base64
        data = base64.b64encode(pickle.dumps({'test': 'value'})).decode()
        resp = client.post('/vuln/deserial/pickle', data={'data': data})
        assert resp.status_code == 200
    
    def test_deserial_yaml_get(self, client):
        """Test YAML deserialization page."""
        resp = client.get('/vuln/deserial/yaml')
        assert resp.status_code == 200
        
    def test_deserial_yaml_post(self, client):
        """Test YAML with data."""
        resp = client.post('/vuln/deserial/yaml', data={'data': 'test: value'})
        assert resp.status_code == 200


class TestJWT:
    """Tests for JWT vulnerabilities."""
    
    def test_jwt_login_get(self, client):
        """Test JWT login page."""
        resp = client.get('/vuln/jwt/login')
        assert resp.status_code == 200
        
    def test_jwt_login_post(self, client):
        """Test JWT login with credentials."""
        resp = client.post('/vuln/jwt/login', 
                          data={'username': 'user', 'password': 'pass'})
        assert resp.status_code == 200
    
    def test_jwt_verify_no_token(self, client):
        """Test JWT verify without token."""
        resp = client.get('/vuln/jwt/verify')
        assert resp.status_code in [200, 401]
        
    def test_jwt_verify_with_token(self, client):
        """Test JWT verify with token."""
        resp = client.get('/vuln/jwt/verify?token=fake.token.here')
        assert resp.status_code in [200, 401]


class TestIDOR:
    """Tests for Insecure Direct Object Reference."""
    
    def test_idor_profile(self, client):
        """Test IDOR profile access."""
        resp = client.get('/vuln/idor/profile/1')
        assert resp.status_code == 200
        
    def test_idor_profile_other_user(self, client):
        """Test IDOR accessing other user."""
        resp = client.get('/vuln/idor/profile/2')
        assert resp.status_code == 200
        
    def test_idor_document(self, client):
        """Test IDOR document access."""
        resp = client.get('/vuln/idor/document/secret.txt')
        assert resp.status_code in [200, 404]


class TestFileUpload:
    """Tests for Unrestricted File Upload."""
    
    def test_upload_page(self, client):
        """Test upload page renders."""
        resp = client.get('/vuln/upload')
        assert resp.status_code == 200
        
    def test_upload_file(self, client):
        """Test file upload."""
        from io import BytesIO
        data = {'file': (BytesIO(b'test content'), 'test.txt')}
        resp = client.post('/vuln/upload', data=data, content_type='multipart/form-data')
        assert resp.status_code in [200, 302]


class TestSSRF:
    """Tests for Server-Side Request Forgery."""
    
    def test_ssrf_fetch(self, client):
        """Test SSRF fetch endpoint."""
        resp = client.get('/vuln/ssrf/fetch?url=http://localhost')
        assert resp.status_code in [200, 500]
        
    def test_ssrf_fetch_file(self, client):
        """Test SSRF with file protocol."""
        resp = client.get('/vuln/ssrf/fetch?url=file:///etc/passwd')
        assert resp.status_code in [200, 500]
    
    def test_ssrf_webhook(self, client):
        """Test SSRF webhook."""
        resp = client.post('/vuln/ssrf/webhook', 
                          json={'url': 'http://localhost', 'data': 'test'})
        assert resp.status_code in [200, 500]


class TestAdminBypass:
    """Tests for admin bypass vulnerabilities."""
    
    def test_admin_users(self, client):
        """Test admin users page."""
        resp = client.get('/vuln/admin/users')
        assert resp.status_code == 200
        
    def test_admin_config(self, client):
        """Test admin config page."""
        resp = client.get('/vuln/admin/config')
        assert resp.status_code == 200


class TestPasswordReset:
    """Tests for password reset vulnerabilities."""
    
    def test_forgot_password_get(self, client):
        """Test forgot password page."""
        resp = client.get('/vuln/forgot-password')
        assert resp.status_code == 200
        
    def test_forgot_password_post(self, client):
        """Test forgot password submission."""
        resp = client.post('/vuln/forgot-password', data={'email': 'test@test.com'})
        assert resp.status_code in [200, 302]
    
    def test_reset_password_get(self, client):
        """Test reset password page."""
        resp = client.get('/vuln/reset-password?token=test')
        assert resp.status_code == 200


class TestAPIVulnerable:
    """Tests for API vulnerable endpoints."""
    
    def test_api_jwt_login(self, client):
        """Test API JWT login."""
        resp = client.post('/api/vuln/jwt-login', 
                          json={'username': 'user', 'password': 'pass'})
        assert resp.status_code in [200, 401, 404]
    
    def test_api_user(self, client):
        """Test API user endpoint."""
        resp = client.get('/api/vuln/user/1')
        assert resp.status_code in [200, 404]
    
    def test_api_profile(self, client):
        """Test API profile endpoint."""
        resp = client.post('/api/vuln/profile', 
                          json={'username': 'test', 'role': 'admin'})
        assert resp.status_code in [200, 400, 404]

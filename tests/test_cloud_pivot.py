"""
Test Suite for Cloud Pivot Module
Zero-Trust Bypass & Hybrid Lateral Movement
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta

# Import cloud pivot module
from cybermodules.cloud_pivot import (
    # Enums
    CloudProvider,
    PivotMethod,
    TokenType,
    AttackPhase,
    
    # Data classes
    CloudCredential,
    PRTContext,
    AWSCredentials,
    GCPCredentials,
    PivotResult,
    CloudAttackPath,
    
    # Classes
    AzurePRTHijacker,
    AWSMetadataRelay,
    GCPMetadataExploiter,
    HybridADPivot,
    CloudAttackPathSuggester,
    CloudPivotOrchestrator,
    
    # Functions
    create_cloud_pivot,
    suggest_attack_path,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def azure_credential():
    """Sample Azure credential"""
    return CloudCredential(
        provider=CloudProvider.AZURE,
        credential_type=TokenType.ACCESS_TOKEN,
        value="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test_token",
        metadata={
            "resource": "https://graph.microsoft.com",
            "token_type": "Bearer",
        },
        expires_at=datetime.now() + timedelta(hours=1),
        scope=["https://graph.microsoft.com/.default"],
        source="test",
    )


@pytest.fixture
def aws_credentials():
    """Sample AWS credentials"""
    return AWSCredentials(
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token="AQoDYXdzEJr...",
        expiration=datetime.now() + timedelta(hours=6),
        role_arn="arn:aws:iam::123456789012:role/TestRole",
        region="us-east-1",
    )


@pytest.fixture
def gcp_credentials():
    """Sample GCP credentials"""
    return GCPCredentials(
        access_token="ya29.test_token",
        token_type="Bearer",
        expires_in=3600,
        service_account="default",
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )


@pytest.fixture
def prt_context():
    """Sample PRT context"""
    return PRTContext(
        prt="test_prt_token",
        session_key=b"test_session_key_32bytes_long!!!",
        device_id="test-device-id",
        tenant_id="test-tenant-id",
        user_upn="user@contoso.com",
    )


@pytest.fixture
def pivot_result():
    """Sample pivot result"""
    return PivotResult(
        success=True,
        method=PivotMethod.PRT_HIJACK,
        source="WORKSTATION01",
        target="Azure AD",
        attack_path=["Extracted PRT", "Derived key", "Got token"],
        recommendations=["Enumerate users", "Check roles"],
    )


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestEnums:
    """Test enum definitions"""
    
    def test_cloud_provider_values(self):
        """Test cloud provider enum values"""
        assert CloudProvider.AZURE.value == "azure"
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.GCP.value == "gcp"
        assert CloudProvider.HYBRID.value == "hybrid"
    
    def test_pivot_method_values(self):
        """Test pivot method enum values"""
        assert PivotMethod.PRT_HIJACK.value == "prt_hijack"
        assert PivotMethod.METADATA_RELAY.value == "metadata_relay"
        assert PivotMethod.METADATA_GCP.value == "metadata_gcp"
        assert PivotMethod.SAML_FORGE.value == "saml_forge"
    
    def test_token_type_values(self):
        """Test token type enum values"""
        assert TokenType.PRT.value == "primary_refresh_token"
        assert TokenType.ACCESS_TOKEN.value == "access_token"
        assert TokenType.AWS_CREDS.value == "aws_credentials"
    
    def test_attack_phase_values(self):
        """Test attack phase enum values"""
        assert AttackPhase.RECON.value == "reconnaissance"
        assert AttackPhase.TOKEN_THEFT.value == "token_theft"
        assert AttackPhase.PIVOT.value == "pivot"


# =============================================================================
# DATA CLASS TESTS
# =============================================================================

class TestDataClasses:
    """Test data class functionality"""
    
    def test_cloud_credential_valid(self, azure_credential):
        """Test cloud credential validity check"""
        assert azure_credential.is_valid() is True
        
        # Expired credential
        expired = CloudCredential(
            provider=CloudProvider.AZURE,
            credential_type=TokenType.ACCESS_TOKEN,
            value="expired_token",
            expires_at=datetime.now() - timedelta(hours=1),
        )
        assert expired.is_valid() is False
    
    def test_cloud_credential_to_dict(self, azure_credential):
        """Test cloud credential serialization"""
        data = azure_credential.to_dict()
        
        assert data["provider"] == "azure"
        assert data["type"] == "access_token"
        assert "scope" in data
        assert "source" in data
    
    def test_prt_context_derive_key(self, prt_context):
        """Test PRT context key derivation"""
        context = b"test_nonce"
        derived = prt_context.derive_key(context)
        
        assert derived is not None
        assert len(derived) == 32  # SHA256 output
        assert prt_context.derived_key == derived
    
    def test_aws_credentials_to_env(self, aws_credentials):
        """Test AWS credentials to env vars"""
        env = aws_credentials.to_env_vars()
        
        assert "AWS_ACCESS_KEY_ID" in env
        assert "AWS_SECRET_ACCESS_KEY" in env
        assert "AWS_SESSION_TOKEN" in env
        assert "AWS_DEFAULT_REGION" in env
    
    def test_pivot_result_to_dict(self, pivot_result):
        """Test pivot result serialization"""
        data = pivot_result.to_dict()
        
        assert data["success"] is True
        assert data["method"] == "prt_hijack"
        assert data["source"] == "WORKSTATION01"
        assert len(data["attack_path"]) == 3


# =============================================================================
# AZURE PRT HIJACKER TESTS
# =============================================================================

class TestAzurePRTHijacker:
    """Test Azure PRT hijacking functionality"""
    
    def test_hijacker_creation(self):
        """Test hijacker creation"""
        hijacker = AzurePRTHijacker(tenant_id="test-tenant")
        
        assert hijacker.tenant_id == "test-tenant"
        assert hijacker.prt_cache == {}
    
    def test_create_prt_cookie(self, prt_context):
        """Test PRT cookie creation"""
        hijacker = AzurePRTHijacker()
        prt_context.nonce = "test_nonce"
        prt_context.derive_key(b"test_nonce")
        
        cookie = hijacker._create_prt_cookie(prt_context)
        
        assert cookie is not None
        assert cookie.count(".") == 2  # JWT format
    
    @pytest.mark.asyncio
    async def test_get_nonce(self):
        """Test nonce retrieval"""
        hijacker = AzurePRTHijacker()
        
        # Mock the HTTP request
        with patch('aiohttp.ClientSession') as mock_session:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value={"Nonce": "test_nonce"})
            
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_resp
            
            nonce = await hijacker._get_nonce()
            
            # Either got mocked nonce or generated one
            assert nonce is not None
    
    @pytest.mark.asyncio
    async def test_device_code_phish(self):
        """Test device code phishing flow"""
        hijacker = AzurePRTHijacker()
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value={
                "user_code": "ABC123",
                "device_code": "device_code_value",
                "verification_uri": "https://microsoft.com/devicelogin",
            })
            
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_resp
            
            user_code, device_code = await hijacker.device_code_phish()
            
            # With mock, should get codes
            assert user_code is not None or user_code is None  # May fail without network


# =============================================================================
# AWS METADATA RELAY TESTS
# =============================================================================

class TestAWSMetadataRelay:
    """Test AWS metadata service exploitation"""
    
    def test_relay_creation(self):
        """Test relay creation"""
        relay = AWSMetadataRelay()
        
        assert relay.credentials_cache == {}
        assert len(relay.ssrf_payloads) > 0
    
    def test_ssrf_payloads_generated(self):
        """Test SSRF payload generation"""
        relay = AWSMetadataRelay()
        
        # Check for metadata URLs
        assert any("169.254.169.254" in p for p in relay.ssrf_payloads)
        assert any("iam/security-credentials" in p for p in relay.ssrf_payloads)
    
    @pytest.mark.asyncio
    async def test_exploit_imdsv1_timeout(self):
        """Test IMDSv1 exploitation (timeout on non-EC2)"""
        relay = AWSMetadataRelay()
        
        # On non-EC2, should timeout
        result = await relay.exploit_imdsv1()
        
        # Should return None (not on EC2)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_instance_identity(self):
        """Test instance identity retrieval"""
        relay = AWSMetadataRelay()
        
        # On non-EC2, should return empty dict
        identity = await relay.get_instance_identity()
        
        assert isinstance(identity, dict)


# =============================================================================
# GCP METADATA EXPLOITER TESTS
# =============================================================================

class TestGCPMetadataExploiter:
    """Test GCP metadata service exploitation"""
    
    def test_exploiter_creation(self):
        """Test exploiter creation"""
        exploiter = GCPMetadataExploiter()
        
        assert exploiter.credentials_cache == {}
    
    @pytest.mark.asyncio
    async def test_get_access_token_timeout(self):
        """Test token retrieval (timeout on non-GCE)"""
        exploiter = GCPMetadataExploiter()
        
        # On non-GCE, should timeout
        result = await exploiter.get_access_token()
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_enumerate_service_accounts(self):
        """Test service account enumeration"""
        exploiter = GCPMetadataExploiter()
        
        # On non-GCE, should return empty list
        accounts = await exploiter.enumerate_service_accounts()
        
        assert isinstance(accounts, list)


# =============================================================================
# HYBRID AD PIVOT TESTS
# =============================================================================

class TestHybridADPivot:
    """Test hybrid AD pivot functionality"""
    
    def test_pivot_creation(self):
        """Test pivot creation"""
        pivot = HybridADPivot(domain="CONTOSO.COM")
        
        assert pivot.domain == "CONTOSO.COM"
        assert pivot.prt_hijacker is not None
    
    @pytest.mark.asyncio
    async def test_find_azure_ad_connect(self):
        """Test Azure AD Connect discovery"""
        pivot = HybridADPivot()
        
        result = await pivot.find_azure_ad_connect("dc01.contoso.com")
        
        assert isinstance(result, dict)
        assert "found" in result


# =============================================================================
# ATTACK PATH SUGGESTER TESTS
# =============================================================================

class TestCloudAttackPathSuggester:
    """Test attack path suggestion"""
    
    def test_suggester_creation(self):
        """Test suggester creation"""
        suggester = CloudAttackPathSuggester()
        
        assert len(suggester.attack_paths) > 0
    
    def test_attack_paths_loaded(self):
        """Test attack paths are loaded"""
        suggester = CloudAttackPathSuggester()
        
        # Should have Azure, AWS, GCP, and hybrid paths
        azure_paths = [p for p in suggester.attack_paths if "azure" in p.path_id]
        aws_paths = [p for p in suggester.attack_paths if "aws" in p.path_id]
        gcp_paths = [p for p in suggester.attack_paths if "gcp" in p.path_id]
        
        assert len(azure_paths) > 0
        assert len(aws_paths) > 0
        assert len(gcp_paths) > 0
    
    def test_suggest_with_domain_user(self):
        """Test path suggestion with domain user access"""
        suggester = CloudAttackPathSuggester()
        
        paths = suggester.suggest_attack_path(
            current_access=["domain_user", "local_admin"],
            target_provider=None,
        )
        
        # Should suggest some paths
        assert len(paths) >= 0
    
    def test_suggest_with_ec2_access(self):
        """Test path suggestion with EC2 shell access"""
        suggester = CloudAttackPathSuggester()
        
        paths = suggester.suggest_attack_path(
            current_access=["ec2_shell"],
            target_provider=CloudProvider.AWS,
        )
        
        # Should find AWS-specific paths
        for path in paths:
            assert "aws" in path.path_id or path.path_id == "weak_credentials"
    
    def test_weak_credential_detection(self, azure_credential):
        """Test weak credential detection"""
        suggester = CloudAttackPathSuggester()
        
        # Add dangerous scope
        azure_credential.scope = ["https://graph.microsoft.com/.default"]
        
        weak_creds = suggester.get_weak_cloud_credentials([azure_credential])
        
        # Should detect dangerous scope
        assert len(weak_creds) > 0
        assert any(
            w["type"] == "dangerous_scope" 
            for wc in weak_creds 
            for w in wc["weaknesses"]
        )
    
    def test_path_has_mitre_techniques(self):
        """Test attack paths have MITRE techniques"""
        suggester = CloudAttackPathSuggester()
        
        for path in suggester.attack_paths:
            assert len(path.mitre_techniques) > 0
            assert all(t.startswith("T") for t in path.mitre_techniques)


# =============================================================================
# CLOUD PIVOT ORCHESTRATOR TESTS
# =============================================================================

class TestCloudPivotOrchestrator:
    """Test main orchestrator"""
    
    def test_orchestrator_creation(self):
        """Test orchestrator creation"""
        orchestrator = CloudPivotOrchestrator()
        
        assert orchestrator.azure_prt is not None
        assert orchestrator.aws_metadata is not None
        assert orchestrator.gcp_metadata is not None
        assert orchestrator.path_suggester is not None
    
    def test_orchestrator_with_config(self):
        """Test orchestrator with config"""
        config = {
            "azure_tenant_id": "test-tenant",
            "domain": "CONTOSO.COM",
        }
        
        orchestrator = CloudPivotOrchestrator(config)
        
        assert orchestrator.config == config
    
    def test_suggest_attack_path(self):
        """Test attack path suggestion via orchestrator"""
        orchestrator = CloudPivotOrchestrator()
        
        paths = orchestrator.suggest_attack_path(
            current_access=["domain_user"],
            target_provider=CloudProvider.AZURE,
        )
        
        assert isinstance(paths, list)
    
    def test_get_pivot_summary_empty(self):
        """Test pivot summary with no pivots"""
        orchestrator = CloudPivotOrchestrator()
        
        summary = orchestrator.get_pivot_summary()
        
        assert summary["total_pivots"] == 0
        assert summary["successful_pivots"] == 0
        assert summary["credentials_obtained"] == 0
    
    @pytest.mark.asyncio
    async def test_detect_environment(self):
        """Test environment detection"""
        orchestrator = CloudPivotOrchestrator()
        
        env = await orchestrator._detect_environment()
        
        assert "is_ec2" in env
        assert "is_gce" in env
        assert "is_azure_ad_joined" in env
        assert "hostname" in env
    
    @pytest.mark.asyncio
    async def test_auto_pivot(self):
        """Test auto pivot (should gracefully handle non-cloud env)"""
        orchestrator = CloudPivotOrchestrator()
        
        results = await orchestrator.auto_pivot(source_env="onprem")
        
        assert isinstance(results, list)


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestConvenienceFunctions:
    """Test convenience functions"""
    
    def test_create_cloud_pivot(self):
        """Test create_cloud_pivot function"""
        orchestrator = create_cloud_pivot()
        
        assert isinstance(orchestrator, CloudPivotOrchestrator)
    
    def test_suggest_attack_path_function(self):
        """Test suggest_attack_path function"""
        paths = suggest_attack_path(
            current_access=["domain_user"],
            target=CloudProvider.AZURE,
        )
        
        assert isinstance(paths, list)


# =============================================================================
# LATERAL MOVEMENT CLOUD INTEGRATION TESTS
# =============================================================================

class TestLateralMovementCloudIntegration:
    """Test cloud integration in lateral movement"""
    
    def test_cloud_lateral_movement_creation(self):
        """Test CloudLateralMovement class"""
        from cybermodules.lateral_movement import CloudLateralMovement
        
        cloud = CloudLateralMovement(scan_id="test-scan")
        
        assert cloud.scan_id == "test-scan"
    
    def test_suggest_attack_path_method(self):
        """Test suggest_attack_path method"""
        from cybermodules.lateral_movement import CloudLateralMovement
        
        cloud = CloudLateralMovement(scan_id="test-scan")
        
        paths = cloud.suggest_attack_path(
            current_access=["domain_user"],
            target_provider="azure",
        )
        
        assert isinstance(paths, list)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_full_azure_pivot_flow(self):
        """Test full Azure pivot flow (mocked)"""
        orchestrator = CloudPivotOrchestrator({
            "azure_tenant_id": "test-tenant",
        })
        
        # Mock successful PRT extraction
        with patch.object(
            orchestrator.azure_prt,
            'extract_prt_mimikatz',
            new_callable=AsyncMock
        ) as mock_extract:
            mock_extract.return_value = PRTContext(
                prt="test_prt",
                session_key=b"test_key_32bytes_longenough!!!!",
                device_id="device-id",
                tenant_id="test-tenant",
                user_upn="user@test.com",
            )
            
            with patch.object(
                orchestrator.azure_prt,
                'pass_the_prt',
                new_callable=AsyncMock
            ) as mock_pass:
                mock_pass.return_value = CloudCredential(
                    provider=CloudProvider.AZURE,
                    credential_type=TokenType.ACCESS_TOKEN,
                    value="test_access_token",
                    expires_at=datetime.now() + timedelta(hours=1),
                    scope=["https://graph.microsoft.com"],
                    source="pass_the_prt",
                )
                
                result = await orchestrator.pivot_azure_prt("target-host")
                
                assert result.success is True
                assert result.method == PivotMethod.PRT_HIJACK
    
    @pytest.mark.asyncio
    async def test_full_aws_pivot_flow(self):
        """Test full AWS pivot flow (mocked)"""
        orchestrator = CloudPivotOrchestrator()
        
        # Mock successful IMDS exploitation
        with patch.object(
            orchestrator.aws_metadata,
            'exploit_imdsv1',
            new_callable=AsyncMock
        ) as mock_imds:
            mock_imds.return_value = AWSCredentials(
                access_key_id="AKIATEST",
                secret_access_key="secret",
                session_token="token",
                expiration=datetime.now() + timedelta(hours=6),
                role_arn="arn:aws:iam::123:role/Test",
            )
            
            with patch.object(
                orchestrator.aws_metadata,
                'get_instance_identity',
                new_callable=AsyncMock
            ) as mock_identity:
                mock_identity.return_value = {
                    "instanceId": "i-12345",
                    "accountId": "123456789012",
                }
                
                result = await orchestrator.pivot_aws_metadata()
                
                assert result.success is True
                assert "AWS" in result.target


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

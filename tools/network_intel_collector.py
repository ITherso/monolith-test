#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  NETWORK INTELLIGENCE COLLECTOR                                              ║
║  Advanced Network Reconnaissance & Intelligence Gathering                    ║
║  Shodan • Censys • BGP/AS • DNS • SSL/TLS • CDN Detection                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Features:
- Passive reconnaissance (Shodan, Censys, VirusTotal)
- BGP/ASN intelligence gathering
- DNS enumeration and analysis
- SSL/TLS certificate intelligence
- CDN origin IP detection
- Subnet discovery and mapping
- WHOIS and domain intelligence
- Threat intelligence correlation

Author: CyberGhost Pro Team
Version: 2.0.0
"""

import os
import sys
import json
import socket
import ssl
import requests
import dns.resolver
import dns.zone
import dns.query
import whois
import ipaddress
import hashlib
import sqlite3
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import logging
import subprocess
import re

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NetworkIntelligence")


# ============================================================================
# ENUMS & CONSTANTS
# ============================================================================

class IntelSource(Enum):
    """Intelligence sources"""
    SHODAN = "shodan"
    CENSYS = "censys"
    VIRUSTOTAL = "virustotal"
    THREATCROWD = "threatcrowd"
    SECURITYTRAILS = "securitytrails"
    BGPVIEW = "bgpview"
    ALIENVAULT = "alienvault"
    DNS = "dns"
    WHOIS = "whois"
    SSL_TLS = "ssl_tls"
    PASSIVE_DNS = "passive_dns"


class AssetType(Enum):
    """Asset types"""
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    SUBNET = "subnet"
    ASN = "asn"
    SSL_CERT = "ssl_certificate"
    SERVICE = "service"
    CDN_ORIGIN = "cdn_origin"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class NetworkAsset:
    """Network asset information"""
    asset_id: str
    asset_type: AssetType
    value: str
    
    # Discovery information
    discovered_via: IntelSource
    discovered_at: datetime = field(default_factory=datetime.now)
    
    # Metadata
    organization: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None
    as_name: Optional[str] = None
    
    # Additional data
    ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    
    # SSL/TLS info
    ssl_cert_hash: Optional[str] = None
    ssl_issuer: Optional[str] = None
    ssl_subject: Optional[str] = None
    
    # CDN info
    is_behind_cdn: bool = False
    cdn_provider: Optional[str] = None
    origin_ips: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_score: float = 0.0
    threat_indicators: List[str] = field(default_factory=list)
    
    # Raw data
    raw_data: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        d = asdict(self)
        d['asset_type'] = self.asset_type.value
        d['discovered_via'] = self.discovered_via.value
        d['discovered_at'] = self.discovered_at.isoformat()
        return d


@dataclass
class IntelligenceReport:
    """Intelligence collection report"""
    report_id: str
    target: str
    
    # Assets discovered
    assets: List[NetworkAsset] = field(default_factory=list)
    total_assets: int = 0
    
    # Statistics
    total_ips: int = 0
    total_domains: int = 0
    total_subdomains: int = 0
    total_services: int = 0
    total_vulnerabilities: int = 0
    
    # Intelligence sources used
    sources_used: List[IntelSource] = field(default_factory=list)
    
    # Timing
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Metadata
    created_by: str = "system"


# ============================================================================
# NETWORK INTELLIGENCE COLLECTOR
# ============================================================================

class NetworkIntelligenceCollector:
    """Main network intelligence collection class"""
    
    def __init__(self, db_path: str = "/tmp/network_intel.db"):
        self.db_path = db_path
        self.api_keys = self._load_api_keys()
        self._init_database()
        
        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Assets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                asset_type TEXT,
                value TEXT,
                discovered_via TEXT,
                discovered_at TEXT,
                organization TEXT,
                country TEXT,
                asn INTEGER,
                ports JSON,
                services JSON,
                vulnerabilities JSON,
                raw_data JSON
            )
        """)
        
        # Intelligence reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                target TEXT,
                total_assets INTEGER,
                sources_used JSON,
                created_at TEXT,
                completed_at TEXT
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_asset_type ON assets(asset_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_value ON assets(value)")
        
        conn.commit()
        conn.close()
    
    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from environment or config"""
        return {
            'shodan': os.getenv('SHODAN_API_KEY', ''),
            'censys_id': os.getenv('CENSYS_API_ID', ''),
            'censys_secret': os.getenv('CENSYS_API_SECRET', ''),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'securitytrails': os.getenv('SECURITYTRAILS_API_KEY', ''),
        }
    
    # ========================================================================
    # MAIN COLLECTION METHODS
    # ========================================================================
    
    def collect_intelligence(self, target: str, 
                           sources: Optional[List[IntelSource]] = None) -> str:
        """
        Collect network intelligence for target
        
        Args:
            target: Domain, IP, or subnet
            sources: Intelligence sources to use (None = all available)
        
        Returns:
            report_id: Intelligence report ID
        """
        report_id = f"intel_{hashlib.md5(target.encode()).hexdigest()[:12]}"
        
        report = IntelligenceReport(
            report_id=report_id,
            target=target,
            started_at=datetime.now()
        )
        
        # Determine target type
        target_type = self._determine_target_type(target)
        
        logger.info(f"[*] Starting intelligence collection for {target} (type: {target_type})")
        
        # Collect from various sources
        if sources is None:
            sources = [IntelSource.DNS, IntelSource.WHOIS, IntelSource.SSL_TLS]
            if self.api_keys.get('shodan'):
                sources.append(IntelSource.SHODAN)
            if self.api_keys.get('censys_id'):
                sources.append(IntelSource.CENSYS)
            if self.api_keys.get('virustotal'):
                sources.append(IntelSource.VIRUSTOTAL)
        
        report.sources_used = sources
        
        # Collect from each source
        for source in sources:
            try:
                assets = self._collect_from_source(target, target_type, source)
                report.assets.extend(assets)
                logger.info(f"[+] {source.value}: {len(assets)} assets discovered")
            except Exception as e:
                logger.error(f"[!] {source.value} collection failed: {e}")
        
        # Process and enrich assets
        report.assets = self._enrich_assets(report.assets)
        
        # Calculate statistics
        report.total_assets = len(report.assets)
        report.total_ips = sum(1 for a in report.assets if a.asset_type == AssetType.IP_ADDRESS)
        report.total_domains = sum(1 for a in report.assets if a.asset_type == AssetType.DOMAIN)
        report.total_services = sum(len(a.services) for a in report.assets)
        report.total_vulnerabilities = sum(len(a.vulnerabilities) for a in report.assets)
        
        # Complete report
        report.completed_at = datetime.now()
        report.duration_seconds = (report.completed_at - report.started_at).total_seconds()
        
        # Save to database
        self._save_report(report)
        
        logger.info(f"[✓] Intelligence collection completed: {report.total_assets} assets")
        
        return report_id
    
    def _determine_target_type(self, target: str) -> str:
        """Determine if target is IP, domain, or subnet"""
        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            pass
        
        try:
            ipaddress.ip_network(target, strict=False)
            return "subnet"
        except ValueError:
            pass
        
        return "domain"
    
    def _collect_from_source(self, target: str, target_type: str, 
                            source: IntelSource) -> List[NetworkAsset]:
        """Collect intelligence from specific source"""
        if source == IntelSource.SHODAN:
            return self._collect_shodan(target, target_type)
        elif source == IntelSource.CENSYS:
            return self._collect_censys(target, target_type)
        elif source == IntelSource.VIRUSTOTAL:
            return self._collect_virustotal(target, target_type)
        elif source == IntelSource.DNS:
            return self._collect_dns(target, target_type)
        elif source == IntelSource.WHOIS:
            return self._collect_whois(target, target_type)
        elif source == IntelSource.SSL_TLS:
            return self._collect_ssl_tls(target, target_type)
        elif source == IntelSource.BGPVIEW:
            return self._collect_bgp(target, target_type)
        else:
            return []
    
    # ========================================================================
    # SHODAN INTELLIGENCE
    # ========================================================================
    
    def _collect_shodan(self, target: str, target_type: str) -> List[NetworkAsset]:
        """Collect intelligence from Shodan"""
        if not self.api_keys.get('shodan'):
            logger.warning("[!] Shodan API key not configured")
            return []
        
        assets = []
        
        try:
            import shodan
            api = shodan.Shodan(self.api_keys['shodan'])
            
            if target_type == "ip":
                # IP lookup
                host = api.host(target)
                asset = self._parse_shodan_host(host)
                if asset:
                    assets.append(asset)
            
            elif target_type == "domain":
                # Domain search
                results = api.search(f'hostname:{target}')
                for result in results['matches']:
                    asset = self._parse_shodan_host(result)
                    if asset:
                        assets.append(asset)
        
        except Exception as e:
            logger.error(f"[!] Shodan collection failed: {e}")
        
        return assets
    
    def _parse_shodan_host(self, host: Dict) -> Optional[NetworkAsset]:
        """Parse Shodan host data"""
        try:
            asset = NetworkAsset(
                asset_id=f"shodan_{host.get('ip_str', '')}",
                asset_type=AssetType.IP_ADDRESS,
                value=host.get('ip_str', ''),
                discovered_via=IntelSource.SHODAN,
                organization=host.get('org', ''),
                country=host.get('country_code', ''),
                asn=host.get('asn'),
                ports=host.get('ports', []),
                raw_data=host
            )
            
            # Extract services
            for service in host.get('data', []):
                service_str = f"{service.get('product', 'unknown')} {service.get('version', '')}"
                asset.services.append(service_str.strip())
                
                # Check for vulnerabilities
                if 'vulns' in service:
                    asset.vulnerabilities.extend(service['vulns'].keys())
            
            return asset
        
        except Exception as e:
            logger.error(f"Failed to parse Shodan host: {e}")
            return None
    
    # ========================================================================
    # CENSYS INTELLIGENCE
    # ========================================================================
    
    def _collect_censys(self, target: str, target_type: str) -> List[NetworkAsset]:
        """Collect intelligence from Censys"""
        if not self.api_keys.get('censys_id'):
            logger.warning("[!] Censys API credentials not configured")
            return []
        
        assets = []
        
        try:
            # Censys API v2
            auth = (self.api_keys['censys_id'], self.api_keys['censys_secret'])
            
            if target_type == "ip":
                url = f"https://search.censys.io/api/v2/hosts/{target}"
                response = requests.get(url, auth=auth, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    asset = self._parse_censys_host(data)
                    if asset:
                        assets.append(asset)
            
            elif target_type == "domain":
                url = "https://search.censys.io/api/v2/hosts/search"
                params = {'q': f'services.http.response.html_title:*{target}*'}
                response = requests.get(url, auth=auth, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    for hit in data.get('result', {}).get('hits', []):
                        asset = self._parse_censys_host(hit)
                        if asset:
                            assets.append(asset)
        
        except Exception as e:
            logger.error(f"[!] Censys collection failed: {e}")
        
        return assets
    
    def _parse_censys_host(self, host: Dict) -> Optional[NetworkAsset]:
        """Parse Censys host data"""
        try:
            asset = NetworkAsset(
                asset_id=f"censys_{host.get('ip', '')}",
                asset_type=AssetType.IP_ADDRESS,
                value=host.get('ip', ''),
                discovered_via=IntelSource.CENSYS,
                asn=host.get('autonomous_system', {}).get('asn'),
                as_name=host.get('autonomous_system', {}).get('name'),
                country=host.get('location', {}).get('country_code'),
                raw_data=host
            )
            
            # Extract services
            for service in host.get('services', []):
                port = service.get('port')
                if port:
                    asset.ports.append(port)
                
                service_name = service.get('service_name', 'unknown')
                asset.services.append(f"{service_name}:{port}")
            
            return asset
        
        except Exception as e:
            logger.error(f"Failed to parse Censys host: {e}")
            return None
    
    # ========================================================================
    # VIRUSTOTAL INTELLIGENCE
    # ========================================================================
    
    def _collect_virustotal(self, target: str, target_type: str) -> List[NetworkAsset]:
        """Collect intelligence from VirusTotal"""
        if not self.api_keys.get('virustotal'):
            logger.warning("[!] VirusTotal API key not configured")
            return []
        
        assets = []
        
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            if target_type == "domain":
                url = f"https://www.virustotal.com/api/v3/domains/{target}"
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract subdomains
                    subdomains_url = f"{url}/subdomains"
                    sub_response = requests.get(subdomains_url, headers=headers, timeout=10)
                    
                    if sub_response.status_code == 200:
                        sub_data = sub_response.json()
                        for subdomain in sub_data.get('data', []):
                            asset = NetworkAsset(
                                asset_id=f"vt_{subdomain.get('id', '')}",
                                asset_type=AssetType.DOMAIN,
                                value=subdomain.get('id', ''),
                                discovered_via=IntelSource.VIRUSTOTAL,
                                raw_data=subdomain
                            )
                            assets.append(asset)
            
            elif target_type == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    asset = NetworkAsset(
                        asset_id=f"vt_{target}",
                        asset_type=AssetType.IP_ADDRESS,
                        value=target,
                        discovered_via=IntelSource.VIRUSTOTAL,
                        country=data.get('data', {}).get('attributes', {}).get('country'),
                        asn=data.get('data', {}).get('attributes', {}).get('asn'),
                        raw_data=data
                    )
                    assets.append(asset)
        
        except Exception as e:
            logger.error(f"[!] VirusTotal collection failed: {e}")
        
        return assets
    
    # ========================================================================
    # DNS INTELLIGENCE
    # ========================================================================
    
    def _collect_dns(self, target: str, target_type: str) -> List[NetworkAsset]:
        """Collect DNS intelligence"""
        assets = []
        
        if target_type != "domain":
            return assets
        
        try:
            # A records
            try:
                answers = self.resolver.resolve(target, 'A')
                for rdata in answers:
                    asset = NetworkAsset(
                        asset_id=f"dns_a_{str(rdata)}",
                        asset_type=AssetType.IP_ADDRESS,
                        value=str(rdata),
                        discovered_via=IntelSource.DNS,
                        raw_data={'record_type': 'A', 'domain': target}
                    )
                    assets.append(asset)
            except Exception:
                pass
            
            # AAAA records
            try:
                answers = self.resolver.resolve(target, 'AAAA')
                for rdata in answers:
                    asset = NetworkAsset(
                        asset_id=f"dns_aaaa_{str(rdata)}",
                        asset_type=AssetType.IP_ADDRESS,
                        value=str(rdata),
                        discovered_via=IntelSource.DNS,
                        raw_data={'record_type': 'AAAA', 'domain': target}
                    )
                    assets.append(asset)
            except Exception:
                pass
            
            # MX records
            try:
                answers = self.resolver.resolve(target, 'MX')
                for rdata in answers:
                    mx_domain = str(rdata.exchange).rstrip('.')
                    asset = NetworkAsset(
                        asset_id=f"dns_mx_{mx_domain}",
                        asset_type=AssetType.DOMAIN,
                        value=mx_domain,
                        discovered_via=IntelSource.DNS,
                        raw_data={'record_type': 'MX', 'priority': rdata.preference}
                    )
                    assets.append(asset)
            except Exception:
                pass
            
            # NS records
            try:
                answers = self.resolver.resolve(target, 'NS')
                for rdata in answers:
                    ns_domain = str(rdata).rstrip('.')
                    asset = NetworkAsset(
                        asset_id=f"dns_ns_{ns_domain}",
                        asset_type=AssetType.DOMAIN,
                        value=ns_domain,
                        discovered_via=IntelSource.DNS,
                        raw_data={'record_type': 'NS'}
                    )
                    assets.append(asset)
            except Exception:
                pass
            
            # TXT records (SPF, DMARC, etc.)
            try:
                answers = self.resolver.resolve(target, 'TXT')
                for rdata in answers:
                    txt_value = str(rdata).strip('"')
                    # Extract domains from SPF records
                    if 'v=spf1' in txt_value:
                        includes = re.findall(r'include:([^\s]+)', txt_value)
                        for inc_domain in includes:
                            asset = NetworkAsset(
                                asset_id=f"dns_spf_{inc_domain}",
                                asset_type=AssetType.DOMAIN,
                                value=inc_domain,
                                discovered_via=IntelSource.DNS,
                                raw_data={'record_type': 'SPF', 'txt': txt_value}
                            )
                            assets.append(asset)
            except Exception:
                pass
            
            # Subdomain enumeration (common subdomains)
            common_subdomains = [
                'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
                'api', 'dev', 'staging', 'test', 'admin',
                'portal', 'vpn', 'remote', 'cdn', 'static'
            ]
            
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{target}"
                    answers = self.resolver.resolve(full_domain, 'A')
                    if answers:
                        asset = NetworkAsset(
                            asset_id=f"dns_subdomain_{full_domain}",
                            asset_type=AssetType.DOMAIN,
                            value=full_domain,
                            discovered_via=IntelSource.DNS,
                            raw_data={'parent_domain': target}
                        )
                        assets.append(asset)
                except Exception:
                    pass
        
        except Exception as e:
            logger.error(f"[!] DNS collection failed: {e}")
        
        return assets
    
    # ========================================================================
    # WHOIS INTELLIGENCE
    # ========================================================================
    
    def _collect_whois(self, target: str, target_type: str) -> List[NetworkAsset]:
        """Collect WHOIS intelligence"""
        assets = []
        
        try:
            w = whois.whois(target)
            
            # Extract email addresses
            emails = w.get('emails', [])
            if isinstance(emails, str):
                emails = [emails]
            
            # Extract name servers
            name_servers = w.get('name_servers', [])
            if isinstance(name_servers, str):
                name_servers = [name_servers]
            
            for ns in name_servers:
                if ns:
                    asset = NetworkAsset(
                        asset_id=f"whois_ns_{ns}",
                        asset_type=AssetType.DOMAIN,
                        value=ns.lower(),
                        discovered_via=IntelSource.WHOIS,
                        organization=w.get('org', ''),
                        raw_data={'whois': dict(w)}
                    )
                    assets.append(asset)
        
        except Exception as e:
            logger.error(f"[!] WHOIS collection failed: {e}")
        
        return assets
    
    # ========================================================================
    # SSL/TLS INTELLIGENCE
    # ========================================================================
    
    def _collect_ssl_tls(self, target: str, target_type: str) -> List[NetworkAsset]:
        """Collect SSL/TLS certificate intelligence"""
        assets = []
        
        if target_type != "domain":
            return assets
        
        try:
            # Get SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate information
                    subject = dict(x[0] for x in cert.get('subject', ()))
                    issuer = dict(x[0] for x in cert.get('issuer', ()))
                    
                    # Extract alternative names
                    san = cert.get('subjectAltName', ())
                    for typ, value in san:
                        if typ == 'DNS':
                            asset = NetworkAsset(
                                asset_id=f"ssl_san_{value}",
                                asset_type=AssetType.DOMAIN,
                                value=value,
                                discovered_via=IntelSource.SSL_TLS,
                                ssl_subject=subject.get('commonName', ''),
                                ssl_issuer=issuer.get('commonName', ''),
                                raw_data={'certificate': cert}
                            )
                            assets.append(asset)
        
        except Exception as e:
            logger.debug(f"SSL/TLS collection failed: {e}")
        
        return assets
    
    # ========================================================================
    # BGP/ASN INTELLIGENCE
    # ========================================================================
    
    def _collect_bgp(self, target: str, target_type: str) -> List[NetworkAsset]:
        """Collect BGP/ASN intelligence"""
        assets = []
        
        if target_type != "ip":
            return assets
        
        try:
            # Use BGPView API (free, no key required)
            url = f"https://api.bgpview.io/ip/{target}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract prefixes
                for prefix_data in data.get('data', {}).get('prefixes', []):
                    prefix = prefix_data.get('prefix', '')
                    if prefix:
                        asset = NetworkAsset(
                            asset_id=f"bgp_prefix_{prefix.replace('/', '_')}",
                            asset_type=AssetType.SUBNET,
                            value=prefix,
                            discovered_via=IntelSource.BGPVIEW,
                            asn=prefix_data.get('asn', {}).get('asn'),
                            as_name=prefix_data.get('asn', {}).get('name'),
                            country=prefix_data.get('asn', {}).get('country_code'),
                            raw_data=prefix_data
                        )
                        assets.append(asset)
        
        except Exception as e:
            logger.error(f"[!] BGP collection failed: {e}")
        
        return assets
    
    # ========================================================================
    # ASSET ENRICHMENT
    # ========================================================================
    
    def _enrich_assets(self, assets: List[NetworkAsset]) -> List[NetworkAsset]:
        """Enrich assets with additional intelligence"""
        enriched = []
        
        for asset in assets:
            try:
                # CDN detection
                if asset.asset_type == AssetType.DOMAIN:
                    asset.is_behind_cdn, asset.cdn_provider = self._detect_cdn(asset.value)
                    
                    # If behind CDN, try to find origin
                    if asset.is_behind_cdn:
                        asset.origin_ips = self._find_cdn_origin(asset.value)
                
                # Risk scoring
                asset.risk_score = self._calculate_risk_score(asset)
                
                enriched.append(asset)
            
            except Exception as e:
                logger.debug(f"Asset enrichment failed: {e}")
                enriched.append(asset)
        
        return enriched
    
    def _detect_cdn(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Detect if domain is behind CDN"""
        cdn_patterns = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'Akamai': ['akamai', 'akamaihd'],
            'Fastly': ['fastly'],
            'AWS CloudFront': ['cloudfront'],
            'Azure CDN': ['azureedge'],
            'Google Cloud CDN': ['googleusercontent'],
        }
        
        try:
            response = requests.head(f"https://{domain}", timeout=5, allow_redirects=True)
            headers = response.headers
            
            for cdn_name, patterns in cdn_patterns.items():
                for pattern in patterns:
                    if any(pattern.lower() in str(v).lower() for v in headers.values()):
                        return True, cdn_name
            
            # Check CNAME
            try:
                answers = self.resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata).lower()
                    for cdn_name, patterns in cdn_patterns.items():
                        for pattern in patterns:
                            if pattern in cname:
                                return True, cdn_name
            except Exception:
                pass
        
        except Exception:
            pass
        
        return False, None
    
    def _find_cdn_origin(self, domain: str) -> List[str]:
        """Try to find origin IP behind CDN"""
        origin_ips = []
        
        # Try common origin subdomains
        origin_subdomains = [
            f'origin.{domain}',
            f'direct.{domain}',
            f'origin-{domain}',
            domain.replace('www.', 'origin.')
        ]
        
        for subdomain in origin_subdomains:
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                for rdata in answers:
                    origin_ips.append(str(rdata))
            except Exception:
                pass
        
        return list(set(origin_ips))
    
    def _calculate_risk_score(self, asset: NetworkAsset) -> float:
        """Calculate risk score for asset"""
        score = 0.0
        
        # Vulnerabilities add risk
        score += len(asset.vulnerabilities) * 10
        
        # Open ports add risk
        high_risk_ports = [21, 22, 23, 3389, 445, 135]
        score += sum(5 for p in asset.ports if p in high_risk_ports)
        
        # Behind CDN reduces risk (harder to attack origin)
        if asset.is_behind_cdn:
            score *= 0.7
        
        # Normalize to 0-100
        return min(score, 100.0)
    
    # ========================================================================
    # DATABASE OPERATIONS
    # ========================================================================
    
    def _save_report(self, report: IntelligenceReport):
        """Save intelligence report to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Save report
        cursor.execute("""
            INSERT OR REPLACE INTO reports (report_id, target, total_assets, sources_used, created_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            report.report_id,
            report.target,
            report.total_assets,
            json.dumps([s.value for s in report.sources_used]),
            report.started_at.isoformat(),
            report.completed_at.isoformat() if report.completed_at else None
        ))
        
        # Save assets
        for asset in report.assets:
            cursor.execute("""
                INSERT OR REPLACE INTO assets (asset_id, asset_type, value, discovered_via, discovered_at, organization, country, asn, ports, services, vulnerabilities, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                asset.asset_id,
                asset.asset_type.value,
                asset.value,
                asset.discovered_via.value,
                asset.discovered_at.isoformat(),
                asset.organization,
                asset.country,
                asset.asn,
                json.dumps(asset.ports),
                json.dumps(asset.services),
                json.dumps(asset.vulnerabilities),
                json.dumps(asset.raw_data)
            ))
        
        conn.commit()
        conn.close()
    
    # ========================================================================
    # PUBLIC API
    # ========================================================================
    
    def get_report(self, report_id: str) -> Optional[Dict]:
        """Get intelligence report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM reports WHERE report_id = ?", (report_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        # Get assets
        cursor.execute("SELECT * FROM assets WHERE asset_id LIKE ?", (f"{report_id}%",))
        asset_rows = cursor.fetchall()
        
        conn.close()
        
        return {
            'report_id': row[0],
            'target': row[1],
            'total_assets': row[2],
            'sources_used': json.loads(row[3]),
            'created_at': row[4],
            'completed_at': row[5],
            'assets': len(asset_rows)
        }
    
    def get_assets(self, report_id: str, asset_type: Optional[AssetType] = None) -> List[Dict]:
        """Get assets from report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if asset_type:
            cursor.execute("""
                SELECT * FROM assets 
                WHERE asset_id LIKE ? AND asset_type = ?
            """, (f"%{report_id.split('_')[1]}%", asset_type.value))
        else:
            cursor.execute("""
                SELECT * FROM assets 
                WHERE asset_id LIKE ?
            """, (f"%{report_id.split('_')[1]}%",))
        
        rows = cursor.fetchall()
        conn.close()
        
        assets = []
        for row in rows:
            assets.append({
                'asset_id': row[0],
                'asset_type': row[1],
                'value': row[2],
                'discovered_via': row[3],
                'organization': row[5],
                'country': row[6],
                'asn': row[7],
                'ports': json.loads(row[8]) if row[8] else [],
                'services': json.loads(row[9]) if row[9] else [],
                'vulnerabilities': json.loads(row[10]) if row[10] else []
            })
        
        return assets
    
    def export_report(self, report_id: str, format: str = "json") -> str:
        """Export intelligence report"""
        report = self.get_report(report_id)
        if not report:
            return json.dumps({"error": "Report not found"})
        
        assets = self.get_assets(report_id)
        report['assets'] = assets
        
        if format == "json":
            return json.dumps(report, indent=2)
        elif format == "html":
            return self._generate_html_report(report)
        else:
            return json.dumps(report)
    
    def _generate_html_report(self, report: Dict) -> str:
        """Generate HTML intelligence report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Intelligence Report - {report['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #0a0e27; color: #fff; }}
        h1 {{ color: #00d4ff; }}
        .summary {{ background: #1a1f3a; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .asset {{ border: 1px solid #2a3f5f; padding: 10px; margin: 10px 0; border-radius: 5px; background: #151929; }}
        .asset-type {{ color: #00d4ff; font-weight: bold; }}
        .vulnerability {{ color: #ff4444; }}
        .service {{ color: #44ff44; }}
    </style>
</head>
<body>
    <h1>Network Intelligence Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Target:</strong> {report['target']}</p>
        <p><strong>Total Assets:</strong> {report['total_assets']}</p>
        <p><strong>Sources Used:</strong> {', '.join(report['sources_used'])}</p>
        <p><strong>Generated:</strong> {report['created_at']}</p>
    </div>
    
    <h2>Discovered Assets</h2>
"""
        
        for asset in report['assets']:
            html += f"""
    <div class="asset">
        <p><span class="asset-type">{asset['asset_type']}</span>: {asset['value']}</p>
        <p><strong>Discovered via:</strong> {asset['discovered_via']}</p>
        {f"<p><strong>Organization:</strong> {asset['organization']}</p>" if asset.get('organization') else ''}
        {f"<p><strong>ASN:</strong> {asset['asn']}</p>" if asset.get('asn') else ''}
        {f"<p><strong>Ports:</strong> {', '.join(map(str, asset['ports']))}</p>" if asset.get('ports') else ''}
        {f"<p class='service'><strong>Services:</strong> {', '.join(asset['services'])}</p>" if asset.get('services') else ''}
        {f"<p class='vulnerability'><strong>Vulnerabilities:</strong> {', '.join(asset['vulnerabilities'])}</p>" if asset.get('vulnerabilities') else ''}
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        return html


# ============================================================================
# SINGLETON & API
# ============================================================================

_network_intel = None

def get_network_intel() -> NetworkIntelligenceCollector:
    """Get network intelligence collector singleton"""
    global _network_intel
    if _network_intel is None:
        _network_intel = NetworkIntelligenceCollector()
    return _network_intel


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Intelligence Collector")
    parser.add_argument("target", help="Target domain, IP, or subnet")
    parser.add_argument("--output", help="Output file (JSON or HTML)")
    parser.add_argument("--sources", nargs="+", help="Intelligence sources to use")
    
    args = parser.parse_args()
    
    # Initialize collector
    collector = get_network_intel()
    
    # Parse sources
    sources = None
    if args.sources:
        source_map = {
            'shodan': IntelSource.SHODAN,
            'censys': IntelSource.CENSYS,
            'virustotal': IntelSource.VIRUSTOTAL,
            'dns': IntelSource.DNS,
            'whois': IntelSource.WHOIS,
            'ssl': IntelSource.SSL_TLS,
            'bgp': IntelSource.BGPVIEW
        }
        sources = [source_map[s] for s in args.sources if s in source_map]
    
    # Collect intelligence
    print(f"[*] Starting intelligence collection for {args.target}")
    report_id = collector.collect_intelligence(args.target, sources)
    
    # Get report
    report = collector.get_report(report_id)
    print(f"\n[✓] Intelligence collection completed!")
    print(f"    Total assets discovered: {report['total_assets']}")
    print(f"    Sources used: {', '.join(report['sources_used'])}")
    
    # Export if requested
    if args.output:
        format = "html" if args.output.endswith(".html") else "json"
        content = collector.export_report(report_id, format)
        
        with open(args.output, 'w') as f:
            f.write(content)
        
        print(f"\n[+] Report exported to {args.output}")

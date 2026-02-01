"""
SOC Deception & Honey Pot Poisoning
- Fake honeypot deploy (decoy servers)
- False flag events (ransomware, exfil)
- AI deception pattern generation
"""

from flask import Blueprint, request, jsonify
import random

soc_deception_bp = Blueprint('soc_deception', __name__)

# Simulated SOC deception logic
class SOCDeception:
    def __init__(self):
        self.events = []

    def deploy_honeypot(self, name):
        event = {'type': 'honeypot', 'name': name, 'status': 'deployed'}
        self.events.append(event)
        return event

    def false_flag(self, flag_type):
        event = {'type': 'false_flag', 'flag': flag_type, 'result': 'triggered'}
        self.events.append(event)
        return event

    def ai_deception(self):
        pattern = random.choice([
            'SOC Analyst Fatigue',
            'AI-generated Decoy Traffic',
            'Fake Ransomware Alert',
            'Phantom Exfiltration',
            'Decoy Credential Leak'
        ])
        event = {'type': 'ai_deception', 'pattern': pattern}
        self.events.append(event)
        return event

    def summary(self):
        return {'events': self.events}

soc_deception = SOCDeception()

@soc_deception_bp.route('/api/soc_deception/honeypot', methods=['POST'])
def honeypot():
    name = request.get_json(force=True).get('name', 'decoy-server')
    return jsonify(soc_deception.deploy_honeypot(name))

@soc_deception_bp.route('/api/soc_deception/false_flag', methods=['POST'])
def false_flag():
    flag_type = request.get_json(force=True).get('flag', 'ransomware')
    return jsonify(soc_deception.false_flag(flag_type))

@soc_deception_bp.route('/api/soc_deception/ai_deception', methods=['POST'])
def ai_deception():
    return jsonify(soc_deception.ai_deception())

@soc_deception_bp.route('/api/soc_deception/summary', methods=['GET'])
def summary():
    return jsonify(soc_deception.summary())

# For integration: expose soc_deception instance
get_soc_deception = lambda: soc_deception

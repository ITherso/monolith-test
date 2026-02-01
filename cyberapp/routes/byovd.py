"""
BYOVD Module - Flask Routes  
Bring Your Own Vulnerable Driver for EDR Bypass
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from byovd_module import get_byovd_module, BYOVDModule
except ImportError:
    get_byovd_module = None

byovd_bp = Blueprint('byovd', __name__, url_prefix='/byovd')


@byovd_bp.route('/')
@login_required
def index():
    """BYOVD Module main page"""
    return render_template('byovd.html')


@byovd_bp.route('/api/drivers')
@login_required
def get_drivers():
    """Get list of vulnerable drivers"""
    if not get_byovd_module:
        return jsonify({"error": "BYOVD module not available"}), 500
    
    module = get_byovd_module()
    drivers = []
    
    for driver_id, driver in module.VULNERABLE_DRIVERS.items():
        drivers.append({
            "id": driver_id,
            "name": driver.name,
            "vendor": driver.vendor,
            "cve": driver.cve,
            "capabilities": driver.capabilities,
            "file_hash": driver.file_hash,
            "reliability": driver.reliability
        })
    
    return jsonify({"drivers": drivers})


@byovd_bp.route('/api/edr-products')
@login_required
def get_edr_products():
    """Get list of supported EDR products"""
    if not get_byovd_module:
        return jsonify({"error": "BYOVD module not available"}), 500
    
    module = get_byovd_module()
    products = []
    
    for product_id, product in module.EDR_PRODUCTS.items():
        products.append({
            "id": product_id,
            "name": product.name,
            "processes": product.processes,
            "services": product.services,
            "drivers": product.drivers,
            "difficulty": product.kill_difficulty
        })
    
    return jsonify({"products": products})


@byovd_bp.route('/api/detect-edr', methods=['POST'])
@login_required
def detect_edr():
    """Detect EDR on target"""
    if not get_byovd_module:
        return jsonify({"error": "BYOVD module not available"}), 500
    
    data = request.get_json()
    target = data.get('target')
    credentials = data.get('credentials', {})
    
    if not target:
        return jsonify({"error": "Target required"}), 400
    
    module = get_byovd_module()
    detected = module.detect_edr(target, credentials)
    
    return jsonify({"target": target, "detected_edr": detected})


@byovd_bp.route('/api/generate-payload', methods=['POST'])
@login_required
def generate_payload():
    """Generate BYOVD payload"""
    if not get_byovd_module:
        return jsonify({"error": "BYOVD module not available"}), 500
    
    data = request.get_json()
    driver_id = data.get('driver')
    edr_products = data.get('edr_products', [])
    
    if not driver_id:
        return jsonify({"error": "Driver required"}), 400
    
    module = get_byovd_module()
    payload = module.generate_payload(driver_id, edr_products)
    
    return jsonify(payload)


@byovd_bp.route('/api/deploy', methods=['POST'])
@login_required
def deploy_byovd():
    """Deploy BYOVD attack"""
    if not get_byovd_module:
        return jsonify({"error": "BYOVD module not available"}), 500
    
    data = request.get_json()
    target = data.get('target')
    driver_id = data.get('driver')
    credentials = data.get('credentials', {})
    
    if not target or not driver_id:
        return jsonify({"error": "Target and driver required"}), 400
    
    module = get_byovd_module()
    result = module.deploy_attack(target, driver_id, credentials)
    
    return jsonify(result)


@byovd_bp.route('/api/kill-edr', methods=['POST'])
@login_required
def kill_edr():
    """Kill EDR processes"""
    if not get_byovd_module:
        return jsonify({"error": "BYOVD module not available"}), 500
    
    data = request.get_json()
    target = data.get('target')
    edr_product = data.get('edr_product')
    driver_id = data.get('driver')
    credentials = data.get('credentials', {})
    
    if not all([target, edr_product, driver_id]):
        return jsonify({"error": "Target, EDR product, and driver required"}), 400
    
    module = get_byovd_module()
    result = module.kill_edr(target, edr_product, driver_id, credentials)
    
    return jsonify(result)


@byovd_bp.route('/api/job/<job_id>')
@login_required
def get_job_status(job_id):
    """Get BYOVD job status"""
    if not get_byovd_module:
        return jsonify({"error": "BYOVD module not available"}), 500
    
    module = get_byovd_module()
    status = module.get_job_status(job_id)
    
    if not status:
        return jsonify({"error": "Job not found"}), 404
    
    return jsonify(status)


@byovd_bp.route('/api/capabilities')
@login_required
def get_capabilities():
    """Get driver capabilities"""
    capabilities = [
        {"id": "read_memory", "name": "Kernel Memory Read", "icon": "👁️"},
        {"id": "write_memory", "name": "Kernel Memory Write", "icon": "✏️"},
        {"id": "kill_process", "name": "Kill Protected Process", "icon": "💀"},
        {"id": "unload_driver", "name": "Unload Kernel Driver", "icon": "📤"},
        {"id": "registry_access", "name": "Registry Access", "icon": "📝"},
        {"id": "file_access", "name": "Protected File Access", "icon": "📂"},
    ]
    return jsonify({"capabilities": capabilities})

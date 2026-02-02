"""
Living off the Forest - Flask API Routes
=========================================

Advanced Active Directory Exploitation:
- Shadow Copy (VSS) Raider - ntds.dit extraction
- ACL Backdoor - Hidden admin via stealthy ACL manipulation

Author: Monolith
"""

import os
import json
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, Response
from typing import Dict, Any, List

# Import core module
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from lotf_ad import (
        LivingOffTheForest,
        ShadowCopyRaider,
        ACLBackdoorManager,
        VSSMethod,
        ACLRight,
        TargetObject
    )
except ImportError:
    LivingOffTheForest = None
    ShadowCopyRaider = None
    ACLBackdoorManager = None


# Create Blueprint
lotf_bp = Blueprint(
    'lotf',
    __name__,
    url_prefix='/lotf-ad'
)

# Initialize
lotf = LivingOffTheForest() if LivingOffTheForest else None


# ============ PAGE ROUTES ============

@lotf_bp.route('/')
def lotf_index():
    """Main dashboard page"""
    return render_template('lotf_ad.html')


# ============ VSS RAIDER API ============

@lotf_bp.route('/api/vss/methods', methods=['GET'])
def get_vss_methods():
    """Get available VSS extraction methods"""
    
    methods = [
        {
            "id": "wmic",
            "name": "WMIC Shadow Copy",
            "description": "Classic wmic shadowcopy call create",
            "opsec_rating": "medium",
            "detection_notes": "Event ID 8222, 8224 logged"
        },
        {
            "id": "vssadmin",
            "name": "vssadmin",
            "description": "vssadmin create shadow /for=C:",
            "opsec_rating": "low",
            "detection_notes": "vssadmin.exe execution triggers EDR"
        },
        {
            "id": "diskshadow",
            "name": "Diskshadow",
            "description": "diskshadow scripted method",
            "opsec_rating": "medium-high",
            "detection_notes": "Less monitored than vssadmin"
        },
        {
            "id": "powershell",
            "name": "PowerShell WMI",
            "description": "PowerShell-based VSS creation",
            "opsec_rating": "medium",
            "detection_notes": "PowerShell logging may capture"
        },
        {
            "id": "esentutl",
            "name": "esentutl / ntdsutil",
            "description": "Built-in Windows tools",
            "opsec_rating": "high",
            "detection_notes": "Legitimate admin tool"
        }
    ]
    
    return jsonify({
        "success": True,
        "methods": methods
    })


@lotf_bp.route('/api/vss/generate', methods=['POST'])
def generate_vss_commands():
    """Generate VSS extraction commands"""
    
    if not lotf:
        return jsonify({"error": "LOTF module not available"}), 500
    
    try:
        data = request.get_json()
        
        method_str = data.get('method', 'diskshadow')
        output_path = data.get('output_path', r'C:\Windows\Temp')
        cleanup = data.get('cleanup', True)
        
        # Parse method
        try:
            method = VSSMethod(method_str)
        except ValueError:
            method = VSSMethod.DISKSHADOW
        
        # Generate commands
        result = lotf.vss_raider.generate_vss_commands(
            method=method,
            output_path=output_path,
            cleanup=cleanup
        )
        
        return jsonify({
            "success": True,
            "result": result
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@lotf_bp.route('/api/vss/secretsdump', methods=['POST'])
def generate_secretsdump():
    """Generate secretsdump commands for offline extraction"""
    
    if not lotf:
        return jsonify({"error": "LOTF module not available"}), 500
    
    try:
        data = request.get_json()
        
        ntds_path = data.get('ntds_path', 'ntds.dit')
        system_path = data.get('system_path', 'SYSTEM')
        output_file = data.get('output_file', 'hashes.txt')
        
        # Generate commands
        commands = lotf.vss_raider.generate_secretsdump_command(
            ntds_path=ntds_path,
            system_path=system_path,
            output_file=output_file
        )
        
        return jsonify({
            "success": True,
            "commands": commands
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@lotf_bp.route('/api/vss/dsinternals', methods=['POST'])
def generate_dsinternals():
    """Generate DSInternals PowerShell script"""
    
    if not lotf:
        return jsonify({"error": "LOTF module not available"}), 500
    
    try:
        data = request.get_json()
        
        ntds_path = data.get('ntds_path', 'ntds.dit')
        system_path = data.get('system_path', 'SYSTEM')
        
        # Generate script
        script = lotf.vss_raider.generate_dsinternals_script(
            ntds_path=ntds_path,
            system_path=system_path
        )
        
        return jsonify({
            "success": True,
            "script": script
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


# ============ ACL BACKDOOR API ============

@lotf_bp.route('/api/acl/rights', methods=['GET'])
def get_acl_rights():
    """Get available ACL rights for backdoor"""
    
    rights = [
        {
            "id": "Self",
            "name": "Self Membership",
            "description": "Add self to group",
            "use_case": "Add yourself to Domain Admins",
            "detection_risk": "low-medium"
        },
        {
            "id": "User-Force-Change-Password",
            "name": "Force Change Password",
            "description": "Reset any user's password",
            "use_case": "Reset admin passwords",
            "detection_risk": "medium"
        },
        {
            "id": "GenericAll",
            "name": "Generic All (Full Control)",
            "description": "Complete control over object",
            "use_case": "Modify any attribute",
            "detection_risk": "medium-high"
        },
        {
            "id": "WriteDacl",
            "name": "Write DACL",
            "description": "Modify object permissions",
            "use_case": "Grant yourself more rights",
            "detection_risk": "medium"
        },
        {
            "id": "WriteOwner",
            "name": "Write Owner",
            "description": "Change object owner",
            "use_case": "Take ownership, then modify",
            "detection_risk": "medium"
        },
        {
            "id": "DS-Replication-Get-Changes",
            "name": "DCSync Rights",
            "description": "Replication rights (both needed)",
            "use_case": "Extract all hashes remotely",
            "detection_risk": "medium-high"
        }
    ]
    
    return jsonify({
        "success": True,
        "rights": rights
    })


@lotf_bp.route('/api/acl/targets', methods=['GET'])
def get_acl_targets():
    """Get available target objects for ACL backdoor"""
    
    targets = [
        {
            "id": "Domain Admins",
            "name": "Domain Admins",
            "description": "Main admin group",
            "impact": "Full domain control"
        },
        {
            "id": "Enterprise Admins",
            "name": "Enterprise Admins",
            "description": "Forest-wide admin group",
            "impact": "Full forest control"
        },
        {
            "id": "AdminSDHolder",
            "name": "AdminSDHolder",
            "description": "ACL template for protected accounts",
            "impact": "Self-healing backdoor to all admins"
        },
        {
            "id": "Domain Root",
            "name": "Domain Root",
            "description": "Domain root object",
            "impact": "DCSync rights"
        },
        {
            "id": "krbtgt",
            "name": "krbtgt Account",
            "description": "Kerberos service account",
            "impact": "Golden Ticket creation"
        },
        {
            "id": "Administrators",
            "name": "Administrators",
            "description": "Built-in admin group",
            "impact": "Local admin on DCs"
        }
    ]
    
    return jsonify({
        "success": True,
        "targets": targets
    })


@lotf_bp.route('/api/acl/generate', methods=['POST'])
def generate_acl_backdoor():
    """Generate ACL backdoor commands"""
    
    if not lotf:
        return jsonify({"error": "LOTF module not available"}), 500
    
    try:
        data = request.get_json()
        
        target_user = data.get('target_user', 'stajyer_ahmet')
        target_object_str = data.get('target_object', 'Domain Admins')
        acl_right_str = data.get('acl_right', 'Self')
        domain = data.get('domain', 'corp.local')
        
        # Parse target object
        target_object = None
        for obj in TargetObject:
            if obj.value == target_object_str:
                target_object = obj
                break
        if not target_object:
            target_object = TargetObject.DOMAIN_ADMINS
        
        # Parse ACL right
        acl_right = None
        for right in ACLRight:
            if right.value == acl_right_str:
                acl_right = right
                break
        if not acl_right:
            acl_right = ACLRight.SELF_MEMBERSHIP
        
        # Generate backdoor
        result = lotf.acl_manager.generate_acl_backdoor(
            target_user=target_user,
            target_object=target_object,
            acl_right=acl_right,
            domain=domain
        )
        
        return jsonify({
            "success": True,
            "result": result
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@lotf_bp.route('/api/acl/adminsd-holder', methods=['POST'])
def generate_adminsd_holder():
    """Generate AdminSDHolder backdoor - most persistent"""
    
    if not lotf:
        return jsonify({"error": "LOTF module not available"}), 500
    
    try:
        data = request.get_json()
        
        target_user = data.get('target_user', 'backdoor_user')
        domain = data.get('domain', 'corp.local')
        
        # Generate AdminSDHolder backdoor
        result = lotf.acl_manager.generate_adminsd_holder_backdoor(
            target_user=target_user,
            domain=domain
        )
        
        return jsonify({
            "success": True,
            "result": result
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


# ============ PLAYBOOK API ============

@lotf_bp.route('/api/playbook/<scenario>', methods=['GET'])
def get_playbook(scenario: str):
    """Get attack playbook for a scenario"""
    
    if not lotf:
        return jsonify({"error": "LOTF module not available"}), 500
    
    playbook = lotf.get_attack_playbook(scenario)
    
    return jsonify({
        "success": True,
        "playbook": playbook
    })


@lotf_bp.route('/api/playbook/scenarios', methods=['GET'])
def get_playbook_scenarios():
    """Get available playbook scenarios"""
    
    scenarios = [
        {
            "id": "full_domain_takeover",
            "name": "Full Domain Takeover",
            "description": "Complete domain compromise from initial access",
            "phases": 6
        },
        {
            "id": "stealth_persistence",
            "name": "Stealth Persistence",
            "description": "Install hard-to-detect backdoors",
            "phases": 3
        }
    ]
    
    return jsonify({
        "success": True,
        "scenarios": scenarios
    })


# ============ DOWNLOAD ENDPOINTS ============

@lotf_bp.route('/api/download/vss-script', methods=['POST'])
def download_vss_script():
    """Download VSS extraction script"""
    
    if not lotf:
        return jsonify({"error": "LOTF module not available"}), 500
    
    try:
        data = request.get_json()
        method = VSSMethod(data.get('method', 'powershell'))
        
        result = lotf.vss_raider.generate_vss_commands(method=method)
        
        if method == VSSMethod.POWERSHELL:
            content = result.get('powershell_script', '')
            filename = 'vss_extract.ps1'
            content_type = 'text/plain'
        elif method == VSSMethod.DISKSHADOW:
            content = result.get('diskshadow_script', '\n'.join(result['commands']))
            filename = 'extract.dsh'
            content_type = 'text/plain'
        else:
            content = '\n'.join(result['commands'])
            filename = 'vss_extract.bat'
            content_type = 'text/plain'
        
        return Response(
            content,
            mimetype=content_type,
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@lotf_bp.route('/api/download/acl-script', methods=['POST'])
def download_acl_script():
    """Download ACL backdoor script"""
    
    if not lotf:
        return jsonify({"error": "LOTF module not available"}), 500
    
    try:
        data = request.get_json()
        
        target_user = data.get('target_user', 'backdoor_user')
        target_object_str = data.get('target_object', 'Domain Admins')
        acl_right_str = data.get('acl_right', 'Self')
        domain = data.get('domain', 'corp.local')
        
        # Parse enums
        target_object = TargetObject.DOMAIN_ADMINS
        for obj in TargetObject:
            if obj.value == target_object_str:
                target_object = obj
                break
        
        acl_right = ACLRight.SELF_MEMBERSHIP
        for right in ACLRight:
            if right.value == acl_right_str:
                acl_right = right
                break
        
        result = lotf.acl_manager.generate_acl_backdoor(
            target_user=target_user,
            target_object=target_object,
            acl_right=acl_right,
            domain=domain
        )
        
        content = result.get('powershell_script', '')
        
        return Response(
            content,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=acl_backdoor.ps1'}
        )
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@lotf_bp.route('/api/download/dsinternals', methods=['POST'])
def download_dsinternals_script():
    """Download DSInternals hash extraction script"""
    
    if not lotf:
        return jsonify({"error": "LOTF module not available"}), 500
    
    try:
        data = request.get_json()
        
        ntds_path = data.get('ntds_path', 'ntds.dit')
        system_path = data.get('system_path', 'SYSTEM')
        
        script = lotf.vss_raider.generate_dsinternals_script(
            ntds_path=ntds_path,
            system_path=system_path
        )
        
        return Response(
            script,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=extract_hashes.ps1'}
        )
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

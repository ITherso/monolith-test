"""
Cloud Pivot Suite Routes
Multi-Cloud Lateral Movement & Security Assessment
"""
from flask import Blueprint, request, jsonify, render_template
from typing import Dict, Any, List
import os
import time
import json

cloud_bp = Blueprint('cloud', __name__, url_prefix='/cloud')

# Import cloud modules
try:
    from cybermodules.cloud_pivot import (
        CloudPivotManager, AWSPivot, AzurePivot, GCPPivot,
        KubernetesPivot, ContainerEscape, CloudCredentialHarvester,
        IMDSExploiter
    )
    CLOUD_AVAILABLE = True
except ImportError:
    CLOUD_AVAILABLE = False

# Store active pivot sessions
_pivot_sessions = {}


@cloud_bp.route('/')
def cloud_index():
    """Cloud Pivot main page"""
    return render_template('cloud.html',
        available=CLOUD_AVAILABLE,
        sessions=list(_pivot_sessions.keys()),
        providers=['aws', 'azure', 'gcp', 'kubernetes', 'container']
    )


@cloud_bp.route('/status', methods=['GET'])
def cloud_status():
    """Get cloud pivot module status"""
    status = {
        'available': CLOUD_AVAILABLE,
        'active_sessions': len(_pivot_sessions),
        'supported_providers': {
            'aws': {
                'name': 'Amazon Web Services',
                'techniques': ['imds_pivot', 'iam_enum', 'ssm_command', 's3_exfil', 'lambda_persist']
            },
            'azure': {
                'name': 'Microsoft Azure',
                'techniques': ['imds_pivot', 'managed_identity', 'keyvault_dump', 'runbook_persist']
            },
            'gcp': {
                'name': 'Google Cloud Platform',
                'techniques': ['metadata_pivot', 'service_account', 'gcs_exfil', 'cloud_function']
            },
            'kubernetes': {
                'name': 'Kubernetes/K8s',
                'techniques': ['service_account_token', 'secrets_dump', 'pod_escape', 'cluster_admin']
            },
            'container': {
                'name': 'Container Escape',
                'techniques': ['privileged_escape', 'mount_escape', 'cgroup_escape', 'docker_sock']
            }
        }
    }
    return jsonify(status)


@cloud_bp.route('/detect', methods=['POST'])
def cloud_detect():
    """Detect cloud environment"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    try:
        manager = CloudPivotManager()
        detection = manager.detect_environment()
        
        return jsonify({
            'detected': True,
            'provider': detection.get('provider', 'unknown'),
            'confidence': detection.get('confidence', 0),
            'indicators': detection.get('indicators', []),
            'metadata_accessible': detection.get('metadata_accessible', False),
            'credentials_found': detection.get('credentials_found', False)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/imds/probe', methods=['POST'])
def cloud_imds_probe():
    """Probe IMDS (Instance Metadata Service)"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    target = data.get('target', '169.254.169.254')
    
    try:
        imds = IMDSExploiter()
        probe_result = imds.probe(target)
        
        return jsonify({
            'accessible': probe_result.get('accessible', False),
            'version': probe_result.get('version', 'unknown'),
            'provider': probe_result.get('provider', 'unknown'),
            'tokens_available': probe_result.get('tokens_available', False),
            'credentials_path': probe_result.get('credentials_path'),
            'techniques': probe_result.get('techniques', [])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/imds/extract', methods=['POST'])
def cloud_imds_extract():
    """Extract credentials from IMDS"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    provider = data.get('provider', 'aws')
    
    try:
        imds = IMDSExploiter()
        creds = imds.extract_credentials(provider)
        
        return jsonify({
            'provider': provider,
            'credentials_extracted': bool(creds),
            'credential_type': creds.get('type', 'unknown') if creds else None,
            'expiration': creds.get('expiration') if creds else None,
            'role_name': creds.get('role_name') if creds else None,
            'access_level': creds.get('access_level', 'unknown') if creds else None
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/aws/enum', methods=['POST'])
def cloud_aws_enum():
    """Enumerate AWS environment"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        aws = AWSPivot(
            access_key=data.get('access_key'),
            secret_key=data.get('secret_key'),
            session_token=data.get('session_token'),
            region=data.get('region', 'us-east-1')
        )
        
        enum_result = aws.enumerate()
        
        return jsonify({
            'account_id': enum_result.get('account_id'),
            'user_arn': enum_result.get('user_arn'),
            'regions_accessible': enum_result.get('regions', []),
            'services': {
                'ec2': enum_result.get('ec2_count', 0),
                's3': enum_result.get('s3_buckets', 0),
                'lambda': enum_result.get('lambda_functions', 0),
                'iam': enum_result.get('iam_users', 0)
            },
            'privilege_escalation_paths': enum_result.get('privesc_paths', [])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/aws/privesc', methods=['POST'])
def cloud_aws_privesc():
    """AWS privilege escalation"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        aws = AWSPivot(
            access_key=data.get('access_key'),
            secret_key=data.get('secret_key'),
            session_token=data.get('session_token'),
            region=data.get('region', 'us-east-1')
        )
        
        technique = data.get('technique', 'auto')
        result = aws.privilege_escalation(technique)
        
        return jsonify({
            'technique': technique,
            'success': result.get('success', False),
            'new_permissions': result.get('new_permissions', []),
            'method_used': result.get('method_used'),
            'evidence': result.get('evidence', [])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/azure/enum', methods=['POST'])
def cloud_azure_enum():
    """Enumerate Azure environment"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        azure = AzurePivot(
            client_id=data.get('client_id'),
            client_secret=data.get('client_secret'),
            tenant_id=data.get('tenant_id'),
            use_managed_identity=data.get('use_managed_identity', True)
        )
        
        enum_result = azure.enumerate()
        
        return jsonify({
            'tenant_id': enum_result.get('tenant_id'),
            'subscription_count': enum_result.get('subscription_count', 0),
            'resources': {
                'vms': enum_result.get('vm_count', 0),
                'storage_accounts': enum_result.get('storage_count', 0),
                'key_vaults': enum_result.get('keyvault_count', 0),
                'app_services': enum_result.get('app_service_count', 0)
            },
            'managed_identity': enum_result.get('managed_identity_info'),
            'role_assignments': enum_result.get('role_assignments', [])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/azure/keyvault', methods=['POST'])
def cloud_azure_keyvault():
    """Dump Azure Key Vault secrets"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    vault_name = data.get('vault_name')
    
    try:
        azure = AzurePivot(
            use_managed_identity=data.get('use_managed_identity', True)
        )
        
        secrets = azure.dump_keyvault(vault_name)
        
        return jsonify({
            'vault_name': vault_name,
            'secrets_found': len(secrets),
            'secrets': [
                {
                    'name': s['name'],
                    'type': s.get('type', 'secret'),
                    'enabled': s.get('enabled', True),
                    'value_preview': s.get('value', '')[:20] + '...' if s.get('value') else None
                }
                for s in secrets
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/gcp/enum', methods=['POST'])
def cloud_gcp_enum():
    """Enumerate GCP environment"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        gcp = GCPPivot(
            credentials_json=data.get('credentials_json'),
            project_id=data.get('project_id')
        )
        
        enum_result = gcp.enumerate()
        
        return jsonify({
            'project_id': enum_result.get('project_id'),
            'service_account': enum_result.get('service_account'),
            'resources': {
                'compute_instances': enum_result.get('compute_count', 0),
                'gcs_buckets': enum_result.get('gcs_count', 0),
                'cloud_functions': enum_result.get('function_count', 0),
                'cloud_run': enum_result.get('cloudrun_count', 0)
            },
            'iam_bindings': enum_result.get('iam_bindings', [])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/kubernetes/enum', methods=['POST'])
def cloud_k8s_enum():
    """Enumerate Kubernetes cluster"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        k8s = KubernetesPivot(
            kubeconfig=data.get('kubeconfig'),
            token=data.get('token'),
            api_server=data.get('api_server')
        )
        
        enum_result = k8s.enumerate()
        
        return jsonify({
            'cluster_info': enum_result.get('cluster_info'),
            'current_context': enum_result.get('current_context'),
            'namespaces': enum_result.get('namespaces', []),
            'resources': {
                'pods': enum_result.get('pod_count', 0),
                'services': enum_result.get('service_count', 0),
                'secrets': enum_result.get('secret_count', 0),
                'configmaps': enum_result.get('configmap_count', 0)
            },
            'rbac': {
                'current_permissions': enum_result.get('permissions', []),
                'is_cluster_admin': enum_result.get('is_cluster_admin', False)
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/kubernetes/secrets', methods=['POST'])
def cloud_k8s_secrets():
    """Dump Kubernetes secrets"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    namespace = data.get('namespace', 'default')
    
    try:
        k8s = KubernetesPivot(
            kubeconfig=data.get('kubeconfig'),
            token=data.get('token'),
            api_server=data.get('api_server')
        )
        
        secrets = k8s.dump_secrets(namespace)
        
        return jsonify({
            'namespace': namespace,
            'secrets_found': len(secrets),
            'secrets': [
                {
                    'name': s['name'],
                    'type': s.get('type', 'Opaque'),
                    'keys': list(s.get('data', {}).keys())
                }
                for s in secrets
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/container/escape', methods=['POST'])
def cloud_container_escape():
    """Container escape techniques"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    technique = data.get('technique', 'auto')
    
    try:
        escape = ContainerEscape()
        
        if technique == 'auto':
            result = escape.auto_escape()
        else:
            result = escape.execute_technique(technique)
        
        return jsonify({
            'technique': result.get('technique_used', technique),
            'success': result.get('success', False),
            'host_access': result.get('host_access', False),
            'method': result.get('method'),
            'evidence': result.get('evidence', []),
            'available_techniques': escape.list_techniques()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/container/detect', methods=['GET'])
def cloud_container_detect():
    """Detect if running in container"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    try:
        escape = ContainerEscape()
        detection = escape.detect_container()
        
        return jsonify({
            'in_container': detection.get('in_container', False),
            'container_type': detection.get('type', 'unknown'),
            'runtime': detection.get('runtime'),
            'privileged': detection.get('privileged', False),
            'capabilities': detection.get('capabilities', []),
            'escape_vectors': detection.get('escape_vectors', [])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/credentials/harvest', methods=['POST'])
def cloud_cred_harvest():
    """Harvest cloud credentials from environment"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        harvester = CloudCredentialHarvester()
        
        sources = data.get('sources', ['env', 'files', 'imds', 'process'])
        creds = harvester.harvest(sources)
        
        return jsonify({
            'credentials_found': len(creds),
            'by_provider': {
                'aws': len([c for c in creds if c.get('provider') == 'aws']),
                'azure': len([c for c in creds if c.get('provider') == 'azure']),
                'gcp': len([c for c in creds if c.get('provider') == 'gcp']),
                'kubernetes': len([c for c in creds if c.get('provider') == 'kubernetes'])
            },
            'credentials': [
                {
                    'provider': c['provider'],
                    'source': c['source'],
                    'type': c['type'],
                    'validity': c.get('validity', 'unknown')
                }
                for c in creds
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/pivot/chain', methods=['POST'])
def cloud_pivot_chain():
    """Execute cloud pivot chain"""
    if not CLOUD_AVAILABLE:
        return jsonify({'error': 'Cloud pivot module not available'}), 500
    
    data = request.get_json() or {}
    
    try:
        manager = CloudPivotManager()
        
        chain_config = data.get('chain', [])
        if not chain_config:
            # Auto-detect and build chain
            chain_config = manager.auto_chain()
        
        result = manager.execute_chain(chain_config)
        
        return jsonify({
            'chain_executed': True,
            'steps_completed': result.get('steps_completed', 0),
            'steps_total': len(chain_config),
            'final_access': result.get('final_access'),
            'timeline': result.get('timeline', []),
            'artifacts': result.get('artifacts', [])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/sessions', methods=['GET'])
def cloud_sessions():
    """List active cloud pivot sessions"""
    sessions = []
    for name, session in _pivot_sessions.items():
        sessions.append({
            'name': name,
            'provider': session.get('provider', 'unknown'),
            'created': session.get('created', 0),
            'status': session.get('status', 'unknown')
        })
    
    return jsonify({
        'sessions': sessions,
        'total': len(sessions)
    })

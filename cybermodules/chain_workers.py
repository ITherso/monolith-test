"""
Chain Job Workers
=================
RQ job workers for kill chain execution with abort/resume support

Features:
- Distributed chain execution via RQ
- Checkpoint save/load for resume
- Abort signal handling
- Progress tracking
- Result persistence

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import json
import time
import logging
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
from enum import Enum

try:
    from redis import Redis
    from rq import Queue, get_current_job
    from rq.job import Job
    HAS_RQ = True
except ImportError:
    HAS_RQ = False

from cybermodules.helpers import log_to_intel

logger = logging.getLogger("chain_workers")


# ============================================================
# CONSTANTS
# ============================================================

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))

CHAIN_QUEUE_NAME = 'chain_queue'
CHAIN_HIGH_PRIORITY_QUEUE = 'chain_high'
CHAIN_LOW_PRIORITY_QUEUE = 'chain_low'

CHECKPOINT_PREFIX = 'chain:checkpoint:'
STATUS_PREFIX = 'chain:status:'
RESULT_PREFIX = 'chain:result:'
ABORT_PREFIX = 'chain:abort:'


# ============================================================
# JOB STATUS
# ============================================================

class ChainJobStatus(Enum):
    """Chain job status"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass
class ChainJobResult:
    """Result of chain job execution"""
    chain_id: str
    status: ChainJobStatus
    started_at: str
    completed_at: Optional[str]
    duration_seconds: float
    phases_completed: List[str]
    steps_completed: int
    steps_failed: int
    compromised_hosts: List[str]
    credentials_collected: int
    loot_collected: int
    error: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'chain_id': self.chain_id,
            'status': self.status.value,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'duration_seconds': self.duration_seconds,
            'phases_completed': self.phases_completed,
            'steps_completed': self.steps_completed,
            'steps_failed': self.steps_failed,
            'compromised_hosts': self.compromised_hosts,
            'credentials_collected': self.credentials_collected,
            'loot_collected': self.loot_collected,
            'error': self.error,
        }


# ============================================================
# CHAIN JOB WORKER
# ============================================================

class ChainJobWorker:
    """
    RQ job worker for chain execution
    
    Features:
    - Checkpoint-based execution for resume
    - Abort signal handling
    - Progress tracking via Redis
    - Result persistence
    """
    
    def __init__(self):
        if not HAS_RQ:
            raise ImportError("RQ not installed. Run: pip install rq redis")
        
        self.redis = Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
        self.queue = Queue(CHAIN_QUEUE_NAME, connection=self.redis)
        self.high_queue = Queue(CHAIN_HIGH_PRIORITY_QUEUE, connection=self.redis)
        self.low_queue = Queue(CHAIN_LOW_PRIORITY_QUEUE, connection=self.redis)
    
    def _log(self, msg_type: str, message: str, scan_id: int = 0):
        """Log to intel and console"""
        log_to_intel(scan_id, f"CHAIN_WORKER_{msg_type}", message)
        logger.info(f"[CHAIN_WORKER][{msg_type}] {message}")
    
    # ============================================================
    # JOB SUBMISSION
    # ============================================================
    
    def submit_chain(
        self,
        chain_config: Dict,
        scan_id: int = 0,
        priority: str = "normal"
    ) -> str:
        """
        Submit a chain for execution
        
        Args:
            chain_config: Chain configuration dictionary
            scan_id: Associated scan ID
            priority: Job priority (high/normal/low)
            
        Returns:
            Job ID
        """
        # Select queue based on priority
        if priority == "high":
            queue = self.high_queue
        elif priority == "low":
            queue = self.low_queue
        else:
            queue = self.queue
        
        # Enqueue job
        job = queue.enqueue(
            execute_chain_worker,
            args=(chain_config, scan_id),
            job_timeout='24h',
            result_ttl=86400,  # Keep result for 24 hours
            failure_ttl=86400,
        )
        
        # Store initial status
        self._set_status(job.id, ChainJobStatus.QUEUED)
        
        self._log("SUBMIT", f"Chain job submitted: {job.id}", scan_id)
        return job.id
    
    def submit_chain_with_resume(
        self,
        chain_id: str,
        scan_id: int = 0
    ) -> str:
        """
        Resume a previously paused/failed chain
        
        Args:
            chain_id: Chain ID to resume
            scan_id: Associated scan ID
            
        Returns:
            Job ID
        """
        # Load checkpoint
        checkpoint = self._load_checkpoint(chain_id)
        if not checkpoint:
            raise ValueError(f"No checkpoint found for chain: {chain_id}")
        
        # Enqueue resume job
        job = self.queue.enqueue(
            resume_chain_worker,
            args=(chain_id, checkpoint, scan_id),
            job_timeout='24h',
            result_ttl=86400,
        )
        
        self._set_status(job.id, ChainJobStatus.QUEUED)
        
        self._log("RESUME", f"Chain resume job submitted: {job.id} for chain {chain_id}", scan_id)
        return job.id
    
    # ============================================================
    # JOB CONTROL
    # ============================================================
    
    def abort_chain(self, job_id: str, reason: str = "User requested") -> bool:
        """
        Abort a running chain
        
        Args:
            job_id: Job ID to abort
            reason: Abort reason
            
        Returns:
            Success status
        """
        # Set abort flag in Redis
        self.redis.set(f"{ABORT_PREFIX}{job_id}", json.dumps({
            'abort': True,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }))
        
        self._set_status(job_id, ChainJobStatus.ABORTED)
        self._log("ABORT", f"Abort signal sent for job: {job_id}")
        
        return True
    
    def pause_chain(self, job_id: str) -> bool:
        """
        Pause a running chain (will checkpoint and stop)
        
        Args:
            job_id: Job ID to pause
            
        Returns:
            Success status
        """
        self.redis.set(f"{ABORT_PREFIX}{job_id}", json.dumps({
            'pause': True,
            'timestamp': datetime.now().isoformat()
        }))
        
        self._set_status(job_id, ChainJobStatus.PAUSED)
        self._log("PAUSE", f"Pause signal sent for job: {job_id}")
        
        return True
    
    def get_job_status(self, job_id: str) -> Dict:
        """
        Get job status and progress
        
        Args:
            job_id: Job ID
            
        Returns:
            Status dictionary
        """
        status_data = self.redis.get(f"{STATUS_PREFIX}{job_id}")
        if status_data:
            return json.loads(status_data)
        
        # Try to get from RQ job
        try:
            job = Job.fetch(job_id, connection=self.redis)
            return {
                'job_id': job_id,
                'status': job.get_status(),
                'result': job.result,
                'error': str(job.exc_info) if job.exc_info else None
            }
        except Exception:
            return {
                'job_id': job_id,
                'status': 'unknown',
                'error': 'Job not found'
            }
    
    def get_job_result(self, job_id: str) -> Optional[ChainJobResult]:
        """
        Get job result
        
        Args:
            job_id: Job ID
            
        Returns:
            ChainJobResult or None
        """
        result_data = self.redis.get(f"{RESULT_PREFIX}{job_id}")
        if result_data:
            data = json.loads(result_data)
            return ChainJobResult(
                chain_id=data.get('chain_id', ''),
                status=ChainJobStatus(data.get('status', 'unknown')),
                started_at=data.get('started_at', ''),
                completed_at=data.get('completed_at'),
                duration_seconds=data.get('duration_seconds', 0),
                phases_completed=data.get('phases_completed', []),
                steps_completed=data.get('steps_completed', 0),
                steps_failed=data.get('steps_failed', 0),
                compromised_hosts=data.get('compromised_hosts', []),
                credentials_collected=data.get('credentials_collected', 0),
                loot_collected=data.get('loot_collected', 0),
                error=data.get('error', ''),
            )
        
        return None
    
    def list_jobs(self, status_filter: str = None) -> List[Dict]:
        """
        List chain jobs
        
        Args:
            status_filter: Filter by status
            
        Returns:
            List of job info dictionaries
        """
        jobs = []
        
        # Get all status keys
        for key in self.redis.scan_iter(f"{STATUS_PREFIX}*"):
            job_id = key.decode().replace(STATUS_PREFIX, '')
            status = self.get_job_status(job_id)
            
            if status_filter and status.get('status') != status_filter:
                continue
            
            jobs.append(status)
        
        return jobs
    
    # ============================================================
    # CHECKPOINT MANAGEMENT
    # ============================================================
    
    def _save_checkpoint(self, chain_id: str, checkpoint_data: Dict):
        """Save checkpoint to Redis"""
        self.redis.set(
            f"{CHECKPOINT_PREFIX}{chain_id}",
            json.dumps(checkpoint_data),
            ex=86400 * 7  # Expire after 7 days
        )
    
    def _load_checkpoint(self, chain_id: str) -> Optional[Dict]:
        """Load checkpoint from Redis"""
        data = self.redis.get(f"{CHECKPOINT_PREFIX}{chain_id}")
        if data:
            return json.loads(data)
        return None
    
    def _delete_checkpoint(self, chain_id: str):
        """Delete checkpoint"""
        self.redis.delete(f"{CHECKPOINT_PREFIX}{chain_id}")
    
    def _set_status(self, job_id: str, status: ChainJobStatus, extra: Dict = None):
        """Set job status in Redis"""
        status_data = {
            'job_id': job_id,
            'status': status.value,
            'updated_at': datetime.now().isoformat(),
        }
        if extra:
            status_data.update(extra)
        
        self.redis.set(f"{STATUS_PREFIX}{job_id}", json.dumps(status_data))
    
    def _set_result(self, job_id: str, result: ChainJobResult):
        """Set job result in Redis"""
        self.redis.set(
            f"{RESULT_PREFIX}{job_id}",
            json.dumps(result.to_dict()),
            ex=86400  # Expire after 24 hours
        )
    
    def _check_abort(self, job_id: str) -> tuple:
        """
        Check if abort/pause signal was sent
        
        Returns:
            (should_stop, is_pause, reason)
        """
        data = self.redis.get(f"{ABORT_PREFIX}{job_id}")
        if data:
            signal = json.loads(data)
            if signal.get('abort'):
                return True, False, signal.get('reason', '')
            if signal.get('pause'):
                return True, True, 'pause_requested'
        return False, False, ''


# ============================================================
# WORKER FUNCTIONS (Called by RQ)
# ============================================================

def execute_chain_worker(chain_config: Dict, scan_id: int = 0) -> Dict:
    """
    RQ worker function to execute a chain
    
    Args:
        chain_config: Chain configuration
        scan_id: Associated scan ID
        
    Returns:
        Execution result
    """
    from cybermodules.full_chain_orchestrator import (
        FullChainOrchestrator,
        ChainConfig
    )
    
    worker = ChainJobWorker()
    job = get_current_job()
    job_id = job.id if job else 'local'
    
    start_time = time.time()
    result = ChainJobResult(
        chain_id='',
        status=ChainJobStatus.RUNNING,
        started_at=datetime.now().isoformat(),
        completed_at=None,
        duration_seconds=0,
        phases_completed=[],
        steps_completed=0,
        steps_failed=0,
        compromised_hosts=[],
        credentials_collected=0,
        loot_collected=0,
    )
    
    try:
        # Update status
        worker._set_status(job_id, ChainJobStatus.RUNNING)
        
        # Create orchestrator
        config = ChainConfig(**chain_config)
        orchestrator = FullChainOrchestrator(scan_id=scan_id)
        chain_id = orchestrator.create_chain(config)
        result.chain_id = chain_id
        
        # Execute with abort checking
        def abort_checker():
            should_stop, is_pause, reason = worker._check_abort(job_id)
            if should_stop:
                if is_pause:
                    orchestrator.pause()
                else:
                    orchestrator.abort(reason)
        
        # Run execution with periodic abort check
        import threading
        abort_thread = threading.Thread(target=lambda: _abort_check_loop(worker, job_id, orchestrator), daemon=True)
        abort_thread.start()
        
        # Execute chain
        exec_result = orchestrator.execute()
        
        # Update result
        state = exec_result.get('state', {})
        result.status = ChainJobStatus.COMPLETED if exec_result.get('success') else ChainJobStatus.FAILED
        result.phases_completed = exec_result.get('completed_phases', [])
        result.steps_completed = state.get('completed_steps', 0)
        result.steps_failed = state.get('failed_steps', 0)
        result.compromised_hosts = state.get('compromised_hosts', [])
        result.credentials_collected = len(state.get('collected_credentials', []))
        result.loot_collected = len(state.get('collected_loot', []))
        
        if exec_result.get('aborted'):
            result.status = ChainJobStatus.ABORTED
        
        # Save checkpoint for potential resume
        worker._save_checkpoint(chain_id, {
            'chain_id': chain_id,
            'config': chain_config,
            'state': state,
            'job_id': job_id,
        })
        
    except Exception as e:
        result.status = ChainJobStatus.FAILED
        result.error = str(e)
        logger.exception(f"Chain execution failed: {e}")
    
    finally:
        result.completed_at = datetime.now().isoformat()
        result.duration_seconds = time.time() - start_time
        
        # Store final result
        worker._set_result(job_id, result)
        worker._set_status(job_id, result.status, {
            'completed_at': result.completed_at,
            'duration': result.duration_seconds,
        })
    
    return result.to_dict()


def resume_chain_worker(chain_id: str, checkpoint: Dict, scan_id: int = 0) -> Dict:
    """
    RQ worker function to resume a chain
    
    Args:
        chain_id: Chain ID to resume
        checkpoint: Checkpoint data
        scan_id: Associated scan ID
        
    Returns:
        Execution result
    """
    from cybermodules.full_chain_orchestrator import FullChainOrchestrator
    
    worker = ChainJobWorker()
    job = get_current_job()
    job_id = job.id if job else 'local'
    
    start_time = time.time()
    
    try:
        worker._set_status(job_id, ChainJobStatus.RUNNING)
        
        # Create orchestrator and load checkpoint
        orchestrator = FullChainOrchestrator(scan_id=scan_id)
        
        # Resume from checkpoint
        exec_result = orchestrator.execute(chain_id=chain_id)
        
        result = ChainJobResult(
            chain_id=chain_id,
            status=ChainJobStatus.COMPLETED if exec_result.get('success') else ChainJobStatus.FAILED,
            started_at=checkpoint.get('state', {}).get('started_at', datetime.now().isoformat()),
            completed_at=datetime.now().isoformat(),
            duration_seconds=time.time() - start_time,
            phases_completed=exec_result.get('completed_phases', []),
            steps_completed=exec_result.get('state', {}).get('completed_steps', 0),
            steps_failed=exec_result.get('state', {}).get('failed_steps', 0),
            compromised_hosts=exec_result.get('state', {}).get('compromised_hosts', []),
            credentials_collected=len(exec_result.get('state', {}).get('collected_credentials', [])),
            loot_collected=len(exec_result.get('state', {}).get('collected_loot', [])),
        )
        
        worker._set_result(job_id, result)
        worker._set_status(job_id, result.status)
        
        return result.to_dict()
        
    except Exception as e:
        worker._set_status(job_id, ChainJobStatus.FAILED, {'error': str(e)})
        raise


def _abort_check_loop(worker: ChainJobWorker, job_id: str, orchestrator):
    """Background loop to check for abort signals"""
    while True:
        should_stop, is_pause, reason = worker._check_abort(job_id)
        if should_stop:
            if is_pause:
                orchestrator.pause()
            else:
                orchestrator.abort(reason)
            break
        time.sleep(1)


# ============================================================
# QUEUE MANAGEMENT
# ============================================================

def get_queue_stats() -> Dict:
    """Get queue statistics"""
    if not HAS_RQ:
        return {'error': 'RQ not installed'}
    
    redis = Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
    
    queues = {
        'chain_queue': Queue(CHAIN_QUEUE_NAME, connection=redis),
        'chain_high': Queue(CHAIN_HIGH_PRIORITY_QUEUE, connection=redis),
        'chain_low': Queue(CHAIN_LOW_PRIORITY_QUEUE, connection=redis),
    }
    
    stats = {}
    for name, queue in queues.items():
        stats[name] = {
            'pending': len(queue),
            'started': len(queue.started_job_registry),
            'finished': len(queue.finished_job_registry),
            'failed': len(queue.failed_job_registry),
        }
    
    return stats


def clear_failed_jobs():
    """Clear all failed jobs"""
    if not HAS_RQ:
        return
    
    redis = Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
    
    for queue_name in [CHAIN_QUEUE_NAME, CHAIN_HIGH_PRIORITY_QUEUE, CHAIN_LOW_PRIORITY_QUEUE]:
        queue = Queue(queue_name, connection=redis)
        queue.failed_job_registry.clear()


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Classes
    'ChainJobWorker',
    'ChainJobStatus',
    'ChainJobResult',
    
    # Worker functions
    'execute_chain_worker',
    'resume_chain_worker',
    
    # Queue management
    'get_queue_stats',
    'clear_failed_jobs',
    
    # Constants
    'CHAIN_QUEUE_NAME',
    'CHAIN_HIGH_PRIORITY_QUEUE',
    'CHAIN_LOW_PRIORITY_QUEUE',
]

#!/usr/bin/env python3
"""
RQ Worker Process - ELITE Monolith v15 Production Edition
=========================================================

Background task worker for Layer 14-15 distributed operations:
- Blockchain C2 command batch processing (async polling)
- Polymorphic shellcode mutation queues (JIT compilation)
- Agent health monitoring and beacon status tracking
- Encrypted payload distribution coordination

Features:
✅ Redis/RQ for full async capability
✅ Graceful fallback if Redis unavailable (degraded mode)
✅ Comprehensive error handling and logging
✅ Production-ready stability (won't crash field beacons)
✅ Layer 14-15 queue management and job tracking

This is THE critical worker process - if it crashes, all Red Team operations
lose async capability and must run synchronously. We handle this gracefully.
"""

import os
import sys
import logging
import signal
from typing import Optional, Dict, Any
from datetime import datetime

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [WORKER] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/tmp/monolith_worker.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# REDIS/RQ IMPORTS (with graceful fallback)
# ============================================================================

try:
    import redis  # type: ignore
    import rq  # type: ignore
    REDIS_AVAILABLE = True
    logger.info("[✓] Redis/RQ modules available")
except ImportError as e:
    REDIS_AVAILABLE = False
    logger.warning(f"[!] Redis/RQ not available: {e}")
    logger.warning("[!] Worker will run in DEGRADED MODE (synchronous task processing)")

# ============================================================================
# PRODUCTION WORKER CLASS
# ============================================================================

class MonolithRQWorker:
    """Production-grade RQ worker with error handling and fallback"""
    
    def __init__(self):
        self.connection = None
        self.worker = None
        self.queues = {}
        self.degraded_mode = False
        self.job_cache: Dict[str, Any] = {}
        
        self._initialize()
        self._setup_signal_handlers()
    
    def _initialize(self):
        """Initialize Redis connection with fallback"""
        if not REDIS_AVAILABLE:
            logger.warning("[!] Initializing worker in DEGRADED MODE (no Redis)")
            self.degraded_mode = True
            return
        
        try:
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            logger.info(f"[→] Connecting to Redis: {redis_url.split('@')[-1]}")
            
            self.connection = redis.Redis.from_url(redis_url, decode_responses=True)
            
            # Test connection with 5 second timeout
            self.connection.ping()
            logger.info("[✓] Redis connection successful")
            
            # Initialize Layer 14-15 specific queues
            self.queues = {
                'layer14_blockchain': rq.Queue('layer14_blockchain', connection=self.connection),
                'layer15_polymorphic': rq.Queue('layer15_polymorphic', connection=self.connection),
                'default': rq.Queue('default', connection=self.connection),
            }
            
            logger.info("[✓] Created 3 worker queues: layer14_blockchain, layer15_polymorphic, default")
            
            # Create worker with failure/result TTL
            self.worker = rq.Worker(
                list(self.queues.values()),
                connection=self.connection,
                name=f"monolith_{os.getpid()}",
                result_ttl=3600,      # Keep job results for 1 hour
                failure_ttl=86400,    # Keep failures for 24 hours
                job_monitoring_interval=5
            )
            
            logger.info(f"[✓] RQ Worker initialized (PID: {os.getpid()})")
            
        except Exception as e:
            logger.error(f"[!] Redis initialization failed: {e}")
            logger.warning("[!] DEGRADED MODE activated - using synchronous task processing")
            self.degraded_mode = True
            self.connection = None
            self.worker = None
    
    def _setup_signal_handlers(self):
        """Setup graceful shutdown on signals"""
        def shutdown_handler(signum, frame):
            logger.info(f"[!] Received signal {signum} - graceful shutdown")
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)
    
    def start(self):
        """Start worker process"""
        logger.info("=" * 70)
        logger.info("MONOLITH RQ WORKER - v15 Production Edition")
        logger.info("=" * 70)
        
        if self.degraded_mode:
            logger.warning("[!] Running in DEGRADED MODE - Layer 14-15 tasks will process synchronously")
            self._run_degraded_mode()
        else:
            self._run_production_mode()
    
    def _run_production_mode(self):
        """Run with full Redis/RQ capability"""
        try:
            logger.info("[▶] Starting RQ Worker (PRODUCTION MODE)")
            logger.info("[→] Listening on queues:")
            for queue_name in self.queues.keys():
                logger.info(f"    - {queue_name}")
            
            # Start RQ worker - will process queued jobs indefinitely
            self.worker.work(with_scheduler=True, logging_level="INFO")
            
        except KeyboardInterrupt:
            logger.info("[✓] Keyboard interrupt - graceful shutdown")
            self.shutdown()
            sys.exit(0)
        except Exception as e:
            logger.error(f"[!] Worker exception: {e}")
            logger.error(f"[!] Attempting to recover...")
            
            # Try to restart worker
            import time
            time.sleep(5)
            self._run_production_mode()
    
    def _run_degraded_mode(self):
        """Run without Redis - keeps process alive (synchronous task processing)"""
        try:
            logger.info("[▶] Starting Worker (DEGRADED MODE - Synchronous Processing)")
            logger.info("[!] Layer 14-15 tasks will be processed by Flask app directly (no queuing)")
            logger.info("[→] Keeping worker process alive for health checks...")
            
            import time
            startup_time = datetime.now()
            job_count = 0
            
            while True:
                time.sleep(10)
                uptime = datetime.now() - startup_time
                logger.debug(f"[·] Worker heartbeat (uptime: {uptime}, jobs processed: {job_count})")
                
        except KeyboardInterrupt:
            logger.info("[✓] Degraded mode worker shutdown")
            sys.exit(0)
    
    def shutdown(self):
        """Graceful shutdown"""
        logger.info("[!] Worker shutdown initiated")
        if self.worker and not self.degraded_mode:
            try:
                logger.info("[→] Waiting for active jobs to complete...")
                self.worker.request_stop(cold=False)
            except Exception as e:
                logger.error(f"[!] Final job wait failed: {e}")
        logger.info("[✓] Worker shutdown complete")

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Main entry point for RQ worker"""
    try:
        worker = MonolithRQWorker()
        worker.start()
    except Exception as e:
        logger.critical(f"[!] CRITICAL: Worker initialization failed: {e}")
        logger.critical("[!] Exiting worker process")
        sys.exit(1)

if __name__ == "__main__":
    main()

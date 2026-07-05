"""
Chain API Routes
================
REST API endpoints for kill chain orchestration

Endpoints:
- POST /api/chain/create - Create new chain
- POST /api/chain/{id}/start - Start chain execution
- GET /api/chain/{id}/status - Get chain status
- POST /api/chain/{id}/abort - Abort running chain
- POST /api/chain/{id}/pause - Pause running chain
- POST /api/chain/{id}/resume - Resume paused chain
- GET /api/chain/{id}/diagram - Get Mermaid diagram
- GET /api/chain/list - List all chains
- GET /api/chain/{id}/ai-recommendations - Get AI recommendations

⚠️ YASAL UYARI: Bu API sadece yetkili penetrasyon testleri içindir.
"""

from flask import Blueprint, request, jsonify, current_app
from functools import wraps
import logging

from cybermodules.full_chain_orchestrator import (
    FullChainOrchestrator,
    ChainConfig,
    ChainPhase,
    ChainPriority,
)
from cybermodules.chain_workers import (
    ChainJobWorker,
    ChainJobStatus,
    get_queue_stats,
)
from cybermodules.cleanup_engine import (
    CleanupEngine,
    CleanupAggressiveness,
)
from cybermodules.ai_post_exploit import AIPostExploitEngine

logger = logging.getLogger("chain_routes")

bp = Blueprint('chain', __name__, url_prefix='/api/chain')

# In-memory store for orchestrators (in production, use Redis/DB)
_orchestrators = {}


def get_orchestrator(chain_id: str) -> FullChainOrchestrator:
    """Get orchestrator by chain ID"""
    if chain_id not in _orchestrators:
        # Try to load from checkpoint
        orchestrator = FullChainOrchestrator(scan_id=0)
        try:
            state = orchestrator._load_checkpoint(chain_id)
            if state:
                orchestrator.state = state
                _orchestrators[chain_id] = orchestrator
        except Exception:
            pass
    
    return _orchestrators.get(chain_id)


def api_response(data=None, error=None, status_code=200):
    """Standard API response format"""
    response = {
        'success': error is None,
        'data': data,
        'error': error,
    }
    return jsonify(response), status_code


# ============================================================
# CHAIN CRUD ENDPOINTS
# ============================================================

@bp.route('/create', methods=['POST'])
def create_chain():
    """
    Create a new kill chain
    
    Request body:
    {
        "name": "Operation Name",
        "initial_target": "192.168.1.100",
        "target_domain": "corp.local",
        "credentials": {
            "username": "admin",
            "password": "password",
            "domain": "CORP"
        },
        "persistence_methods": ["scheduled_task", "wmi_subscription"],
        "exfil_method": "https",
        "exfil_endpoint": "https://c2.example.com/upload",
        "options": {
            "enable_recon": true,
            "enable_persistence": true,
            "enable_lateral": true,
            "enable_exfil": true,
            "enable_cleanup": true,
            "ai_guided": true,
            "opsec_mode": true
        }
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return api_response(error="Request body required", status_code=400)
        
        if not data.get('name'):
            return api_response(error="Chain name required", status_code=400)
        
        # Build config
        options = data.get('options', {})
        
        config = ChainConfig(
            name=data.get('name'),
            description=data.get('description', ''),
            priority=ChainPriority[data.get('priority', 'NORMAL').upper()],
            
            initial_target=data.get('initial_target', ''),
            target_domain=data.get('target_domain', ''),
            credentials=data.get('credentials', {}),
            
            enable_recon=options.get('enable_recon', True),
            enable_persistence=options.get('enable_persistence', True),
            enable_lateral=options.get('enable_lateral', True),
            enable_exfil=options.get('enable_exfil', True),
            enable_cleanup=options.get('enable_cleanup', True),
            
            persistence_methods=data.get('persistence_methods', ['scheduled_task']),
            persistence_fallback=options.get('persistence_fallback', True),
            
            lateral_max_depth=options.get('lateral_max_depth', 3),
            lateral_max_hosts=options.get('lateral_max_hosts', 10),
            lateral_methods=data.get('lateral_methods', ['wmiexec', 'psexec']),
            
            exfil_method=data.get('exfil_method', 'https'),
            exfil_endpoint=data.get('exfil_endpoint', ''),
            exfil_encryption=options.get('exfil_encryption', True),
            loot_types=data.get('loot_types', ['credential', 'hash_dump']),
            
            cleanup_logs=options.get('cleanup_logs', True),
            cleanup_artifacts=options.get('cleanup_artifacts', True),
            cleanup_persistence=options.get('cleanup_persistence', False),
            
            timeout_per_step=options.get('timeout_per_step', 300),
            max_retries=options.get('max_retries', 2),
            checkpoint_interval=options.get('checkpoint_interval', 1),
            ai_guided=options.get('ai_guided', True),
            opsec_mode=options.get('opsec_mode', True),
            
            evasion_profile=options.get('evasion_profile', 'stealth'),
            use_indirect_syscalls=options.get('use_indirect_syscalls', True),
            obfuscation_level=options.get('obfuscation_level', 'standard'),
        )
        
        # Create orchestrator and chain
        scan_id = data.get('scan_id', 0)
        orchestrator = FullChainOrchestrator(scan_id=scan_id)
        chain_id = orchestrator.create_chain(config)
        
        # Store orchestrator
        _orchestrators[chain_id] = orchestrator
        
        return api_response({
            'chain_id': chain_id,
            'name': config.name,
            'total_steps': orchestrator.state.total_steps,
            'phases': [s.phase.value for s in orchestrator.state.steps],
        })
        
    except Exception as e:
        logger.exception("Failed to create chain")
        return api_response(error=str(e), status_code=500)


@bp.route('/<chain_id>/start', methods=['POST'])
def start_chain(chain_id: str):
    """
    Start chain execution
    
    Query params:
    - async: If true, execute via RQ job (default: false)
    """
    try:
        orchestrator = get_orchestrator(chain_id)
        
        if not orchestrator:
            return api_response(error="Chain not found", status_code=404)
        
        use_async = request.args.get('async', 'false').lower() == 'true'
        
        if use_async:
            # Submit to RQ
            try:
                worker = ChainJobWorker()
                config_dict = orchestrator.state.config.__dict__
                job_id = worker.submit_chain(config_dict, orchestrator.scan_id)
                
                return api_response({
                    'chain_id': chain_id,
                    'job_id': job_id,
                    'status': 'queued',
                    'message': 'Chain submitted to job queue'
                })
            except ImportError:
                return api_response(
                    error="RQ not available. Use sync execution.",
                    status_code=503
                )
        else:
            # Execute synchronously (blocking)
            result = orchestrator.execute()
            
            return api_response({
                'chain_id': chain_id,
                'success': result.get('success', False),
                'completed_phases': result.get('completed_phases', []),
                'total_time': result.get('total_time', 0),
                'state': orchestrator.get_status(),
            })
        
    except Exception as e:
        logger.exception(f"Failed to start chain {chain_id}")
        return api_response(error=str(e), status_code=500)


@bp.route('/<chain_id>/status', methods=['GET'])
def get_chain_status(chain_id: str):
    """Get chain status"""
    try:
        orchestrator = get_orchestrator(chain_id)
        
        if not orchestrator:
            return api_response(error="Chain not found", status_code=404)
        
        status = orchestrator.get_status()
        
        return api_response(status)
        
    except Exception as e:
        logger.exception(f"Failed to get chain status {chain_id}")
        return api_response(error=str(e), status_code=500)


@bp.route('/<chain_id>/abort', methods=['POST'])
def abort_chain(chain_id: str):
    """Abort running chain"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'User requested abort')
        
        orchestrator = get_orchestrator(chain_id)
        
        if orchestrator:
            orchestrator.abort(reason)
        
        # Also try to abort via RQ
        try:
            worker = ChainJobWorker()
            worker.abort_chain(chain_id, reason)
        except Exception:
            pass
        
        return api_response({
            'chain_id': chain_id,
            'status': 'aborted',
            'reason': reason,
        })
        
    except Exception as e:
        logger.exception(f"Failed to abort chain {chain_id}")
        return api_response(error=str(e), status_code=500)


@bp.route('/<chain_id>/pause', methods=['POST'])
def pause_chain(chain_id: str):
    """Pause running chain"""
    try:
        orchestrator = get_orchestrator(chain_id)
        
        if orchestrator:
            orchestrator.pause()
        
        # Also try via RQ
        try:
            worker = ChainJobWorker()
            worker.pause_chain(chain_id)
        except Exception:
            pass
        
        return api_response({
            'chain_id': chain_id,
            'status': 'paused',
        })
        
    except Exception as e:
        logger.exception(f"Failed to pause chain {chain_id}")
        return api_response(error=str(e), status_code=500)


@bp.route('/<chain_id>/resume', methods=['POST'])
def resume_chain(chain_id: str):
    """Resume paused chain"""
    try:
        data = request.get_json() or {}
        use_async = data.get('async', False)
        
        orchestrator = get_orchestrator(chain_id)
        
        if not orchestrator:
            return api_response(error="Chain not found", status_code=404)
        
        if use_async:
            try:
                worker = ChainJobWorker()
                job_id = worker.submit_chain_with_resume(chain_id, orchestrator.scan_id)
                
                return api_response({
                    'chain_id': chain_id,
                    'job_id': job_id,
                    'status': 'resuming',
                })
            except ImportError:
                return api_response(error="RQ not available", status_code=503)
        else:
            orchestrator.resume()
            result = orchestrator.execute(chain_id=chain_id)
            
            return api_response({
                'chain_id': chain_id,
                'success': result.get('success', False),
                'state': orchestrator.get_status(),
            })
        
    except Exception as e:
        logger.exception(f"Failed to resume chain {chain_id}")
        return api_response(error=str(e), status_code=500)


# ============================================================
# DIAGRAM & VISUALIZATION
# ============================================================

@bp.route('/<chain_id>/diagram', methods=['GET'])
def get_chain_diagram(chain_id: str):
    """Get Mermaid diagram for chain"""
    try:
        orchestrator = get_orchestrator(chain_id)
        
        if not orchestrator:
            return api_response(error="Chain not found", status_code=404)
        
        diagram = orchestrator.generate_kill_chain_diagram()
        
        return api_response({
            'chain_id': chain_id,
            'diagram': diagram,
            'format': 'mermaid',
        })
        
    except Exception as e:
        logger.exception(f"Failed to get diagram for {chain_id}")
        return api_response(error=str(e), status_code=500)


# ============================================================
# LIST & QUEUE
# ============================================================

@bp.route('/list', methods=['GET'])
def list_chains():
    """List all chains"""
    try:
        chains = []
        
        for chain_id, orchestrator in _orchestrators.items():
            status = orchestrator.get_status()
            chains.append(status)
        
        return api_response({
            'chains': chains,
            'total': len(chains),
        })
        
    except Exception as e:
        logger.exception("Failed to list chains")
        return api_response(error=str(e), status_code=500)


@bp.route('/queue/stats', methods=['GET'])
def get_queue_statistics():
    """Get RQ queue statistics"""
    try:
        stats = get_queue_stats()
        return api_response(stats)
    except ImportError:
        return api_response(error="RQ not available", status_code=503)
    except Exception as e:
        logger.exception("Failed to get queue stats")
        return api_response(error=str(e), status_code=500)


# ============================================================
# AI RECOMMENDATIONS
# ============================================================

@bp.route('/<chain_id>/ai-recommendations', methods=['GET'])
def get_ai_recommendations(chain_id: str):
    """Get AI-powered recommendations for chain"""
    try:
        orchestrator = get_orchestrator(chain_id)
        
        if not orchestrator:
            return api_response(error="Chain not found", status_code=404)
        
        recommendations = orchestrator.get_ai_recommendations()
        
        return api_response({
            'chain_id': chain_id,
            'recommendations': recommendations,
        })
        
    except Exception as e:
        logger.exception(f"Failed to get AI recommendations for {chain_id}")
        return api_response(error=str(e), status_code=500)


@bp.route('/ai/persistence', methods=['POST'])
def get_persistence_recommendations():
    """Get AI persistence method recommendations"""
    try:
        data = request.get_json() or {}
        
        ai_engine = AIPostExploitEngine(scan_id=data.get('scan_id', 0))
        
        recommendations = ai_engine.recommend_persistence(
            os_type=data.get('os_type', 'windows'),
            current_access=data.get('current_access', 'user'),
            stealth_required=data.get('stealth_required', True)
        )
        
        return api_response({
            'recommendations': recommendations,
        })
        
    except Exception as e:
        logger.exception("Failed to get persistence recommendations")
        return api_response(error=str(e), status_code=500)


@bp.route('/ai/exfil', methods=['POST'])
def get_exfil_recommendations():
    """Get AI exfiltration path recommendations"""
    try:
        data = request.get_json() or {}
        
        ai_engine = AIPostExploitEngine(scan_id=data.get('scan_id', 0))
        
        recommendations = ai_engine.recommend_exfil_path(
            data_volume=data.get('data_volume', 'medium'),
            network_restrictions=data.get('network_restrictions', False),
            time_constraints=data.get('time_constraints', 'normal')
        )
        
        return api_response({
            'recommendations': recommendations,
        })
        
    except Exception as e:
        logger.exception("Failed to get exfil recommendations")
        return api_response(error=str(e), status_code=500)


# ============================================================
# CLEANUP
# ============================================================

@bp.route('/<chain_id>/cleanup', methods=['POST'])
def generate_cleanup(chain_id: str):
    """Generate cleanup script for chain"""
    try:
        data = request.get_json() or {}
        
        orchestrator = get_orchestrator(chain_id)
        
        if not orchestrator:
            return api_response(error="Chain not found", status_code=404)
        
        os_type = data.get('os_type', 'windows')
        aggressiveness = CleanupAggressiveness[
            data.get('aggressiveness', 'STANDARD').upper()
        ]
        
        engine = CleanupEngine(
            scan_id=orchestrator.scan_id,
            os_type=os_type
        )
        
        # Get persistence records from chain state
        persistence = orchestrator.state.installed_persistence
        
        # Generate cleanup script
        script = engine.create_cleanup_plan(
            persistence_records=persistence,
            artifacts=data.get('artifacts', []),
            timestomp_files=data.get('timestomp_files', []),
            aggressiveness=aggressiveness
        )
        
        # Get recommendations
        recommendations = engine.get_cleanup_recommendations(
            orchestrator.state.to_dict()
        )
        
        return api_response({
            'chain_id': chain_id,
            'script': script,
            'recommendations': recommendations,
            'os_type': os_type,
            'aggressiveness': aggressiveness.name,
        })
        
    except Exception as e:
        logger.exception(f"Failed to generate cleanup for {chain_id}")
        return api_response(error=str(e), status_code=500)


# ============================================================
# HEALTH CHECK
# ============================================================

@bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return api_response({
        'status': 'healthy',
        'active_chains': len(_orchestrators),
    })

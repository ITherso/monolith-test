"""
God Mode Anti-Forensics Flask Routes
====================================

İzleri silmek değil, YOK ETMEK!
"""

from flask import Blueprint, render_template, request, jsonify
import sys
import os

# Tools modülünü import et
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from god_mode_antiforensics import (
        GodModeAntiForensics, 
        TimeStomp, 
        PhantomEventLogCleaner,
        TimestampSource,
        CleanerMethod
    )
except ImportError:
    GodModeAntiForensics = None

god_mode_bp = Blueprint('god_mode', __name__, url_prefix='/god-mode')


# ============ PAGE ROUTES ============

@god_mode_bp.route('/')
def index():
    """God Mode Anti-Forensics Dashboard"""
    return render_template('god_mode_antiforensics.html')


# ============ TIME STOMPING API ============

@god_mode_bp.route('/api/timestomp/generate', methods=['POST'])
def generate_timestomp():
    """Time Stomping script üret"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    target_file = data.get('target_file', 'C:\\malware\\payload.exe')
    source_type = data.get('source_type', 'system_file')
    reference_file = data.get('reference_file', 'calc.exe')
    custom_date = data.get('custom_date')
    
    # Source type mapping
    source_map = {
        'system_file': TimestampSource.SYSTEM_FILE,
        'random_old': TimestampSource.RANDOM_OLD,
        'specific_date': TimestampSource.SPECIFIC_DATE,
        'windows_install': TimestampSource.WINDOWS_INSTALL
    }
    
    source = source_map.get(source_type, TimestampSource.SYSTEM_FILE)
    
    timestomp = TimeStomp()
    
    # Custom date parse
    from datetime import datetime
    custom_datetime = None
    if custom_date:
        try:
            custom_datetime = datetime.fromisoformat(custom_date)
        except:
            pass
    
    result = timestomp.generate_timestomp_powershell(
        target_file=target_file,
        source=source,
        reference_file=reference_file,
        custom_date=custom_datetime
    )
    
    return jsonify(result)


@god_mode_bp.route('/api/timestomp/advanced', methods=['POST'])
def generate_advanced_timestomp():
    """Gelişmiş Time Stomping (MFT level)"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    target_file = data.get('target_file', 'C:\\malware\\payload.exe')
    reference_file = data.get('reference_file', 'C:\\Windows\\System32\\calc.exe')
    
    timestomp = TimeStomp()
    result = timestomp.generate_advanced_timestomp(
        target_file=target_file,
        reference_file=reference_file
    )
    
    return jsonify(result)


@god_mode_bp.route('/api/timestomp/batch', methods=['POST'])
def generate_batch_timestomp():
    """Toplu Time Stomping"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    target_folder = data.get('target_folder', 'C:\\malware')
    file_pattern = data.get('file_pattern', '*.exe')
    reference_file = data.get('reference_file', 'calc.exe')
    
    timestomp = TimeStomp()
    result = timestomp.generate_batch_timestomp(
        target_folder=target_folder,
        file_pattern=file_pattern,
        reference_file=reference_file
    )
    
    return jsonify(result)


@god_mode_bp.route('/api/timestomp/reference-files')
def get_reference_files():
    """Referans alınabilecek sistem dosyaları"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    timestomp = TimeStomp()
    
    files = []
    for name, info in timestomp.system_files.items():
        files.append({
            "name": name,
            "path": info.path,
            "created": info.created.isoformat(),
            "modified": info.modified.isoformat(),
            "description": info.description
        })
    
    return jsonify({"reference_files": files})


# ============ PHANTOM CLEANER API ============

@god_mode_bp.route('/api/phantom/generate', methods=['POST'])
def generate_phantom_cleaner():
    """Phantom Event Log Cleaner script üret"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    target_events = data.get('target_events', [4624, 4625, 4648, 4672, 4688])
    log_type = data.get('log_type', 'Security')
    time_range_hours = data.get('time_range_hours', 24)
    keywords = data.get('keywords', [])
    
    cleaner = PhantomEventLogCleaner()
    result = cleaner.generate_phantom_cleaner(
        target_events=target_events,
        log_type=log_type,
        time_range_hours=time_range_hours,
        keywords=keywords
    )
    
    return jsonify(result)


@god_mode_bp.route('/api/phantom/sysmon-killer')
def get_sysmon_killer():
    """Sysmon Killer script"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    cleaner = PhantomEventLogCleaner()
    result = cleaner.generate_sysmon_killer()
    
    return jsonify(result)


@god_mode_bp.route('/api/phantom/alternative', methods=['POST'])
def get_alternative_cleaner():
    """Alternatif log temizleme yöntemleri"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    method = data.get('method', 'memory')
    
    method_map = {
        'phantom': CleanerMethod.PHANTOM,
        'memory': CleanerMethod.PATCH_IN_MEMORY,
        'evt': CleanerMethod.EVT_MANIPULATION,
        'api': CleanerMethod.EVENTLOG_API
    }
    
    cleaner_method = method_map.get(method, CleanerMethod.PATCH_IN_MEMORY)
    
    cleaner = PhantomEventLogCleaner()
    result = cleaner.generate_alternative_cleaner(method=cleaner_method)
    
    return jsonify(result)


@god_mode_bp.route('/api/phantom/profiles')
def get_cleanup_profiles():
    """Saldırı tipine göre temizlik profilleri"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    cleaner = PhantomEventLogCleaner()
    
    profiles = {}
    for profile_type in ['lateral_movement', 'credential_theft', 'persistence', 'privilege_escalation', 'full_cleanup']:
        profiles[profile_type] = cleaner.get_event_cleanup_profile(profile_type)
    
    return jsonify({"profiles": profiles})


@god_mode_bp.route('/api/phantom/profile/<profile_type>')
def get_cleanup_profile(profile_type):
    """Belirli bir cleanup profili"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    cleaner = PhantomEventLogCleaner()
    profile = cleaner.get_event_cleanup_profile(profile_type)
    
    return jsonify(profile)


@god_mode_bp.route('/api/phantom/suspicious-events')
def get_suspicious_events():
    """Şüpheli event'lerin listesi"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    cleaner = PhantomEventLogCleaner()
    
    events = {}
    for log_type, event_list in cleaner.suspicious_events.items():
        events[log_type] = [
            {
                "event_id": e.event_id,
                "source": e.source,
                "description": e.description,
                "suspicion_level": e.suspicion_level
            }
            for e in event_list
        ]
    
    return jsonify({"events": events})


# ============ QUICK ACTIONS ============

@god_mode_bp.route('/api/quick-action/timestomp-like-calc', methods=['POST'])
def quick_timestomp_calc():
    """Hızlı: calc.exe tarihleriyle timestomp"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    target_file = data.get('target_file', 'C:\\malware\\payload.exe')
    
    timestomp = TimeStomp()
    result = timestomp.generate_timestomp_powershell(
        target_file=target_file,
        source=TimestampSource.SYSTEM_FILE,
        reference_file="calc.exe"
    )
    
    return jsonify(result)


@god_mode_bp.route('/api/quick-action/clean-lateral', methods=['POST'])
def quick_clean_lateral():
    """Hızlı: Lateral movement izlerini temizle"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    time_range = data.get('time_range_hours', 24)
    
    cleaner = PhantomEventLogCleaner()
    profile = cleaner.get_event_cleanup_profile('lateral_movement')
    
    result = cleaner.generate_phantom_cleaner(
        target_events=profile['events'].get('Security', []),
        log_type='Security',
        time_range_hours=time_range,
        keywords=profile.get('keywords', [])
    )
    
    result['profile'] = profile
    return jsonify(result)


@god_mode_bp.route('/api/quick-action/full-cleanup', methods=['POST'])
def quick_full_cleanup():
    """Hızlı: Tam temizlik"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    time_range = data.get('time_range_hours', 48)
    
    cleaner = PhantomEventLogCleaner()
    profile = cleaner.get_event_cleanup_profile('full_cleanup')
    
    results = {}
    for log_type, events in profile['events'].items():
        if log_type in ['Security', 'System', 'PowerShell']:
            log_name = log_type if log_type != 'PowerShell' else 'Microsoft-Windows-PowerShell/Operational'
            results[log_type] = cleaner.generate_phantom_cleaner(
                target_events=events,
                log_type=log_name,
                time_range_hours=time_range
            )
    
    return jsonify({
        "profile": profile,
        "scripts": results
    })


# ============ MODULE INFO ============

@god_mode_bp.route('/api/info')
def get_module_info():
    """Modül bilgisi"""
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    god = GodModeAntiForensics()
    return jsonify(god.get_module_info())


# ============ DOWNLOAD ENDPOINTS ============

@god_mode_bp.route('/api/download/timestomp', methods=['POST'])
def download_timestomp():
    """Time Stomping scriptini indir"""
    from flask import Response
    
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    target_file = data.get('target_file', 'C:\\malware\\payload.exe')
    reference_file = data.get('reference_file', 'calc.exe')
    
    timestomp = TimeStomp()
    result = timestomp.generate_timestomp_powershell(
        target_file=target_file,
        source=TimestampSource.SYSTEM_FILE,
        reference_file=reference_file
    )
    
    return Response(
        result['script'],
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=timestomp.ps1'}
    )


@god_mode_bp.route('/api/download/phantom-cleaner', methods=['POST'])
def download_phantom_cleaner():
    """Phantom Cleaner scriptini indir"""
    from flask import Response
    
    if not GodModeAntiForensics:
        return jsonify({"error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    target_events = data.get('target_events', [4624, 4625, 4648, 4672, 4688])
    log_type = data.get('log_type', 'Security')
    time_range = data.get('time_range_hours', 24)
    
    cleaner = PhantomEventLogCleaner()
    result = cleaner.generate_phantom_cleaner(
        target_events=target_events,
        log_type=log_type,
        time_range_hours=time_range
    )
    
    return Response(
        result['script'],
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=phantom_cleaner.ps1'}
    )

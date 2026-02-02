"""
Orbital & RF Warfare Flask Routes
=================================
API endpoints for satellite downlink capture, GPS spoofing, and GSM monitoring.

Author: ITherso
"""

from flask import Blueprint, render_template, request, jsonify, Response
from flask_login import login_required
import json
import time
import queue
import threading
from datetime import datetime

# Import the RF Warfare module
import sys
sys.path.insert(0, '/home/kali/Desktop/tools')
from orbital_rf_warfare import (
    get_orbital_rf_warfare,
    SatelliteSystem,
    GSMBand,
    GPSSpoofMode
)

orbital_rf_bp = Blueprint('orbital_rf', __name__, url_prefix='/orbital-rf')

# SSE event queues for real-time updates
satcom_events = queue.Queue()
gsm_events = queue.Queue()


# =============================================================================
# MAIN DASHBOARD
# =============================================================================

@orbital_rf_bp.route('/')
@login_required
def orbital_rf_dashboard():
    """Main Orbital & RF Warfare dashboard"""
    warfare = get_orbital_rf_warfare()
    status = warfare.get_status()
    satellites = warfare.get_satellite_systems()
    gsm_bands = warfare.get_gsm_bands()
    gps_locations = warfare.gps_spoofer.get_famous_locations()
    
    return render_template(
        'orbital_rf_warfare.html',
        status=status,
        satellites=satellites,
        gsm_bands=gsm_bands,
        gps_locations=gps_locations
    )


# =============================================================================
# SDR DEVICE MANAGEMENT
# =============================================================================

@orbital_rf_bp.route('/api/status', methods=['GET'])
@login_required
def get_status():
    """Get overall module status"""
    warfare = get_orbital_rf_warfare()
    return jsonify(warfare.get_status())


@orbital_rf_bp.route('/api/devices/detect', methods=['POST'])
@login_required
def detect_devices():
    """Detect connected SDR devices"""
    warfare = get_orbital_rf_warfare()
    devices = warfare.sdr_manager.detect_devices()
    
    return jsonify({
        "success": True,
        "devices": [
            {
                "index": d.device_index,
                "name": d.device_name,
                "manufacturer": d.manufacturer,
                "serial": d.serial,
                "freq_range": d.supported_frequencies,
                "tx_capable": d.is_transmit_capable
            }
            for d in devices
        ]
    })


@orbital_rf_bp.route('/api/devices/select', methods=['POST'])
@login_required
def select_device():
    """Select an SDR device"""
    data = request.get_json()
    device_index = data.get('device_index', 0)
    
    warfare = get_orbital_rf_warfare()
    success = warfare.sdr_manager.select_device(device_index)
    
    return jsonify({
        "success": success,
        "device_index": device_index
    })


# =============================================================================
# SATCOM DOWNLINK SNIFFER
# =============================================================================

@orbital_rf_bp.route('/api/satcom/systems', methods=['GET'])
@login_required
def get_satellite_systems():
    """Get supported satellite systems"""
    warfare = get_orbital_rf_warfare()
    return jsonify(warfare.get_satellite_systems())


@orbital_rf_bp.route('/api/satcom/start', methods=['POST'])
@login_required
def start_satcom_capture():
    """Start satellite downlink capture"""
    data = request.get_json()
    system_name = data.get('system', 'iridium')
    duration = data.get('duration', 300)
    
    try:
        system = SatelliteSystem(system_name)
    except ValueError:
        return jsonify({
            "success": False,
            "error": f"Unknown satellite system: {system_name}"
        }), 400
    
    warfare = get_orbital_rf_warfare()
    
    # Live feed callback to push SSE events
    def live_callback(capture_data):
        satcom_events.put(capture_data)
    
    result = warfare.satcom_sniffer.start_capture(
        system,
        duration_seconds=duration,
        live_feed_callback=live_callback
    )
    
    return jsonify(result)


@orbital_rf_bp.route('/api/satcom/stop', methods=['POST'])
@login_required
def stop_satcom_capture():
    """Stop satellite capture"""
    warfare = get_orbital_rf_warfare()
    result = warfare.satcom_sniffer.stop_capture()
    return jsonify(result)


@orbital_rf_bp.route('/api/satcom/captures', methods=['GET'])
@login_required
def get_satcom_captures():
    """Get captured satellite data"""
    limit = request.args.get('limit', 100, type=int)
    warfare = get_orbital_rf_warfare()
    captures = warfare.satcom_sniffer.get_captures(limit)
    return jsonify(captures)


@orbital_rf_bp.route('/api/satcom/stats', methods=['GET'])
@login_required
def get_satcom_stats():
    """Get satellite capture statistics"""
    warfare = get_orbital_rf_warfare()
    stats = warfare.satcom_sniffer.get_live_stats()
    return jsonify(stats)


@orbital_rf_bp.route('/api/satcom/stream')
@login_required
def satcom_stream():
    """SSE stream for live satellite captures"""
    def generate():
        while True:
            try:
                data = satcom_events.get(timeout=30)
                # Convert datetime objects for JSON
                if 'timestamp' in data:
                    if hasattr(data['timestamp'], 'isoformat'):
                        data['timestamp'] = data['timestamp'].isoformat()
                yield f"data: {json.dumps(data)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat', 'time': datetime.now().isoformat()})}\n\n"
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    )


# =============================================================================
# GPS SPOOFING
# =============================================================================

@orbital_rf_bp.route('/api/gps/locations', methods=['GET'])
@login_required
def get_gps_locations():
    """Get famous no-fly zone locations"""
    warfare = get_orbital_rf_warfare()
    locations = warfare.gps_spoofer.get_famous_locations()
    
    formatted = []
    for name, coords in locations.items():
        formatted.append({
            "id": name,
            "name": name.replace("_", " ").title(),
            "lat": coords[0],
            "lon": coords[1],
            "alt": coords[2]
        })
    
    return jsonify(formatted)


@orbital_rf_bp.route('/api/gps/check-hardware', methods=['GET'])
@login_required
def check_gps_hardware():
    """Check if TX-capable hardware is available"""
    warfare = get_orbital_rf_warfare()
    result = warfare.gps_spoofer.check_hardware()
    return jsonify(result)


@orbital_rf_bp.route('/api/gps/configure', methods=['POST'])
@login_required
def configure_gps_spoof():
    """Configure GPS spoofing parameters"""
    data = request.get_json()
    
    location_name = data.get('location')
    custom_lat = data.get('lat')
    custom_lon = data.get('lon')
    custom_alt = data.get('alt')
    mode = data.get('mode', 'static')
    duration = data.get('duration', 60)
    
    try:
        spoof_mode = GPSSpoofMode(mode)
    except ValueError:
        spoof_mode = GPSSpoofMode.STATIC
    
    warfare = get_orbital_rf_warfare()
    result = warfare.gps_spoofer.generate_spoof_config(
        location_name=location_name,
        custom_lat=custom_lat,
        custom_lon=custom_lon,
        custom_alt=custom_alt,
        mode=spoof_mode,
        duration_seconds=duration
    )
    
    return jsonify(result)


@orbital_rf_bp.route('/api/gps/start', methods=['POST'])
@login_required
def start_gps_spoof():
    """Start GPS spoofing transmission"""
    warfare = get_orbital_rf_warfare()
    result = warfare.gps_spoofer.start_transmission()
    return jsonify(result)


@orbital_rf_bp.route('/api/gps/stop', methods=['POST'])
@login_required
def stop_gps_spoof():
    """Stop GPS spoofing transmission"""
    warfare = get_orbital_rf_warfare()
    result = warfare.gps_spoofer.stop_transmission()
    return jsonify(result)


# =============================================================================
# GSM IMSI CATCHER
# =============================================================================

@orbital_rf_bp.route('/api/gsm/bands', methods=['GET'])
@login_required
def get_gsm_bands():
    """Get supported GSM bands"""
    warfare = get_orbital_rf_warfare()
    return jsonify(warfare.get_gsm_bands())


@orbital_rf_bp.route('/api/gsm/scan', methods=['POST'])
@login_required
def scan_gsm_bands():
    """Scan for GSM base stations"""
    warfare = get_orbital_rf_warfare()
    result = warfare.gsm_monitor.scan_gsm_bands()
    return jsonify(result)


@orbital_rf_bp.route('/api/gsm/start', methods=['POST'])
@login_required
def start_gsm_monitor():
    """Start GSM IMSI monitoring"""
    data = request.get_json()
    band_name = data.get('band', 'gsm900')
    frequency = data.get('frequency')
    duration = data.get('duration', 300)
    
    # Map band name to enum
    band_map = {b.value[0]: b for b in GSMBand}
    band = band_map.get(band_name)
    
    if not band:
        return jsonify({
            "success": False,
            "error": f"Unknown GSM band: {band_name}"
        }), 400
    
    warfare = get_orbital_rf_warfare()
    result = warfare.gsm_monitor.start_monitoring(
        band,
        frequency_mhz=frequency,
        duration_seconds=duration
    )
    
    return jsonify(result)


@orbital_rf_bp.route('/api/gsm/stop', methods=['POST'])
@login_required
def stop_gsm_monitor():
    """Stop GSM monitoring"""
    warfare = get_orbital_rf_warfare()
    result = warfare.gsm_monitor.stop_monitoring()
    return jsonify(result)


@orbital_rf_bp.route('/api/gsm/records', methods=['GET'])
@login_required
def get_imsi_records():
    """Get captured IMSI records"""
    limit = request.args.get('limit', 100, type=int)
    warfare = get_orbital_rf_warfare()
    records = warfare.gsm_monitor.get_imsi_records(limit)
    return jsonify(records)


@orbital_rf_bp.route('/api/gsm/analysis', methods=['GET'])
@login_required
def get_imsi_analysis():
    """Get IMSI density analysis"""
    warfare = get_orbital_rf_warfare()
    analysis = warfare.gsm_monitor.get_density_analysis()
    return jsonify(analysis)


@orbital_rf_bp.route('/api/gsm/export', methods=['GET'])
@login_required
def export_imsi_data():
    """Export IMSI data to file"""
    format_type = request.args.get('format', 'json')
    
    warfare = get_orbital_rf_warfare()
    filepath = warfare.gsm_monitor.export_imsi_data(format=format_type)
    
    if filepath:
        return jsonify({
            "success": True,
            "filepath": filepath
        })
    else:
        return jsonify({
            "success": False,
            "error": "Export failed"
        }), 500


@orbital_rf_bp.route('/api/gsm/stream')
@login_required
def gsm_stream():
    """SSE stream for live IMSI captures"""
    def generate():
        warfare = get_orbital_rf_warfare()
        last_count = 0
        
        while True:
            time.sleep(2)
            
            records = warfare.gsm_monitor.get_imsi_records(limit=10)
            current_count = len(warfare.gsm_monitor.imsi_records)
            
            if current_count > last_count:
                # New records available
                new_records = records[-(current_count - last_count):]
                for record in new_records:
                    yield f"data: {json.dumps(record)}\n\n"
                last_count = current_count
            else:
                # Heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat', 'total': current_count})}\n\n"
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    )


# =============================================================================
# COMBINED OPERATIONS
# =============================================================================

@orbital_rf_bp.route('/api/quick-scan', methods=['POST'])
@login_required
def quick_rf_scan():
    """
    Perform quick RF environment scan
    
    Detects devices, scans GSM bands, and checks satellite frequencies.
    """
    warfare = get_orbital_rf_warfare()
    
    results = {
        "devices": [],
        "gsm_cells": [],
        "satellite_status": {}
    }
    
    # Detect devices
    devices = warfare.sdr_manager.detect_devices()
    results["devices"] = [
        {
            "name": d.device_name,
            "tx_capable": d.is_transmit_capable
        }
        for d in devices
    ]
    
    # If device available, scan GSM
    if devices:
        gsm_results = warfare.gsm_monitor.scan_gsm_bands()
        results["gsm_cells"] = gsm_results.get("strongest_cells", [])[:5]
    
    # Check satellite system availability
    for system in SatelliteSystem:
        config = warfare.satcom_sniffer.SATELLITE_CONFIGS.get(system, {})
        freq = config.get("center_freq_mhz", 0)
        
        # Check if any device can receive this frequency
        can_receive = any(
            d.supported_frequencies[0] <= freq <= d.supported_frequencies[1]
            for d in devices
        )
        
        results["satellite_status"][system.value] = {
            "frequency_mhz": freq,
            "supported": can_receive
        }
    
    return jsonify(results)


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@orbital_rf_bp.errorhandler(Exception)
def handle_error(error):
    """Global error handler for RF operations"""
    return jsonify({
        "success": False,
        "error": str(error),
        "type": type(error).__name__
    }), 500

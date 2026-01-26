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

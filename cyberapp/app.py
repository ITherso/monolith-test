from pathlib import Path

from flask import Flask
from cyberapp.routes.kerberos import kerberos_bp

from cyberapp.migrations import run_migrations
from cyberapp.settings import SECRET_KEY
from cyberapp.routes.monitoring import monitoring_bp
from cyberapp.routes.auth import auth_bp
from cyberapp.routes.dashboard import dashboard_bp
from cyberapp.routes.scans import scans_bp
from cyberapp.routes.phishing import phishing_bp
from cyberapp.routes.infra import infra_bp
from cyberapp.routes.ops import ops_bp
from cyberapp.routes.exploits import exploits_bp
from cyberapp.services.errors import register_error_handlers
from cyberapp.extensions import socketio


def create_app(run_migrations_on_start=True):
    templates_dir = Path(__file__).resolve().parents[1] / "templates"
    app = Flask(__name__, template_folder=str(templates_dir))
    app.secret_key = SECRET_KEY

    app.register_blueprint(monitoring_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(phishing_bp)
    app.register_blueprint(infra_bp)
    app.register_blueprint(ops_bp)
    app.register_blueprint(exploits_bp)
    app.register_blueprint(kerberos_bp)

    register_error_handlers(app)

    # SocketIO başlatma (None kontrolü ile)
    if socketio is not None:
        socketio.init_app(app)

    # Migration çalıştırma
    if run_migrations_on_start:
        run_migrations()

    return app
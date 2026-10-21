import os
from cyberapp.security import load_security_settings

DB_NAME = "monolith_supreme.db"
_security = load_security_settings()
SECRET_KEY = _security["FLASK_SECRET_KEY"]
ADMIN_USER = "admin"
ANALYST_USER = "analyst"

ADMIN_PASS = _security["ADMIN_PASS"]
ANALYST_PASS = _security["ANALYST_PASS"]

TIMEOUT = 60
try:
    _cpu = os.cpu_count() or 1
    MAX_THREADS = min(75, _cpu * 4)
except Exception:
    MAX_THREADS = 32
READ_LIMIT = 15 * 1024 * 1024
LHOST = "192.168.1.100"
LPORT = 4444
BLOCKCHAIN_NODE = "http://localhost:8545"
AI_MODEL_PATH = "/opt/monolith/models/vuln_predictor.pkl"

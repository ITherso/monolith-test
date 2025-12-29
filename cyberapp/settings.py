import os
import secrets

DB_NAME = "monolith_supreme.db"
SECRET_KEY = secrets.token_urlsafe(32)
ADMIN_USER = "admin"
ANALYST_USER = "analyst"

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

_env_admin = os.getenv("ADMIN_PASS")
_env_file = os.path.join(os.path.dirname(__file__), "../.env")

ADMIN_PASS = None
if _env_admin:
    ADMIN_PASS = _env_admin
elif os.path.exists(_env_file):
    try:
        with open(_env_file, "r") as ef:
            for line in ef:
                if line.strip().startswith("ADMIN_PASS="):
                    ADMIN_PASS = line.strip().split("=", 1)[1]
                    break
    except Exception:
        ADMIN_PASS = None

if not ADMIN_PASS:
    ADMIN_PASS = secrets.token_urlsafe(16)
    try:
        with open(_env_file, "a") as ef:
            ef.write(f"ADMIN_PASS={ADMIN_PASS}\n")
    except Exception:
        pass

_env_analyst = os.getenv("ANALYST_PASS")
ANALYST_PASS = None
if _env_analyst:
    ANALYST_PASS = _env_analyst
elif os.path.exists(_env_file):
    try:
        with open(_env_file, "r") as ef:
            for line in ef:
                if line.strip().startswith("ANALYST_PASS="):
                    ANALYST_PASS = line.strip().split("=", 1)[1]
                    break
    except Exception:
        ANALYST_PASS = None

if not ANALYST_PASS:
    ANALYST_PASS = secrets.token_urlsafe(16)
    try:
        with open(_env_file, "a") as ef:
            ef.write(f"ANALYST_PASS={ANALYST_PASS}\n")
    except Exception:
        pass

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

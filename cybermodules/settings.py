from dataclasses import dataclass

from cyberapp import settings


@dataclass(frozen=True)
class Settings:
    DB_NAME: str = settings.DB_NAME
    SECRET_KEY: str = settings.SECRET_KEY
    ADMIN_USER: str = settings.ADMIN_USER
    ADMIN_PASS: str = settings.ADMIN_PASS
    ANALYST_USER: str = settings.ANALYST_USER
    ANALYST_PASS: str = settings.ANALYST_PASS
    TIMEOUT: int = settings.TIMEOUT
    MAX_THREADS: int = settings.MAX_THREADS
    READ_LIMIT: int = settings.READ_LIMIT
    LHOST: str = settings.LHOST
    LPORT: int = settings.LPORT
    BLOCKCHAIN_NODE: str = settings.BLOCKCHAIN_NODE
    AI_MODEL_PATH: str = settings.AI_MODEL_PATH


settings = Settings()

# Backwards-compatible exports for existing modules.
DB_NAME = settings.DB_NAME
SECRET_KEY = settings.SECRET_KEY
ADMIN_USER = settings.ADMIN_USER
ADMIN_PASS = settings.ADMIN_PASS
ANALYST_USER = settings.ANALYST_USER
ANALYST_PASS = settings.ANALYST_PASS
TIMEOUT = settings.TIMEOUT
MAX_THREADS = settings.MAX_THREADS
READ_LIMIT = settings.READ_LIMIT
LHOST = settings.LHOST
LPORT = settings.LPORT
BLOCKCHAIN_NODE = settings.BLOCKCHAIN_NODE
AI_MODEL_PATH = settings.AI_MODEL_PATH

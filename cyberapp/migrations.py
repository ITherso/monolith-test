from pathlib import Path

try:
    from alembic import command
    from alembic.config import Config
except Exception:
    command = None
    Config = None

from cyberapp.settings import DB_NAME
from cyberapp.services.logger import get_logger

logger = get_logger("monolith.migrations")


def _alembic_config():
    if Config is None:
        return None
    root_dir = Path(__file__).resolve().parents[1]
    config_path = root_dir / "alembic.ini"
    config = Config(str(config_path))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{DB_NAME}")
    config.set_main_option("script_location", str(root_dir / "alembic_migrations"))
    return config


def run_migrations():
    if command is None:
        logger.warning("Alembic not installed; skipping migrations")
        return
    command.upgrade(_alembic_config(), "head")


def current_revision():
    if command is None:
        logger.warning("Alembic not installed; cannot show current revision")
        return
    command.current(_alembic_config())


def create_revision(message):
    if command is None:
        logger.warning("Alembic not installed; cannot create revision")
        return
    command.revision(_alembic_config(), message=message)

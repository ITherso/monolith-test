from pathlib import Path

try:
    from alembic import command
    from alembic.config import Config
except ImportError:
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
        raise RuntimeError("Alembic is required to initialize or upgrade the database")
    try:
        command.upgrade(_alembic_config(), "head")
    except Exception:
        logger.exception("Database migration failed")
        raise
    logger.info("Migrations completed successfully")


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

from pathlib import Path

try:
    from alembic import command
    from alembic.config import Config
except ImportError:
    command = None
    Config = None

from cyberapp.services.logger import get_logger
from cyberapp.settings import DB_NAME

logger = get_logger("monolith.migrations")


def _sqlite_url(db_path):
    if db_path == ":memory:":
        return "sqlite:///:memory:"
    return f"sqlite:///{Path(db_path).expanduser().resolve().as_posix()}"


def _alembic_config(db_path=None):
    if Config is None:
        return None
    root_dir = Path(__file__).resolve().parents[1]
    config_path = root_dir / "alembic.ini"
    config = Config(str(config_path)) if config_path.is_file() else Config()
    database_url = _sqlite_url(db_path or DB_NAME)
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    config.set_main_option("script_location", str(root_dir / "alembic_migrations"))
    return config


def run_migrations(db_path=None):
    if command is None:
        raise RuntimeError("Alembic is required to initialize or upgrade the database")
    try:
        command.upgrade(_alembic_config(db_path), "head")
    except Exception:
        logger.exception("Database migration failed")
        raise
    logger.info("Migrations completed successfully")


def current_revision(db_path=None):
    if command is None:
        logger.warning("Alembic not installed; cannot show current revision")
        return
    command.current(_alembic_config(db_path))


def create_revision(message, db_path=None):
    if command is None:
        logger.warning("Alembic not installed; cannot create revision")
        return
    command.revision(_alembic_config(db_path), message=message)

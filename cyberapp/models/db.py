import sqlite3
from contextlib import contextmanager

from flask import current_app, has_app_context

from cyberapp.settings import DB_NAME


def configured_database(db_path=None):
    """Resolve the database selected by the active app without changing globals."""
    if db_path is not None:
        return db_path
    if has_app_context():
        configured = current_app.config.get("DATABASE")
        if configured:
            return configured
    return DB_NAME


@contextmanager
def db_conn(db_path=None):
    conn = sqlite3.connect(configured_database(db_path))
    try:
        yield conn
    finally:
        conn.close()

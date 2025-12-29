from contextlib import contextmanager
import sqlite3

from cyberapp.settings import DB_NAME


@contextmanager
def db_conn(db_path=None):
    conn = sqlite3.connect(db_path or DB_NAME)
    try:
        yield conn
    finally:
        conn.close()

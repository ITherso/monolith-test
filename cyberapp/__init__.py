"""Monolith application package."""

from cyberapp.app import create_app  # noqa: F401
from cyberapp.extensions import socketio  # noqa: F401
from cyberapp.migrations import run_migrations  # noqa: F401

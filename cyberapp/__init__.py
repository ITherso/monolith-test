"""Monolith application package."""

__all__ = ["create_app", "create_management_app", "socketio", "run_migrations"]


def __getattr__(name):
    # Configuration and schema imports must not initialize every feature module.
    if name == "create_app":
        from cyberapp.app import create_app

        return create_app
    if name == "create_management_app":
        from cyberapp.management_app import create_management_app

        return create_management_app
    if name == "socketio":
        from cyberapp.extensions import socketio

        return socketio
    if name == "run_migrations":
        from cyberapp.migrations import run_migrations

        return run_migrations
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

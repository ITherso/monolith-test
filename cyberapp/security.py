"""Persistent defaults for management-panel credentials and signed sessions."""

import json
import os
import secrets
import tempfile
from pathlib import Path


def load_security_settings(root=None, environ=None):
    """Honor explicit configuration; generate missing secrets once, across workers."""
    root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    use_process_environment = environ is None
    environ = os.environ if use_process_environment else environ
    configured = {}
    env_file = root / ".env"
    if env_file.exists():
        from dotenv import dotenv_values, load_dotenv

        if use_process_environment:
            # Other existing services still read their configuration via getenv.
            load_dotenv(env_file, override=False)
        configured.update(dotenv_values(env_file, interpolate=False))
    configured.update(environ)
    names = ("FLASK_SECRET_KEY", "ADMIN_PASS", "ANALYST_PASS")
    if configured.get("FLASK_SECRET_KEY") == "default-dev-key-change-in-production":
        raise ValueError(
            "Replace the public development FLASK_SECRET_KEY before starting"
        )
    missing = [name for name in names if not configured.get(name)]
    if not missing:
        return {name: configured[name] for name in names}

    instance = root / "instance"
    instance.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = instance / "security.json"
    if not path.exists():
        # Publish a complete file atomically. A concurrent worker uses the winner's
        # file instead of generating a different session key or truncating it.
        fd, temporary = tempfile.mkstemp(prefix=".security-", dir=instance)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({name: secrets.token_urlsafe(32) for name in names}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary)
    try:
        with path.open(encoding="utf-8") as stream:
            generated = json.load(stream)
        if not isinstance(generated, dict) or any(
            not isinstance(generated.get(name), str) or len(generated[name]) < 32
            for name in missing
        ):
            raise ValueError("Invalid generated secret data")
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "Cannot read instance/security.json; restore a valid file"
        ) from exc
    return {name: configured.get(name) or generated[name] for name in names}

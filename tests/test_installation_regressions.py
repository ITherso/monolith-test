"""Schema and packaging checks that never import or start application modules."""

import ast
import importlib.util
import logging
import sqlite3
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parents[1]
HEAD = "0006_merge_schema_heads"


@pytest.fixture
def migrations(monkeypatch, tmp_path):
    # Loading the package normally imports the app and all its optional modules.
    # Supply only the configuration and logger needed by the schema wrapper.
    settings = ModuleType("cyberapp.settings")
    settings.DB_NAME = str(tmp_path / "schema.sqlite3")
    logger = ModuleType("cyberapp.services.logger")
    logger.get_logger = logging.getLogger
    monkeypatch.setitem(sys.modules, settings.__name__, settings)
    monkeypatch.setitem(sys.modules, logger.__name__, logger)

    spec = importlib.util.spec_from_file_location(
        "installation_migrations", ROOT / "cyberapp" / "migrations.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "previous_revision", [None, "0005_add_ai_post_exploit", "0005_lateral_extended"]
)
def test_schema_upgrades_from_fresh_and_both_branches(migrations, previous_revision):
    config = migrations._alembic_config()
    assert ScriptDirectory.from_config(config).get_heads() == [HEAD]

    if previous_revision:
        migrations.command.upgrade(config, previous_revision)
        with sqlite3.connect(migrations.DB_NAME) as conn:
            conn.execute("INSERT INTO scans (id, target) VALUES (1, 'schema-test')")
            conn.execute(
                "INSERT INTO lateral_movement (id, scan_id, source_host) "
                "VALUES (1, 1, 'existing-source')"
            )

    migrations.run_migrations()
    migrations.run_migrations()  # Re-running an applied upgrade must be harmless.

    with sqlite3.connect(migrations.DB_NAME) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchall() == [
            (HEAD,)
        ]
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "ai_post_exploit_analysis",
            "priv_esc_vectors",
            "lateral_movement",
        } <= tables
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(lateral_movement)")
        }
        assert {
            "source_host",
            "error_message",
            "command_output",
            "execution_time",
            "credentials_type",
            "access_level",
        } <= columns
        if previous_revision:
            assert conn.execute(
                "SELECT source_host FROM lateral_movement WHERE id=1"
            ).fetchone() == ("existing-source",)


def test_downgrade_preserves_column_owned_by_earlier_revision(migrations):
    migrations.run_migrations()
    migrations.command.downgrade(migrations._alembic_config(), "0004_add_loot_exfil")
    with sqlite3.connect(migrations.DB_NAME) as conn:
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(lateral_movement)")
        }
    assert "source_host" in columns
    assert "error_message" not in columns


def test_migration_failure_is_not_reported_as_success(migrations, monkeypatch):
    def fail_upgrade(*args, **kwargs):
        raise RuntimeError("schema upgrade failed")

    monkeypatch.setattr(migrations.command, "upgrade", fail_upgrade)
    with pytest.raises(RuntimeError, match="schema upgrade failed"):
        migrations.run_migrations()


def test_missing_alembic_is_not_silently_skipped(migrations, monkeypatch):
    monkeypatch.setattr(migrations, "command", None)
    with pytest.raises(RuntimeError, match="Alembic is required"):
        migrations.run_migrations()


def test_container_ports_and_healthcheck_match_cli():
    cli = ast.parse((ROOT / "cyberapp" / "cli.py").read_text(encoding="utf-8"))
    run_call = next(
        node
        for node in ast.walk(cli)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "app"
        and node.func.attr == "run"
    )
    port = ast.literal_eval(
        next(kw.value for kw in run_call.keywords if kw.arg == "port")
    )
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    app = compose["services"]["app"]
    assert app["ports"] == [f"5000:{port}"]
    assert app["environment"]["MONOLITH_PORT"] == str(port)
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert f"EXPOSE {port}" in dockerfile
    assert f"http://localhost:{port}/health" in dockerfile

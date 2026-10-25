"""Read-only panel status responses with inert modules and temporary SQLite."""

import ast
import importlib.util
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from flask import Flask, url_for

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = "/api/management/scans/1/status"
LEGACY = "/scan_status/1"


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extracted_alias():
    source = ROOT / "cyberapp/routes/scans.py"
    function = next(
        node
        for node in ast.parse(source.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name == "scan_status"
    )
    function.decorator_list = []
    namespace = {}
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    return namespace["scan_status"]


def login(client, role="analyst"):
    with client.session_transaction() as session:
        session.update(logged_in=True, user="panel-fixture", role=role)


@pytest.fixture
def panel():
    database = sqlite3.connect(":memory:")
    database.executescript(
        "CREATE TABLE scans(id INTEGER PRIMARY KEY, status, target);"
        "CREATE TABLE scan_progress(scan_id INTEGER PRIMARY KEY, progress, eta_seconds);"
        "CREATE TABLE vulns(id INTEGER PRIMARY KEY, scan_id INTEGER);"
        "INSERT INTO scans VALUES(1,'RUNNING','must-not-be-fetched.invalid');"
        "INSERT INTO scan_progress VALUES(1,45.5,0);"
        "INSERT INTO vulns VALUES(1,1);"
        "INSERT INTO vulns VALUES(2,1);"
    )

    @contextmanager
    def factory():
        yield database

    db_stub = ModuleType("cyberapp.models.db")
    db_stub.db_conn = Mock(side_effect=factory)
    stubs = {"cyberapp.models.db": db_stub}
    for name in ("cyberapp", "cyberapp.models", "cyberapp.routes"):
        package = ModuleType(name)
        package.__path__ = []
        stubs[name] = package
    with patch.dict(sys.modules, stubs):
        monitoring = load("isolated_panel_monitoring", "cyberapp/routes/monitoring.py")
        authorization = load(
            "isolated_panel_authorization", "cyberapp/authorization.py"
        )
        sys.modules["cyberapp.routes.monitoring"] = monitoring
        alias = extracted_alias()

        def make_app(alias_first=True):
            app = Flask("panel-connection-fixture")
            app.config.update(TESTING=True, SECRET_KEY="panel-fixture-only")
            authorization.install_admin_access_control(app)

            def add_alias():
                app.add_url_rule(
                    "/scan_status/<int:scan_id>", "scans.scan_status", alias
                )

            if alias_first:
                add_alias()
            app.register_blueprint(monitoring.monitoring_bp)
            if not alias_first:
                add_alias()
            return app

        app = make_app()
        client = app.test_client()
        login(client)
        yield SimpleNamespace(
            database=database,
            module=monitoring,
            factory=db_stub.db_conn,
            client=client,
            app=app,
            make_app=make_app,
        )
    database.close()


def assert_response(response, code):
    assert response.status_code == code
    assert response.mimetype == "application/json"
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("alias_first", [False, True])
def test_alias_registration_order_cannot_change_contract(panel, alias_first):
    app = panel.make_app(alias_first)
    client = app.test_client()
    login(client)
    canonical = client.get(CANONICAL)
    legacy = client.get(LEGACY)
    assert_response(canonical, 200)
    assert_response(legacy, 200)
    assert (
        canonical.json
        == legacy.json
        == {
            "scan_id": 1,
            "status": "RUNNING",
            "target": "must-not-be-fetched.invalid",
            "progress": 45.5,
            "progress_available": True,
            "eta_seconds": 0,
            "eta_available": True,
            "vuln_count": 2,
        }
    )


def test_url_builder_prefers_canonical_api_and_preserves_mount_prefix(panel):
    with panel.app.test_request_context(
        "/", environ_overrides={"SCRIPT_NAME": "/panel"}
    ):
        assert url_for("monitoring.scan_status", scan_id=1) == "/panel" + CANONICAL


@pytest.mark.parametrize("path", [CANONICAL, LEGACY])
def test_expired_session_gets_json_401_without_database_access(panel, path):
    with panel.client.session_transaction() as session:
        session.clear()
    response = panel.client.get(path, headers={"Accept": "application/json"})
    assert_response(response, 401)
    assert response.json == {"error": "login_required"}
    assert not response.history
    panel.factory.assert_not_called()


@pytest.mark.parametrize("role", ["analyst", "admin"])
def test_authenticated_readers_can_read_status(panel, role):
    login(panel.client, role)
    assert_response(panel.client.get(CANONICAL), 200)


def test_post_is_not_a_scan_start_or_write_endpoint(panel):
    assert panel.client.post(CANONICAL).status_code == 405
    panel.factory.assert_not_called()


@pytest.mark.parametrize("identifier", [0, 2**63, 10**100])
def test_invalid_id_is_400_without_database_access(panel, identifier):
    response = panel.client.get(f"/api/management/scans/{identifier}/status")
    assert_response(response, 400)
    assert response.json == {"error": "invalid_scan_id"}
    panel.factory.assert_not_called()


@pytest.mark.parametrize("path", ["/api/management/scans/99/status", "/scan_status/99"])
def test_missing_scan_is_404_instead_of_unknown_success(panel, path):
    response = panel.client.get(path)
    assert_response(response, 404)
    assert response.json == {"error": "not_found"}


def test_missing_progress_remains_unknown_even_for_completed_record(panel):
    panel.database.execute("DELETE FROM scan_progress")
    panel.database.execute("UPDATE scans SET status='COMPLETED'")
    response = panel.client.get(CANONICAL)
    assert_response(response, 200)
    assert response.json["status"] == "COMPLETED"
    assert response.json["progress"] == 0
    assert response.json["progress_available"] is False
    assert response.json["eta_seconds"] is None
    assert response.json["eta_available"] is False


@pytest.mark.parametrize(
    "progress,expected,available",
    [
        (None, 0, False),
        ("bad", 0, False),
        (b"bad", 0, False),
        (float("inf"), 0, False),
        (-8, 0, True),
        (130, 100, True),
        (0, 0, True),
        (99.25, 99.25, True),
    ],
)
def test_progress_is_finite_typed_and_bounded(panel, progress, expected, available):
    panel.database.execute("UPDATE scan_progress SET progress=?", (progress,))
    response = panel.client.get(CANONICAL)
    assert_response(response, 200)
    assert response.json["progress"] == expected
    assert response.json["progress_available"] is available


@pytest.mark.parametrize("eta", [None, -1, "later", b"later", float("inf")])
def test_invalid_eta_is_unavailable(panel, eta):
    panel.database.execute("UPDATE scan_progress SET eta_seconds=?", (eta,))
    response = panel.client.get(CANONICAL)
    assert response.json["eta_seconds"] is None
    assert response.json["eta_available"] is False


@pytest.mark.parametrize("status,target", [(None, None), (42, b"blob"), (" ", 0)])
def test_invalid_record_text_is_not_interpreted_or_echoed_as_objects(
    panel, status, target
):
    panel.database.execute("UPDATE scans SET status=?,target=?", (status, target))
    response = panel.client.get(CANONICAL)
    assert_response(response, 200)
    assert response.json["status"] == "UNKNOWN"
    assert response.json["target"] == ""


def test_large_or_wrong_typed_database_values_are_bounded_in_sql(panel):
    large = "x" * 100_000
    panel.database.execute(
        "UPDATE scans SET status=?, target=? WHERE id=1", (large, large)
    )
    panel.database.execute(
        "UPDATE scan_progress SET progress=?, eta_seconds=? WHERE scan_id=1",
        (large, large),
    )
    response = panel.client.get(CANONICAL)
    assert_response(response, 200)
    assert response.json["status"] == "x" * 256
    assert response.json["target"] == "x" * 2048
    assert response.json["progress_available"] is False
    assert response.json["eta_available"] is False
    assert large not in response.get_data(as_text=True)


def test_database_failure_is_generic_503_without_credentials_or_paths(panel):
    with patch.object(
        panel.module,
        "db_conn",
        side_effect=RuntimeError("secret-db-password C:/private/db.sqlite"),
    ):
        response = panel.client.get(CANONICAL)
    assert_response(response, 503)
    assert response.json == {"error": "scan_status_unavailable"}
    assert b"secret" not in response.data
    assert b"private" not in response.data


def test_metrics_reports_recorded_counts_and_exact_running_prefixes(panel):
    panel.database.executemany(
        "INSERT INTO scans VALUES(?,?,?)",
        (
            (2, "NOT_RUNNING", "finished.invalid"),
            (3, "HAZIRLANIYOR...", "preparing.invalid"),
            (4, " devam ediyor", "active.invalid"),
            (5, "REHAZIRLANIYOR", "finished-too.invalid"),
            (6, None, "unknown.invalid"),
        ),
    )

    response = panel.client.get("/metrics")

    assert_response(response, 200)
    assert response.json == {
        "scans_total": 6,
        "vulns_total": 2,
        "running_scans": 3,
    }


def test_metrics_database_failure_is_generic_and_never_cached(panel):
    with patch.object(
        panel.module,
        "db_conn",
        side_effect=RuntimeError("secret-db-password C:/private/db.sqlite"),
    ):
        response = panel.client.get("/metrics")

    assert_response(response, 503)
    assert response.json == {"error": "metrics_unavailable"}
    assert b"secret" not in response.data
    assert b"private" not in response.data


def test_metrics_is_read_only(panel):
    snapshot = tuple(panel.database.iterdump())
    panel.client.get("/metrics")
    assert tuple(panel.database.iterdump()) == snapshot


def test_read_only_endpoint_preserves_all_recorded_data(panel):
    before = panel.database.iterdump()
    snapshot = tuple(before)
    panel.client.get(CANONICAL)
    panel.client.get(LEGACY)
    assert tuple(panel.database.iterdump()) == snapshot


def test_monitoring_import_boundary_is_stdlib_flask_and_inert_database_only():
    tree = ast.parse(
        (ROOT / "cyberapp/routes/monitoring.py").read_text(encoding="utf-8")
    )
    imports = {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert imports == {"flask", "markupsafe", "cyberapp.models.db"}
    assert {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } == {"math"}

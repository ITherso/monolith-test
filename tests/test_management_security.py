"""Management regressions in isolated Flask apps; no feature modules are loaded."""

import ast
import importlib.util
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest
from flask import Blueprint, Flask, jsonify
from jinja2 import DictLoader

ROOT = Path(__file__).resolve().parents[1]


def load_file(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def settings_stub():
    module = ModuleType("cyberapp.settings")
    module.SECRET_KEY = "test-signing-key-with-sufficient-entropy"
    module.ADMIN_USER, module.ADMIN_PASS = "admin", "configured-admin-password"
    module.ANALYST_USER, module.ANALYST_PASS = "analyst", "configured-analyst-password"
    return module


@pytest.fixture
def security():
    return load_file("isolated_security", "cyberapp/security.py")


def test_generated_defaults_survive_restart_and_are_distinct(tmp_path, security):
    first = security.load_security_settings(tmp_path, {})
    second = security.load_security_settings(tmp_path, {})
    assert first == second
    assert len(set(first.values())) == 3
    assert all(len(value) >= 32 for value in first.values())
    assert not (tmp_path / ".env").exists()


def test_partial_override_does_not_rotate_other_generated_secrets(tmp_path, security):
    first = security.load_security_settings(tmp_path, {})
    changed = security.load_security_settings(
        tmp_path, {"ADMIN_PASS": "new-explicit-admin"}
    )
    assert changed["ADMIN_PASS"] == "new-explicit-admin"
    assert changed["FLASK_SECRET_KEY"] == first["FLASK_SECRET_KEY"]
    assert changed["ANALYST_PASS"] == first["ANALYST_PASS"]


def test_parallel_workers_share_one_complete_secret_file(tmp_path, security):
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: security.load_security_settings(tmp_path, {}), range(16))
        )
    assert all(result == results[0] for result in results)
    assert json.loads((tmp_path / "instance/security.json").read_text()) == results[0]
    assert not list((tmp_path / "instance").glob(".security-*"))


def test_explicit_configuration_and_dotenv_are_preserved(tmp_path, security):
    (tmp_path / ".env").write_text(
        'ADMIN_PASS="existing password"\nANALYST_PASS=existing-analyst\n'
        'FLASK_SECRET_KEY=existing-private-session-key\n',
        encoding="utf-8",
    )
    result = security.load_security_settings(
        tmp_path, {"ANALYST_PASS": "environment-wins"}
    )
    assert result == {
        "ADMIN_PASS": "existing password",
        "ANALYST_PASS": "environment-wins",
        "FLASK_SECRET_KEY": "existing-private-session-key",
    }
    assert not (tmp_path / "instance").exists()


def test_dotenv_still_configures_other_services_without_overriding_environment(
    tmp_path, security
):
    (tmp_path / ".env").write_text(
        "MONOLITH_QUEUE=rq\nREDIS_URL=redis://configured/1\nSESSION_COOKIE_SECURE=true\n"
        "TEST_SECRET_VALUE=expanded-config-value\nADMIN_PASS=${TEST_SECRET_VALUE}\n",
        encoding="utf-8",
    )
    with patch.dict(os.environ, {"REDIS_URL": "redis://environment/2"}, clear=True):
        values = security.load_security_settings(tmp_path)
        assert values["ADMIN_PASS"] == "expanded-config-value"
        assert os.getenv("MONOLITH_QUEUE") == "rq"
        assert os.getenv("SESSION_COOKIE_SECURE") == "true"
        assert os.getenv("REDIS_URL") == "redis://environment/2"


def test_public_signing_key_and_corrupt_secret_file_fail_closed(tmp_path, security):
    with pytest.raises(ValueError, match="public development"):
        security.load_security_settings(
            tmp_path, {"FLASK_SECRET_KEY": "default-dev-key-change-in-production"}
        )
    (tmp_path / "instance").mkdir()
    (tmp_path / "instance/security.json").write_text("not-json")
    with pytest.raises(RuntimeError, match="security.json"):
        security.load_security_settings(tmp_path, {})


@pytest.fixture
def auth_client():
    settings = settings_stub()
    audit = ModuleType("cyberapp.services.audit")
    audit.log_audit = lambda *args: None
    with patch.dict(
        sys.modules, {"cyberapp.settings": settings, "cyberapp.services.audit": audit}
    ):
        auth = load_file("isolated_auth", "cyberapp/routes/auth.py")
    app = Flask("auth-test")
    app.config.update(TESTING=True, SECRET_KEY=settings.SECRET_KEY)
    app.jinja_loader = DictLoader({"login.html": "Login"})
    app.register_blueprint(auth.auth_bp)
    return app.test_client(), settings


@pytest.mark.parametrize("account,role", [("ADMIN", "admin"), ("ANALYST", "analyst")])
def test_configured_accounts_keep_login_contract(auth_client, account, role):
    client, settings = auth_client
    with client.session_transaction() as session:
        session["stale"] = True
    response = client.post(
        "/login",
        data={
            "user": getattr(settings, account + "_USER"),
            "pass": getattr(settings, account + "_PASS"),
        },
    )
    assert response.status_code == 302 and response.location == "/"
    with client.session_transaction() as session:
        assert session["logged_in"] is True
        assert session["role"] == role
        assert "stale" not in session
    assert client.get("/logout").status_code == 302
    with client.session_transaction() as session:
        assert not session


def test_unicode_passwords_keep_working(auth_client):
    client, settings = auth_client
    settings.ADMIN_PASS = "özelleştirilmiş-parola-🔑"
    # auth.py imports configured values once, just as it does at process startup.
    audit = ModuleType("cyberapp.services.audit")
    audit.log_audit = lambda *args: None
    with patch.dict(
        sys.modules, {"cyberapp.settings": settings, "cyberapp.services.audit": audit}
    ):
        auth = load_file("unicode_auth", "cyberapp/routes/auth.py")
    app = Flask("unicode-auth")
    app.config.update(TESTING=True, SECRET_KEY=settings.SECRET_KEY)
    app.register_blueprint(auth.auth_bp)
    assert (
        app.test_client()
        .post("/login", data={"user": "admin", "pass": settings.ADMIN_PASS})
        .status_code
        == 302
    )


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"user": "admin", "pass": "wrong"},
        {"user": "' OR '1'='1' --", "pass": "irrelevant"},
    ],
)
def test_bad_credentials_cannot_keep_or_create_authenticated_session(auth_client, data):
    client, _ = auth_client
    with client.session_transaction() as session:
        session.update(logged_in=True, role="admin")
    assert client.post("/login", data=data).status_code == 200
    with client.session_transaction() as session:
        assert not session.get("logged_in")


def build_management_app(failure=None, soc_failure=False):
    """Exercise the real factory with inert replacement blueprints only."""
    calls = []
    modules = {}

    def import_blueprint(path):
        calls.append(path)
        if path == failure:
            raise ImportError("test missing module")

        class BlueprintModule:
            def __init__(self):
                self.blueprints = {}

            def __getattr__(self, name):
                if name not in self.blueprints:
                    self.blueprints[name] = Blueprint(
                        path.replace(".", "_") + "_" + name, __name__
                    )
                return self.blueprints[name]

        if path not in modules:
            modules[path] = BlueprintModule()
        return modules[path]

    soc = ModuleType("evasion.soc_deception")
    if not soc_failure:
        soc.soc_deception_bp = Blueprint("test_soc", __name__)
    errors = ModuleType("cyberapp.services.errors")
    errors.register_error_handlers = lambda app: None
    safety = ModuleType("cyberapp.host_safety")
    safety.enforce_host_safety = lambda: None
    stubs = {
        "evasion.soc_deception": soc,
        "cyberapp.settings": settings_stub(),
        "cyberapp.services.errors": errors,
        "cyberapp.host_safety": safety,
    }
    # Even an accidental package import cannot reach an on-disk feature module.
    for package in ("evasion", "cybermodules", "tools", "cyberapp"):
        stub = ModuleType(package)
        stub.__path__ = []
        stubs[package] = stub
    with patch.dict(sys.modules, stubs):
        with patch("importlib.import_module", side_effect=import_blueprint):
            module = load_file("isolated_management_app", "cyberapp/app.py")
        app = module.create_app(False, {"TESTING": True})
    return app, calls


def test_management_app_excludes_training_routes_and_keeps_health_alias():
    app, calls = build_management_app()
    assert not any(path.endswith((".vulnerable", ".api_vulnerable")) for path in calls)
    assert not {"vulnerable", "api_vuln"}.intersection(app.blueprints)
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    client = app.test_client()
    for path in ("/vuln/", "/api/v1/internal/debug"):
        assert client.get(path).status_code == 404
    for path in ("/health", "/api/elite/orchestration/health"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json["production_ready"] is False
    assert app.config["PRODUCTION_READY"] is False


def test_health_reports_missing_feature_instead_of_false_success():
    app, _ = build_management_app(failure="cyberapp.routes.cloud_assets")
    response = app.test_client().get("/health")
    assert response.status_code == 503
    assert response.json["status"] == "DEGRADED"
    assert response.json["failed_blueprint_count"] == 1


def test_health_reports_special_import_failure():
    app, _ = build_management_app(soc_failure=True)
    response = app.test_client().get("/health")
    assert response.status_code == 503
    assert response.json["failed_blueprint_count"] == 1


def test_debug_response_never_includes_process_secrets():
    path = ROOT / "cyberapp/routes/api_vulnerable.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "internal_debug"
    )
    function.decorator_list = []
    namespace = {"jsonify": jsonify, "os": os}
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"),
        namespace,
    )
    with (
        Flask("debug-test").app_context(),
        patch.dict(os.environ, {"PRIVATE_TEST_KEY": "must-not-leak"}),
    ):
        response = namespace["internal_debug"]()
        assert "must-not-leak" not in response.get_data(as_text=True)
        assert response.json["environment"] == {"redacted": True}


def test_package_import_does_not_initialize_feature_modules():
    tree = ast.parse((ROOT / "cyberapp/__init__.py").read_text(encoding="utf-8"))
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in tree.body)

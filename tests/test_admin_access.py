"""Access-control contracts with inert Flask handlers; no feature modules run."""

import ast
import importlib.util
from pathlib import Path

import pytest
from flask import Blueprint, Flask, session

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def authorization():
    spec = importlib.util.spec_from_file_location(
        "isolated_authorization", ROOT / "cyberapp/authorization.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def protected_app(authorization):
    app = Flask("admin-access-test")
    app.config.update(TESTING=True, SECRET_KEY="isolated-admin-contract-only")
    entered = []

    def handler(name):
        def inert_handler():
            entered.append(name)
            return {"entered": name}

        return inert_handler

    blueprints = {
        "auth": (("/login", "login"), ("/logout", "logout")),
        "dashboard": (("/", "index"), ("/attack-playground", "attack_playground")),
        "feature_status": (("/feature-status", "feature_status_page"),),
        "ops": (("/threathunter/events", "start_threathunter"),),
        "scans": (("/scans", "scans_list"), ("/payloads", "payloads_generator")),
        "c2": (("/c2", "index"), ("/api/c2/run", "run")),
        "evasion": (("/evasion", "index"),),
        "persistence": (("/persistence", "index"),),
    }
    for name, routes in blueprints.items():
        blueprint = Blueprint(name, __name__)
        for path, endpoint in routes:
            blueprint.add_url_rule(
                path,
                endpoint,
                handler(f"{name}.{endpoint}"),
                methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            )
        app.register_blueprint(blueprint)
    app.add_url_rule(
        "/health", "orchestration_health_check", handler("health"), methods=["GET"]
    )
    app.add_url_rule("/direct-operation", "direct_operation", handler("direct"))
    authorization.install_admin_access_control(app)
    late = Blueprint("future_module", __name__)
    late.add_url_rule("/future-operation", "operation", handler("late"))
    app.register_blueprint(late)
    return app, app.test_client(), entered


def set_session(client, **values):
    with client.session_transaction() as current:
        current.clear()
        current.update(values)


def login(client, role="analyst"):
    set_session(client, logged_in=True, user="configured-test-user", role=role)


@pytest.mark.parametrize("path", ["/login", "/logout", "/health"])
def test_public_management_routes_keep_working(protected_app, path):
    _, client, entered = protected_app
    assert client.get(path).status_code == 200
    assert len(entered) == 1


@pytest.mark.parametrize(
    "path", ["/", "/feature-status", "/threathunter/events", "/scans"]
)
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_analyst_retains_read_access_to_reviewed_management_views(
    protected_app, path, method
):
    _, client, _ = protected_app
    login(client)
    assert client.open(path, method=method).status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/c2",
        "/api/c2/run",
        "/evasion",
        "/persistence",
        "/payloads",
        "/attack-playground",
        "/direct-operation",
        "/future-operation",
    ],
)
def test_non_admin_cannot_enter_any_sensitive_or_new_handler(protected_app, path):
    _, client, entered = protected_app
    login(client)
    response = client.get(path)
    assert response.status_code == 403
    assert entered == []


@pytest.mark.parametrize("role", ["analyst", "viewer", "ADMIN", "", None])
def test_only_exact_admin_role_is_authorized(protected_app, role):
    _, client, entered = protected_app
    login(client, role)
    response = client.post("/api/c2/run", json={"role": "admin"})
    assert response.status_code == 403
    assert response.json == {"error": "admin_required"}
    assert entered == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_reader_allowlist_does_not_authorize_mutating_methods(protected_app, method):
    _, client, entered = protected_app
    login(client)
    response = client.open("/feature-status", method=method)
    assert response.status_code == 403
    assert response.json == {"error": "admin_required"}
    assert entered == []


@pytest.mark.parametrize(
    "path,method,kwargs,status",
    [
        ("/c2", "GET", {}, 302),
        ("/c2", "GET", {"headers": {"Accept": "application/json"}}, 401),
        ("/c2", "GET", {"json": {"anything": True}}, 401),
        ("/api/c2/run", "GET", {}, 401),
        ("/c2", "POST", {}, 401),
        ("/c2", "OPTIONS", {}, 401),
        ("/feature-status", "GET", {}, 302),
    ],
)
def test_unauthenticated_requests_stop_before_handler(
    protected_app, path, method, kwargs, status
):
    _, client, entered = protected_app
    response = client.open(path, method=method, **kwargs)
    assert response.status_code == status
    assert response.headers["Cache-Control"] == "no-store"
    if status == 302:
        assert response.headers["Location"] == "/login"
    else:
        assert response.json == {"error": "login_required"}
    assert entered == []


def test_login_redirect_preserves_mount_prefix(protected_app):
    _, client, entered = protected_app
    response = client.get("/c2", environ_overrides={"SCRIPT_NAME": "/panel"})
    assert response.status_code == 302
    assert response.headers["Location"] == "/panel/login"
    assert entered == []
    hostile = client.get("/c2", environ_overrides={"SCRIPT_NAME": "//evil.invalid"})
    assert hostile.status_code == 302
    assert hostile.headers["Location"] == "/login"


@pytest.mark.parametrize(
    "claims",
    [
        {"logged_in": False, "user": "admin", "role": "admin"},
        {"logged_in": "true", "user": "admin", "role": "admin"},
        {"logged_in": 1, "user": "admin", "role": "admin"},
        {"logged_in": True, "user": "", "role": "admin"},
        {"logged_in": True, "user": None, "role": "admin"},
        {"logged_in": True, "user": 123, "role": "admin"},
        {"logged_in": True, "role": "admin"},
    ],
)
def test_partial_or_malformed_sessions_are_not_authenticated(protected_app, claims):
    _, client, entered = protected_app
    set_session(client, **claims)
    response = client.get("/api/c2/run")
    assert response.status_code == 401
    assert response.json == {"error": "login_required"}
    assert entered == []


def test_role_headers_query_and_body_cannot_upgrade_analyst(protected_app):
    _, client, entered = protected_app
    login(client)
    response = client.post(
        "/api/c2/run?role=admin&logged_in=true",
        json={"role": "admin", "user": "admin", "logged_in": True},
        headers={"X-Role": "admin", "X-User": "admin", "X-Admin": "true"},
    )
    assert response.status_code == 403
    assert response.json == {"error": "admin_required"}
    assert entered == []


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
def test_admin_can_reach_inert_handler_after_authorization(protected_app, method):
    _, client, entered = protected_app
    login(client, "admin")
    assert client.open("/api/c2/run", method=method).status_code == 200
    assert entered == ["c2.run"]


def test_unmatched_paths_and_unsupported_methods_keep_routing_errors(protected_app):
    _, client, entered = protected_app
    assert client.get("/missing").status_code == 404
    assert client.post("/direct-operation").status_code == 405
    assert entered == []


def test_socket_wrapper_checks_session_again_for_each_message(authorization):
    app = Flask("socket-authorization-test")
    app.secret_key = "isolated-socket-contract-only"
    entered = []

    @authorization.socket_admin_required
    def inert_event(message):
        """Fixture event documentation."""
        entered.append(message)
        return "handled"

    assert inert_event.__name__ == "inert_event"
    assert inert_event.__doc__ == "Fixture event documentation."
    with app.test_request_context("/socket-fixture"):
        assert inert_event({"role": "admin"}) is False
        session.update(logged_in=True, user="admin-test", role="analyst")
        assert inert_event({"role": "admin"}) is False
        session["role"] = "admin"
        assert inert_event({"value": "authorized"}) == "handled"
        session["role"] = "analyst"
        assert inert_event({"value": "revoked"}) is False
    assert entered == [{"value": "authorized"}]


def test_socket_authorization_fails_closed_outside_a_request(authorization):
    assert authorization.is_authenticated_session() is False
    assert authorization.admin_session_authorized() is False
    entered = []

    @authorization.socket_admin_required
    def inert_event():
        entered.append(True)

    assert inert_event() is False
    assert entered == []


def test_authorization_imports_no_operational_or_system_modules():
    tree = ast.parse((ROOT / "cyberapp/authorization.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])
    assert imported.issubset({"__future__", "functools", "typing", "flask"})


def test_factory_installs_access_control_before_registering_feature_blueprints():
    tree = ast.parse((ROOT / "cyberapp/app.py").read_text(encoding="utf-8"))
    factory = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "create_app"
    )
    installs = [
        node
        for node in ast.walk(factory)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "install_admin_access_control"
    ]
    registrations = [
        node
        for node in ast.walk(factory)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "register_blueprint"
    ]
    assert len(installs) == 1
    assert registrations
    assert installs[0].lineno < min(node.lineno for node in registrations)
    for node in ast.walk(factory):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            assert node.func.id != "init_websocket"
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            assert (node.func.value.id, node.func.attr) != ("socketio", "init_app")


@pytest.mark.parametrize(
    "relative,handler_name,event_name",
    [
        ("cyberapp/routes/exploits.py", "handle_shell", "shell_command"),
        ("cyberapp/routes/browser_persistence.py", "ws_connect", "connect"),
        ("cyberapp/routes/browser_persistence.py", "ws_data", "data"),
        ("cyberapp/routes/browser_persistence.py", "ws_disconnect", "disconnect"),
    ],
)
def test_existing_socket_events_register_the_authorized_wrapper(
    relative, handler_name, event_name
):
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    handler = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == handler_name
    )
    # Python applies inner decorators first; SocketIO must receive the wrapper.
    register, guard = handler.decorator_list
    assert isinstance(register, ast.Call)
    assert isinstance(register.func, ast.Attribute) and register.func.attr == "on"
    assert register.args[0].value == event_name
    assert isinstance(guard, ast.Name) and guard.id == "socket_admin_required"

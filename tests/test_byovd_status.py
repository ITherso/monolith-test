"""BYOVD availability contracts; never import or execute a driver backend."""

import ast
import importlib.util
import sys
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask
from jinja2 import DictLoader

ROOT = Path(__file__).resolve().parents[1]
UNAVAILABLE = (
    ("GET", "/byovd/api/drivers"),
    ("GET", "/byovd/api/edr-products"),
    ("POST", "/byovd/api/detect-edr"),
    ("POST", "/byovd/api/generate-payload"),
    ("POST", "/byovd/api/deploy"),
    ("POST", "/byovd/api/kill-edr"),
    ("GET", "/byovd/api/job/inert-job"),
)


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def client():
    route = load("isolated_byovd_status_route", "cyberapp/routes/byovd.py")
    authorization = load(
        "isolated_byovd_status_authorization", "cyberapp/authorization.py"
    )
    app = Flask("byovd-status-fixture")
    app.config.update(TESTING=True, SECRET_KEY="byovd-status-fixture-only")
    app.jinja_loader = DictLoader(
        {
            "base.html": "<html><body>{% block content %}{% endblock %}</body></html>",
            "byovd.html": (ROOT / "templates/byovd.html").read_text(encoding="utf-8"),
        }
    )
    authorization.install_admin_access_control(app)
    app.register_blueprint(route.byovd_bp)
    return app.test_client()


def login(client, role="admin"):
    with client.session_transaction() as current:
        current.update(logged_in=True, user="byovd-status-fixture", role=role)


def assert_no_execution(payload):
    assert payload["module"] == "byovd"
    assert payload["status"] == "unavailable"
    for key in (
        "success",
        "available",
        "executed",
        "host_probe_performed",
        "driver_loaded",
        "kernel_access",
        "edr_terminated",
    ):
        assert payload[key] is False


def test_import_has_no_operational_dependencies_or_search_path_mutation():
    source = (ROOT / "cyberapp/routes/byovd.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert [
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    ] == ["flask"]
    assert not any(isinstance(node, ast.Import) for node in ast.walk(tree))
    previous = list(sys.path)
    with patch.dict(sys.modules, {"byovd_module": None, "tools.byovd_module": None}):
        route = load("isolated_byovd_without_backend", "cyberapp/routes/byovd.py")
    assert route.byovd_bp.name == "byovd"
    assert sys.path == previous
    assert "login_required" not in route.__dict__


@pytest.mark.parametrize("method,path", UNAVAILABLE)
def test_admin_gets_explicit_unavailable_without_parsing_body(client, method, path):
    login(client)
    with patch.object(
        client.application.request_class,
        "get_json",
        side_effect=AssertionError("operational input must not be read"),
    ):
        response = client.open(
            path,
            method=method,
            data=b'{"target":"must-not-connect.invalid","credentials":{"password":"SECRET"}',
            content_type="application/json",
        )
    assert response.status_code == 501
    assert response.headers["Cache-Control"] == "no-store"
    assert_no_execution(response.json)
    assert response.json["error"] == "byovd_backend_unavailable"
    assert b"SECRET" not in response.data
    assert b"must-not-connect" not in response.data


@pytest.mark.parametrize("role,expected", [(None, 401), ("analyst", 403)])
@pytest.mark.parametrize("method,path", UNAVAILABLE)
def test_existing_admin_policy_denies_before_unavailable_handler(
    client, role, expected, method, path
):
    if role:
        login(client, role)
    response = client.open(path, method=method, headers={"Accept": "application/json"})
    assert response.status_code == expected
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json == {
        "error": "login_required" if role is None else "admin_required"
    }


@pytest.mark.parametrize("path", ["/byovd/api/status", "/byovd/api/capabilities"])
@pytest.mark.parametrize("role,expected", [(None, 401), ("analyst", 403)])
def test_status_and_capability_descriptors_remain_admin_only(
    client, path, role, expected
):
    if role:
        login(client, role)
    assert (
        client.get(path, headers={"Accept": "application/json"}).status_code == expected
    )


def test_status_is_a_fresh_static_descriptor_not_a_success_result(client):
    login(client)
    first = client.get("/byovd/api/status")
    assert first.status_code == 200
    assert first.headers["Cache-Control"] == "no-store"
    assert_no_execution(first.json)
    first.json["available"] = True
    assert_no_execution(client.get("/byovd/api/status").json)
    assert client.post("/byovd/api/status").status_code == 405


def test_capability_labels_are_unavailable_catalog_metadata(client):
    login(client)
    response = client.get("/byovd/api/capabilities")
    assert response.status_code == 200
    assert_no_execution(response.json)
    assert response.json["catalog_only"] is True
    assert len(response.json["capabilities"]) == 6
    assert all(item["available"] is False for item in response.json["capabilities"])


class Controls(HTMLParser):
    def __init__(self):
        super().__init__()
        self.operations = []
        self.inputs = []
        self.events = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.events.extend(name for name in attributes if name.startswith("on"))
        if tag == "button" and "data-operation" in attributes:
            self.operations.append(attributes)
        if tag == "input":
            self.inputs.append(attributes)


def test_actual_page_keeps_disabled_controls_and_uses_prefixed_status_only(client):
    login(client)
    response = client.get("/byovd/", environ_overrides={"SCRIPT_NAME": "/panel"})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    body = response.get_data(as_text=True)
    controls = Controls()
    controls.feed(body)
    assert len(controls.operations) == 4
    assert all("disabled" in item for item in controls.operations)
    assert len(controls.inputs) == 3
    assert all("disabled" in item for item in controls.inputs)
    assert controls.events == []
    assert '"/panel/byovd/api/status"' in body
    assert body.count("await fetch(") == 1
    assert "method: 'GET'" in body
    assert "method: 'POST'" not in body
    assert "output.textContent" in body
    assert ".innerHTML" not in body
    for false_claim in (
        "Ready for kernel operations",
        "Module initialized",
        "Driver loaded successfully!",
        "EDR signatures loaded",
    ):
        assert false_claim not in body


def test_page_denials_preserve_management_authorization(client):
    assert (
        client.get("/byovd/", headers={"Accept": "application/json"}).status_code == 401
    )
    login(client, "analyst")
    assert (
        client.get("/byovd/", headers={"Accept": "application/json"}).status_code == 403
    )

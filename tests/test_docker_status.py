"""Docker failure contracts with selected definitions and inert Flask handlers."""

import ast
import importlib.util
import warnings
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Blueprint, Flask, jsonify, render_template

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/docker_escape.py"
OPERATIONS = ("detect", "enumerate", "get-payload", "attempt")


def source_tree():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(SOURCE.read_text(encoding="utf-8"))


def compile_nodes(nodes, namespace):
    future = ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0
    )
    module = ast.Module(body=[future, *nodes], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(SOURCE), "exec"), namespace)
    return namespace


def method(name, namespace=None):
    cls = next(
        n
        for n in source_tree().body
        if isinstance(n, ast.ClassDef) and n.name == "DockerEscape"
    )
    function = next(
        n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name
    )
    function.decorator_list = []
    return compile_nodes([function], dict(namespace or {}))[name]


@pytest.fixture
def view():
    names = {
        "_docker_response",
        "_docker_unavailable",
        "index",
        "api_status",
        "api_detect",
        "api_enumerate",
        "api_get_payload",
        "api_attempt",
        "api_methods",
    }
    tree = source_tree()
    functions = [
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names
    ]
    assert {n.name for n in functions} == names
    enum = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "EscapeMethod"
    )
    trap = Mock(side_effect=AssertionError("operational code must not run"))
    request = Mock()
    request.get_json.side_effect = AssertionError("body must not be parsed")
    namespace = {
        "docker_escape_bp": Blueprint(
            "docker_escape", __name__, url_prefix="/docker-escape"
        ),
        "Enum": Enum,
        "jsonify": jsonify,
        "render_template": render_template,
        "request": request,
        "_escape": trap,
        "DockerEscape": trap,
    }
    compile_nodes([enum, *functions], namespace)
    spec = importlib.util.spec_from_file_location(
        "isolated_docker_authorization", ROOT / "cyberapp/authorization.py"
    )
    authorization = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(authorization)
    app = Flask("docker-status-fixture", template_folder=str(ROOT / "templates"))
    app.config.update(TESTING=True, SECRET_KEY="docker-status-fixture-only")
    authorization.install_admin_access_control(app)
    app.register_blueprint(namespace["docker_escape_bp"])
    client = app.test_client()
    with client.session_transaction() as session:
        session.update(logged_in=True, user="docker-fixture", role="admin")
    yield SimpleNamespace(
        app=app, client=client, namespace=namespace, trap=trap, request=request
    )
    assert trap.mock_calls == []
    assert request.mock_calls == []


def assert_inert_flags(payload):
    for field in (
        "success",
        "available",
        "initialized",
        "execution_available",
        "executed",
        "host_probe_performed",
    ):
        assert payload[field] is False


@pytest.mark.parametrize("available", [False, True])
def test_attempt_cannot_claim_access_for_any_recorded_vector(available):
    attempt = method("attempt_escape", {"EscapeResult": SimpleNamespace})
    instance = SimpleNamespace(
        escape_results=[],
        escape_vectors=[SimpleNamespace(available=available, payload="never executed")],
    )
    result = attempt(instance, "inert-method")
    assert result.method == "inert-method"
    for flag in ("success", "host_access", "root_on_host", "payload_executed"):
        assert getattr(result, flag) is False
    assert instance.escape_results == [result]
    assert "Not executed" in result.output
    assert "manually" not in result.output


def test_attempt_never_reads_vectors_or_probes_host():
    class Instance:
        escape_results = []

        @property
        def escape_vectors(self):
            raise AssertionError("vector enumeration must not happen")

        def detect_container(self):
            raise AssertionError("local host must not be probed")

    result = method("attempt_escape", {"EscapeResult": SimpleNamespace})(
        Instance(), "inert-method"
    )
    assert result.success is False and result.payload_executed is False


def test_status_distinguishes_inspected_metadata_from_container_detection():
    info = SimpleNamespace(
        is_container=False,
        runtime=SimpleNamespace(value="unknown"),
        container_id="",
        privileged=False,
        capabilities=["supplied metadata"],
        docker_sock_mounted=False,
        kernel_version="supplied",
    )
    status = method("get_status")(
        SimpleNamespace(container_info=info, escape_vectors=[], escape_results=[])
    )
    assert status["inspection_performed"] is True
    assert status["container_detected"] is False
    assert status["host_probe_performed"] is False
    status["container_info"]["capabilities"].append("changed copy")
    assert info.capabilities == ["supplied metadata"]


def test_uninspected_status_does_not_infer_container_information():
    status = method("get_status")(
        SimpleNamespace(container_info=None, escape_vectors=[], escape_results=[])
    )
    assert status["inspection_performed"] is False
    assert status["container_detected"] is False
    assert status["container_info"] is None
    assert status["execution_available"] is False
    assert status["successful_escapes"] == 0


def test_historical_fake_success_without_payload_execution_is_not_counted():
    fake = SimpleNamespace(success=True, host_access=True, payload_executed=False)
    executed_without_access = SimpleNamespace(
        success=True, host_access=False, payload_executed=True
    )
    status = method("get_status")(
        SimpleNamespace(
            container_info=None,
            escape_vectors=[SimpleNamespace(available=True)],
            escape_results=[fake, executed_without_access],
        )
    )
    assert status["escape_attempts"] == 2
    assert status["successful_escapes"] == 0
    assert status["available_escapes"] == 0
    assert status["success_count_evidence"] == "recorded_flags_only"


def test_status_api_is_static_uncacheable_metadata_without_constructing_a_tool(view):
    response = view.client.get("/docker-escape/api/status")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert_inert_flags(response.json)
    assert response.json["status"]["container_detected"] is None
    assert response.json["status"]["container_info"] is None
    assert response.json["status"]["successful_escapes"] is None


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(
    "body", [b"invalid-json", b'{"target":"never-contact.invalid"}']
)
def test_operation_routes_fail_before_parsing_input_or_accessing_instance(
    view, operation, body
):
    response = view.client.post(
        "/docker-escape/api/" + operation, data=body, content_type="application/json"
    )
    assert response.status_code == 501
    assert response.headers["Cache-Control"] == "no-store"
    assert_inert_flags(response.json)
    assert response.json["error"] == "docker_escape_unavailable"
    for field in ("host_access", "root_on_host", "payload_executed"):
        assert response.json[field] is False
        assert response.json["result"][field] is False
    assert response.json["result"]["success"] is False
    assert b"never-contact" not in response.data


@pytest.mark.parametrize("role,code", [(None, 401), ("analyst", 403)])
def test_admin_guard_stops_read_and_operation_routes(view, role, code):
    with view.client.session_transaction() as session:
        session.clear()
        if role:
            session.update(logged_in=True, user="fixture", role=role)
    for suffix in ("status", "escape-methods"):
        response = view.client.get(
            "/docker-escape/api/" + suffix, headers={"Accept": "application/json"}
        )
        assert response.status_code == code
    for operation in OPERATIONS:
        assert view.client.post("/docker-escape/api/" + operation).status_code == code


def test_method_catalog_is_metadata_only_and_uncacheable(view):
    response = view.client.get("/docker-escape/api/escape-methods")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json["catalog_only"] is True
    assert response.json["available"] is False
    assert response.json["host_probe_performed"] is False
    assert len(response.json["methods"]) == 13


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.buttons = []
        self.handlers = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "button":
            self.buttons.append(attributes)
        self.handlers.extend(name for name in attributes if name.startswith("on"))


def test_panel_uses_prefixed_read_only_status_and_disabled_controls(view):
    response = view.client.get(
        "/docker-escape/", environ_overrides={"SCRIPT_NAME": "/panel"}
    )
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    parser = PageParser()
    parser.feed(text)
    assert len(parser.buttons) == 10
    assert all("disabled" in button for button in parser.buttons)
    assert parser.handlers == []
    script = text.split(
        "const output = document.getElementById('docker-module-status');"
    )[-1].split("</script>", 1)[0]
    assert script.count("fetch(") == 1
    assert '"/panel/docker-escape/api/status"' in script
    assert "method: 'GET'" in script and "method: 'POST'" not in script
    assert "output.textContent" in script and ".innerHTML" not in script
    assert "detectContainer()" not in script
    assert "Not implemented" in text


def test_module_global_does_not_instantiate_docker_tool():
    assignment = next(
        node
        for node in source_tree().body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_escape"
            for target in node.targets
        )
    )
    assert isinstance(assignment.value, ast.Constant)
    assert assignment.value.value is None

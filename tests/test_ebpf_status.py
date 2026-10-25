"""Unavailable eBPF contracts; never import or execute the operational tool."""

import ast
import importlib.util
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Blueprint, Flask, jsonify, render_template

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/ebpf_rootkit.py"
OPERATIONS = (
    ("GET", "/api/check-support"),
    ("GET", "/api/programs"),
    ("POST", "/api/generate/process-hide"),
    ("POST", "/api/generate/file-hide"),
    ("POST", "/api/generate/xdp-filter"),
    ("GET", "/api/persistence"),
    ("GET", "/api/anti-forensics"),
    ("GET", "/api/loader-script"),
    ("GET", "/api/export"),
)


class ForbiddenBackend:
    def __getattr__(self, _name):
        raise AssertionError("No native backend, host probe or generator may run")


def source_tree():
    return ast.parse(SOURCE.read_text(encoding="utf-8"))


def isolated_method(name, namespace=None):
    definition = next(
        item
        for item in source_tree().body
        if isinstance(item, ast.ClassDef) and item.name == "eBPFRootkit"
    )
    function = next(
        item
        for item in definition.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    scope = {} if namespace is None else dict(namespace)
    module = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__", names=[ast.alias(name="annotations")], level=0
            ),
            function,
        ],
        type_ignores=[],
    )
    exec(compile(ast.fix_missing_locations(module), str(SOURCE), "exec"), scope)
    return scope[name]


@pytest.fixture
def management():
    blueprint = Blueprint("ebpf_rootkit", __name__, url_prefix="/ebpf-rootkit")
    names = {
        "_ebpf_status_descriptor",
        "_ebpf_response",
        "_ebpf_unavailable",
        "no_ebpf_caching",
        "index",
        "api_status",
        "api_check_support",
        "api_list_programs",
        "api_gen_process_hide",
        "api_gen_file_hide",
        "api_gen_xdp",
        "api_persistence",
        "api_anti_forensics",
        "api_loader",
        "api_export",
    }
    functions = [
        item
        for item in source_tree().body
        if isinstance(item, ast.FunctionDef) and item.name in names
    ]
    assert len(functions) == len(names)
    backend = ForbiddenBackend()
    scope = {
        "ebpf_rootkit_bp": blueprint,
        "jsonify": jsonify,
        "render_template": render_template,
        "_rootkit": backend,
        "request": backend,
        "os": backend,
        "eBPFRootkit": Mock(side_effect=AssertionError("must not construct")),
    }
    exec(
        compile(ast.Module(body=functions, type_ignores=[]), str(SOURCE), "exec"), scope
    )
    spec = importlib.util.spec_from_file_location(
        "isolated_ebpf_authorization", ROOT / "cyberapp/authorization.py"
    )
    authorization = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(authorization)
    app = Flask("ebpf-metadata-fixture", template_folder=str(ROOT / "templates"))
    app.config.update(TESTING=True, SECRET_KEY="ebpf-status-fixture-only")
    authorization.install_admin_access_control(app)
    app.register_blueprint(blueprint)
    yield SimpleNamespace(app=app, client=app.test_client(), scope=scope)
    scope["eBPFRootkit"].assert_not_called()


def login(client, role="admin"):
    with client.session_transaction() as session:
        session.clear()
        session.update(logged_in=True, user="metadata-fixture", role=role)


@pytest.mark.parametrize("method,path", OPERATIONS)
def test_operations_fail_before_request_parsing_or_backend_access(
    management, method, path
):
    login(management.client)
    response = management.client.open(
        "/ebpf-rootkit" + path,
        method=method,
        data=b"\xff invalid JSON must not be parsed",
        content_type="application/json",
    )
    assert response.status_code == 501
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json["error"] == "ebpf_runtime_unavailable"
    for key in (
        "success",
        "available",
        "executed",
        "compiled",
        "loaded",
        "attached",
        "support_verified",
        "host_probe_performed",
    ):
        assert response.json[key] is False


@pytest.mark.parametrize("role,code", [(None, 401), ("analyst", 403)])
@pytest.mark.parametrize("method,path", OPERATIONS + (("GET", "/api/status"),))
def test_global_admin_guard_stops_requests_before_metadata_or_actions(
    management, role, code, method, path
):
    if role:
        login(management.client, role)
    response = management.client.open(
        "/ebpf-rootkit" + path, method=method, headers={"Accept": "application/json"}
    )
    assert response.status_code == code
    assert response.headers["Cache-Control"] == "no-store"


def test_admin_can_read_fresh_unverified_descriptor_without_runtime(management):
    login(management.client)
    response = management.client.get("/ebpf-rootkit/api/status")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json["success"] is False
    assert response.json["descriptor_retrieved"] is True
    status = response.json["status"]
    assert status["implementation"] == "not_implemented"
    assert status["host_state"] == "not_inspected"
    assert status["kernel_version"] is None
    for key in (
        "runtime_available",
        "executed",
        "compiled",
        "loaded",
        "attached",
        "support_verified",
        "host_probe_performed",
    ):
        assert status[key] is False
    for key in (
        "loaded_programs",
        "hidden_processes",
        "hidden_files",
        "hidden_connections",
        "captured_packets",
    ):
        assert status[key] == 0
    first = response.get_json()
    first["status"]["requested_records"]["tampered"] = 4
    assert (
        management.client.get("/ebpf-rootkit/api/status").json["status"][
            "requested_records"
        ]
        == {}
    )


def test_compiler_does_not_return_a_digest_or_invoke_compiler():
    compiler = isolated_method(
        "_compile_bpf_code",
        {"hashlib": ForbiddenBackend(), "subprocess": ForbiddenBackend()},
    )
    with pytest.raises(NotImplementedError, match="unavailable"):
        compiler(ForbiddenBackend(), "synthetic inert source")


def test_kernel_and_support_remain_unknown_without_host_probes():
    namespace = {"os": ForbiddenBackend()}
    kernel = isolated_method("_get_kernel_version", namespace)
    support = isolated_method("check_ebpf_support", namespace)
    assert kernel(ForbiddenBackend()) is None
    result = support(SimpleNamespace(kernel_version=(99, 99, 99)))
    assert result["kernel_version"] is None
    assert result["host_probe_performed"] is False
    assert result["support_verified"] is False
    for key in (
        "ebpf_available",
        "bpf_syscall",
        "kprobe_support",
        "xdp_support",
        "lsm_support",
    ):
        assert result[key] is None


def test_requested_records_cannot_be_reported_as_actual_hidden_or_loaded(management):
    get_status = isolated_method(
        "get_status",
        {"_ebpf_status_descriptor": management.scope["_ebpf_status_descriptor"]},
    )
    stale = SimpleNamespace(
        initialized=True,
        programs={"stale": SimpleNamespace(loaded=True)},
        hidden_processes=[1, 2],
        hidden_files=[3],
        hidden_connections=[4],
        packet_rules=[5],
    )
    status = get_status(stale)
    assert status["loaded_programs"] == 0
    assert status["hidden_processes"] == 0
    assert status["hidden_files"] == 0
    assert status["hidden_connections"] == 0
    assert status["initialized"] is False
    assert status["requested_records"] == {
        "programs": 1,
        "processes": 2,
        "files": 1,
        "connections": 1,
        "packet_rules": 1,
    }


def test_global_backend_is_not_constructed_and_missing_routes_stay_missing(management):
    assignment = next(
        item
        for item in source_tree().body
        if isinstance(item, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_rootkit"
            for target in item.targets
        )
    )
    assert isinstance(assignment.value, ast.Constant) and assignment.value.value is None
    login(management.client)
    for path in ("keylogger", "privesc", "network-hide"):
        assert (
            management.client.post("/ebpf-rootkit/api/generate/" + path).status_code
            == 404
        )


class ControlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.controls = []
        self.events = []
        self.status_url = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag in {"button", "input", "select"}:
            self.controls.append(attributes)
        self.events.extend(name for name in attributes if name.startswith("on"))
        if attributes.get("id") == "ebpf-status-panel":
            self.status_url = attributes["data-status-url"]


def test_page_preserves_labels_but_enables_only_prefixed_metadata_refresh(management):
    login(management.client)
    response = management.client.get(
        "/ebpf-rootkit/", environ_overrides={"SCRIPT_NAME": "/panel"}
    )
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    rendered = response.get_data(as_text=True)
    parser = ControlParser()
    parser.feed(rendered)
    assert parser.status_url == "/panel/ebpf-rootkit/api/status"
    assert parser.events == []
    assert len(parser.controls) > 15
    for control in parser.controls:
        assert ("disabled" in control) == (control.get("id") != "refresh-ebpf-status")
    for label in (
        "Process Hiding",
        "File Hiding",
        "XDP Packet Filter",
        "Keylogger",
        "Privesc",
        "Anti-Forensics",
    ):
        assert label in rendered
    template = (ROOT / "templates/ebpf_rootkit.html").read_text(encoding="utf-8")
    assert template.count("fetch(") == 1
    assert "method: 'GET'" in template
    assert ".innerHTML" not in template
    assert "/god-mode/api/" not in template
    assert "setInterval(" not in template

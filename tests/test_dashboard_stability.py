"""Dashboard display data checks without loading application or feature modules."""

import ast
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest
from flask import Flask, render_template
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def data():
    return load("isolated_dashboard_data", "cyberapp/dashboard_data.py")


@pytest.mark.parametrize("content", [b"{", b'"text"', b"null", b"{}", b"42", b"\xff"])
def test_malformed_or_wrong_shape_leaderboard_is_empty(tmp_path, data, content):
    source = tmp_path / "leaderboard.json"
    source.write_bytes(content)
    assert data.load_leaderboard(source) == []
    assert source.read_bytes() == content


def test_missing_source_and_nonregular_source_do_not_break_display(tmp_path, data):
    assert data.load_leaderboard(tmp_path / "missing.json") == []
    with patch.object(data.os, "open", side_effect=AssertionError("must not open")):
        assert data.load_leaderboard(tmp_path) == []


def test_unc_source_is_rejected_without_resolving_or_reading(data):
    with patch.object(data, "Path", side_effect=AssertionError("must not resolve")):
        assert data.load_leaderboard("//server/share/leaderboard.json") == []


def test_oversized_and_deep_json_are_unavailable(tmp_path, data):
    source = tmp_path / "leaderboard.json"
    source.write_bytes(b"x" * (data.MAX_JSON_BYTES + 1))
    with patch.object(data.os, "open", side_effect=AssertionError("must not open")):
        assert data.load_leaderboard(source) == []
    source.write_bytes(b"[" * 5000 + b"]" * 5000)
    assert data.load_leaderboard(source) == []


def test_leaderboard_validates_rows_and_limits_valid_output(tmp_path, data):
    source = tmp_path / "leaderboard.json"
    rows = [
        None,
        "entry",
        {"user": "missing-score"},
        {"user": 123, "score": 4},
        {"user": " ", "score": 4},
        {"user": "x" * 129, "score": 4},
        {"user": "bool-score", "score": True},
        {"user": "negative-score", "score": -1},
        {"user": "text-score", "score": "200"},
        {"user": "nan-score", "score": float("nan")},
        {"user": "infinity-score", "score": float("inf")},
    ]
    valid = [
        {"user": f"user-{index}", "score": index, "ignored": "extra"}
        for index in range(12)
    ]
    source.write_text(json.dumps(rows + valid), encoding="utf-8")
    assert data.load_leaderboard(source) == [
        {"user": f"user-{index}", "score": index} for index in range(10)
    ]


def test_evasion_counters_are_typed_and_absence_does_not_claim_enabled(tmp_path, data):
    source = tmp_path / "stats.json"
    absent = data.load_evasion_stats(source)
    assert absent["evasion_enabled"] is False
    assert absent["telemetry_available"] is False
    assert absent["last_evasion_action"] is None
    assert all(absent[field] == 0 for field in data.COUNTER_FIELDS)
    source.write_text(
        json.dumps(
            {
                "timestomp_count": 7,
                "logs_cleared_count": -4,
                "artifacts_removed_count": True,
                "payloads_obfuscated_count": "12",
                "last_evasion_action": ["invalid"],
                "evasion_enabled": "true",
                "extra_key": "ignored",
            }
        ),
        encoding="utf-8",
    )
    result = data.load_evasion_stats(source)
    assert result == {**absent, "timestomp_count": 7, "telemetry_available": True}
    source.write_text(
        '{"evasion_enabled":true,"last_evasion_action":"recorded"}', encoding="utf-8"
    )
    assert data.load_evasion_stats(source)["evasion_enabled"] is True
    assert data.load_evasion_stats(source)["last_evasion_action"] == "recorded"


@pytest.mark.parametrize("content", [b"{", b"[]", b"null", b"2"])
def test_malformed_or_wrong_shape_stats_keep_safe_defaults(tmp_path, data, content):
    source = tmp_path / "stats.json"
    source.write_bytes(content)
    assert data.load_evasion_stats(source)["evasion_enabled"] is False
    assert data.load_evasion_stats(source)["timestomp_count"] == 0
    assert data.load_evasion_stats(source)["telemetry_available"] is False


def test_path_and_quoted_executable_presence_is_detected_without_execution(
    tmp_path, data, monkeypatch
):
    directory = tmp_path / "tools with spaces"
    directory.mkdir()
    tool = directory / "display-probe.exe"
    tool.write_bytes(b"not an executable; fixture is never launched")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(directory))
    assert data.executable_available("display-probe.exe --status") is True
    assert data.executable_available(f'"{tool}" --status') is True
    assert data.executable_available("unknown-display-probe") is False


@pytest.mark.parametrize("command", [None, 123, False, "", "  ", '"unterminated'])
def test_missing_or_invalid_tool_commands_are_unavailable(data, command):
    assert data.executable_available(command) is False


def test_only_first_token_is_resolved_and_arguments_are_not_evaluated(data):
    with patch.object(data.shutil, "which", return_value=None) as lookup:
        assert (
            data.executable_available('display-probe --version "argument with spaces"')
            is False
        )
    lookup.assert_called_once_with("display-probe")


@pytest.fixture
def dashboard(data, tmp_path):
    scans = ModuleType("cyberapp.models.scans")
    scans.list_recent_scans = lambda limit: []
    arsenal = ModuleType("cybermodules.arsenal")
    arsenal.TOOLS = {"present": "display-probe", "missing": None}
    ad = ModuleType("cybermodules.ad_enum")
    ad.has_ldap = False
    # Stub parent packages too, so no package guard or operational import can run.
    stubs = {
        "cyberapp.dashboard_data": data,
        "cyberapp.models.scans": scans,
        "cybermodules.arsenal": arsenal,
        "cybermodules.ad_enum": ad,
        "web3": None,
        "openai": None,
    }
    for name in ("cyberapp", "cyberapp.models", "cybermodules"):
        package = ModuleType(name)
        package.__path__ = []
        stubs[name] = package
    with patch.dict(sys.modules, stubs):
        route = load("isolated_dashboard_route", "cyberapp/routes/dashboard.py")
    route.LEADERBOARD_FILE = str(tmp_path / "leaderboard.json")
    route.EVASION_STATS_FILE = str(tmp_path / "stats.json")
    app = Flask("dashboard-stability-test")
    app.config.update(TESTING=True, SECRET_KEY="dashboard-fixture-only")
    app.register_blueprint(route.dashboard_bp)
    client = app.test_client()
    return route, client, stubs


def test_dashboard_keeps_login_boundary_without_reading_data(dashboard):
    route, client, _ = dashboard
    with patch.object(
        route, "load_leaderboard", side_effect=AssertionError("unauthenticated read")
    ):
        assert client.get("/").status_code == 302


def test_corrupt_display_files_no_longer_break_logged_in_dashboard(dashboard):
    route, client, stubs = dashboard
    Path(route.LEADERBOARD_FILE).write_bytes(b'{"truncated":')
    Path(route.EVASION_STATS_FILE).write_bytes(b"[]")
    with client.session_transaction() as session:
        session.update(logged_in=True, user="analyst", role="analyst")

    def rendered(template, **values):
        assert template == "dashboard.html"
        assert values["leaderboard"] == []
        assert values["evasion_stats"]["evasion_enabled"] is False
        assert values["available_tools"] == 1
        assert values["total_tools"] == 2
        assert values["has_openai"] is False
        assert values["blockchain_ready"] is False
        return "dashboard rendered"

    with (
        patch.dict(sys.modules, stubs),
        patch.object(route, "render_template", side_effect=rendered),
        patch.object(
            route,
            "executable_available",
            side_effect=lambda command: command is not None,
        ),
    ):
        response = client.get("/")
    assert response.status_code == 200
    assert response.get_data(as_text=True) == "dashboard rendered"


def test_scan_database_failure_keeps_panel_readable_without_claiming_empty_success(
    dashboard,
):
    route, client, stubs = dashboard
    with client.session_transaction() as session:
        session.update(logged_in=True, user="analyst", role="analyst")

    def rendered(template, **values):
        assert template == "dashboard.html"
        assert values["scans"] == []
        assert values["scans_available"] is False
        return "scan records temporarily unavailable"

    with (
        patch.dict(sys.modules, stubs),
        patch.object(
            route, "list_recent_scans", side_effect=RuntimeError("PRIVATE-DB-PATH")
        ),
        patch.object(route, "render_template", side_effect=rendered),
        patch.object(route, "executable_available", return_value=False),
    ):
        response = client.get("/")
    assert response.status_code == 503
    assert b"PRIVATE-DB-PATH" not in response.data
    assert response.get_data(as_text=True) == "scan records temporarily unavailable"


def test_data_helper_never_imports_or_executes_operational_code():
    tree = ast.parse((ROOT / "cyberapp/dashboard_data.py").read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imports <= {"json", "math", "os", "shlex", "shutil", "stat"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {"system", "popen", "spawn", "unlink", "write"}


def render_status_fragment(stats, installed=False):
    source = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
    fragment = source.split("<!-- System Status -->", 1)[1].split("{% endblock %}", 1)[
        0
    ]
    # The surrounding dashboard's unrelated scripts are not rendered or executed.
    for operation in ("<script", "fetch(", "onclick=", "<button", "<form"):
        assert operation not in fragment
    return (
        Environment(autoescape=True)
        .from_string(fragment)
        .render(
            has_openai=installed,
            has_ldap=installed,
            blockchain_ready=installed,
            available_tools=3,
            total_tools=30,
            tools_ok=False,
            evasion_stats=stats,
        )
    )


@pytest.mark.parametrize("installed", [False, True])
def test_package_presence_is_not_reported_as_service_readiness(
    data, tmp_path, installed
):
    rendered = render_status_fragment(
        data.load_evasion_stats(tmp_path / "missing"), installed
    )
    assert rendered.count("SDK INSTALLED" if installed else "SDK MISSING") == 3
    assert "3/30 Located" in rendered
    assert "Service connections and execution have not been verified." in rendered
    for false_claim in ("ONLINE", "ACTIVE", "READY", "SIMULATION", " Ready"):
        assert false_claim not in rendered


def test_missing_telemetry_shows_unknown_counts_and_unmeasured_rate(tmp_path, data):
    rendered = render_status_fragment(data.load_evasion_stats(tmp_path / "missing"))
    assert "No recorded telemetry available." in rendered
    assert "Not measured" in rendered
    assert rendered.count(">—</p>") == 4
    for false_value in (
        ">95%<",
        ">142<",
        ">89<",
        ">67<",
        ">234<",
        "AV Bypass",
        "stroke-dashoffset",
    ):
        assert false_value not in rendered


def test_supplied_typed_counts_replace_placeholder_numbers(tmp_path, data):
    source = tmp_path / "stats.json"
    source.write_text(
        json.dumps(dict(zip(data.COUNTER_FIELDS, (11, 23, 37, 41)))), encoding="utf-8"
    )
    rendered = render_status_fragment(data.load_evasion_stats(source))
    for count in (11, 23, 37, 41):
        assert f">{count}</p>" in rendered
    assert (
        "Supplied telemetry; records are not verified execution or bypass results."
        in rendered
    )
    assert "Recorded obfuscations" in rendered
    assert "Not measured" in rendered
    assert "95%" not in rendered


def test_real_dashboard_renders_prefixed_status_links_and_safe_initial_values(
    data, tmp_path
):
    app = Flask("dashboard-prefix-fixture", template_folder=str(ROOT / "templates"))
    app.secret_key = "dashboard-render-fixture-only"
    app.add_url_rule("/login", "auth.login", lambda: "inert login")
    app.add_url_rule(
        "/api/management/scans/<int:scan_id>/status",
        "monitoring.scan_status",
        lambda scan_id: {"scan_id": scan_id},
    )
    hostile = '<img src=x onerror="fixture()">'
    with app.test_request_context("/", environ_overrides={"SCRIPT_NAME": "/panel"}):
        rendered = render_template(
            "dashboard.html",
            scans=[(7, "supplied.invalid", "date", hostile, "analyst", hostile, None)],
            leaderboard=[],
            available_tools=0,
            total_tools=0,
            tools_ok=False,
            has_openai=False,
            has_ldap=False,
            blockchain_ready=False,
            evasion_stats=data.load_evasion_stats(tmp_path / "missing.json"),
        )
    assert 'data-status-url="/panel/api/management/scans/7/status"' in rendered
    assert 'href="/panel/login"' in rendered
    assert hostile not in rendered
    assert '&lt;img src=x onerror=' in rendered
    assert rendered.count("Read-only dashboard updates.") == 1
    assert "refreshScanProgress" not in rendered
    assert "style=\"width: &lt;img" not in rendered
    assert 'class="scan-eta ' in rendered
    assert 'id="scan-connection-message"' in rendered

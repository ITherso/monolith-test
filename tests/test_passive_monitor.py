"""Real file ingestion checks with no OS collection or operational imports."""

import ast
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest
from flask import Flask

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def monitor_module():
    return load("isolated_passive_monitor", "cyberapp/passive_monitor.py")


def test_real_log_records_are_read_once_and_source_is_not_modified(
    tmp_path, monitor_module
):
    log = tmp_path / "events.jsonl"
    data = (
        json.dumps(
            {
                "process_name": "C:\\Windows\\System32\\calc.exe",
                "network_destination": "recorded.test",
            }
        )
        + "\n"
    ).encode()
    log.write_bytes(data)
    monitor = monitor_module.PassiveEventMonitor(log)
    findings = monitor.poll_once()
    assert findings[0]["kind"] == "calculator_network_activity"
    assert findings[0]["compromise_confirmed"] is False
    assert monitor.poll_once() == []
    assert monitor.events_processed == 1
    assert log.read_bytes() == data


def test_append_partial_records_and_truncation(tmp_path, monitor_module):
    log = tmp_path / "events.jsonl"
    log.write_text('{"action":', encoding="utf-8")
    monitor = monitor_module.PassiveEventMonitor(log)
    assert monitor.poll_once() == []
    with log.open("a", encoding="utf-8") as stream:
        stream.write('"persistence_created"}\n')
    assert monitor.poll_once()[0]["kind"] == "persistence_entry_recorded"
    log.write_text('{}\n', encoding="utf-8")
    assert monitor.poll_once() == []
    assert monitor.events_processed == 2


def test_invalid_and_oversized_records_are_bounded_and_skipped(
    tmp_path, monitor_module
):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"not-json\n[]\n" + b"x" * 1_048_577 + b"\n{}\n")
    monitor = monitor_module.PassiveEventMonitor(log)
    assert monitor.poll_once() == []
    assert monitor.invalid_records == 3
    assert monitor.events_processed == 1


def test_security_event_and_ordinary_event(monitor_module):
    monitor = monitor_module.PassiveEventMonitor
    assert monitor.analyze({"process_name": "calc.exe"}) == []
    assert (
        monitor.analyze(
            {
                "action": "security_configuration_changed",
                "setting": "real_time_protection",
                "enabled": False,
            }
        )[0]["kind"]
        == "protection_disabled_recorded"
    )


def test_valid_json_waits_for_newline_and_nested_json_is_skipped(
    tmp_path, monitor_module
):
    log = tmp_path / "events.jsonl"
    log.write_text('{"action":"persistence_created"}', encoding="utf-8")
    monitor = monitor_module.PassiveEventMonitor(log)
    assert monitor.poll_once() == []
    assert monitor.events_processed == 0
    with log.open("ab") as stream:
        stream.write(b"\n" + b"[" * 5000 + b"]" * 5000 + b"\n{}\n")
    assert len(monitor.poll_once()) == 1
    assert monitor.events_processed == 2
    assert monitor.invalid_records == 1


def test_record_limit_resumes_without_skipping_or_repeating(tmp_path, monitor_module):
    log = tmp_path / "events.jsonl"
    record = b'{"action":"persistence_created"}\n'
    log.write_bytes(record * (monitor_module.MAX_POLL_RECORDS + 2))
    monitor = monitor_module.PassiveEventMonitor(log)
    assert len(monitor.poll_once()) == monitor_module.MAX_POLL_RECORDS
    assert len(monitor.poll_once()) == 2
    assert monitor.poll_once() == []


def test_oversized_record_discard_continues_across_polls_and_appends(
    tmp_path, monitor_module
):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"x" * (monitor_module.MAX_POLL_BYTES + 20))
    monitor = monitor_module.PassiveEventMonitor(log)
    assert monitor.poll_once() == []
    assert monitor.offset == monitor_module.MAX_POLL_BYTES
    assert monitor.invalid_records == 1
    assert monitor.poll_once() == []
    with log.open("ab") as stream:
        # This JSON-looking suffix still belongs to the discarded record.
        stream.write(b'{"action":"persistence_created"}\n{}\n')
    assert monitor.poll_once() == []
    assert monitor.invalid_records == 1
    assert monitor.events_processed == 1


def test_rotation_restarts_at_beginning(tmp_path, monitor_module):
    log = tmp_path / "events.jsonl"
    log.write_text('{}\n', encoding="utf-8")
    monitor = monitor_module.PassiveEventMonitor(log)
    monitor.poll_once()
    log.rename(tmp_path / "old.jsonl")
    log.write_text('{"action":"persistence_created"}\n', encoding="utf-8")
    assert len(monitor.poll_once()) == 1
    assert monitor.events_processed == 2


def test_nonregular_sources_are_rejected_before_open(tmp_path, monitor_module):
    with patch.object(monitor_module.os, "open", side_effect=AssertionError("opened")):
        with pytest.raises(ValueError, match="regular file"):
            monitor_module.PassiveEventMonitor(tmp_path).poll_once()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable on Windows")
def test_fifo_is_rejected_without_blocking(tmp_path, monitor_module):
    log = tmp_path / "pipe"
    os.mkfifo(log)
    with patch.object(monitor_module.os, "open", side_effect=AssertionError("opened")):
        with pytest.raises(ValueError, match="regular file"):
            monitor_module.PassiveEventMonitor(log).poll_once()


def test_source_absence_and_network_path_do_not_fake_monitoring(
    tmp_path, monitor_module
):
    with pytest.raises(FileNotFoundError):
        monitor_module.PassiveEventMonitor(tmp_path / "missing.jsonl").poll_once()
    with pytest.raises(ValueError):
        monitor_module.PassiveEventMonitor("//remote/events.jsonl")


def test_hunter_callback_and_stop_without_threads_or_app_import(
    tmp_path, monitor_module
):
    log = tmp_path / "events.jsonl"
    log.write_text('{"action":"persistence_created"}\n', encoding="utf-8")
    with patch.dict(sys.modules, {"cyberapp.passive_monitor": monitor_module}):
        hunter_module = load("isolated_threat_hunter", "cybermodules/threat_hunter.py")
    seen = []
    hunter = hunter_module.ThreatHunter(
        event_log=log, on_finding=lambda finding: (seen.append(finding), hunter.stop())
    )
    hunter.start()
    assert seen and not hunter.running
    assert len(hunter.findings) == 1
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(RuntimeError, match="JSONL"):
            hunter_module.ThreatHunter().start()


def test_monitor_has_no_process_network_or_unsafe_parser_imports():
    tree = ast.parse((ROOT / "cyberapp/passive_monitor.py").read_text(encoding="utf-8"))
    names = {
        alias.name.split('.')[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert names == {"json", "os", "stat"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {"system", "popen", "spawn", "write", "unlink"}
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "eval", "compile", "open"}
        for node in ast.walk(tree)
    )


@pytest.fixture
def passive_client(monitor_module):
    db = ModuleType("cyberapp.models.db")
    db.db_conn = lambda: pytest.fail("Passive preview must not access the database")
    with patch.dict(
        sys.modules,
        {"cyberapp.models.db": db, "cyberapp.passive_monitor": monitor_module},
    ):
        route = load("isolated_ops_preview", "cyberapp/routes/ops.py")
    app = Flask("passive-preview-test")
    app.config.update(TESTING=True, SECRET_KEY="passive-tests-only")
    app.register_blueprint(route.ops_bp)
    return app.test_client()


def login(client):
    with client.session_transaction() as session:
        session.update(logged_in=True, user="analyst", role="analyst")


def test_passive_preview_requires_login_and_configured_source(passive_client):
    for path in ("/threathunter/start", "/threathunter/events"):
        assert passive_client.get(path).status_code == 302
    login(passive_client)
    with patch.dict("os.environ", {}, clear=True):
        response = passive_client.get("/threathunter/start")
    assert response.status_code == 503
    assert response.json["status"] == "source_required"


def test_preview_reads_configured_log_without_threads_or_user_path(
    tmp_path, passive_client
):
    source = tmp_path / "configured.jsonl"
    data = b'{"action":"persistence_created"}\n'
    source.write_bytes(data)
    login(passive_client)
    with patch.dict("os.environ", {"MONOLITH_EVENT_LOG": str(source)}):
        response = passive_client.get(
            "/threathunter/events?path=missing&interface=eth1"
        )
        legacy = passive_client.get("/threathunter/start")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json == legacy.json
    assert response.json["status"] == "analyzed"
    assert response.json["background_monitor_started"] is False
    assert response.json["packet_capture"] is False
    assert response.json["events_processed"] == 1
    assert len(response.json["findings"]) == 1
    assert response.json["partial"] is False
    assert "dashboard" not in response.json
    assert source.read_bytes() == data


@pytest.mark.parametrize(
    "source_kind,status,error",
    [("missing", 503, "source_unavailable"), ("directory", 400, "invalid_source")],
)
def test_preview_reports_source_failures_without_paths(
    tmp_path, passive_client, source_kind, status, error
):
    source = tmp_path if source_kind == "directory" else tmp_path / "private-name.jsonl"
    login(passive_client)
    with patch.dict("os.environ", {"MONOLITH_EVENT_LOG": str(source)}):
        response = passive_client.get("/threathunter/events")
    assert response.status_code == status
    assert response.json["status"] == error
    assert str(source) not in response.get_data(as_text=True)


def test_preview_marks_bounded_results_as_partial(
    tmp_path, passive_client, monitor_module
):
    source = tmp_path / "many.jsonl"
    source.write_bytes(b"{}\n" * (monitor_module.MAX_POLL_RECORDS + 1))
    login(passive_client)
    with patch.dict("os.environ", {"MONOLITH_EVENT_LOG": str(source)}):
        response = passive_client.get("/threathunter/events")
    assert response.json["events_processed"] == monitor_module.MAX_POLL_RECORDS
    assert response.json["partial"] is True

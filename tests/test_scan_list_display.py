"""Read-only scan list behavior with inert dependencies and temporary SQLite."""

import importlib.util
import re
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

import pytest
from flask import Flask

ROOT = Path(__file__).resolve().parents[1]


def _module(name, **attributes):
    module = ModuleType(name)
    for key, value in attributes.items():
        setattr(module, key, value)
    return module


def _load_route(database_factory):
    stubs = {
        "cyberapp.models.db": _module("cyberapp.models.db", db_conn=database_factory),
        "cybermodules.autoexploit": _module(
            "cybermodules.autoexploit", AutoExploit=object
        ),
        "cyberapp.services.worker": _module(
            "cyberapp.services.worker", run_worker=lambda *args, **kwargs: None
        ),
        "cyberapp.services.audit": _module(
            "cyberapp.services.audit", log_audit=lambda *args, **kwargs: None
        ),
        "cyberapp.services.queue": _module(
            "cyberapp.services.queue", enqueue_job=lambda *args, **kwargs: None
        ),
    }
    for name in (
        "cyberapp",
        "cyberapp.models",
        "cyberapp.services",
        "cybermodules",
    ):
        package = ModuleType(name)
        package.__path__ = []
        stubs[name] = package

    spec = importlib.util.spec_from_file_location(
        "isolated_scan_list_routes", ROOT / "cyberapp/routes/scans.py"
    )
    route = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, stubs):
        spec.loader.exec_module(route)
    return route


@pytest.fixture
def scan_list():
    database = sqlite3.connect(":memory:")
    database.executescript(
        "CREATE TABLE scans(id INTEGER PRIMARY KEY, target, date, status, user_id);"
        "CREATE TABLE scan_progress(scan_id INTEGER PRIMARY KEY, progress, eta_seconds);"
        "INSERT INTO scans VALUES(1,'complete.invalid','2026-10-25','COMPLETED','admin');"
        "INSERT INTO scans VALUES(2,'running.invalid','2026-10-25','hazirlaniyor','admin');"
        "INSERT INTO scans VALUES(3,'failed.invalid','2026-10-25','FAILED','admin');"
        "INSERT INTO scans VALUES(10,'finished.invalid','2026-10-25','NOT_RUNNING','admin');"
        "INSERT INTO scans VALUES(11,'finished-too.invalid','2026-10-25','REHAZIRLANIYOR','admin');"
        "INSERT INTO scans VALUES(12,'unfinished.invalid','2026-10-25','NOT_COMPLETED','admin');"
        "INSERT INTO scan_progress VALUES(1,120,0);"
        "INSERT INTO scan_progress VALUES(3,-5,-1);"
    )

    @contextmanager
    def database_factory():
        yield database

    route = _load_route(database_factory)
    app = Flask("scan-list-test", template_folder=str(ROOT / "templates"))
    app.config.update(TESTING=True, SECRET_KEY="scan-list-test-only")
    app.register_blueprint(route.scans_bp)
    client = app.test_client()
    with client.session_transaction() as signed_session:
        signed_session.update(logged_in=True, user="fixture-admin", role="admin")
    yield route, database, client
    database.close()


@pytest.mark.parametrize("path", ["/scans", "/scan"])
def test_list_routes_share_real_counts_and_progress(scan_list, path):
    _, _, client = scan_list
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    body = response.get_data(as_text=True)
    assert re.search(r'id="completed-scan-count"[^>]*>\s*1\s*</p>', body)
    assert re.search(r'id="running-scan-count"[^>]*>\s*1\s*</p>', body)
    assert re.search(r'id="failed-scan-count"[^>]*>\s*1\s*</p>', body)
    assert re.search(r'data-scan-progress="1"[^>]*>\s*100%\s*<span[^>]*>ETA 0s', body)
    assert re.search(r'data-scan-progress="2"[^>]*>\s*<span[^>]*>Unknown</span>', body)
    assert re.search(r'data-scan-progress="3"[^>]*>\s*0%', body)


def test_non_text_database_fields_cannot_break_or_inject_the_page(scan_list):
    _, database, client = scan_list
    database.execute("INSERT INTO scans VALUES(4,123,456,789,zeroblob(8))")
    response = client.get("/scans")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-scan-progress="4"' in body
    assert "UNKNOWN" in body


def test_large_database_fields_are_bounded_before_rendering(scan_list):
    route, database, client = scan_list
    large = "x" * 100_000
    database.execute(
        "UPDATE scans SET target=?, date=?, status=?, user_id=? WHERE id=1",
        (large, large, large, large),
    )
    database.execute(
        "UPDATE scan_progress SET progress=?, eta_seconds=? WHERE scan_id=1",
        (large, large),
    )
    response = client.get("/scans")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert large not in body
    scans, progress, *_ = route._load_scans()
    first = next(scan for scan in scans if scan[0] == 1)
    assert len(first[1]) == 2048
    assert progress[1]["available"] is False
    assert progress[1]["eta_available"] is False
    assert re.search(r'data-scan-progress="1"[^>]*>\s*<span[^>]*>Unknown</span>', body)


def test_status_counts_require_known_prefixes(scan_list):
    route, _, _ = scan_list
    _, _, completed, running, failed = route._load_scans()
    assert (completed, running, failed) == (1, 1, 1)


def test_analyst_sees_prefix_aware_read_links_without_admin_actions(scan_list):
    _, _, client = scan_list
    with client.session_transaction() as signed_session:
        signed_session["role"] = "analyst"
    response = client.get("/scans", environ_overrides={"SCRIPT_NAME": "/panel"})
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'href="/panel/details/1"' in body
    assert 'href="/panel"' in body
    for operation in ("/report/", "/delete/", "/autoexploit/"):
        assert operation not in body


@pytest.mark.parametrize(
    "row,expected",
    [
        (None, (0, False, None, False)),
        ((float("nan"), float("inf")), (0, False, None, False)),
        ((True, False), (0, False, None, False)),
        ((10**1000, 10**1000), (0, False, None, False)),
        ((-4.5, 1.9), (0, True, 1, True)),
        ((101.5, 0), (100, True, 0, True)),
    ],
)
def test_progress_metadata_is_typed_bounded_and_honest(scan_list, row, expected):
    route, _, _ = scan_list
    snapshot = route._progress_snapshot(row)
    assert (
        snapshot["percent"],
        snapshot["available"],
        snapshot["eta_seconds"],
        snapshot["eta_available"],
    ) == expected


@pytest.mark.parametrize("path", ["/scans", "/scan"])
def test_database_error_is_generic_and_not_cached(scan_list, path):
    route, _, client = scan_list
    route.db_conn = Mock(
        side_effect=RuntimeError("private-password C:/sensitive/database.sqlite")
    )
    response = client.get(path)
    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert response.get_data(as_text=True) == "Scan records are temporarily unavailable"
    assert b"private-password" not in response.data
    assert b"sensitive" not in response.data


def test_unauthenticated_list_does_not_touch_database(scan_list):
    route, _, client = scan_list
    route.db_conn = Mock(side_effect=AssertionError("must not read database"))
    with client.session_transaction() as signed_session:
        signed_session.clear()
    response = client.get("/scans")
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"
    route.db_conn.assert_not_called()

"""Real management-only app checks without starting a server or feature runtime."""

import ast
import sqlite3
import sys
from pathlib import Path

import pytest

from cyberapp.management_app import create_management_app
from cyberapp.management_cli import build_parser
from cyberapp.models.db import db_conn

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def management_app(tmp_path):
    database = tmp_path / "management.sqlite3"
    before = set(sys.modules)
    app = create_management_app(
        config={
            "TESTING": True,
            "SECRET_KEY": "management-mode-test-signing-key",
            "DATABASE": str(database),
        }
    )
    newly_loaded = set(sys.modules) - before
    forbidden = ("cybermodules", "tools", "evasion", "c2")
    assert not any(
        name == prefix or name.startswith(prefix + ".")
        for name in newly_loaded
        for prefix in forbidden
    )
    return app, database


def login(client, role="analyst"):
    with client.session_transaction() as session:
        session.update(logged_in=True, user="fixture-user", role=role)


def seed_record(database):
    with sqlite3.connect(database) as conn:
        cursor = conn.execute(
            "INSERT INTO scans (target, status, user_id) VALUES (?, ?, ?)",
            ('<img src=x onerror="fixture()">', "RUNNING", "fixture-user"),
        )
        scan_id = cursor.lastrowid
        conn.execute(
            "INSERT INTO scan_progress (scan_id, progress, eta_seconds) VALUES (?, ?, ?)",
            (scan_id, 25, 0),
        )
        conn.execute(
            "INSERT INTO vulns (scan_id, type, url, fix, severity) VALUES (?, ?, ?, ?, ?)",
            (scan_id, "stored <script>fixture()</script>", "/path", "update", "HIGH"),
        )
        conn.execute(
            "INSERT INTO techno (scan_id, name, detected_via, confidence) VALUES (?, ?, ?, ?)",
            (scan_id, "nginx", "header", 90),
        )
        conn.execute(
            "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
            (scan_id, "NOTE", "stored observation"),
        )
        conn.execute(
            "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
            (scan_id, "fixture", "stored output"),
        )
        conn.commit()
    return scan_id


def test_factory_migrates_selected_database_and_public_health_is_honest(
    management_app,
):
    app, database = management_app
    assert database.is_file()
    with app.app_context(), db_conn() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert {"scans", "vulns", "audit_logs", "ai_vulnerability_reports"} <= tables

    response = app.test_client().get("/health")
    assert response.status_code == 200
    assert response.json == {
        "status": "OPERATIONAL",
        "mode": "management",
        "database_ready": True,
        "operational_modules_loaded_by_management_factory": False,
        "production_ready": False,
        "timestamp": response.json["timestamp"],
    }
    assert str(database) not in response.get_data(as_text=True)
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_management_pages_require_login_and_keep_admin_boundary(management_app):
    app, _ = management_app
    client = app.test_client()
    assert client.get("/").status_code == 302
    assert client.get("/api/management/summary").status_code == 401

    login(client)
    assert client.get("/").status_code == 200
    assert client.get("/feature-status").status_code == 200
    assert client.get("/ai-vulnerability").status_code == 403
    assert client.get("/audit").status_code == 403

    login(client, "admin")
    assert client.get("/ai-vulnerability").status_code == 200
    assert client.get("/audit").status_code == 200


def test_real_login_route_uses_configured_accounts_and_audits(management_app):
    app, database = management_app
    routes = sys.modules["cyberapp.management_routes"]
    client = app.test_client()
    with client.session_transaction() as session:
        session.update(logged_in=True, user="stale", role="admin")
    oversized = client.post("/login", data={"user": "u" * 10_000, "pass": "wrong"})
    assert oversized.status_code == 200
    failed = client.post("/login", data={"user": routes.ADMIN_USER, "pass": "wrong"})
    assert failed.status_code == 200
    with client.session_transaction() as session:
        assert not session.get("logged_in")

    logged_in = client.post(
        "/login",
        data={"user": routes.ADMIN_USER, "pass": routes.ADMIN_PASS},
    )
    assert logged_in.status_code == 302
    assert logged_in.headers["Location"] == "/dashboard"
    with client.session_transaction() as session:
        assert session["role"] == "admin"
        assert session["user"] == routes.ADMIN_USER
    with sqlite3.connect(database) as connection:
        actions = {
            row[0] for row in connection.execute("SELECT action FROM audit_logs")
        }
        longest_user, longest_detail = connection.execute(
            "SELECT MAX(length(user_id)), MAX(length(detail)) FROM audit_logs"
        ).fetchone()
    assert {"login_failed", "login_success"} <= actions
    assert longest_user <= 128
    assert longest_detail <= 2048


def test_login_page_exposes_no_default_password_or_false_online_claim(management_app):
    app, _ = management_app
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "AYmG1NEl2MqHiKAkNBsyvw" not in body
    assert "Demo:" not in body
    assert "System Online" not in body
    assert "Yapılandırılmış admin veya analyst" in body
    for external in (
        "cdn.tailwindcss.com",
        "cdn.jsdelivr.net",
        "fonts.googleapis.com",
        "cdnjs.cloudflare.com",
    ):
        assert external not in body
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]

    login(client, "admin")
    for path in ("/feature-status", "/ai-vulnerability"):
        page = client.get(path)
        assert page.status_code == 200
        assert "https://cdn." not in page.get_data(as_text=True)
        assert "fonts.googleapis.com" not in page.get_data(as_text=True)


def test_dashboard_and_detail_show_real_stored_records_as_escaped_text(
    management_app,
):
    app, database = management_app
    scan_id = seed_record(database)
    client = app.test_client()
    login(client)

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    body = dashboard.get_data(as_text=True)
    assert "&lt;img src=x onerror=" in body
    assert '<img src=x onerror="fixture()">' not in body
    assert f'data-scan-id="{scan_id}"' in body
    assert "25%" in body
    assert "ETA: 0 s" in body
    assert 'class="scan-vulnerability-count">1<' in body
    assert 'role="status" aria-live="polite"' in body
    assert 'aria-valuemin="0" aria-valuemax="100"' in body
    assert 'aria-valuetext="25%"' in body

    detail = client.get(f"/management/scans/{scan_id}")
    assert detail.status_code == 200
    detail_body = detail.get_data(as_text=True)
    assert "stored &lt;script&gt;fixture()&lt;/script&gt;" in detail_body
    assert "stored observation" in detail_body
    assert "stored output" in detail_body
    assert "<script>fixture()</script>" not in detail_body


def test_management_json_is_bounded_read_only_and_uses_selected_database(
    management_app,
):
    app, database = management_app
    scan_id = seed_record(database)
    before = database.read_bytes()
    client = app.test_client()
    login(client)

    summary = client.get("/api/management/summary")
    assert summary.status_code == 200
    assert summary.json["read_only"] is True
    assert summary.json["target_contacted"] is False
    assert summary.json["totals"] == {
        "scans": 1,
        "vulnerabilities": 1,
        "running": 1,
    }
    record = client.get(f"/api/management/scans/{scan_id}/record")
    assert record.status_code == 200
    assert record.json["scan"]["progress"] == 25
    assert record.json["scan"]["eta_seconds"] == 0
    assert record.json["target_contacted"] is False
    assert database.read_bytes() == before
    assert summary.headers["Cache-Control"] == "no-store"
    assert record.headers["Cache-Control"] == "no-store"


def test_large_database_text_is_truncated_before_it_reaches_responses(management_app):
    app, database = management_app
    scan_id = seed_record(database)
    large = "x" * 100_000
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE scans SET target = ? WHERE id = ?", (large, scan_id))
        connection.execute(
            "UPDATE vulns SET fix = ? WHERE scan_id = ?", (large, scan_id)
        )
        connection.execute(
            "UPDATE intel SET data = ? WHERE scan_id = ?", (large, scan_id)
        )
        connection.execute(
            "UPDATE scan_progress SET progress = ?, eta_seconds = ? WHERE scan_id = ?",
            (large, large, scan_id),
        )
        connection.execute(
            "UPDATE techno SET confidence = ? WHERE scan_id = ?", (large, scan_id)
        )
        connection.execute(
            "UPDATE tool_logs SET output = ? WHERE scan_id = ?", (large, scan_id)
        )
        connection.execute("INSERT INTO audit_logs (detail) VALUES (?)", (large,))
        connection.commit()
    client = app.test_client()
    login(client, "admin")
    summary = client.get("/api/management/summary").json
    record = client.get(f"/api/management/scans/{scan_id}/record").json
    status = client.get(f"/api/management/scans/{scan_id}/status").json
    assert len(summary["scans"][0]["target"]) == 2048
    assert summary["scans"][0]["progress"] is None
    assert summary["scans"][0]["eta_seconds"] is None
    assert status["progress_available"] is False
    assert status["eta_available"] is False
    assert len(record["vulnerabilities"][0]["fix"]) == 4096
    assert record["technologies"][0]["confidence"] is None
    assert len(record["intel"][0]["data"]) == 4096
    assert len(record["logs"][0]["output"]) == 4096
    audit = client.get("/audit").get_data(as_text=True)
    assert large not in audit
    assert "x" * 2048 in audit


def test_admin_offline_analysis_and_saved_record_review_work(management_app):
    app, database = management_app
    scan_id = seed_record(database)
    client = app.test_client()
    login(client, "admin")

    supplied = client.post(
        "/api/ai-vulnerability/analyze",
        json={
            "headers": {"Server": "nginx/1.24.0"},
            "html": "",
            "cookies": {},
            "existing_vulns": [],
            "response_scheme": "https",
        },
    )
    assert supplied.status_code == 200
    assert supplied.json["analysis_metadata"]["network_probe_performed"] is False
    assert supplied.json["analysis_metadata"]["exploit_executed"] is False

    saved = client.post(f"/api/ai-vulnerability/scans/{scan_id}/review", json={})
    assert saved.status_code == 200
    report = client.get(f"/api/ai-vulnerability/reports/{scan_id}")
    assert report.status_code == 200
    assert report.json["scan_id"] == scan_id


def test_audit_page_escapes_stored_fields(management_app):
    app, database = management_app
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO audit_logs (user_id, role, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
            (
                "fixture-user",
                "admin",
                "stored",
                '<img src=x onerror="auditFixture()">',
                "127.0.0.1",
            ),
        )
        conn.commit()
    client = app.test_client()
    login(client, "admin")
    response = client.get("/audit")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "&lt;img src=x onerror=" in body
    assert '<img src=x onerror="auditFixture()">' not in body


def test_missing_and_unavailable_records_return_generic_errors(
    management_app, tmp_path
):
    app, _ = management_app
    client = app.test_client()
    login(client)
    assert client.get("/management/scans/987654").status_code == 404
    assert client.get("/api/management/scans/987654/record").json == {
        "error": "not_found"
    }

    broken = create_management_app(
        run_migrations_on_start=False,
        config={
            "TESTING": True,
            "SECRET_KEY": "broken-management-fixture",
            "DATABASE": str(tmp_path),
        },
    )
    broken_client = broken.test_client()
    login(broken_client)
    page = broken_client.get("/")
    assert page.status_code == 503
    assert "şu anda okunamıyor" in page.get_data(as_text=True)
    health = broken_client.get("/health")
    assert health.status_code == 503
    assert health.json["database_ready"] is False
    assert str(tmp_path) not in page.get_data(as_text=True)
    assert str(tmp_path) not in health.get_data(as_text=True)


def test_database_path_is_normalized_once_and_memory_database_is_rejected(
    monkeypatch, tmp_path
):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.chdir(first)
    app = create_management_app(
        config={
            "TESTING": True,
            "SECRET_KEY": "relative-database-fixture",
            "DATABASE": "records.sqlite3",
        }
    )
    selected = Path(app.config["DATABASE"])
    assert selected == first / "records.sqlite3"
    monkeypatch.chdir(second)
    assert app.test_client().get("/health").status_code == 200
    assert selected.is_file()
    assert not (second / "records.sqlite3").exists()

    with pytest.raises(ValueError, match="persistent SQLite file"):
        create_management_app(
            run_migrations_on_start=False,
            config={"DATABASE": ":memory:", "SECRET_KEY": "memory-fixture"},
        )


def test_health_rejects_partial_schema(tmp_path):
    database = tmp_path / "partial.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE scans(id INTEGER PRIMARY KEY)")
    app = create_management_app(
        run_migrations_on_start=False,
        config={
            "TESTING": True,
            "SECRET_KEY": "partial-schema-fixture",
            "DATABASE": database,
        },
    )
    response = app.test_client().get("/health")
    assert response.status_code == 503
    assert response.json["status"] == "DEGRADED"
    assert response.json["database_ready"] is False


def test_health_rejects_head_revision_with_missing_required_columns(tmp_path):
    database = tmp_path / "damaged.sqlite3"
    app = create_management_app(
        config={
            "TESTING": True,
            "SECRET_KEY": "damaged-schema-fixture",
            "DATABASE": database,
        }
    )
    assert app.test_client().get("/health").status_code == 200
    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE scans RENAME TO scans_complete")
        connection.execute("CREATE TABLE scans(id INTEGER PRIMARY KEY)")
        connection.execute("DROP TABLE scans_complete")
        connection.commit()
    response = app.test_client().get("/health")
    assert response.status_code == 503
    assert response.json["database_ready"] is False


def test_management_routes_do_not_offer_record_mutation(management_app):
    app, _ = management_app
    client = app.test_client()
    login(client, "admin")
    paths = (
        "/",
        "/dashboard",
        "/api/management/summary",
        "/management/scans/1",
        "/api/management/scans/1/record",
    )
    for path in paths:
        for method in ("post", "delete"):
            response = getattr(client, method)(path)
            assert response.status_code == 405
            if path.startswith("/api/"):
                assert response.is_json
                assert response.json == {"error": "method_not_allowed"}


def test_management_source_has_a_fixed_safe_import_boundary():
    forbidden = ("cybermodules", "tools", "evasion", "c2", "cyberapp.app")
    for relative in (
        "cyberapp/management_app.py",
        "cyberapp/management_cli.py",
        "cyberapp/management_data.py",
        "cyberapp/management_routes.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        assert not any(
            name == prefix or name.startswith(prefix + ".")
            for name in imported
            for prefix in forbidden
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                called = getattr(node.func, "attr", getattr(node.func, "id", ""))
                assert called not in {
                    "system",
                    "popen",
                    "Popen",
                    "create_connection",
                }


def test_management_cli_accepts_only_loopback_and_valid_ports():
    parser = build_parser()
    args = parser.parse_args(["--host", "::1", "--port", "8081"])
    assert args.host == "::1"
    assert args.port == 8081
    with pytest.raises(SystemExit):
        parser.parse_args(["--host", "0.0.0.0"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--host", "localhost"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--port", "0"])

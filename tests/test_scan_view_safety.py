"""Read-only scan detail rendering using an extracted handler and temporary DB."""

import ast
import sqlite3
from contextlib import contextmanager
from html.parser import HTMLParser
from pathlib import Path

import pytest
from flask import Flask, redirect, render_template, session
from jinja2 import DictLoader

ROOT = Path(__file__).resolve().parents[1]
HOSTILE = '<img src=x onerror="alert(1)"><script>fixture-marker</script>'


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active_tags = []
        self.event_attributes = []
        self.data = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "img", "iframe", "svg", "object", "embed"}:
            self.active_tags.append(tag)
        self.event_attributes.extend(name for name, _ in attrs if name.startswith("on"))

    def handle_data(self, data):
        self.data.append(data)


@pytest.fixture
def detail_view():
    source = ROOT / "cyberapp/routes/scans.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "details"
    )
    function.decorator_list = []
    database = sqlite3.connect(":memory:")
    database.executescript(
        "CREATE TABLE scans (id INTEGER, target TEXT, date TEXT, status TEXT);"
        "CREATE TABLE vulns (id INTEGER, scan_id INTEGER, type TEXT, url TEXT, fix TEXT, severity TEXT);"
        "CREATE TABLE techno (id INTEGER, scan_id INTEGER, name TEXT, via TEXT);"
        "CREATE TABLE intel (id INTEGER, scan_id INTEGER, type, info);"
        "CREATE TABLE tool_logs (id INTEGER, scan_id INTEGER, tool_name, output);"
        "INSERT INTO scans VALUES (1, 'fixture.invalid', '2026-10-24', 'COMPLETED');"
        "INSERT INTO vulns VALUES (1, 1, 'Fixture', '/fixture', 'Remediation text', 'CRITICAL');"
        "INSERT INTO techno VALUES (1, 1, 'Fixture technology', 'supplied record');"
        "INSERT INTO intel VALUES (1, 1, 'Fixture intelligence', 'supplied detail');"
        "INSERT INTO tool_logs VALUES (1, 1, 'fixture', 'supplied output');"
    )

    @contextmanager
    def db_conn():
        yield database

    context = {}

    def render_details(template, **values):
        context.clear()
        context.update(values)
        return render_template(template, **values)

    namespace = {
        "session": session,
        "redirect": redirect,
        "db_conn": db_conn,
        "render_template": render_details,
    }
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    app = Flask("scan-detail-test")
    app.config.update(TESTING=True, SECRET_KEY="scan-view-fixture-only")
    app.jinja_loader = DictLoader(
        {
            "base.html": "<!doctype html><html><body>{% block body %}{% endblock %}</body></html>",
            "details.html": (ROOT / "templates/details.html").read_text(
                encoding="utf-8"
            ),
        }
    )
    app.add_url_rule("/details/<int:scan_id>", view_func=namespace["details"])
    client = app.test_client()
    with client.session_transaction() as signed_session:
        signed_session.update(logged_in=True, user="fixture-analyst", role="analyst")
    yield database, client, context, namespace
    database.close()


@pytest.mark.parametrize(
    "table,column",
    [
        ("scans", "target"),
        ("scans", "date"),
        ("scans", "status"),
        ("vulns", "type"),
        ("vulns", "url"),
        ("vulns", "fix"),
        ("vulns", "severity"),
        ("techno", "name"),
        ("techno", "via"),
        ("intel", "type"),
        ("intel", "info"),
    ],
)
def test_database_fields_render_as_literal_text(detail_view, table, column):
    database, client, _, _ = detail_view
    # The identifiers come exclusively from this fixed test matrix.
    database.execute(f"UPDATE {table} SET {column} = ?", (HOSTILE,))
    response = client.get("/details/1")
    assert response.status_code == 200
    parser = PageParser()
    parser.feed(response.get_data(as_text=True))
    assert parser.active_tags == []
    assert parser.event_attributes == []
    assert HOSTILE in "".join(parser.data)


@pytest.mark.parametrize("column", ["tool_name", "output"])
def test_log_fragments_are_safe_even_if_a_template_displays_them(detail_view, column):
    database, client, context, _ = detail_view
    database.execute(f"UPDATE tool_logs SET {column} = ?", (HOSTILE,))
    assert client.get("/details/1").status_code == 200
    parser = PageParser()
    parser.feed(context["logs_html"])
    assert parser.active_tags == []
    assert parser.event_attributes == []
    assert HOSTILE in "".join(parser.data)


def test_null_and_numeric_preview_values_do_not_break_the_page(detail_view):
    database, client, context, _ = detail_view
    database.execute("INSERT INTO intel VALUES (2, 1, NULL, NULL)")
    database.execute("INSERT INTO intel VALUES (3, 1, 123, 456)")
    database.execute("INSERT INTO tool_logs VALUES (2, 1, NULL, NULL)")
    database.execute("INSERT INTO tool_logs VALUES (3, 1, 789, 12345)")
    database.execute("INSERT INTO vulns VALUES (2, 1, NULL, NULL, NULL, NULL)")
    database.execute("INSERT INTO techno VALUES (2, 1, NULL, NULL)")
    response = client.get("/details/1")
    assert response.status_code == 200
    assert "456" in response.get_data(as_text=True)
    assert "12345" in context["logs_html"]
    assert "Unknown" in response.get_data(as_text=True)
    assert context["critical_count"] == 1


def test_preview_limits_apply_before_escaping_and_keep_counts(detail_view):
    database, client, context, _ = detail_view
    database.execute("UPDATE intel SET info = ?", ("<" * 201,))
    database.execute("UPDATE tool_logs SET output = ?", ("&" * 151,))
    database.execute("INSERT INTO vulns VALUES (2, 1, 'High', '/', '', 'HIGH')")
    database.execute("INSERT INTO vulns VALUES (3, 1, 'Medium', '/', '', 'MEDIUM')")
    assert client.get("/details/1").status_code == 200
    assert context["intel_html"].count("&lt;") == 200
    assert context["logs_html"].count("&amp;") == 150
    assert [
        context[name] for name in ("critical_count", "high_count", "medium_count")
    ] == [1, 1, 1]


def test_missing_scan_and_empty_results_remain_supported(detail_view):
    database, client, context, _ = detail_view
    assert client.get("/details/999").status_code == 404
    for table in ("vulns", "techno", "intel", "tool_logs"):
        database.execute(f"DELETE FROM {table}")
    response = client.get("/details/1")
    assert response.status_code == 200
    assert "Güvenlik açığı bulunamadı" in response.get_data(as_text=True)
    assert context["critical_count"] == 0


def test_database_failure_does_not_leak_or_render_exception_text(detail_view):
    _, client, _, namespace = detail_view

    @contextmanager
    def unavailable_database():
        raise RuntimeError("private database path " + HOSTILE)
        yield  # Make the fixture a context manager without opening anything.

    namespace["db_conn"] = unavailable_database
    response = client.get("/details/1")
    assert response.status_code == 500
    assert response.get_data(as_text=True) == "Scan details could not be loaded"


def test_unauthenticated_request_does_not_query_database(detail_view):
    database, client, _, _ = detail_view
    database.close()
    with client.session_transaction() as signed_session:
        signed_session.clear()
    response = client.get("/details/1")
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"

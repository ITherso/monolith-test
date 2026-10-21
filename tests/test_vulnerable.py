"""Disabled training routes stay absent from the management application's surface.

The factory runs with inert blueprint replacements. No training or feature module
is imported, and requests cannot reach a command, deserializer, or network client.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

FORBIDDEN_MODULES = {
    "cyberapp.routes.vulnerable",
    "cyberapp.routes.api_vulnerable",
}


@pytest.fixture(scope="module")
def management_app():
    helper_path = Path(__file__).with_name("test_management_security.py")
    spec = importlib.util.spec_from_file_location(
        "training_route_test_helpers", helper_path
    )
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    app, imports = helpers.build_management_app()
    assert not FORBIDDEN_MODULES.intersection(imports)
    assert not FORBIDDEN_MODULES.intersection(sys.modules)
    assert not {"vulnerable", "api_vuln"}.intersection(app.blueprints)
    return app


@pytest.mark.parametrize("logged_in", [False, True], ids=["anonymous", "authenticated"])
@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/vuln/"),
        ("GET", "/vuln/sqli/login"),
        ("POST", "/vuln/sqli/login"),
        ("GET", "/vuln/sqli/search"),
        ("GET", "/vuln/cmdi/ping"),
        ("POST", "/vuln/cmdi/ping"),
        ("GET", "/vuln/cmdi/nslookup"),
        ("POST", "/vuln/cmdi/nslookup"),
        ("GET", "/vuln/ssti/greeting"),
        ("GET", "/vuln/ssti/email"),
        ("GET", "/vuln/deserial/pickle"),
        ("POST", "/vuln/deserial/pickle"),
        ("GET", "/vuln/deserial/yaml"),
        ("POST", "/vuln/deserial/yaml"),
        ("GET", "/vuln/jwt/login"),
        ("POST", "/vuln/jwt/login"),
        ("GET", "/vuln/jwt/verify"),
        ("GET", "/vuln/idor/profile/1"),
        ("GET", "/vuln/idor/document/example.txt"),
        ("GET", "/vuln/upload"),
        ("POST", "/vuln/upload"),
        ("GET", "/vuln/uploads/example.txt"),
        ("GET", "/vuln/ssrf/fetch"),
        ("POST", "/vuln/ssrf/webhook"),
        ("GET", "/vuln/admin/users"),
        ("GET", "/vuln/admin/delete/1"),
        ("GET", "/vuln/admin/config"),
        ("GET", "/vuln/forgot-password"),
        ("POST", "/vuln/forgot-password"),
        ("GET", "/vuln/reset-password"),
        ("POST", "/vuln/reset-password"),
        ("POST", "/api/v1/auth/token"),
        ("GET", "/api/v1/auth/verify"),
        ("GET", "/api/v1/users/1"),
        ("GET", "/api/v1/users/1/secrets"),
        ("POST", "/api/v1/users/register"),
        ("GET", "/api/v1/schema"),
        ("GET", "/api/v1/internal/debug"),
        ("POST", "/api/v1/admin/exec"),
        ("GET", "/api/v1/files/example.txt"),
    ],
)
def test_training_routes_return_not_found(management_app, logged_in, method, path):
    client = management_app.test_client()
    if logged_in:
        with client.session_transaction() as session:
            session.update(logged_in=True, user="admin", role="admin")
    assert client.open(path, method=method).status_code == 404

"""Release metadata contracts with mocked HTTP only; never import the framework."""

import ast
import importlib.util
import io
import json
from http.client import IncompleteRead
from pathlib import Path
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest
import tomllib

ROOT = Path(__file__).resolve().parents[1]


class Response(io.BytesIO):
    status = 200

    def __init__(self, body):
        super().__init__(body)
        self.read_limit = None

    def read(self, size=-1):
        self.read_limit = size
        return super().read(size)


@pytest.fixture
def checker(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "isolated_release_updates", ROOT / "cyberapp/release_updates.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(
        module.request,
        "urlopen",
        Mock(side_effect=AssertionError("Real network access is forbidden")),
    )
    return module


def published_release(**changes):
    release = {
        "tag_name": "v0.2.0",
        "name": "Release 0.2.0",
        "body": "Release notes",
        "draft": False,
        "prerelease": False,
        "published_at": "2026-10-22T09:00:00Z",
        "assets": [],
    }
    release.update(changes)
    return release


def serve(checker, monkeypatch, payload):
    response = Response(json.dumps(payload).encode("utf-8"))
    opener = Mock(return_value=response)
    monkeypatch.setattr(checker.request, "urlopen", opener)
    return response, opener


def test_current_version_matches_project_metadata(checker):
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert checker.CURRENT_VERSION == project["project"]["version"] == "0.1.0"


def test_only_fetches_latest_release_metadata_and_closes_response(checker, monkeypatch):
    asset = (
        "https://github.com/ITherso/monolith-test/releases/download/v0.2.0/example.zip"
    )
    response, opener = serve(
        checker,
        monkeypatch,
        published_release(assets=[{"browser_download_url": asset}]),
    )
    result = checker.check_release_updates()
    assert result["update_available"] is True
    assert result["status"] == "update_available"
    assert result["current_version"] == "0.1.0"
    assert result["latest_version"] == "v0.2.0"
    assert (
        result["release_url"]
        == "https://github.com/ITherso/monolith-test/releases/tag/v0.2.0"
    )
    assert result["release_notes"] == "Release notes"
    assert result["download_url"] == asset
    assert response.closed
    assert response.read_limit == checker.MAX_RESPONSE_BYTES + 1
    opener.assert_called_once()
    req = opener.call_args.args[0]
    assert (
        req.full_url
        == "https://api.github.com/repos/ITherso/monolith-test/releases/latest"
    )
    assert req.get_method() == "GET"
    assert req.data is None
    assert req.get_header("Authorization") is None
    assert opener.call_args.kwargs == {"timeout": 10}


@pytest.mark.parametrize(
    "current,latest,status,available",
    [
        ("0.1.0", "v0.2.0", "update_available", True),
        ("0.9.0", "v0.10.0", "update_available", True),
        ("1.10.0", "v1.9.0", "current_newer", False),
        ("v0.1", "0.1.0", "up_to_date", False),
        ("0.1.0", "v0.1.0+build.9", "up_to_date", False),
        ("0.1.0", "V0.1.0", "up_to_date", False),
    ],
)
def test_numeric_version_comparison_does_not_offer_downgrades(
    checker, monkeypatch, current, latest, status, available
):
    serve(checker, monkeypatch, published_release(tag_name=latest))
    result = checker.check_release_updates(current)
    assert result["status"] == status
    assert result["update_available"] is available


@pytest.mark.parametrize(
    "changes", [{"draft": True}, {"prerelease": True}, {"published_at": None}]
)
def test_unpublished_or_prerelease_metadata_never_offers_an_update(
    checker, monkeypatch, changes
):
    response, _ = serve(checker, monkeypatch, published_release(**changes))
    result = checker.check_release_updates()
    assert result["update_available"] is False
    assert result["status"] == "no_published_release"
    assert response.closed


@pytest.mark.parametrize(
    "tag", ["latest", "v1", "v0.2.0-rc.1", "01.2.3", " v0.2.0", None, 2]
)
def test_unknown_version_formats_are_not_assumed_newer(checker, monkeypatch, tag):
    serve(checker, monkeypatch, published_release(tag_name=tag))
    result = checker.check_release_updates()
    assert result["status"] == "unsupported_version"
    assert result["update_available"] is False


def test_invalid_current_version_does_not_contact_the_network(checker):
    result = checker.check_release_updates("unknown")
    assert result["status"] == "unsupported_version"
    checker.request.urlopen.assert_not_called()


def test_no_release_404_is_distinct_from_connectivity_failure(checker, monkeypatch):
    response_body = io.BytesIO(b'{"message":"Not Found"}')
    failure = HTTPError(checker.LATEST_RELEASE_URL, 404, "Not Found", {}, response_body)
    monkeypatch.setattr(checker.request, "urlopen", Mock(side_effect=failure))
    result = checker.check_release_updates()
    assert result["update_available"] is False
    assert result["status"] == "no_release"
    assert "error" not in result
    assert response_body.closed


@pytest.mark.parametrize("code", [403, 429, 500])
def test_http_failures_are_not_reported_as_up_to_date(checker, monkeypatch, code):
    failure = HTTPError(checker.LATEST_RELEASE_URL, code, "Error", {}, io.BytesIO())
    monkeypatch.setattr(checker.request, "urlopen", Mock(side_effect=failure))
    result = checker.check_release_updates()
    assert result["status"] == "http_error"
    assert result["http_status"] == code
    assert result["update_available"] is False


@pytest.mark.parametrize(
    "failure", [TimeoutError(), URLError("offline"), OSError("offline")]
)
def test_network_failure_is_reported_without_an_update_claim(
    checker, monkeypatch, failure
):
    monkeypatch.setattr(checker.request, "urlopen", Mock(side_effect=failure))
    result = checker.check_release_updates()
    assert result["status"] == "unavailable"
    assert result["update_available"] is False
    assert result["error"]


@pytest.mark.parametrize("body", [b"not JSON", b"\xff", b'{"tag_name":'])
def test_invalid_json_does_not_escape_and_response_is_closed(
    checker, monkeypatch, body
):
    response = Response(body)
    monkeypatch.setattr(checker.request, "urlopen", Mock(return_value=response))
    result = checker.check_release_updates()
    assert result["status"] == "invalid_response"
    assert result["update_available"] is False
    assert response.closed


@pytest.mark.parametrize(
    "payload",
    [
        [],
        None,
        {},
        published_release(draft="false"),
        published_release(prerelease=0),
        published_release(body=[]),
        published_release(name={}),
        published_release(published_at="invalid"),
        published_release(published_at="2026-10-22T09:00:00"),
        published_release(published_at=123),
    ],
)
def test_malformed_release_fields_are_reported_honestly(checker, monkeypatch, payload):
    serve(checker, monkeypatch, payload)
    result = checker.check_release_updates()
    assert result["status"] == "invalid_response"
    assert result["update_available"] is False


def test_response_size_is_bounded_and_context_is_closed(checker, monkeypatch):
    response = Response(b" " * (checker.MAX_RESPONSE_BYTES + 100))
    monkeypatch.setattr(checker.request, "urlopen", Mock(return_value=response))
    result = checker.check_release_updates()
    assert result["status"] == "invalid_response"
    assert response.read_limit == checker.MAX_RESPONSE_BYTES + 1
    assert response.closed


def test_interrupted_response_is_unavailable_and_context_is_closed(
    checker, monkeypatch
):
    response = Response(b"unused")
    response.read = Mock(side_effect=IncompleteRead(b"partial", 100))
    monkeypatch.setattr(checker.request, "urlopen", Mock(return_value=response))
    result = checker.check_release_updates()
    assert result["status"] == "unavailable"
    assert result["update_available"] is False
    assert response.closed


def test_optional_notes_and_assets_are_safe_metadata_only(checker, monkeypatch):
    serve(
        checker,
        monkeypatch,
        published_release(
            body=None,
            assets=[None, {}, {"browser_download_url": "file:///tmp/example"}],
        ),
    )
    result = checker.check_release_updates()
    assert result["update_available"] is True
    assert result["release_notes"] == "No release notes"
    assert result["download_url"] is None


def test_legacy_wrapper_delegates_without_importing_operational_modules(checker):
    tree = ast.parse((ROOT / "cybermodules/auto_update.py").read_text(encoding="utf-8"))
    original = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "AutoUpdater"
    )
    original.body = [
        node
        for node in original.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"__init__", "check_for_updates"}
    ]
    delegated = Mock(return_value={"update_available": False, "status": "no_release"})
    namespace = {
        "CURRENT_VERSION": checker.CURRENT_VERSION,
        "LATEST_RELEASE_URL": checker.LATEST_RELEASE_URL,
        "check_release_updates": delegated,
    }
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[original], type_ignores=[])),
            "isolated_update_wrapper",
            "exec",
        ),
        namespace,
    )
    updater = namespace["AutoUpdater"]()
    assert updater.version == "0.1.0"
    assert updater.update_url == checker.LATEST_RELEASE_URL
    assert updater.check_for_updates()["status"] == "no_release"
    delegated.assert_called_once_with("0.1.0")

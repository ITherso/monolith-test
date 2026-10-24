"""Real PDF encryption and isolated generator checks; no application imports."""

import ast
import builtins
import importlib.util
import json
import logging
import os
import tempfile
from datetime import datetime
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import pytest
from pypdf import PdfReader, PdfWriter
from pypdf.errors import FileNotDecryptedError

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "fixture-password-şifre-2026"
PRIVATE_TITLE = "CONFIDENTIAL-REPORT-FIXTURE"


@pytest.fixture
def security():
    spec = importlib.util.spec_from_file_location(
        "isolated_report_security", ROOT / "cyberapp/report_security.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def plain_pdf(tmp_path):
    path = tmp_path / "source.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=300)
    writer.add_blank_page(width=400, height=500)
    writer.add_metadata({"/Title": PRIVATE_TITLE})
    with path.open("wb") as stream:
        writer.write(stream)
    return path


def assert_encrypted_report(path):
    with path.open("rb") as stream:
        reader = PdfReader(stream)
        assert reader.is_encrypted
        assert reader.decrypt("wrong-password") == 0
        with pytest.raises(FileNotDecryptedError):
            len(reader.pages)
        assert reader.decrypt(PASSWORD)
        assert len(reader.pages) == 2
        assert reader.pages[0].mediabox.width == 200
        assert reader.pages[1].mediabox.height == 500
        assert reader.metadata.title == PRIVATE_TITLE
        encryption = reader.trailer["/Encrypt"]
        assert encryption["/Length"] == 256
        assert encryption["/CF"]["/StdCF"]["/CFM"] == "/AESV3"
    assert PRIVATE_TITLE.encode() not in path.read_bytes()


def test_atomic_aes256_preserves_pages_and_metadata(security, plain_pdf):
    security.encrypt_pdf_atomic(plain_pdf, PASSWORD)
    assert_encrypted_report(plain_pdf)
    assert not list(plain_pdf.parent.glob(".*.encrypted-*.pdf"))


@pytest.mark.parametrize("password", ["", None, 123])
def test_invalid_password_preserves_original(security, plain_pdf, password):
    original = plain_pdf.read_bytes()
    with pytest.raises(ValueError, match="nonempty"):
        security.encrypt_pdf_atomic(plain_pdf, password)
    assert plain_pdf.read_bytes() == original


def test_invalid_pdf_preserves_original_data(security, tmp_path):
    path = tmp_path / "invalid.pdf"
    original = b"original non-PDF data that must not be overwritten"
    path.write_bytes(original)
    with pytest.raises(Exception):
        security.encrypt_pdf_atomic(path, PASSWORD)
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_existing_encrypted_pdf_is_not_replaced(security, plain_pdf):
    security.encrypt_pdf_atomic(plain_pdf, PASSWORD)
    original = plain_pdf.read_bytes()
    with pytest.raises(ValueError, match="already encrypted"):
        security.encrypt_pdf_atomic(plain_pdf, "different-password")
    assert plain_pdf.read_bytes() == original


def test_backend_failure_preserves_original(security, plain_pdf, monkeypatch):
    original = plain_pdf.read_bytes()

    def fail_encrypt(*args, **kwargs):
        raise RuntimeError("encryption backend unavailable")

    monkeypatch.setattr(security.PdfWriter, "encrypt", fail_encrypt)
    with pytest.raises(RuntimeError, match="backend unavailable"):
        security.encrypt_pdf_atomic(plain_pdf, PASSWORD)
    assert plain_pdf.read_bytes() == original
    assert not list(plain_pdf.parent.glob(".*.encrypted-*.pdf"))


def test_unencrypted_backend_output_is_never_published(
    security, plain_pdf, monkeypatch
):
    original = plain_pdf.read_bytes()
    monkeypatch.setattr(security.PdfWriter, "encrypt", lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="password verification failed"):
        security.encrypt_pdf_atomic(plain_pdf, PASSWORD)
    assert plain_pdf.read_bytes() == original
    assert not list(plain_pdf.parent.glob(".*.encrypted-*.pdf"))


def test_atomic_replace_failure_preserves_original(security, plain_pdf, monkeypatch):
    original = plain_pdf.read_bytes()

    def fail_replace(*args):
        raise PermissionError("destination locked")

    monkeypatch.setattr(security.os, "replace", fail_replace)
    with pytest.raises(PermissionError, match="destination locked"):
        security.encrypt_pdf_atomic(plain_pdf, PASSWORD)
    assert plain_pdf.read_bytes() == original
    assert not list(plain_pdf.parent.glob(".*.encrypted-*.pdf"))


def isolated_pdf_generator(renderer, security):
    """Load the real PDF wrapper without importing its operational parent package."""

    def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "cyberapp.pdf_renderer":
            return renderer
        if name == "cyberapp.report_security":
            return security
        raise AssertionError(f"Unexpected import in isolated PDF generator: {name}")

    source = ROOT / "tools/report_generator.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    node = next(
        item
        for item in tree.body
        if isinstance(item, ast.ClassDef) and item.name == "PDFGenerator"
    )
    namespace = {
        "__name__": "isolated_pdf_generator",
        "__builtins__": dict(vars(builtins), __import__=restricted_import),
        "Path": Path,
        "os": os,
        "tempfile": tempfile,
        "logger": logging.getLogger("isolated-pdf-test"),
    }
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    return namespace["PDFGenerator"]()


@pytest.fixture
def isolated_generator(security, plain_pdf):
    """Inject a renderer fixture for wrapper failure and publication contracts."""
    fixture_bytes = plain_pdf.read_bytes()
    staged_paths = []
    renderer = SimpleNamespace(fail=False, no_output=False)

    def render_html_pdf(html_content, outputfile):
        assert html_content == "<p>Private fixture</p>"
        staged_paths.append(Path(outputfile))
        if not renderer.no_output:
            Path(outputfile).write_bytes(fixture_bytes)
        if renderer.fail:
            raise RuntimeError("fixture conversion failed")

    renderer.render_html_pdf = render_html_pdf
    return isolated_pdf_generator(renderer, security), renderer, staged_paths


def test_generator_publishes_only_encrypted_pdf(isolated_generator, tmp_path):
    generator, _, staged_paths = isolated_generator
    output = tmp_path / "published.pdf"
    assert (
        generator.generate_pdf("<p>Private fixture</p>", str(output), PASSWORD) is True
    )
    assert_encrypted_report(output)
    assert all(not path.exists() for path in staged_paths)
    assert not list(tmp_path.glob(".pdf-report-*"))


@pytest.mark.parametrize("has_existing_report", [False, True])
@pytest.mark.parametrize("failure", ["render", "no-output", "encryption", "publish"])
def test_generator_failure_preserves_destination_and_cleans_plaintext(
    isolated_generator, tmp_path, monkeypatch, failure, has_existing_report
):
    generator, renderer, staged_paths = isolated_generator
    output = tmp_path / "published.pdf"
    original = b"previous report that must survive a failed update"
    if has_existing_report:
        output.write_bytes(original)

    if failure == "render":
        renderer.fail = True
    elif failure == "no-output":
        renderer.no_output = True
    elif failure == "encryption":
        monkeypatch.setattr(generator, "_encrypt_pdf", lambda *args: False)
    else:
        real_replace = os.replace

        def fail_publish(source, destination):
            if Path(destination) == output:
                raise PermissionError("destination locked")
            return real_replace(source, destination)

        monkeypatch.setattr(os, "replace", fail_publish)

    assert (
        generator.generate_pdf("<p>Private fixture</p>", str(output), PASSWORD) is False
    )
    if has_existing_report:
        assert output.read_bytes() == original
    else:
        assert not output.exists()
    assert all(not path.exists() for path in staged_paths)
    assert not list(tmp_path.glob(".pdf-report-*"))


def test_generator_keeps_explicit_unencrypted_export_contract(
    isolated_generator, tmp_path
):
    generator, _, staged_paths = isolated_generator
    output = tmp_path / "published.pdf"
    assert generator.generate_pdf("<p>Private fixture</p>", str(output)) is True
    with output.open("rb") as stream:
        assert not PdfReader(stream).is_encrypted
    assert all(not path.exists() for path in staged_paths)


def test_generator_encrypt_wrapper_reports_backend_failure(
    isolated_generator, plain_pdf, security, monkeypatch
):
    generator, _, _ = isolated_generator
    original = plain_pdf.read_bytes()

    def fail_encrypt(*args):
        raise RuntimeError("fixture encryption failure")

    monkeypatch.setattr(security, "encrypt_pdf_atomic", fail_encrypt)
    assert generator._encrypt_pdf(str(plain_pdf), PASSWORD) is False
    assert plain_pdf.read_bytes() == original


@pytest.fixture
def report_caller(isolated_generator, tmp_path):
    """Extract the real caller method with inert non-PDF components only."""
    source = ROOT / "tools/report_generator.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    report_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ReportGenerator"
    )
    method = next(
        node
        for node in report_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "generate_report"
    )
    formats = Enum("ReportFormat", ["HTML", "PDF", "ALL", "JSON", "MARKDOWN"])
    fixed_time = datetime(2026, 1, 1, 12, 0, 0)

    def report_result():
        return SimpleNamespace(
            success=False,
            pdf_path="",
            html_path="",
            json_path="",
            report_path="",
            mitre_coverage={},
            ai_summary="",
            sigma_rules=[],
            yara_rules=[],
            twitter_thread=[],
            demo_script="",
            error="",
        )

    namespace = {
        "os": os,
        "json": json,
        "Optional": Optional,
        "ChainLog": SimpleNamespace,
        "ReportResult": report_result,
        "ReportFormat": formats,
        "datetime": SimpleNamespace(now=lambda: fixed_time),
        "logger": logging.getLogger("isolated-report-caller"),
    }
    exec(
        compile(ast.Module(body=[method], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    generator, renderer, staged_paths = isolated_generator
    config = SimpleNamespace(
        format=formats.PDF,
        output_dir=str(tmp_path),
        anonymize_data=False,
        enable_mitre_map=False,
        enable_ai_summary=False,
        enable_sigma_generate=False,
        enable_yara_generate=False,
        include_twitter_thread=False,
        include_demo_script=False,
        encrypt_pdf=True,
        pdf_password=PASSWORD,
    )
    caller = SimpleNamespace(
        config=config,
        pdf_generator=generator,
        html_generator=SimpleNamespace(
            generate_html=lambda *args: "<p>Private fixture</p>"
        ),
        mitre_mapper=SimpleNamespace(
            generate_heatmap_data=lambda *args: {},
            generate_mermaid_diagram=lambda *args: "",
        ),
    )
    chain = SimpleNamespace(chain_id="fixture")
    output = tmp_path / "report_fixture_20260101_120000.pdf"
    return SimpleNamespace(
        run=lambda: namespace["generate_report"](caller, chain),
        caller=caller,
        renderer=renderer,
        staged_paths=staged_paths,
        output=output,
        formats=formats,
    )


@pytest.mark.parametrize("report_format", ["PDF", "ALL"])
@pytest.mark.parametrize("has_existing_report", [False, True])
def test_caller_reports_pdf_failure_without_a_claimed_path(
    report_caller, report_format, has_existing_report
):
    report_caller.caller.config.format = getattr(report_caller.formats, report_format)
    report_caller.renderer.fail = True
    original = b"previous destination must survive"
    if has_existing_report:
        report_caller.output.write_bytes(original)
    result = report_caller.run()
    assert result.success is False
    assert result.pdf_path == ""
    assert result.error == "PDF report generation failed"
    if has_existing_report:
        assert report_caller.output.read_bytes() == original
    else:
        assert not report_caller.output.exists()
    assert all(not path.exists() for path in report_caller.staged_paths)


@pytest.mark.parametrize("password", ["", None])
@pytest.mark.parametrize("report_format", ["PDF", "ALL"])
def test_caller_requires_password_before_rendering_encrypted_pdf(
    report_caller, password, report_format
):
    report_caller.caller.config.format = getattr(report_caller.formats, report_format)
    report_caller.caller.config.pdf_password = password
    original = b"previous destination must survive"
    report_caller.output.write_bytes(original)
    result = report_caller.run()
    assert result.success is False
    assert result.pdf_path == ""
    assert result.error == "PDF encryption requires a nonempty password"
    assert report_caller.output.read_bytes() == original
    assert not report_caller.staged_paths


@pytest.mark.parametrize("report_format", ["PDF", "ALL"])
def test_caller_reports_success_only_after_actual_encrypted_publication(
    report_caller, report_format
):
    report_caller.caller.config.format = getattr(report_caller.formats, report_format)
    result = report_caller.run()
    assert result.success is True
    assert result.error == ""
    assert result.pdf_path == str(report_caller.output)
    assert_encrypted_report(report_caller.output)


def test_caller_preserves_explicit_unencrypted_configuration(report_caller):
    report_caller.caller.config.encrypt_pdf = False
    report_caller.caller.config.pdf_password = ""
    result = report_caller.run()
    assert result.success is True
    with report_caller.output.open("rb") as stream:
        assert not PdfReader(stream).is_encrypted


def test_actual_offline_render_encrypt_and_publish_without_converter(
    security, tmp_path
):
    spec = importlib.util.spec_from_file_location(
        "isolated_real_pdf_renderer", ROOT / "cyberapp/pdf_renderer.py"
    )
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    generator = isolated_pdf_generator(renderer, security)
    output = tmp_path / "real-report.pdf"
    assert generator.generate_pdf(
        "<h1>Güvenlik Raporu</h1><p>Doğrulama: şifre, ölçüm ve çözüm.</p>"
        "<table><tr><th>Bulgu</th><th>Durum</th></tr>"
        "<tr><td>Örnek kayıt</td><td>İncelendi</td></tr></table>"
        "<script>SHOULD-NOT-APPEAR</script>",
        str(output),
        PASSWORD,
    )
    with output.open("rb") as stream:
        reader = PdfReader(stream)
        assert reader.is_encrypted
        assert reader.decrypt("wrong-password") == 0
        assert reader.decrypt(PASSWORD)
        text = "\n".join(page.extract_text() for page in reader.pages)
        assert "Güvenlik Raporu" in text
        assert "şifre, ölçüm ve çözüm" in text
        assert "Örnek kayıt" in text
        assert "SHOULD-NOT-APPEAR" not in text
    assert not list(tmp_path.glob(".pdf-report-*"))


@pytest.mark.parametrize("password", [None, 123])
def test_generator_invalid_password_does_not_render_or_replace(
    isolated_generator, tmp_path, password
):
    generator, _, staged_paths = isolated_generator
    output = tmp_path / "original.pdf"
    output.write_bytes(b"original")
    assert not generator.generate_pdf("<p>Private fixture</p>", str(output), password)
    assert output.read_bytes() == b"original"
    assert staged_paths == []

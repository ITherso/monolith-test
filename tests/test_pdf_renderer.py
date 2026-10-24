"""Real offline PDF generation from supplied text; no application imports."""

import builtins
import importlib.util
import io
import socket
import subprocess
from pathlib import Path
from urllib import request

import pytest
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def renderer():
    spec = importlib.util.spec_from_file_location(
        "isolated_pdf_renderer", ROOT / "cyberapp/pdf_renderer.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_text(path):
    with path.open("rb") as stream:
        return "\n".join(page.extract_text() for page in PdfReader(stream).pages)


def test_real_pdf_preserves_headings_paragraphs_tables_code_and_turkish(
    tmp_path, renderer
):
    output = tmp_path / "report.pdf"
    renderer.render_html_pdf(
        "<h1>Security report</h1><p>Türkçe: çğıöşü ÇĞİÖŞÜ</p>"
        "<ul><li>First finding</li><li>Second finding</li></ul>"
        "<table><tr><th>Asset</th><th>Status</th></tr>"
        "<tr><td>example.invalid</td><td>Review required</td></tr></table>"
        "<pre>&lt;literal evidence&gt;\nline two</pre>",
        output,
    )
    text = read_text(output)
    for expected in (
        "Security report",
        "Türkçe: çğıöşü ÇĞİÖŞÜ",
        "First finding",
        "Second finding",
        "Asset",
        "example.invalid",
        "Review required",
        "<literal evidence>",
        "line two",
        "Page 1",
    ):
        assert expected in text
    assert output.read_bytes().startswith(b"%PDF-")


def test_embedded_markup_is_literal_and_unsupported_emoji_is_visible_fallback(
    tmp_path, renderer
):
    output = tmp_path / "literal.pdf"
    renderer.render_html_pdf("<p>&lt;img src=x&gt; &amp; literal 🔥</p>", output)
    text = read_text(output)
    assert "<img src=x> & literal ?" in text
    assert "\u25a0" not in text


def test_resources_and_active_content_are_never_loaded(tmp_path, renderer, monkeypatch):
    secret = tmp_path / "private.txt"
    secret.write_text("HOST-PRIVATE-CONTENT", encoding="utf-8")

    def forbidden(*args, **kwargs):
        raise AssertionError("External execution or resource fetch attempted")

    original_open = builtins.open
    original_io_open = io.open

    def checked_open(original, path, *args, **kwargs):
        if not isinstance(path, int) and Path(path) == secret:
            raise AssertionError("Private asset read attempted")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(
        builtins,
        "open",
        lambda path, *args, **kwargs: checked_open(
            original_open, path, *args, **kwargs
        ),
    )
    monkeypatch.setattr(
        io,
        "open",
        lambda path, *args, **kwargs: checked_open(
            original_io_open, path, *args, **kwargs
        ),
    )
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    output = tmp_path / "inert.pdf"
    renderer.render_html_pdf(
        f'<head><title>HEAD-SECRET</title><style>STYLE-SECRET</style></head>'
        f'<script>SCRIPT-SECRET</script><iframe src="{secret}">IFRAME-SECRET</iframe>'
        f'<object>OBJECT-SECRET</object><embed src="{secret}">'
        '<svg>SVG-SECRET</svg><math>MATH-SECRET</math><canvas>CANVAS-SECRET</canvas>'
        f'<p>Visible evidence</p><img src="{secret}">'
        '<img src="https://example.invalid/private"><link href="file:///private.css">'
        '<a href="javascript:alert(1)">Link label</a>',
        output,
    )
    text = read_text(output)
    assert "Visible evidence" in text and "Link label" in text
    assert "SECRET" not in text and "HOST-PRIVATE" not in text
    assert "javascript:" not in text and "https:" not in text


def test_embed_void_element_does_not_hide_following_report_text(tmp_path, renderer):
    output = tmp_path / "void.pdf"
    renderer.render_html_pdf(
        '<embed src="https://example.invalid/private"><p>Following report</p>', output
    )
    assert "Following report" in read_text(output)


def test_control_characters_have_visible_replacement(tmp_path, renderer):
    output = tmp_path / "controls.pdf"
    renderer.render_html_pdf("<p>Before\x00After</p>", output)
    assert "Before?After" in read_text(output)


def test_malformed_html_finishes_pending_table_and_text(tmp_path, renderer):
    output = tmp_path / "malformed.pdf"
    renderer.render_html_pdf(
        "<h1>Heading<p>Body<table><tr><td>Cell one<td>Cell two", output
    )
    text = read_text(output)
    assert all(item in text for item in ("Heading", "Body", "Cell one", "Cell two"))


def test_long_document_spans_pages_and_keeps_last_record(tmp_path, renderer):
    output = tmp_path / "long.pdf"
    html = "<h1>Long evidence report</h1>" + "".join(
        f"<p>Record {index}: {'read-only evidence ' * 12}</p>" for index in range(120)
    )
    renderer.render_html_pdf(html, output)
    with output.open("rb") as stream:
        reader = PdfReader(stream)
        assert len(reader.pages) > 1
        assert "Record 119" in reader.pages[-1].extract_text()


def test_long_token_and_large_table_cell_do_not_overflow(tmp_path, renderer):
    output = tmp_path / "wrapped.pdf"
    token = "W" * 12000
    renderer.render_html_pdf(
        f"<p>{token}</p><table><tr><th>Evidence</th></tr><tr><td>{token}</td></tr></table>",
        output,
    )
    assert read_text(output).count("W") == 24000


def test_narrow_table_with_large_header_uses_readable_linear_fallback(
    tmp_path, renderer
):
    output = tmp_path / "table.pdf"
    heading = "W" * 600
    renderer.render_html_pdf(
        "<table><tr>" + "".join(f"<th>{heading}</th>" for _ in range(12)) + "</tr>"
        "<tr>" + "<td>Final row</td>" * 12 + "</tr></table>",
        output,
    )
    text = read_text(output)
    assert "Row 1, column 1:" in text
    assert text.count("Final row") == 12


def test_table_spans_pages_with_repeated_headers(tmp_path, renderer):
    output = tmp_path / "table-pages.pdf"
    renderer.render_html_pdf(
        "<table><tr><th>Evidence index</th><th>Review status</th></tr>"
        + "".join(
            f"<tr><td>Item {index}</td><td>Recorded evidence</td></tr>"
            for index in range(150)
        )
        + "</table>",
        output,
    )
    with output.open("rb") as stream:
        reader = PdfReader(stream)
        assert len(reader.pages) > 1
        assert all("Evidence index" in page.extract_text() for page in reader.pages)
        assert "Item 149" in reader.pages[-1].extract_text()


@pytest.mark.parametrize("placement", ["header", "body"])
def test_newline_heavy_table_cells_linearize_without_losing_text(
    tmp_path, renderer, placement
):
    output = tmp_path / f"tall-{placement}.pdf"
    tall = "TallLine<br/>" * 100
    header, body = (
        (tall, "Final body evidence") if placement == "header" else ("Evidence", tall)
    )
    renderer.render_html_pdf(
        f"<table><tr><th>{header}</th></tr><tr><td>{body}</td></tr></table>",
        output,
    )
    text = read_text(output)
    assert "Row 1, column 1:" in text
    assert text.count("TallLine") == 100
    assert ("Final body evidence" if placement == "header" else "Evidence") in text
    with output.open("rb") as stream:
        assert len(PdfReader(stream).pages) > 1


@pytest.mark.parametrize(
    "html", ["", "<div> </div>", "<script>secret</script>", None, b"bytes"]
)
def test_empty_or_nontext_report_fails_without_output(tmp_path, renderer, html):
    output = tmp_path / "empty.pdf"
    with pytest.raises(ValueError):
        renderer.render_html_pdf(html, output)
    assert not output.exists()


@pytest.mark.parametrize(
    "limit,value,html",
    [
        ("MAX_HTML_BYTES", 20, "<p>" + "x" * 30 + "</p>"),
        ("MAX_TEXT_CHARS", 20, "<p>" + "x" * 30 + "</p>"),
        ("MAX_BLOCKS", 2, "<p>one</p><p>two</p><p>three</p>"),
        ("MAX_TABLE_ROWS", 1, "<table><tr><td>a</td></tr><tr><td>b</td></tr></table>"),
        ("MAX_TABLE_COLUMNS", 1, "<table><tr><td>a</td><td>b</td></tr></table>"),
        ("MAX_TABLE_CELLS", 1, "<table><tr><td>a</td><td>b</td></tr></table>"),
    ],
)
def test_resource_limits_fail_before_opening_destination(
    tmp_path, renderer, monkeypatch, limit, value, html
):
    output = tmp_path / "limited.pdf"
    monkeypatch.setattr(renderer, limit, value)
    with pytest.raises(ValueError):
        renderer.render_html_pdf(html, output)
    assert not output.exists()


def test_nested_tables_fail_clearly(tmp_path, renderer):
    with pytest.raises(ValueError, match="Nested"):
        renderer.render_html_pdf(
            "<table><tr><td><table><tr><td>x</td></tr></table></td></tr></table>",
            tmp_path / "nested.pdf",
        )

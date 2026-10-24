"""Offline report text rendering. HTML cannot load assets or execute code here."""

from html.parser import HTMLParser
from pathlib import Path
from threading import Lock
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, TableStyle

MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_TEXT_CHARS = 500_000
MAX_BLOCKS = 2000
MAX_TABLE_ROWS = 500
MAX_TABLE_COLUMNS = 12
MAX_TABLE_CELLS = 4000
PARAGRAPH_CHARS = 2000
_FONT = "MonolithReportVera"
_BOLD_FONT = "MonolithReportVeraBold"
_FONT_LOCK = Lock()
_FONT_GLYPHS = None
_DROP_CONTENT = frozenset(
    {"script", "style", "head", "iframe", "object", "svg", "math", "canvas"}
)
_BLOCK_TAGS = frozenset(
    {
        "div",
        "section",
        "article",
        "p",
        "blockquote",
        "li",
        "pre",
        "header",
        "footer",
        "ul",
        "ol",
    }
) | frozenset(f"h{level}" for level in range(1, 7))


def _register_fonts():
    """Use only the redistributable fonts supplied by the installed PDF library."""
    global _FONT_GLYPHS
    with _FONT_LOCK:
        if _FONT_GLYPHS is None:
            directory = Path(reportlab.__file__).parent / "fonts"
            regular = TTFont(_FONT, str(directory / "Vera.ttf"))
            bold = TTFont(_BOLD_FONT, str(directory / "VeraBd.ttf"))
            pdfmetrics.registerFont(regular)
            pdfmetrics.registerFont(bold)
            _FONT_GLYPHS = frozenset(regular.face.charToGlyph).intersection(
                bold.face.charToGlyph
            )
    return _FONT_GLYPHS


class _ReportHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks = []
        self.parts = []
        self.kind = "body"
        self.suppressed = []
        self.rows = None
        self.row = []
        self.cell = None
        self.table_header = False
        self.caption = None
        self.caption_parts = []
        self.text_chars = 0
        self.cell_count = 0

    def _add(self, kind, value, header=False):
        if len(self.blocks) >= MAX_BLOCKS:
            raise ValueError("The report contains too many content blocks")
        self.blocks.append((kind, value, header))

    def _flush(self):
        text = "".join(self.parts).strip()
        if text:
            self._add(self.kind, text)
        self.parts = []
        self.kind = "body"

    def _finish_cell(self):
        if self.cell is not None:
            self.row.append("".join(self.cell).strip())
            self.cell = None
            self.cell_count += 1
            if self.cell_count > MAX_TABLE_CELLS or len(self.row) > MAX_TABLE_COLUMNS:
                raise ValueError("The report table exceeds the cell limit")

    def _finish_row(self):
        self._finish_cell()
        if self.row:
            if len(self.rows) >= MAX_TABLE_ROWS:
                raise ValueError("The report table contains too many rows")
            self.rows.append(self.row)
            self.row = []

    def _finish_table(self):
        self._finish_row()
        caption = "".join(self.caption_parts).strip()
        if caption:
            self._add("body", caption)
        if self.rows:
            self._add("table", self.rows, self.table_header)
        self.rows = None
        self.caption_parts = []
        self.caption = None
        self.table_header = False

    def handle_starttag(self, tag, attrs):
        if tag in _DROP_CONTENT:
            if not self.suppressed and self.rows is None:
                self._flush()
            self.suppressed.append(tag)
            return
        if self.suppressed:
            return
        if tag == "table":
            if self.rows is not None:
                raise ValueError("Nested report tables are not supported")
            self._flush()
            self.rows = []
            return
        if self.rows is not None:
            if tag == "tr":
                self._finish_row()
            elif tag in {"td", "th"}:
                self._finish_cell()
                self.cell = []
                if tag == "th" and not self.rows:
                    self.table_header = True
            elif tag == "caption":
                self.caption = True
            elif tag in {"br", "p", "div"} and self.cell is not None:
                self.cell.append("\n")
            return
        if tag in _BLOCK_TAGS:
            self._flush()
            self.kind = tag if tag.startswith("h") and len(tag) == 2 else "body"
            if tag == "pre":
                self.kind = "code"
            elif tag == "li":
                self.parts.append("- ")
        elif tag == "br":
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if self.suppressed:
            if tag in self.suppressed:
                del self.suppressed[self.suppressed.index(tag) :]
            return
        if self.rows is not None:
            if tag in {"td", "th"}:
                self._finish_cell()
            elif tag == "tr":
                self._finish_row()
            elif tag == "table":
                self._finish_table()
            elif tag == "caption":
                self.caption = None
            return
        if tag in _BLOCK_TAGS:
            self._flush()

    def handle_data(self, data):
        if self.suppressed:
            return
        self.text_chars += len(data)
        if self.text_chars > MAX_TEXT_CHARS:
            raise ValueError("The report contains too much visible text")
        if self.rows is not None:
            if self.caption:
                self.caption_parts.append(data)
            elif self.cell is not None:
                self.cell.append(data)
        else:
            self.parts.append(data)

    def finish(self):
        self.close()
        if self.rows is not None:
            self._finish_table()
        self._flush()
        return self.blocks


def _visible_text(value, glyphs):
    return "".join(
        character
        if character in "\n\t" or (ord(character) >= 32 and ord(character) in glyphs)
        else "?"
        for character in value
    )


def _paragraphs(text, style, glyphs):
    text = _visible_text(text, glyphs).replace("\t", "    ")
    result = []
    while text:
        length = min(len(text), PARAGRAPH_CHARS)
        if length < len(text):
            boundary = text.rfind(" ", length // 2, length)
            if boundary > 0:
                length = boundary
        chunk, text = text[:length], text[length:]
        result.append(Paragraph(escape(chunk).replace("\n", "<br/>"), style))
    return result


def render_html_pdf(html_content: str, output_path: str | Path) -> None:
    """Render a bounded HTML text subset; callers stage the publication path.

    Styling, images, scripts, interactive charts and remote/local assets are never
    evaluated. Unsupported font glyphs become a visible '?' rather than a box.
    """
    if not isinstance(html_content, str):
        raise ValueError("Report HTML must be text")
    if len(html_content.encode("utf-8")) > MAX_HTML_BYTES:
        raise ValueError("Report HTML exceeds the size limit")
    parser = _ReportHTML()
    parser.feed(html_content)
    blocks = parser.finish()
    if not blocks or not any(
        (
            any(cell.strip() for row in value for cell in row)
            if kind == "table"
            else value.strip()
        )
        for kind, value, _header in blocks
    ):
        raise ValueError("The report has no visible text")
    glyphs = _register_fonts()
    body = ParagraphStyle(
        "ReportBody",
        fontName=_FONT,
        fontSize=10,
        leading=14,
        spaceAfter=8,
        alignment=TA_LEFT,
        splitLongWords=True,
    )
    code = ParagraphStyle(
        "ReportCode",
        parent=body,
        fontSize=8.5,
        leading=12,
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=5,
    )
    headings = {
        f"h{level}": ParagraphStyle(
            f"ReportHeading{level}",
            parent=body,
            fontName=_BOLD_FONT,
            fontSize=21 - level * 2,
            leading=25 - level * 2,
            spaceBefore=10,
            spaceAfter=8,
            textColor=colors.HexColor("#173451"),
        )
        for level in range(1, 7)
    }
    table_style = ParagraphStyle(
        "ReportCell", parent=body, fontSize=8.5, leading=11, spaceAfter=0
    )
    story = []
    content_width = A4[0] - 84
    # SimpleDocTemplate's frame has six points of padding on each side. Keep
    # every table row below half its usable height so a repeated header and at
    # least one data row can fit together on a fresh page.
    usable_page_height = A4[1] - 48 - 44 - 12
    row_height_limit = (usable_page_height - 30) / 2
    for kind, value, header in blocks:
        if kind != "table":
            story.extend(
                _paragraphs(
                    value, headings.get(kind, code if kind == "code" else body), glyphs
                )
            )
            continue
        # Very long cells become sequential labelled text so no indivisible row
        # can overflow a page or force ReportLab's table layout into failure.
        columns = max(len(row) for row in value)
        cell_limit = max(40, int((content_width / columns - 12) / 10) * 30)
        linearize = any(len(cell) > cell_limit for row in value for cell in row)
        data = []
        if not linearize:
            data = [
                [
                    Paragraph(
                        escape(_visible_text(cell, glyphs)).replace("\n", "<br/>"),
                        table_style,
                    )
                    for cell in row
                ]
                + [""] * (columns - len(row))
                for row in value
            ]
            cell_width = content_width / columns - 12
            linearize = any(
                max(
                    (cell.wrap(cell_width, usable_page_height)[1] if cell else 0)
                    for cell in row
                )
                + 12
                > row_height_limit
                for row in data
            )
        if linearize:
            for index, row in enumerate(value, 1):
                for column, cell in enumerate(row, 1):
                    story.extend(
                        _paragraphs(
                            f"Row {index}, column {column}: {cell}", body, glyphs
                        )
                    )
            continue
        table = LongTable(
            data,
            colWidths=[content_width / columns] * columns,
            repeatRows=1 if header else 0,
            splitByRow=1,
            splitInRow=1,
            spaceBefore=5,
            spaceAfter=10,
        )
        commands = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
        if header:
            commands.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dce9f5")))
        table.setStyle(TableStyle(commands))
        story.append(table)

    def page_furniture(canvas, document):
        canvas.saveState()
        canvas.setFont(_FONT, 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(42, A4[1] - 26, "MONOLITH / SECURITY REPORT")
        canvas.drawRightString(A4[0] - 42, 25, f"Page {document.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=42,
        rightMargin=42,
        topMargin=48,
        bottomMargin=44,
        title="Security report",
        author="MONOLITH",
        creator="MONOLITH offline report renderer",
    )
    document.build(story, onFirstPage=page_furniture, onLaterPages=page_furniture)

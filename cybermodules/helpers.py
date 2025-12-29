import warnings

from cybermodules.error_handling import ErrorHandler
# Ortak yardımcı fonksiyonlar
warnings.filterwarnings(
    "ignore",
    message="You have both PyFPDF & fpdf2 installed",
    category=UserWarning,
)
from fpdf import FPDF

class PDFReport(FPDF):
	def header(self):
		self.set_font('Arial', 'B', 15)
		self.set_text_color(0, 100, 0)
		self.cell(0, 10, 'MONOLITH SECURITY REPORT', 0, 1, 'C')
		self.ln(5)

	def chapter_title(self, title, rgb):
		self.set_font('Arial', 'B', 12)
		self.set_fill_color(*rgb)
		self.cell(0, 8, title, 0, 1, 'L', True)
		self.ln(4)

def tr_fix(txt):
	if isinstance(txt, str):
		return txt.encode('latin-1', 'replace').decode('latin-1')
	return str(txt)

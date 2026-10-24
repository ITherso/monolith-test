"""Atomic password protection for generated PDF reports; no application imports."""

import os
import secrets
import tempfile
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DictionaryObject


def encrypt_pdf_atomic(pdf_path: str | Path, password: str) -> None:
    """Replace an unencrypted PDF with AES-256 output only after verification.

    Errors propagate and leave the original file unchanged. Intermediate output is
    encrypted before it is written; no additional plaintext PDF is created here.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("A nonempty PDF password is required")

    path = Path(pdf_path)
    temporary_path = None
    try:
        with path.open("rb") as source:
            reader = PdfReader(source)
            if reader.is_encrypted:
                raise ValueError("The source PDF is already encrypted")
            page_count = len(reader.pages)
            writer = PdfWriter(clone_from=reader)
            writer.encrypt(
                password,
                owner_password=secrets.token_urlsafe(48),
                algorithm="AES-256",
            )
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{path.name}.encrypted-",
                suffix=".pdf",
                dir=path.parent,
                delete=False,
            ) as encrypted:
                temporary_path = Path(encrypted.name)
                writer.write(encrypted)
                encrypted.flush()
                os.fsync(encrypted.fileno())

        # Close the source and verification streams before replacing on Windows.
        with temporary_path.open("rb") as encrypted:
            verified = PdfReader(encrypted)
            if not verified.is_encrypted or not verified.decrypt(password):
                raise ValueError("Encrypted PDF password verification failed")
            encryption = verified.trailer["/Encrypt"]
            if not isinstance(encryption, DictionaryObject):
                raise ValueError("Invalid PDF encryption settings")
            if encryption.get("/Length") != 256 or encryption.get("/V") != 5:
                raise ValueError("The PDF was not encrypted with AES-256")
            filters = encryption.get("/CF")
            standard = (
                filters.get("/StdCF") if isinstance(filters, DictionaryObject) else None
            )
            if (
                not isinstance(standard, DictionaryObject)
                or standard.get("/CFM") != "/AESV3"
            ):
                raise ValueError("The PDF encryption algorithm is not AES-256")
            if len(verified.pages) != page_count:
                raise ValueError("Encrypted PDF page count verification failed")
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

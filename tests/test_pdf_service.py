"""
Tests for PDF report service.
"""

from io import BytesIO

from pypdf import PdfReader

from app.database.models import URLScan
from app.services.pdf_service import PDFService


def extract_pdf_text(pdf_bytes: bytes) -> str:
    """
    Extract text from generated PDF bytes.
    """

    reader = PdfReader(BytesIO(pdf_bytes))

    return "\n".join(
        page.extract_text() or ""
        for page in reader.pages
    )


def test_generate_pdf_with_reasons() -> None:
    """
    PDF service should generate a valid PDF containing report data.
    """

    scan = URLScan(
        url="https://example.com/login",
        hostname="example.com",
        registered_domain="example.com",
        protocol="https",
        risk_score=50,
        risk_level="High Risk",
        reasons=(
            "Suspicious keyword detected.\n"
            "External redirect detected."
        ),
    )

    result = PDFService.generate(scan)

    assert result.startswith(b"%PDF")
    assert len(result) > 100

    text = extract_pdf_text(result)

    assert "URL Security Report" in text
    assert "https://example.com/login" in text
    assert "example.com" in text
    assert "Risk Score: 50/100" in text
    assert "Risk Level: High Risk" in text
    assert "Suspicious keyword detected." in text
    assert "External redirect detected." in text


def test_generate_pdf_without_reasons() -> None:
    """
    PDF service should generate a valid PDF when no reasons exist.
    """

    scan = URLScan(
        url="https://www.google.com",
        hostname="www.google.com",
        registered_domain="google.com",
        protocol="https",
        risk_score=0,
        risk_level="Safe",
        reasons=None,
    )

    result = PDFService.generate(scan)

    assert result.startswith(b"%PDF")
    assert len(result) > 100

    text = extract_pdf_text(result)

    assert "URL Security Report" in text
    assert "https://www.google.com" in text
    assert "Risk Score: 0/100" in text
    assert "Risk Level: Safe" in text
    assert "No suspicious indicators detected." in text
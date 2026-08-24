"""
PDF report generation service.
"""

from io import BytesIO

from reportlab.lib.units import cm
from reportlab.pdfgen import canvas

from app.database.models import URLScan


class PDFService:
    """
    Generate PDF reports for URL scans.
    """

    @staticmethod
    def generate(scan: URLScan) -> bytes:
        """
        Generate a PDF report from a stored scan.
        """

        buffer = BytesIO()

        pdf = canvas.Canvas(buffer)

        y = 28 * cm

        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(2 * cm, y, "URL Security Report")

        y -= 1.5 * cm

        pdf.setFont("Helvetica", 11)

        fields = [
            ("URL", scan.url),
            ("Hostname", scan.hostname),
            ("Registered Domain", scan.registered_domain),
            ("Protocol", scan.protocol),
            ("Risk Score", f"{scan.risk_score}/100"),
            ("Risk Level", scan.risk_level),
        ]

        for title, value in fields:
            pdf.drawString(
                2 * cm,
                y,
                f"{title}: {value}",
            )
            y -= 0.8 * cm

        y -= 0.5 * cm

        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(
            2 * cm,
            y,
            "Reasons",
        )

        y -= 0.8 * cm

        pdf.setFont("Helvetica", 11)

        if scan.reasons:
            for reason in scan.reasons.splitlines():
                pdf.drawString(
                    2 * cm,
                    y,
                    f"- {reason}",
                )
                y -= 0.7 * cm
        else:
            pdf.drawString(
                2 * cm,
                y,
                "- No suspicious indicators detected.",
            )

        pdf.save()

        data = buffer.getvalue()

        buffer.close()

        return data
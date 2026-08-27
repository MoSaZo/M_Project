"""
Report service.

Provides application-level operations for analysis reports.

Report construction belongs to the analyzer package.
This service converts stored analysis data into
application-facing report representations.
"""

from typing import Any

from app.database.models import URLScan
from app.schemas.responses import URLAnalysisResponse


class ReportService:
    """
    Application service for working with analysis reports.
    """

    @staticmethod
    def to_response(
        analysis: dict[str, Any],
    ) -> URLAnalysisResponse:
        """
        Convert an analysis dictionary into the API response schema.
        """

        return URLAnalysisResponse.model_validate(
            analysis,
        )

    @staticmethod
    def build_summary(
        analysis: dict[str, Any],
    ) -> str:
        """
        Build a concise human-readable risk summary.
        """

        risk_level = str(
            analysis.get("risk_level", "Unknown"),
        )

        risk_score = int(
            analysis.get("risk_score", 0),
        )

        reasons = analysis.get(
            "reasons",
            [],
        )

        if isinstance(reasons, list) and reasons:
            primary_reason = str(reasons[0])

            return (
                f"{risk_level} ({risk_score}/100): "
                f"{primary_reason}"
            )

        return f"{risk_level} ({risk_score}/100)."

    @staticmethod
    def build_text_report(
        scan: URLScan,
    ) -> str:
        """
        Build a plain-text security report from a stored URL scan.
        """

        lines = [
            "URL SECURITY REPORT",
            "=" * 50,
            "",
            f"URL: {scan.url}",
            f"Hostname: {scan.hostname or 'N/A'}",
            (
                "Registered Domain: "
                f"{scan.registered_domain or 'N/A'}"
            ),
            f"Protocol: {scan.protocol or 'N/A'}",
            f"Risk Score: {scan.risk_score}/100",
            f"Risk Level: {scan.risk_level}",
            "",
            "Reasons",
            "-" * 50,
        ]

        if scan.reasons:
            for reason in scan.reasons.splitlines():
                lines.append(f"- {reason}")
        else:
            lines.append(
                "- No suspicious indicators detected.",
            )

        return "\n".join(lines)


report_service = ReportService()
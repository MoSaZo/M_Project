"""
Report service.

Provides application-level operations for analysis reports.
"""

from app.database.models import URLScan
from app.schemas.responses import URLAnalysisResponse


class ReportService:
    """
    Application service responsible for report formatting.
    """

    @staticmethod
    def to_response(
        analysis: dict,
    ) -> URLAnalysisResponse:
        """
        Convert an analysis dictionary into the API response schema.
        """

        return URLAnalysisResponse.model_validate(
            analysis,
        )

    @staticmethod
    def build_summary(
        analysis: dict,
    ) -> str:
        """
        Build a concise human-readable summary.
        """

        reasons = analysis.get(
            "reasons",
            [],
        )

        if isinstance(reasons, list):
            reason_text = (
                reasons[0]
                if reasons
                else "No suspicious indicators detected."
            )
        else:
            reason_text = str(reasons)

        return (
            f"{analysis['risk_level']} "
            f"({analysis['risk_score']}/100): "
            f"{reason_text}"
        )

    @staticmethod
    def build_text_report(
        scan: URLScan,
    ) -> str:
        """
        Build a plain-text report from a stored analysis.
        """

        lines = [
            "=" * 40,
            "URL SECURITY REPORT",
            "=" * 40,
            "",
            f"URL: {scan.url}",
            f"Hostname: {scan.hostname}",
            f"Registered Domain: {scan.registered_domain}",
            f"Protocol: {scan.protocol}",
            "",
            f"Risk Score: {scan.risk_score}/100",
            f"Risk Level: {scan.risk_level}",
            "",
            "Reasons:",
        ]

        if scan.reasons:
            for reason in scan.reasons.splitlines():
                lines.append(f"- {reason}")
        else:
            lines.append("- No suspicious indicators detected.")

        lines.extend(
            [
                "",
                f"Generated: {scan.created_at}",
            ]
        )

        return "\n".join(lines)
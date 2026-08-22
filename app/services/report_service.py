"""
Report service.

Provides application-level operations for analysis reports.

Report construction belongs to the analyzer package.
This service converts generated analysis data into
application-facing report representations.
"""

from typing import Any

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


report_service = ReportService()

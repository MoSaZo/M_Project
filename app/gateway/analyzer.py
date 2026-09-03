"""
Gateway analyzer adapter.

Connects gateway DNS observations to the main
URL phishing analysis pipeline.
"""

from app.analyzer.analyzer import analyze_url
from app.gateway.models import DNSRecord
from app.gateway.results import AnalysisResult


class GatewayAnalyzer:
    """
    Adapter between the Gateway and the main phishing
    detection analysis pipeline.
    """

    def analyze(
        self,
        record: DNSRecord,
    ) -> AnalysisResult:
        """
        Analyze a DNS-observed domain using the main
        application analysis pipeline.
        """

        domain = (
            record.query
            .strip()
            .lower()
            .rstrip(".")
        )

        if not domain:
            raise ValueError(
                "DNS record contains an empty query."
            )

        url = f"https://{domain}"

        result = analyze_url(
            url,
        )

        return AnalysisResult(
            domain=domain,

            # ML result
            score=float(
                result.get(
                    "ml_probability",
                    0.0,
                )
            ),

            prediction=str(
                result.get(
                    "ml_prediction",
                    "unknown",
                )
            ),

            probability=float(
                result.get(
                    "ml_probability",
                    0.0,
                )
            ),

            # Final risk result
            risk_score=int(
                result.get(
                    "risk_score",
                    0,
                )
            ),

            risk_level=str(
                result.get(
                    "risk_level",
                    "Unknown",
                )
            ),
        )
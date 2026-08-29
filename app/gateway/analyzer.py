"""
Gateway analyzer adapter.
"""

from app.gateway.models import DNSRecord
from app.gateway.results import AnalysisResult


class GatewayAnalyzer:
    """
    Adapter between Gateway and the phishing detection model.
    """

    def analyze(self, record: DNSRecord) -> AnalysisResult:
        return AnalysisResult(
            domain=record.query,
            score=0.0,
            prediction="unknown",
        )
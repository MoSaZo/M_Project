"""
Gateway analyzer adapter.
"""

from app.gateway.models import DNSRecord
from app.gateway.results import AnalysisResult
from models.predictor import predict_url


class GatewayAnalyzer:
    """
    Adapter between Gateway and the phishing detection model.
    """

    def analyze(
        self,
        record: DNSRecord,
    ) -> AnalysisResult:

        result = predict_url(
            record.query,
        )

        return AnalysisResult(
            domain=record.query,
            score=float(
                result["probability"],
            ),
            prediction=str(
                result["prediction"],
            ),
        )
from app.gateway.analyzer import GatewayAnalyzer
from app.gateway.models import DNSRecord
from app.gateway.results import AnalysisResult

from datetime import datetime


def make_record(query="google.com"):
    return DNSRecord(
        timestamp=datetime.now(),
        query=query,
        answer="8.8.8.8",
        record_type="A",
        source_ip="1.1.1.1",
        destination_ip="8.8.8.8",
        response=True,
    )


def test_analyzer_returns_dictionary():
    analyzer = GatewayAnalyzer()

    result = analyzer.analyze(make_record())

    assert isinstance(result, AnalysisResult)


def test_result_contains_domain():
    analyzer = GatewayAnalyzer()

    result = analyzer.analyze(make_record())

    assert result.domain == "google.com"


def test_result_contains_score():
    analyzer = GatewayAnalyzer()

    result = analyzer.analyze(make_record())

    assert isinstance(result.score, float)


def test_result_contains_prediction():
    analyzer = GatewayAnalyzer()

    result = analyzer.analyze(make_record())

    assert isinstance(result.prediction, str)
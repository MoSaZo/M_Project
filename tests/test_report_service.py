from app.database.models import URLScan
from app.services.report_service import ReportService

def test_to_response() -> None:
    """
    Analysis dictionary should be converted to the response schema.
    """

    analysis = {
        "url": "https://www.google.com",
        "hostname": "www.google.com",
        "registered_domain": "google.com",
        "subdomain": "www",
        "subdomain_levels": 1,
        "domain": "google",
        "suffix": "com",
        "protocol": "https",
        "path": "/",
        "has_query": False,
        "query_parameter_count": 0,
        "risk_score": 0,
        "risk_level": "Safe",
        "reasons": [],
        "indicators": [],
        "ml_prediction": "legitimate",
        "ml_probability": 0.99,
    }

    result = ReportService.to_response(analysis)

    assert result.url == "https://www.google.com"
    assert result.hostname == "www.google.com"
    assert result.registered_domain == "google.com"
    assert result.domain == "google"
    assert result.suffix == "com"
    assert result.protocol == "https"
    assert result.path == "/"
    assert result.has_query is False
    assert result.query_parameter_count == 0
    assert result.risk_score == 0
    assert result.risk_level == "Safe"
    assert result.reasons == []
    assert result.indicators == []
    assert result.ml_prediction == "legitimate"
    assert result.ml_probability == 0.99

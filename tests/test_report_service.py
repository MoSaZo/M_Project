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

def test_build_summary_with_reason() -> None:
    analysis = {
        "risk_level": "High",
        "risk_score": 92,
        "reasons": [
            "Suspicious domain",
            "Contains IP address",
        ],
    }

    summary = ReportService.build_summary(
        analysis,
    )

    assert (
        summary
        == "High (92/100): Suspicious domain"
    )


def test_build_summary_without_reason() -> None:
    analysis = {
        "risk_level": "Safe",
        "risk_score": 0,
        "reasons": [],
    }

    summary = ReportService.build_summary(
        analysis,
    )

    assert summary == "Safe (0/100)."


def test_build_summary_missing_fields() -> None:
    summary = ReportService.build_summary(
        {},
    )

    assert summary == "Unknown (0/100)."


def test_build_text_report_with_reasons() -> None:
    scan = URLScan(
        url="https://evil.com",
        hostname="evil.com",
        registered_domain="evil.com",
        protocol="https",
        risk_score=91,
        risk_level="High",
        reasons="Reason one\nReason two",
    )

    report = ReportService.build_text_report(
        scan,
    )

    assert "URL SECURITY REPORT" in report
    assert "https://evil.com" in report
    assert "- Reason one" in report
    assert "- Reason two" in report


def test_build_text_report_without_reasons() -> None:
    scan = URLScan(
        url="https://google.com",
        hostname="google.com",
        registered_domain="google.com",
        protocol="https",
        risk_score=0,
        risk_level="Safe",
        reasons="",
    )

    report = ReportService.build_text_report(
        scan,
    )

    assert (
        "- No suspicious indicators detected."
        in report
    )
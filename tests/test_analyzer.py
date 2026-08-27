"""
Tests for URL analyzer.
"""

import pytest

from app.analyzer.analyzer import analyze_url


def test_google_url_is_safe() -> None:
    """
    Google should be classified as safe.
    """

    result = analyze_url(
        "https://www.google.com",
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Safe"
    assert result["hostname"] == "www.google.com"
    assert result["registered_domain"] == "google.com"


def test_url_with_subdomain() -> None:
    """
    Analyzer should correctly detect subdomains.
    """

    result = analyze_url(
        "https://login.example.com",
    )

    assert result["hostname"] == "login.example.com"
    assert result["registered_domain"] == "example.com"
    assert result["subdomain"] == "login"
    assert result["subdomain_levels"] == 1


def test_url_with_query_parameters() -> None:
    """
    Analyzer should count query parameters.
    """

    result = analyze_url(
        "https://example.com/login?user=test&redirect=home",
    )

    assert result["has_query"] is True
    assert result["query_parameter_count"] == 2


def test_url_with_path() -> None:
    """
    Analyzer should preserve the URL path.
    """

    result = analyze_url(
        "https://example.com/account/login",
    )

    assert result["path"] == "/account/login"


def test_http_url() -> None:
    """
    HTTP URLs should be analyzed successfully.
    """

    result = analyze_url(
        "http://example.com",
    )

    assert result["protocol"] == "http"


def test_invalid_empty_url() -> None:
    """
    Empty URLs should raise ValueError.
    """

    with pytest.raises(ValueError):
        analyze_url("")


def test_invalid_url_without_hostname() -> None:
    """
    URLs without a valid hostname should raise ValueError.
    """

    with pytest.raises(ValueError):
        analyze_url("http://")

def test_brand_impersonation() -> None:
    """
    Trusted brand inside another domain should be detected.
    """

    result = analyze_url(
        "https://github.com.evil.com",
    )

    assert result["risk_level"] == "Suspicious"
    assert result["risk_score"] >= 35

    assert any(
        "trusted-domain impersonation"
        in reason.lower()
        for reason in result["reasons"]
    )


def test_brand_impersonation_with_keyword() -> None:
    """
    Brand impersonation combined with login keyword.
    """

    result = analyze_url(
        "https://login.github.com.evil.com",
    )

    assert result["risk_level"] == "High Risk"
    assert result["risk_score"] >= 50


def test_ip_over_http_is_high_risk() -> None:
    """
    IP over HTTP should trigger compound rule.
    """

    result = analyze_url(
        "http://127.0.0.1/login",
    )

    assert result["risk_level"] == "High Risk"

    assert any(
        "IP address used over HTTP"
        in reason
        for reason in result["reasons"]
    )


def test_external_redirect() -> None:
    """
    External redirects should be detected.
    """

    result = analyze_url(
        "https://example.com/login"
        "?next=https%3A%2F%2Fevil.com%2Flogin",
    )

    assert result["risk_level"] == "High Risk"

    assert any(
        "External redirect"
        in reason
        for reason in result["reasons"]
    )


def test_real_trusted_subdomain_is_safe() -> None:
    """
    Legitimate GitHub subdomain must not be flagged.
    """

    result = analyze_url(
        "https://www.github.com",
    )

    assert result["risk_level"] == "Safe"

    assert not any(
        "trusted-domain impersonation"
        in reason.lower()
        for reason in result["reasons"]
    )


def test_api_subdomain_is_safe() -> None:
    """
    API subdomain must remain safe.
    """

    result = analyze_url(
        "https://api.github.com",
    )

    assert result["risk_level"] == "Safe"


def test_at_symbol_detection() -> None:
    """
    URLs containing @ should be detected.
    """

    result = analyze_url(
        "https://google.com@evil.com",
    )

    assert result["risk_score"] >= 20

    assert any(
        "@ symbol"
        in reason
        for reason in result["reasons"]
    )


def test_long_url_detection() -> None:
    """
    Very long URLs should increase risk.
    """

    url = (
        "https://example.com/"
        + ("a" * 160)
    )

    result = analyze_url(url)

    assert result["risk_score"] >= 20


def test_keyword_phishing_url() -> None:
    """
    Keyword-heavy phishing URL.
    """

    result = analyze_url(
        "http://secure-login-account-verify.example.com/reset/password",
    )

    assert result["risk_level"] == "High Risk"

    assert any(
        "Suspicious keywords"
        in reason
        for reason in result["reasons"]
    )


def test_clean_github_url() -> None:
    """
    Clean GitHub URL should stay safe.
    """

    result = analyze_url(
        "https://github.com",
    )

    assert result["risk_level"] == "Safe"
    assert result["risk_score"] == 0
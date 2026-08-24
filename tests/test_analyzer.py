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
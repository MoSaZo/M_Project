"""
Tests for utility functions.
"""

from app.utils.formatters import (
    format_analysis_summary,
    format_reasons,
    format_risk_score,
)
from app.utils.helpers import (
    clamp,
    safe_int,
    safe_str,
)
from app.utils.url_utils import (
    get_hostname,
    get_protocol,
    is_http,
    is_https,
)
from app.utils.validators import (
    validate_limit,
    validate_url,
)


# ---------------------------
# Formatters
# ---------------------------

def test_format_risk_score() -> None:
    assert format_risk_score(75) == "75/100"


def test_format_reasons_with_reasons() -> None:
    result = format_reasons(
        ["Suspicious hostname", "HTTP protocol"],
    )

    assert result == (
        "- Suspicious hostname\n"
        "- HTTP protocol"
    )


def test_format_reasons_without_reasons() -> None:
    assert (
        format_reasons([])
        == "No suspicious indicators detected."
    )

    assert (
        format_reasons(None)
        == "No suspicious indicators detected."
    )


def test_format_analysis_summary() -> None:
    result = format_analysis_summary(
        {
            "url": "https://example.com",
            "risk_score": 25,
            "risk_level": "Low",
        },
    )

    assert result == (
        "URL: https://example.com\n"
        "Risk Score: 25/100\n"
        "Risk Level: Low"
    )


def test_format_analysis_summary_defaults() -> None:
    result = format_analysis_summary({})

    assert result == (
        "URL: \n"
        "Risk Score: 0/100\n"
        "Risk Level: Unknown"
    )


# ---------------------------
# Helpers
# ---------------------------

def test_safe_int() -> None:
    assert safe_int("42") == 42
    assert safe_int(10.5) == 10
    assert safe_int("invalid") == 0
    assert safe_int(None) == 0
    assert safe_int("invalid", default=99) == 99


def test_safe_str() -> None:
    assert safe_str("hello") == "hello"
    assert safe_str(123) == "123"
    assert safe_str(None) == ""
    assert safe_str(None, default="N/A") == "N/A"


def test_clamp() -> None:
    assert clamp(50, 0, 100) == 50
    assert clamp(-10, 0, 100) == 0
    assert clamp(150, 0, 100) == 100
    assert clamp(25.5, 0, 100) == 25.5


# ---------------------------
# URL utilities
# ---------------------------

def test_get_hostname() -> None:
    assert (
        get_hostname("https://www.example.com/path")
        == "www.example.com"
    )

    assert get_hostname("https://example.com") == "example.com"


def test_get_hostname_without_hostname() -> None:
    assert get_hostname("not-a-valid-host") == ""


def test_get_protocol() -> None:
    assert (
        get_protocol("HTTPS://example.com")
        == "https"
    )

    assert (
        get_protocol("http://example.com")
        == "http"
    )


def test_is_https() -> None:
    assert is_https("https://example.com") is True
    assert is_https("http://example.com") is False


def test_is_http() -> None:
    assert is_http("http://example.com") is True
    assert is_http("https://example.com") is False


# ---------------------------
# Validators
# ---------------------------

def test_validate_url() -> None:
    assert (
        validate_url("https://example.com")
        == "https://example.com"
    )

    assert (
        validate_url("example.com")
        == "http://example.com"
    )

    assert (
        validate_url("  https://example.com  ")
        == "https://example.com"
    )


def test_validate_url_rejects_invalid_values() -> None:
    import pytest

    with pytest.raises(
        ValueError,
        match="URL must be a string.",
    ):
        validate_url(None)  # type: ignore[arg-type]

    with pytest.raises(
        ValueError,
        match="URL cannot be empty.",
    ):
        validate_url("   ")

    with pytest.raises(
        ValueError,
        match="URL must contain a hostname.",
    ):
        validate_url("http://")


def test_validate_limit() -> None:
    assert validate_limit(1) == 1
    assert validate_limit(50) == 50
    assert validate_limit(100) == 100
    assert validate_limit(50, maximum=50) == 50


def test_validate_limit_rejects_invalid_values() -> None:
    import pytest

    with pytest.raises(
        ValueError,
        match="Limit must be greater than 0.",
    ):
        validate_limit(0)

    with pytest.raises(
        ValueError,
        match="Limit must be greater than 0.",
    ):
        validate_limit(-1)

    with pytest.raises(
        ValueError,
        match="Limit cannot exceed 100.",
    ):
        validate_limit(101)

    with pytest.raises(
        ValueError,
        match="Limit cannot exceed 50.",
    ):
        validate_limit(51, maximum=50)
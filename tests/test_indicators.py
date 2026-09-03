import pytest

from app.analyzer.indicators import (
    check_at_symbol,
    check_double_encoding,
    check_external_redirect,
    check_http,
    check_ip_address,
    check_keywords,
    check_long_path,
    check_long_url,
    check_multiple_hyphens,
    check_subdomains,
    check_trusted_domain_impersonation,
    check_typosquatting,
    check_encoding,
)
from app.analyzer.parser import parse_url


def parse(url: str) -> dict:
    return parse_url(url)


def test_at_symbol():
    result = check_at_symbol(
        parse("https://google.com@evil.com")
    )

    assert len(result) == 1
    assert result[0]["score"] == 20


def test_ip_address():
    result = check_ip_address(
        parse("http://127.0.0.1/login")
    )

    assert len(result) == 1
    assert result[0]["score"] == 25
    assert result[0]["severity"] == "High"


def test_normal_domain_is_not_ip():
    result = check_ip_address(
        parse("https://example.com")
    )

    assert result == []


def test_four_subdomains():
    result = check_subdomains(
        parse("https://a.b.c.d.example.com")
    )

    assert len(result) == 1
    assert result[0]["score"] == 20


def test_two_subdomains():
    result = check_subdomains(
        parse("https://a.b.example.com")
    )

    assert len(result) == 1
    assert result[0]["score"] == 10


def test_multiple_hyphens():
    result = check_multiple_hyphens(
        parse("https://secure-login-account.example.com")
    )

    assert len(result) == 1
    assert result[0]["score"] == 10


def test_long_url():
    url = "https://example.com/" + ("a" * 150)

    result = check_long_url(parse(url))

    assert len(result) == 1
    assert result[0]["score"] == 10


def test_long_path():
    url = "https://example.com/" + ("a" * 60)

    result = check_long_path(parse(url))

    assert len(result) == 1
    assert result[0]["score"] == 10


def test_http():
    result = check_http(
        parse("http://example.com/login")
    )

    assert len(result) == 1
    assert result[0]["score"] == 5


def test_https_is_not_flagged_as_http():
    result = check_http(
        parse("https://example.com/login")
    )

    assert result == []


def test_keywords_in_hostname():
    result = check_keywords(
        parse("https://secure-login.example.com")
    )

    assert len(result) == 1
    assert result[0]["score"] == 8


def test_keywords_in_path():
    result = check_keywords(
        parse("https://example.com/login/verify")
    )

    assert len(result) == 1
    assert result[0]["score"] == 4


def test_trusted_domain_impersonation():
    result = check_trusted_domain_impersonation(
        parse("https://github.com.evil.com")
    )

    assert len(result) == 1
    assert result[0]["score"] == 25
    assert result[0]["severity"] == "High"


def test_real_trusted_domain_is_not_flagged():
    result = check_trusted_domain_impersonation(
        parse("https://github.com")
    )

    assert result == []


def test_trusted_domain_subdomain_is_not_flagged():
    result = check_trusted_domain_impersonation(
        parse("https://www.github.com")
    )

    assert result == []


@pytest.mark.parametrize(
    "url",
    [
        "https://apmplus.volces.com.queniusz.com",
        "https://volces.com.evil.com",
    ],
)
def test_trusted_domain_impersonation_detects_nested_trusted_domain(
    url,
):
    result = check_trusted_domain_impersonation(
        parse(url)
    )

    assert len(result) == 1
    assert result[0]["score"] == 25
    assert result[0]["severity"] == "High"
    assert "volces.com" in result[0]["reason"]


def test_external_redirect():
    result = check_external_redirect(
        parse(
            "https://example.com/login"
            "?next=https%3A%2F%2Fevil.com%2Flogin"
        )
    )

    assert len(result) == 1
    assert result[0]["score"] == 15
    assert "evil.com" in result[0]["reason"]


def test_same_domain_redirect_is_not_external():
    result = check_external_redirect(
        parse(
            "https://example.com/login"
            "?next=https%3A%2F%2Fexample.com%2Faccount"
        )
    )

    assert result == []


def test_encoding():
    result = check_encoding(
        parse("https://example.com/%41%42%43%44%45")
    )

    assert len(result) == 1
    assert result[0]["score"] == 10


def test_double_encoding():
    result = check_double_encoding(
        parse("https://example.com/login%252Fverify")
    )

    assert len(result) == 1
    assert result[0]["score"] == 15


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com",
        "https://www.github.com",
        "https://api.github.com",
    ],
)
def test_legitimate_github_urls_have_no_impersonation(url):
    result = check_trusted_domain_impersonation(
        parse(url)
    )

    assert result == []


@pytest.mark.parametrize(
    "url",
    [
        "https://mail.yahoo.com",
        "https://edge.gycpi.b.yahoodns.net",
        "https://hif-dliq.deepseek.com",
        "https://apmplus.volces.com",
    ],
)
def test_known_legitimate_gateway_domains_have_no_typosquatting(
    url,
):
    result = check_typosquatting(
        parse(url)
    )

    assert result == []
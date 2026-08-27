import pytest

from app.analyzer.compound_rules import (
    apply_compound_rules,
    rule_ip_over_http,
    rule_redirect_with_keywords,
    rule_subdomains_with_keywords,
)
from app.analyzer.indicators import collect_indicators
from app.analyzer.parser import parse_url


def parse(url: str) -> dict:
    return parse_url(url)


def test_ip_over_http():
    parsed = parse("http://127.0.0.1/login")

    result = rule_ip_over_http(parsed)

    assert len(result) == 1
    assert result[0]["score"] == 10
    assert "IP address used over HTTP" in result[0]["reason"]


def test_ip_over_https_does_not_trigger():
    parsed = parse("https://127.0.0.1/login")

    result = rule_ip_over_http(parsed)

    assert result == []


def test_domain_over_http_does_not_trigger():
    parsed = parse("http://example.com/login")

    result = rule_ip_over_http(parsed)

    assert result == []


def test_redirect_with_keywords():
    url = (
        "https://example.com/login"
        "?next=https%3A%2F%2Fevil.com%2Flogin"
    )

    parsed = parse(url)
    indicators = collect_indicators(parsed)

    result = rule_redirect_with_keywords(
        parsed,
        indicators,
    )

    assert len(result) == 1
    assert result[0]["score"] == 8
    assert "redirect target" in result[0]["reason"]


def test_redirect_without_keywords_does_not_trigger():
    url = (
        "https://example.com/home"
        "?next=https%3A%2F%2Fevil.com%2Fhome"
    )

    parsed = parse(url)
    indicators = collect_indicators(parsed)

    result = rule_redirect_with_keywords(
        parsed,
        indicators,
    )

    assert result == []


def test_keywords_without_redirect_do_not_trigger():
    parsed = parse(
        "https://secure-login.example.com"
    )
    indicators = collect_indicators(parsed)

    result = rule_redirect_with_keywords(
        parsed,
        indicators,
    )

    assert result == []


def test_subdomains_with_keywords():
    parsed = parse(
        "https://login.a.b.example.com"
    )
    indicators = collect_indicators(parsed)

    result = rule_subdomains_with_keywords(
        parsed,
        indicators,
    )

    assert len(result) == 1
    assert result[0]["score"] == 8
    assert "multiple subdomains" in result[0]["reason"]


def test_subdomains_without_keywords_do_not_trigger():
    parsed = parse(
        "https://a.b.c.example.com"
    )
    indicators = collect_indicators(parsed)

    result = rule_subdomains_with_keywords(
        parsed,
        indicators,
    )

    assert result == []


def test_two_subdomains_with_keywords_do_not_trigger():
    parsed = parse(
        "https://login.a.example.com"
    )
    indicators = collect_indicators(parsed)

    result = rule_subdomains_with_keywords(
        parsed,
        indicators,
    )

    assert result == []


def test_apply_compound_rules_ip_http():
    parsed = parse("http://127.0.0.1/login")
    indicators = collect_indicators(parsed)

    result = apply_compound_rules(
        parsed,
        indicators,
    )

    reasons = [
        indicator["reason"]
        for indicator in result
    ]

    assert any(
        "IP address used over HTTP" in reason
        for reason in reasons
    )


def test_apply_compound_rules_redirect():
    url = (
        "https://example.com/login"
        "?next=https%3A%2F%2Fevil.com%2Flogin"
    )

    parsed = parse(url)
    indicators = collect_indicators(parsed)

    result = apply_compound_rules(
        parsed,
        indicators,
    )

    reasons = [
        indicator["reason"]
        for indicator in result
    ]

    assert any(
        "redirect target" in reason
        for reason in reasons
    )


def test_apply_compound_rules_subdomains():
    parsed = parse(
        "https://login.a.b.example.com"
    )
    indicators = collect_indicators(parsed)

    result = apply_compound_rules(
        parsed,
        indicators,
    )

    reasons = [
        indicator["reason"]
        for indicator in result
    ]

    assert any(
        "multiple subdomains" in reason
        for reason in reasons
    )
"""
Compound phishing risk rules.

Contains rules that detect combinations of multiple
suspicious URL characteristics.

Individual indicators are handled by indicators.py.
Final risk calculation is handled by risk_engine.py.
"""

import ipaddress
from typing import Any


def _has_ip_address(
    parsed: dict[str, Any],
) -> bool:
    """
    Determine whether the URL hostname is an IP address.
    """

    try:
        ipaddress.ip_address(
            parsed["hostname"],
        )
        return True
    except ValueError:
        return False


def _has_suspicious_keywords(
    indicators: list[dict[str, Any]],
) -> bool:
    """
    Determine whether suspicious keyword detection
    produced an indicator.
    """

    return any(
        "suspicious keywords detected"
        in str(
            indicator.get("reason", ""),
        ).lower()
        for indicator in indicators
    )


def _has_external_redirect(
    indicators: list[dict[str, Any]],
) -> bool:
    """
    Determine whether an external redirect was detected.
    """

    return any(
        "external redirect detected"
        in str(
            indicator.get("reason", ""),
        ).lower()
        for indicator in indicators
    )


def _has_many_subdomains(
    parsed: dict[str, Any],
) -> bool:
    """
    Determine whether the URL has three or more
    subdomain levels.
    """

    subdomain_levels = parsed.get(
        "subdomain_levels",
    )

    if subdomain_levels is None:
        subdomain = parsed.get(
            "subdomain",
            "",
        )

        subdomain_levels = len(
            [
                part
                for part in subdomain.split(".")
                if part
            ]
        )

    return subdomain_levels >= 3


def rule_ip_over_http(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect an IP address being used over HTTP.
    """

    if not (
        _has_ip_address(parsed)
        and parsed["parsed"].scheme.lower() == "http"
    ):
        return []

    return [
        {
            "score": 10,
            "reason": (
                "High-risk combination detected: "
                "IP address used over HTTP."
            ),
        }
    ]


def rule_redirect_with_keywords(
    parsed: dict[str, Any],
    indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Detect an external redirect combined with
    suspicious phishing-related keywords.
    """

    if not (
        _has_external_redirect(indicators)
        and _has_suspicious_keywords(indicators)
    ):
        return []

    return [
        {
            "score": 8,
            "reason": (
                "Suspicious combination detected: "
                "redirect target combined with "
                "phishing-related keywords."
            ),
        }
    ]


def rule_subdomains_with_keywords(
    parsed: dict[str, Any],
    indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Detect multiple subdomains combined with
    suspicious phishing-related keywords.
    """

    if not (
        _has_many_subdomains(parsed)
        and _has_suspicious_keywords(indicators)
    ):
        return []

    return [
        {
            "score": 8,
            "reason": (
                "Suspicious combination detected: "
                "multiple subdomains combined with "
                "phishing-related keywords."
            ),
        }
    ]


def apply_compound_rules(
    parsed: dict[str, Any],
    indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Apply all compound phishing rules.
    """

    compound_indicators: list[dict[str, Any]] = []

    compound_indicators.extend(
        rule_ip_over_http(parsed),
    )

    compound_indicators.extend(
        rule_redirect_with_keywords(
            parsed,
            indicators,
        ),
    )

    compound_indicators.extend(
        rule_subdomains_with_keywords(
            parsed,
            indicators,
        ),
    )

    return compound_indicators
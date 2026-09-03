"""
URL phishing indicator detection.

Contains individual rules that inspect a parsed URL
and return detected risk indicators.

This module does not calculate the final risk level
and does not apply compound rules.
"""

import ipaddress
from typing import Any
from urllib.parse import unquote
from urllib.parse import urlparse

import tldextract

from app.analyzer.constants import LONG_PATH_THRESHOLD
from app.analyzer.constants import LONG_URL_THRESHOLD
from app.analyzer.constants import REDIRECT_PARAMETERS
from app.analyzer.constants import SUSPICIOUS_CHARACTERS
from app.analyzer.constants import SUSPICIOUS_KEYWORDS

from app.analyzer.constants import TRUSTED_DOMAINS
from app.analyzer.constants import TRUSTED_BRANDS
from app.analyzer.constants import TYPOSQUATTING_SCORE
from app.analyzer.constants import (
    TYPOSQUATTING_MAX_LENGTH_DIFFERENCE,
)
from app.analyzer.constants import (
    TYPOSQUATTING_SIMILARITY_THRESHOLD,
)

def _indicator(
    score: int,
    reason: str,
    severity: str | None = None,
) -> dict[str, Any]:
    """
    Build a standardized indicator dictionary.
    """

    result: dict[str, Any] = {
        "score": score,
        "reason": reason,
    }

    if severity is not None:
        result["severity"] = severity

    return result


def check_long_url(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect unusually long URLs.
    """

    if len(parsed["url"]) <= LONG_URL_THRESHOLD:
        return []

    return [
        _indicator(
            score=10,
            reason="URL is unusually long.",
        )
    ]


def check_at_symbol(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect the @ symbol in a URL.
    """

    if "@" not in parsed["url"]:
        return []

    return [
        _indicator(
            score=20,
            reason="URL contains the @ symbol.",
        )
    ]


def check_ip_address(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect URLs that use an IP address as hostname.
    """

    hostname = parsed["hostname"]

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return []

    return [
        _indicator(
            score=25,
            severity="High",
            reason=(
                "URL uses an IP address instead "
                "of a domain name."
            ),
        )
    ]


def check_subdomains(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect excessive subdomain levels.
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

    if subdomain_levels >= 4:
        return [
            _indicator(
                score=20,
                reason=(
                    "URL contains "
                    f"{subdomain_levels} "
                    "subdomains."
                ),
            )
        ]

    if subdomain_levels == 3:
        return [
            _indicator(
                score=15,
                reason=(
                    "URL contains several "
                    "subdomain levels."
                ),
            )
        ]

    if subdomain_levels == 2:
        return [
            _indicator(
                score=10,
                reason=(
                    "URL contains multiple "
                    "subdomains."
                ),
            )
        ]

    return []


def check_suspicious_characters(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect suspicious characters in the URL.
    """

    url = parsed["url"]
    indicators = []

    for char in SUSPICIOUS_CHARACTERS:
        if char in url:
            indicators.append(
                _indicator(
                    score=5,
                    reason=(
                        "URL contains suspicious "
                        f"character: {char}"
                    ),
                )
            )

    return indicators


def check_multiple_hyphens(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect multiple hyphens in the hostname.
    """

    hostname = parsed["hostname"]

    if hostname.count("-") < 2:
        return []

    return [
        _indicator(
            score=10,
            reason=(
                "Domain contains multiple "
                "hyphens."
            ),
        )
    ]

def check_trusted_domain_impersonation(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect trusted-domain names used inside the subdomain
    of a different registered domain.

    Examples:

        github.com
        www.github.com

    are legitimate.

    But:

        github.com.evil.com
        login.github.com.evil.com

    indicate possible trusted-brand impersonation.
    """

    registered_domain = (
        parsed["registered_domain"]
        .lower()
        .rstrip(".")
    )

    subdomain = (
        parsed.get("subdomain", "")
        .lower()
        .strip(".")
    )

    if not subdomain:
        return []

    for trusted_domain in TRUSTED_DOMAINS:
        trusted_domain = (
            trusted_domain.lower()
            .rstrip(".")
        )

        # The actual registered domain is already trusted.
        if registered_domain == trusted_domain:
            continue

        # Match the trusted domain as a complete suffix
        # inside the subdomain, not as an arbitrary substring.
        if (
            subdomain == trusted_domain
            or subdomain.endswith(
                "." + trusted_domain
            )
        ):
            return [
                _indicator(
                    score=25,
                    severity="High",
                    reason=(
                        "Possible trusted-domain impersonation: "
                        f"'{trusted_domain}' appears in the "
                        "subdomain of another domain."
                    ),
                )
            ]

    return []

def check_typosquatting(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect possible typosquatting attacks.

    Compares the registered domain name against a list
    of trusted brand names using normalized
    Levenshtein-like similarity from SequenceMatcher.

    Examples:

        google.com
        g00gle.com
        gooogle.com
        goog1e.com

    may indicate an attempt to imitate a trusted brand.
    """

    from difflib import SequenceMatcher

    registered_domain = (
        parsed["registered_domain"]
        .lower()
        .rstrip(".")
    )

    if not registered_domain:
        return []

    # Do not compare a trusted domain with itself.
    if registered_domain in TRUSTED_DOMAINS:
        return []

    domain_name = (
        parsed.get(
            "domain",
            "",
        )
        .lower()
        .strip()
    )

    if not domain_name:
        return []

    best_brand = None
    best_domain = None
    best_similarity = 0.0

    for brand, trusted_domain in TRUSTED_BRANDS.items():

        # Exact brand/domain match is legitimate.
        if domain_name == brand:
            continue

        length_difference = abs(
            len(domain_name) - len(brand)
        )

        if (
            length_difference
            > TYPOSQUATTING_MAX_LENGTH_DIFFERENCE
        ):
            continue

        similarity = SequenceMatcher(
            None,
            domain_name,
            brand,
        ).ratio()

        if similarity > best_similarity:
            best_similarity = similarity
            best_brand = brand
            best_domain = trusted_domain

    if (
        best_brand is None
        or best_domain is None
        or best_similarity
        < TYPOSQUATTING_SIMILARITY_THRESHOLD
    ):
        return []

    return [
        _indicator(
            score=TYPOSQUATTING_SCORE,
            severity="High",
            reason=(
                "Possible typosquatting detected: "
                f"domain '{domain_name}' resembles "
                f"trusted brand '{best_brand}' "
                f"({best_domain}) "
                f"with {best_similarity:.0%} similarity."
            ),
        )
    ]

def check_long_path(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect unusually long URL paths.
    """

    if len(parsed["path"]) <= LONG_PATH_THRESHOLD:
        return []

    return [
        _indicator(
            score=10,
            reason=(
                "URL has an unusually "
                "long path."
            ),
        )
    ]


def check_http(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect insecure HTTP URLs.
    """

    protocol = parsed["parsed"].scheme.lower()

    if protocol != "http":
        return []

    return [
        _indicator(
            score=5,
            reason=(
                "URL uses HTTP instead "
                "of HTTPS."
            ),
        )
    ]


def check_keywords(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect phishing-related keywords.

    Keyword weights:

    - hostname: 4 points
    - path: 2 points
    - query: 1 point

    Total keyword score is capped at 20.
    """

    hostname = parsed["hostname"].lower()
    decoded_path = parsed["decoded_path"].lower()
    decoded_query = parsed["decoded_query"].lower()
    
    registered_domain = (
        parsed["registered_domain"]
        .lower()
        .rstrip(".")
    )

    if registered_domain in TRUSTED_DOMAINS:
        return []

    keyword_locations: dict[str, list[str]] = {
        "hostname": [],
        "path": [],
        "query": [],
    }

    for word in SUSPICIOUS_KEYWORDS:
        if word in hostname:
            keyword_locations["hostname"].append(word)
        elif word in decoded_path:
            keyword_locations["path"].append(word)
        elif word in decoded_query:
            keyword_locations["query"].append(word)

    keyword_score = 0
    found_keywords: list[str] = []

    for location, words in keyword_locations.items():
        if not words:
            continue

        found_keywords.extend(words)

        if location == "hostname":
            keyword_score += len(words) * 4
        elif location == "path":
            keyword_score += len(words) * 2
        else:
            keyword_score += len(words)

    keyword_score = min(
        keyword_score,
        20,
    )

    if not found_keywords:
        return []

    location_parts = [
        f"{location}: {', '.join(words)}"
        for location, words in keyword_locations.items()
        if words
    ]

    registered_domain = (
        parsed["registered_domain"]
        .lower()
        .rstrip(".")
    )

    if registered_domain in TRUSTED_DOMAINS:
        return []

    return [
        _indicator(
            score=keyword_score,
            reason=(
                "Suspicious keywords detected — "
                + "; ".join(location_parts)
            ),
        )
    ]


def check_query_parameters(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Report the presence of query parameters.

    This is informational only and contributes
    zero risk points.
    """

    query_params = parsed["query_params"]

    if not query_params:
        return []

    return [
        _indicator(
            score=0,
            reason=(
                f"URL contains {len(query_params)} "
                "query parameter(s)."
            ),
        )
    ]


def check_external_redirect(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect external redirect targets.
    """

    query_params = parsed["query_params"]
    registered_domain = parsed["registered_domain"]

    findings: list[dict[str, str]] = []

    for key, value in query_params:
        if key.lower() not in REDIRECT_PARAMETERS:
            continue

        decoded_value = unquote(
            value.strip(),
        )

        if not decoded_value.startswith(
            ("http://", "https://"),
        ):
            continue

        target = urlparse(decoded_value)
        target_hostname = target.hostname or ""

        if not target_hostname:
            continue

        target_extracted = tldextract.extract(
            decoded_value,
        )

        target_registered_domain = target_extracted.domain

        if target_extracted.suffix:
            target_registered_domain = (
                f"{target_extracted.domain}."
                f"{target_extracted.suffix}"
            )

        if (
            target_registered_domain.lower()
            != registered_domain.lower()
        ):
            findings.append(
                {
                    "parameter": key,
                    "target": target_hostname,
                }
            )

    if not findings:
        return []

    redirect_details = [
        f"{finding['parameter']} → {finding['target']}"
        for finding in findings
    ]

    return [
        _indicator(
            score=15,
            reason=(
                "External redirect detected: "
                + ", ".join(redirect_details)
            ),
        )
    ]


def check_encoding(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect excessive URL encoding.
    """

    encoded_count = parsed["url"].count("%")

    if encoded_count < 5:
        return []

    return [
        _indicator(
            score=10,
            reason=(
                "URL contains excessive encoding "
                f"({encoded_count} encoded characters)."
            ),
        )
    ]


def check_double_encoding(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect possible double URL encoding.
    """

    double_encoded_count = parsed["url"].lower().count(
        "%25",
    )

    if double_encoded_count == 0:
        return []

    return [
        _indicator(
            score=15,
            reason=(
                "URL contains possible double encoding "
                f"({double_encoded_count} occurrence(s) of %25)."
            ),
        )
    ]


def collect_indicators(
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Run all individual indicator checks.

    Compound rules are intentionally excluded.
    """

    indicators: list[dict[str, Any]] = []

    checks = (
        check_long_url,
        check_at_symbol,
        check_ip_address,
        check_subdomains,
        check_suspicious_characters,
        check_multiple_hyphens,
        check_trusted_domain_impersonation,
        check_typosquatting,
        check_long_path,
        check_http,
        check_keywords,
        check_query_parameters,
        check_external_redirect,
        check_encoding,
        check_double_encoding,
    )

    for check in checks:
        indicators.extend(
            check(parsed),
        )

    return indicators
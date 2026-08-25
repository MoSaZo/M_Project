"""
Feature extraction for URL phishing ML models.
"""

import ipaddress
from urllib.parse import parse_qsl
from urllib.parse import urlparse

import tldextract

from app.analyzer.constants import (
    REDIRECT_PARAMETERS,
    SUSPICIOUS_KEYWORDS,
)


def extract_url_features(url: str) -> dict[str, float]:
    """
    Extract numeric features from a URL.

    The feature set is intentionally based only on
    URL characteristics so the trained model can be
    used independently of the PhiUSIIL dataset schema.
    """

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    extracted = tldextract.extract(url)

    subdomain_parts = [
        part
        for part in extracted.subdomain.split(".")
        if part
    ]

    query_params = parse_qsl(
        query,
        keep_blank_values=True,
    )

    try:
        is_ip = int(
            ipaddress.ip_address(hostname) is not None,
        )
    except ValueError:
        is_ip = 0

    hostname_lower = hostname.lower()
    path_lower = path.lower()
    query_lower = query.lower()

    suspicious_keyword_count = sum(
        1
        for keyword in SUSPICIOUS_KEYWORDS
        if (
            keyword in hostname_lower
            or keyword in path_lower
            or keyword in query_lower
        )
    )

    redirect_parameter_count = sum(
        1
        for key, _ in query_params
        if key.lower() in REDIRECT_PARAMETERS
    )

    special_characters = sum(
        1
        for char in url
        if not char.isalnum()
    )

    digit_count = sum(
        1
        for char in url
        if char.isdigit()
    )

    return {
        "url_length": float(len(url)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "dot_count": float(hostname.count(".")),
        "subdomain_count": float(len(subdomain_parts)),
        "hyphen_count": float(hostname.count("-")),
        "digit_count": float(digit_count),
        "special_character_count": float(
            special_characters,
        ),
        "query_parameter_count": float(
            len(query_params),
        ),
        "has_at_symbol": float("@" in url),
        "is_ip_address": float(is_ip),
        "is_https": float(
            parsed.scheme.lower() == "https",
        ),
        "suspicious_keyword_count": float(
            suspicious_keyword_count,
        ),
        "redirect_parameter_count": float(
            redirect_parameter_count,
        ),
        "percent_count": float(
            url.count("%"),
        ),
        "double_encoding_count": float(
            url.lower().count("%25"),
        ),
    }


FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "subdomain_count",
    "hyphen_count",
    "digit_count",
    "special_character_count",
    "query_parameter_count",
    "has_at_symbol",
    "is_ip_address",
    "is_https",
    "suspicious_keyword_count",
    "redirect_parameter_count",
    "percent_count",
    "double_encoding_count",
]
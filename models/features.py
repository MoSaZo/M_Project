"""
Feature extraction for URL phishing ML models.
"""

import ipaddress
import math
from collections import Counter
from urllib.parse import parse_qsl
from urllib.parse import urlparse

import tldextract

from app.analyzer.constants import (
    REDIRECT_PARAMETERS,
    SUSPICIOUS_KEYWORDS,
)


def _safe_ratio(
    numerator: int,
    denominator: int,
) -> float:
    """Calculate a ratio safely."""
    if denominator == 0:
        return 0.0

    return float(numerator / denominator)


def _calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return float(
        -sum(
            (count / length)
            * math.log2(count / length)
            for count in counts.values()
        )
    )


def extract_url_features(
    url: str,
) -> dict[str, float]:
    """
    Extract numeric features from a URL.

    Features are based only on URL characteristics
    and do not depend on external reputation data.
    """

    url = url.strip()

    if not url.startswith(
        ("http://", "https://")
    ):
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

    domain = extracted.domain or ""
    suffix = extracted.suffix or ""

    query_params = parse_qsl(
        query,
        keep_blank_values=True,
    )

    try:
        is_ip = int(
            ipaddress.ip_address(hostname)
            is not None,
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
        if key.lower()
        in REDIRECT_PARAMETERS
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

    hostname_digit_count = sum(
        1
        for char in hostname
        if char.isdigit()
    )

    hostname_letter_count = sum(
        1
        for char in hostname
        if char.isalpha()
    )

    hostname_special_count = sum(
        1
        for char in hostname
        if not char.isalnum()
    )

    path_digit_count = sum(
        1
        for char in path
        if char.isdigit()
    )

    path_special_count = sum(
        1
        for char in path
        if not char.isalnum()
    )

    path_segment_count = len(
        [
            segment
            for segment in path.split("/")
            if segment
        ]
    )

    double_slash_in_path = int(
        "//" in path
    )

    has_punycode = int(
        "xn--" in hostname_lower
    )

    url_digit_ratio = _safe_ratio(
        digit_count,
        len(url),
    )

    url_special_ratio = _safe_ratio(
        special_characters,
        len(url),
    )

    hostname_hyphen_ratio = _safe_ratio(
        hostname.count("-"),
        len(hostname),
    )

    return {
        # Original features.
        "url_length": float(len(url)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "dot_count": float(
            hostname.count(".")
        ),
        "subdomain_count": float(
            len(subdomain_parts)
        ),
        "hyphen_count": float(
            hostname.count("-")
        ),
        "digit_count": float(digit_count),
        "special_character_count": float(
            special_characters
        ),
        "query_parameter_count": float(
            len(query_params)
        ),
        "has_at_symbol": float(
            "@" in url
        ),
        "is_ip_address": float(is_ip),
        "is_https": float(
            parsed.scheme.lower()
            == "https"
        ),
        "suspicious_keyword_count": float(
            suspicious_keyword_count
        ),
        "redirect_parameter_count": float(
            redirect_parameter_count
        ),
        "percent_count": float(
            url.count("%")
        ),
        "double_encoding_count": float(
            url.lower().count("%25")
        ),

        # Hostname/domain features.
        "domain_length": float(
            len(domain)
        ),
        "tld_length": float(
            len(suffix)
        ),
        "subdomain_length": float(
            len(extracted.subdomain)
        ),
        "hostname_digit_count": float(
            hostname_digit_count
        ),
        "hostname_letter_count": float(
            hostname_letter_count
        ),
        "hostname_special_count": float(
            hostname_special_count
        ),
        "hostname_hyphen_ratio": (
            hostname_hyphen_ratio
        ),
        "domain_hyphen_count": float(
            domain.count("-")
        ),
        "hostname_entropy": (
            _calculate_entropy(
                hostname_lower
            )
        ),

        # Path features.
        "path_digit_count": float(
            path_digit_count
        ),
        "path_special_count": float(
            path_special_count
        ),
        "path_segment_count": float(
            path_segment_count
        ),
        "has_double_slash_in_path": float(
            double_slash_in_path
        ),

        # Encoding/query features.
        "query_key_count": float(
            len(
                {
                    key.lower()
                    for key, _ in query_params
                }
            )
        ),
        "has_punycode": float(
            has_punycode
        ),

        # Ratio features.
        "url_digit_ratio": url_digit_ratio,
        "url_special_ratio": (
            url_special_ratio
        ),
    }


FEATURE_NAMES = [
    # Original features.
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

    # Hostname/domain features.
    "domain_length",
    "tld_length",
    "subdomain_length",
    "hostname_digit_count",
    "hostname_letter_count",
    "hostname_special_count",
    "hostname_hyphen_ratio",
    "domain_hyphen_count",
    "hostname_entropy",

    # Path features.
    "path_digit_count",
    "path_special_count",
    "path_segment_count",
    "has_double_slash_in_path",

    # Query/encoding features.
    "query_key_count",
    "has_punycode",

    # Ratio features.
    "url_digit_ratio",
    "url_special_ratio",
]

MODEL_FEATURE_NAMES = [
    feature
    for feature in FEATURE_NAMES
    if feature != "is_https"
]

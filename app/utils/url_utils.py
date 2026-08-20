"""
URL-related utility functions.
"""

from urllib.parse import urlparse


def get_hostname(
    url: str,
) -> str:
    """
    Extract hostname from a URL.

    Returns an empty string when no hostname exists.
    """

    parsed = urlparse(url)

    return parsed.hostname or ""


def get_protocol(
    url: str,
) -> str:
    """
    Extract URL protocol.
    """

    parsed = urlparse(url)

    return parsed.scheme.lower()


def is_https(
    url: str,
) -> bool:
    """
    Determine whether a URL uses HTTPS.
    """

    return get_protocol(url) == "https"


def is_http(
    url: str,
) -> bool:
    """
    Determine whether a URL uses HTTP.
    """

    return get_protocol(url) == "http"
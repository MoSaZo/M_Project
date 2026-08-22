"""
Validation utilities.
"""

from urllib.parse import urlparse


def validate_url(
    url: str,
) -> str:
    """
    Validate and normalize a URL.

    Args:
        url:
            URL to validate.

    Returns:
        Normalized URL.

    Raises:
        ValueError:
            If the URL is invalid.
    """

    if not isinstance(url, str):
        raise ValueError(
            "URL must be a string."
        )

    url = url.strip()

    if not url:
        raise ValueError(
            "URL cannot be empty."
        )

    if not url.startswith(
        ("http://", "https://"),
    ):
        url = "http://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError(
            "URL must contain a hostname."
        )

    return url


def validate_limit(
    limit: int,
    maximum: int = 100,
) -> int:
    """
    Validate a pagination/history limit.
    """

    if limit < 1:
        raise ValueError(
            "Limit must be greater than 0."
        )

    if limit > maximum:
        raise ValueError(
            f"Limit cannot exceed {maximum}."
        )

    return limit
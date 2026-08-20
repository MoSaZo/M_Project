"""
URL parser.

Parses and normalizes URLs into a structure
used by the analyzer pipeline.
"""

from typing import Any
from urllib.parse import parse_qsl
from urllib.parse import unquote
from urllib.parse import urlparse

import tldextract


def parse_url(url: str) -> dict[str, Any]:
    """
    Parse and normalize a URL.

    Args:
        url:
            URL to parse.

    Returns:
        Parsed URL information.

    Raises:
        ValueError:
            If the URL is empty or has no hostname.
    """

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

    hostname = parsed.hostname or ""

    if not hostname:
        raise ValueError(
            "Hostname not found."
        )

    extracted = tldextract.extract(url)

    registered_domain = extracted.domain

    if extracted.suffix:
        registered_domain = (
            f"{extracted.domain}."
            f"{extracted.suffix}"
        )

    subdomain_parts = [
        part
        for part in extracted.subdomain.split(".")
        if part
    ]

    return {
        "url": url,
        "parsed": parsed,
        "hostname": hostname,
        "path": parsed.path,
        "query": parsed.query,
        "decoded_path": unquote(
            parsed.path,
        ),
        "decoded_query": unquote(
            parsed.query,
        ),
        "query_params": parse_qsl(
            parsed.query,
            keep_blank_values=True,
        ),
        "subdomain": extracted.subdomain,
        "domain": extracted.domain,
        "suffix": extracted.suffix,
        "registered_domain": registered_domain,
        "subdomain_levels": len(
            subdomain_parts,
        ),
    }
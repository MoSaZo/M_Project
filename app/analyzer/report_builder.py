"""
Analysis report builder.

Constructs the final URL analysis response
from parsed URL data and calculated risk information.
"""

from typing import Any


def build_report(
    parsed: dict[str, Any],
    risk: dict[str, Any],
) -> dict[str, Any]:
    """
    Build the final URL analysis report.
    """

    return {
        "url": parsed["url"],
        "hostname": parsed["hostname"],
        "registered_domain": parsed["registered_domain"],
        "subdomain": parsed["subdomain"],
        "subdomain_levels": parsed["subdomain_levels"],
        "domain": parsed["domain"],
        "suffix": parsed["suffix"],
        "protocol": parsed["parsed"].scheme,
        "path": parsed["decoded_path"],
        "has_query": bool(parsed["query"]),
        "query_parameter_count": len(
            parsed["query_params"],
        ),
        **risk,
    }
"""
Database response schemas.

Pydantic models used for database-backed responses.
"""

from datetime import datetime

from pydantic import BaseModel


class ScanResponse(BaseModel):
    """
    URL scan history response.
    """

    id: int

    url: str

    hostname: str | None

    registered_domain: str | None

    subdomain: str | None

    protocol: str | None

    subdomain_levels: int | None

    tld: str | None

    query_parameter_count: int

    risk_score: int

    risk_level: str

    risk_summary: str | None

    reasons: str | None

    created_at: datetime

    model_config = {
        "from_attributes": True,
    }
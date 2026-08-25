"""
Pydantic response schemas.

Defines API response models.
"""

from pydantic import BaseModel


class IndicatorResponse(BaseModel):
    """
    A single URL risk indicator.
    """

    score: int

    severity: str

    reason: str


class URLAnalysisResponse(BaseModel):
    """
    Complete URL analysis response.
    """

    id: int | None = None

    url: str

    hostname: str

    registered_domain: str

    subdomain: str

    subdomain_levels: int

    domain: str

    suffix: str

    protocol: str

    path: str

    has_query: bool

    query_parameter_count: int

    risk_score: int

    risk_level: str

    ml_prediction: str

    ml_probability: float

    reasons: list[str]

    indicators: list[IndicatorResponse]
"""
API schemas for gateway monitoring.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class GatewayEventResponse(BaseModel):
    """
    Public representation of a gateway event.
    """

    id: int
    timestamp: datetime

    domain: str
    answer: str
    record_type: str

    source_ip: str
    destination_ip: str
    response: bool

    # ML analysis
    score: float
    prediction: str
    probability: float

    # Final risk assessment
    risk_score: int
    risk_level: str

    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )


class GatewayEventsResponse(BaseModel):
    """
    Paginated gateway events.
    """

    items: list[GatewayEventResponse]

    count: int = Field(
        validation_alias="total",
        serialization_alias="count",
    )

    limit: int
    offset: int


class GatewayStatsResponse(BaseModel):
    """
    Aggregated gateway security statistics.
    """

    total: int = Field(
        validation_alias="total_events",
        serialization_alias="total",
    )

    phishing: int = Field(
        validation_alias="phishing_events",
        serialization_alias="phishing",
    )

    legitimate: int = Field(
        validation_alias="legitimate_events",
        serialization_alias="legitimate",
    )

    average_score: float
    highest_score: float
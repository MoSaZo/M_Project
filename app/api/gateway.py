"""
Gateway monitoring API endpoints.
"""

from fastapi import APIRouter
from fastapi import Depends
from fastapi import Query
from sqlalchemy.orm import Session

from app.api.dependencies import database_session
from app.database.gateway_repository import GatewayEventRepository
from app.schemas.gateway import GatewayEventResponse
from app.schemas.gateway import GatewayEventsResponse
from app.schemas.gateway import GatewayStatsResponse


router = APIRouter(
    prefix="/gateway",
    tags=["Gateway"],
)


@router.get(
    "/events",
    response_model=GatewayEventsResponse,
)
def list_gateway_events(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    prediction: str | None = None,
    db: Session = Depends(
        database_session,
    ),
) -> GatewayEventsResponse:
    """
    Return persisted gateway events.
    """

    repository = GatewayEventRepository(db)

    events = repository.list_events(
        limit=limit,
        offset=offset,
        prediction=prediction,
    )

    return GatewayEventsResponse(
        items=[
            GatewayEventResponse(
                id=event.id,
                timestamp=event.timestamp,
                domain=event.domain,
                answer=event.answer,
                record_type=event.record_type,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                response=event.response,
                score=event.score,
                prediction=event.prediction,
                probability=event.probability,
                risk_score=event.risk_score,
                risk_level=event.risk_level,
                created_at=event.created_at,
            )
            for event in events
        ],
        total=repository.count_events(
            prediction=prediction,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/stats",
    response_model=GatewayStatsResponse,
)
def gateway_stats(
    db: Session = Depends(
        database_session,
    ),
) -> GatewayStatsResponse:
    """
    Return gateway security statistics.
    """

    repository = GatewayEventRepository(db)

    return GatewayStatsResponse(
        total_events=repository.count_events(),
        phishing_events=repository.count_events(
            prediction="phishing",
        ),
        legitimate_events=repository.count_events(
            prediction="legitimate",
        ),
        average_score=repository.average_score(),
        highest_score=repository.highest_score(),
    )
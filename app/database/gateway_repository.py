"""
Repository for persistent gateway DNS events.
"""

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.gateway_models import GatewayEvent
from app.gateway.models import DNSRecord
from app.gateway.results import AnalysisResult


class GatewayEventRepository:
    """
    Persist and query gateway DNS records and their
    analysis results.
    """

    def __init__(
        self,
        db: Session,
    ) -> None:
        self.db = db

    def create(
        self,
        record: DNSRecord,
        result: AnalysisResult,
    ) -> GatewayEvent:
        """
        Persist a DNS observation together with the
        complete analysis result.
        """

        event = GatewayEvent(
            timestamp=record.timestamp,
            domain=record.query,
            answer=record.answer,
            record_type=record.record_type,
            source_ip=record.source_ip,
            destination_ip=record.destination_ip,
            response=record.response,
            score=result.score,
            prediction=result.prediction,
            probability=result.probability,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
        )

        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)

        return event

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        prediction: str | None = None,
    ) -> list[type[GatewayEvent]]:
        """
        Return persisted gateway events.
        """

        query = (
            self.db.query(GatewayEvent)
            .order_by(
                GatewayEvent.timestamp.desc(),
                GatewayEvent.id.desc(),
            )
        )

        if prediction is not None:
            query = query.filter(
                GatewayEvent.prediction == prediction,
            )

        return (
            query
            .offset(offset)
            .limit(limit)
            .all()
        )

    def count_events(
        self,
        prediction: str | None = None,
    ) -> int:
        """
        Count gateway events.
        """

        query = self.db.query(
            func.count(GatewayEvent.id),
        )

        if prediction is not None:
            query = query.filter(
                GatewayEvent.prediction == prediction,
            )

        return int(
            query.scalar() or 0,
        )

    def average_score(self) -> float:
        """
        Return the average ML score.
        """

        value = self.db.query(
            func.avg(GatewayEvent.score),
        ).scalar()

        return float(value or 0.0)

    def highest_score(self) -> float:
        """
        Return the highest ML score.
        """

        value = self.db.query(
            func.max(GatewayEvent.score),
        ).scalar()

        return float(value or 0.0)

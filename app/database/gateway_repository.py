"""
Repository for persistent gateway DNS events.
"""

from sqlalchemy.orm import Session

from app.database.gateway_models import GatewayEvent
from app.gateway.models import DNSRecord
from app.gateway.results import AnalysisResult


class GatewayEventRepository:
    """
    Persist gateway DNS records and their analysis results.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        record: DNSRecord,
        result: AnalysisResult,
    ) -> GatewayEvent:
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
        )

        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)

        return event
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.database import Base
from app.database.gateway_models import GatewayEvent
from app.database.gateway_repository import GatewayEventRepository
from app.gateway.models import DNSRecord
from app.gateway.results import AnalysisResult


def make_record() -> DNSRecord:
    return DNSRecord(
        timestamp=datetime.now(),
        query="example.com",
        answer="93.184.216.34",
        record_type="A",
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        response=True,
    )


def make_result() -> AnalysisResult:
    return AnalysisResult(
        domain="example.com",
        score=0.25,
        prediction="legitimate",
    )


def test_repository_persists_gateway_event():
    engine = create_engine(
        "sqlite:///:memory:",
        future=True,
    )

    Base.metadata.create_all(bind=engine)

    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    db = SessionLocal()

    try:
        repository = GatewayEventRepository(db)

        event = repository.create(
            make_record(),
            make_result(),
        )

        assert event.id is not None
        assert event.domain == "example.com"
        assert event.answer == "93.184.216.34"
        assert event.score == 0.25
        assert event.prediction == "legitimate"

    finally:
        db.close()


def test_repository_event_can_be_queried():
    engine = create_engine(
        "sqlite:///:memory:",
        future=True,
    )

    Base.metadata.create_all(bind=engine)

    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    db = SessionLocal()

    try:
        repository = GatewayEventRepository(db)

        repository.create(
            make_record(),
            make_result(),
        )

        event = (
            db.query(GatewayEvent)
            .filter_by(domain="example.com")
            .first()
        )

        assert event is not None
        assert event.prediction == "legitimate"

    finally:
        db.close()
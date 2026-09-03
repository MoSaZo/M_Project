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

def make_session():
    engine = create_engine(
        "sqlite:///:memory:",
        future=True,
    )

    Base.metadata.create_all(
        bind=engine,
    )

    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    return SessionLocal()


def test_list_events_returns_latest_first():
    db = make_session()

    try:
        repository = GatewayEventRepository(db)

        first = make_record()
        first.query = "first.example.com"

        second = make_record()
        second.query = "second.example.com"

        repository.create(
            first,
            AnalysisResult(
                domain="first.example.com",
                score=0.2,
                prediction="legitimate",
            ),
        )

        repository.create(
            second,
            AnalysisResult(
                domain="second.example.com",
                score=0.9,
                prediction="phishing",
            ),
        )

        events = repository.list_events()

        assert len(events) == 2
        assert (
            events[0].domain
            == "second.example.com"
        )

    finally:
        db.close()


def test_list_events_filters_prediction():
    db = make_session()

    try:
        repository = GatewayEventRepository(db)

        safe = make_record()
        safe.query = "safe.example.com"

        evil = make_record()
        evil.query = "evil.example.com"

        repository.create(
            safe,
            AnalysisResult(
                domain="safe.example.com",
                score=0.1,
                prediction="legitimate",
            ),
        )

        repository.create(
            evil,
            AnalysisResult(
                domain="evil.example.com",
                score=0.9,
                prediction="phishing",
            ),
        )

        events = repository.list_events(
            prediction="phishing",
        )

        assert len(events) == 1
        assert (
            events[0].domain
            == "evil.example.com"
        )

    finally:
        db.close()


def test_count_events():
    db = make_session()

    try:
        repository = GatewayEventRepository(db)

        repository.create(
            make_record(),
            AnalysisResult(
                domain="example.com",
                score=0.7,
                prediction="phishing",
            ),
        )

        assert repository.count_events() == 1

        assert (
            repository.count_events(
                prediction="phishing",
            )
            == 1
        )

        assert (
            repository.count_events(
                prediction="legitimate",
            )
            == 0
        )

    finally:
        db.close()


def test_score_statistics():
    db = make_session()

    try:
        repository = GatewayEventRepository(db)

        first = make_record()

        second = make_record()
        second.query = "evil.example.com"

        repository.create(
            first,
            AnalysisResult(
                domain="example.com",
                score=0.25,
                prediction="legitimate",
            ),
        )

        repository.create(
            second,
            AnalysisResult(
                domain="evil.example.com",
                score=0.75,
                prediction="phishing",
            ),
        )

        assert repository.average_score() == 0.5
        assert repository.highest_score() == 0.75

    finally:
        db.close()

from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.database import Base
from app.database.gateway_models import GatewayEvent
from app.database.gateway_repository import GatewayEventRepository
from app.gateway.models import DNSRecord
from app.gateway.monitor import DNSMonitor


def make_record() -> DNSRecord:
    return DNSRecord(
        timestamp=datetime.now(),
        query="paypal-login-security-example.com",
        answer="192.0.2.10",
        record_type="A",
        source_ip="192.168.1.20",
        destination_ip="8.8.8.8",
        response=True,
    )


def test_monitor_pipeline_analyzes_and_persists(
    monkeypatch,
):
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

    db = SessionLocal()

    monitor = DNSMonitor.__new__(
        DNSMonitor,
    )

    monitor.collector = __import__(
        "app.gateway.collector",
        fromlist=["DNSCollector"],
    ).DNSCollector()

    from app.gateway.analyzer import GatewayAnalyzer

    monitor.analyzer = GatewayAnalyzer()

    def fake_session():
        return db

    monkeypatch.setattr(
        "app.gateway.monitor.SessionLocal",
        fake_session,
    )

    monkeypatch.setattr(
        "app.gateway.monitor.write",
        lambda record: None,
    )

    result = monitor.process_record(
        make_record(),
    )

    event = (
        db.query(GatewayEvent)
        .filter_by(
            domain="paypal-login-security-example.com",
        )
        .first()
    )

    try:
        assert result.prediction == "phishing"
        assert result.score > 0.0

        assert event is not None
        assert event.domain == (
            "paypal-login-security-example.com"
        )
        assert event.prediction == "phishing"
        assert event.score == result.score

    finally:
        db.close()
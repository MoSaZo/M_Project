from datetime import datetime

from app.database.database import Base
from app.database.database import engine
from app.database.gateway_models import GatewayEvent


def test_gateway_event_model_is_registered():
    assert "gateway_events" in Base.metadata.tables


def test_gateway_event_table_can_be_created():
    Base.metadata.create_all(bind=engine)

    assert "gateway_events" in Base.metadata.tables


def test_gateway_event_fields():
    event = GatewayEvent(
        timestamp=datetime.now(),
        domain="example.com",
        answer="93.184.216.34",
        record_type="A",
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        response=True,
        score=0.25,
        prediction="legitimate",
    )

    assert event.domain == "example.com"
    assert event.score == 0.25
    assert event.prediction == "legitimate"
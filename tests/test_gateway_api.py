from datetime import datetime

from app.database.database import Base
from app.database.database import engine
from app.database.database import SessionLocal
from app.database.gateway_models import GatewayEvent


def create_gateway_event(
    domain: str,
    score: float,
    prediction: str,
) -> GatewayEvent:
    return GatewayEvent(
        timestamp=datetime.now(),
        domain=domain,
        answer="192.0.2.10",
        record_type="A",
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        response=True,
        score=score,
        prediction=prediction,
    )


def test_gateway_events_endpoint(client):
    response = client.get(
        "/api/gateway/events",
    )

    assert response.status_code == 200

    data = response.json()

    assert "items" in data
    assert "count" in data
    assert "limit" in data
    assert "offset" in data


def test_gateway_events_prediction_filter(client):
    db = SessionLocal()

    try:
        db.add(
            create_gateway_event(
                "safe.example.com",
                0.1,
                "legitimate",
            )
        )

        db.add(
            create_gateway_event(
                "evil.example.com",
                0.9,
                "phishing",
            )
        )

        db.commit()

        response = client.get(
            "/api/gateway/events",
            params={
                "prediction": "phishing",
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["count"] == 1
        assert len(data["items"]) == 1
        assert (
            data["items"][0]["domain"]
            == "evil.example.com"
        )

    finally:
        db.query(GatewayEvent).delete()
        db.commit()
        db.close()


def test_gateway_stats_endpoint(client):
    db = SessionLocal()

    try:
        db.add(
            create_gateway_event(
                "safe.example.com",
                0.1,
                "legitimate",
            )
        )

        db.add(
            create_gateway_event(
                "evil.example.com",
                0.9,
                "phishing",
            )
        )

        db.commit()

        response = client.get(
            "/api/gateway/stats",
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 2
        assert data["phishing"] == 1
        assert data["legitimate"] == 1
        assert data["average_score"] == 0.5
        assert data["highest_score"] == 0.9

    finally:
        db.query(GatewayEvent).delete()
        db.commit()
        db.close()

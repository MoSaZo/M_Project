"""
Pytest fixtures for API tests.
"""

import pytest
from fastapi.testclient import TestClient

from app.database.database import SessionLocal
from app.database.gateway_models import GatewayEvent
from app.main import app


@pytest.fixture
def client() -> TestClient:
    """
    Create a FastAPI test client with
    an isolated gateway-event state.
    """

    db = SessionLocal()

    try:
        db.query(GatewayEvent).delete()
        db.commit()
    finally:
        db.close()

    return TestClient(app)
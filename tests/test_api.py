"""
Tests for API endpoints.
"""

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app


def test_analyze_google_url(
    client: TestClient,
) -> None:
    """
    Analyze a safe URL through the API.
    """

    response = client.post(
        "/api/analyze",
        json={
            "url": "https://www.google.com",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["url"] == "https://www.google.com"
    assert data["hostname"] == "www.google.com"
    assert data["registered_domain"] == "google.com"
    assert data["risk_score"] == 0
    assert data["risk_level"] == "Safe"


def test_analyze_empty_url(
    client: TestClient,
) -> None:
    """
    Empty URL should return HTTP 400.
    """

    response = client.post(
        "/api/analyze",
        json={
            "url": "",
        },
    )

    assert response.status_code == 400

    data = response.json()

    assert data["detail"] == "URL cannot be empty."

    assert response.status_code == 400

def test_root_serves_frontend(
    client: TestClient,
) -> None:
    """
    Root endpoint should serve the frontend index page.
    """

    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "text/html",
    )


def test_health_check(
    client: TestClient,
) -> None:
    """
    Health endpoint should report the application as healthy.
    """

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
    }

def test_lifespan_creates_database_tables() -> None:
    """
    Application startup should create database tables.
    """

    with patch(
        "app.main.create_tables",
    ) as mock_create_tables:

        with TestClient(app):
            pass

    mock_create_tables.assert_called_once()
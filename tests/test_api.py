"""
Tests for API endpoints.
"""

from fastapi.testclient import TestClient


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
"""
Tests for history API endpoints.
"""

from fastapi.testclient import TestClient


def test_history_returns_list(
    client: TestClient,
) -> None:
    """
    History endpoint should return a list of scans.
    """

    response = client.get(
        "/api/history",
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)


def test_history_item_not_found(
    client: TestClient,
) -> None:
    """
    Requesting a non-existing history item should return HTTP 404.
    """

    response = client.get(
        "/api/history/99999",
    )

    assert response.status_code == 404


def test_history_contains_created_scan(
    client: TestClient,
) -> None:
    """
    A newly created analysis should appear in history.
    """

    analysis_response = client.post(
        "/api/analyze",
        json={
            "url": "https://www.google.com",
        },
    )

    assert analysis_response.status_code == 200

    scan_id = analysis_response.json()["id"]

    response = client.get(
        f"/api/history/{scan_id}",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == scan_id
    assert data["url"] == "https://www.google.com"
    assert data["hostname"] == "www.google.com"
    assert data["risk_score"] == 0
    assert data["risk_level"] == "Safe"

def test_duplicate_url_is_not_saved_twice(
    client: TestClient,
) -> None:
    """
    Analyzing the same URL twice should not create duplicate
    history records.
    """

    url = "https://www.google.com"

    first_response = client.post(
        "/api/analyze",
        json={"url": url},
    )

    assert first_response.status_code == 200

    second_response = client.post(
        "/api/analyze",
        json={"url": url},
    )

    assert second_response.status_code == 200

    response = client.get("/api/history")

    assert response.status_code == 200

    data = response.json()

    matching_records = [
        item
        for item in data
        if item["url"] == url
    ]

    assert len(matching_records) == 1

def test_history_rejects_zero_limit(
    client: TestClient,
) -> None:
    """
    History endpoint should reject a zero limit.
    """

    response = client.get(
        "/api/history?limit=0",
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Limit must be greater than 0.",
    }


def test_history_rejects_limit_above_100(
    client: TestClient,
) -> None:
    """
    History endpoint should reject limits above 100.
    """

    response = client.get(
        "/api/history?limit=101",
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Limit cannot exceed 100.",
    }


def test_history_item_rejects_invalid_scan_id(
    client: TestClient,
) -> None:
    """
    History item endpoint should reject a non-positive scan ID.
    """

    response = client.get(
        "/api/history/0",
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Scan ID must be greater than 0.",
    }
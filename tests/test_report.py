"""
Tests for report endpoints.
"""

from fastapi.testclient import TestClient


def test_report_not_found(
    client: TestClient,
) -> None:
    """
    Requesting a non-existing report should return HTTP 404.
    """

    response = client.get(
        "/api/report/99999",
    )

    assert response.status_code == 404


def test_report_returns_text(
    client: TestClient,
) -> None:
    """
    Existing report should return a plain-text report.
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
        f"/api/report/{scan_id}",
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "text/plain",
    )

    assert "URL SECURITY REPORT" in response.text
    assert "https://www.google.com" in response.text
    assert "Risk Score:" in response.text
    assert "Risk Level:" in response.text
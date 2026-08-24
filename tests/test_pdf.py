"""
Tests for PDF report endpoints.
"""

from fastapi.testclient import TestClient


def test_pdf_report_not_found(
    client: TestClient,
) -> None:
    """
    Requesting a non-existing PDF report should return HTTP 404.
    """

    response = client.get(
        "/api/report/99999/pdf",
    )

    assert response.status_code == 404


def test_pdf_report_returns_pdf(
    client: TestClient,
) -> None:
    """
    Existing report should return a valid PDF response.
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
        f"/api/report/{scan_id}/pdf",
    )

    assert response.status_code == 200

    assert response.headers["content-type"].startswith(
        "application/pdf",
    )

    assert (
        response.headers["content-disposition"]
        == f'attachment; filename="report-{scan_id}.pdf"'
    )

    assert response.content.startswith(
        b"%PDF",
    )
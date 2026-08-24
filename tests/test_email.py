"""
Tests for email API endpoints.
"""

from unittest.mock import patch

from fastapi.testclient import TestClient


def test_send_awareness_email(
    client: TestClient,
) -> None:
    """
    Awareness email endpoint should accept a valid request.
    """

    with patch(
        "app.api.email.send_awareness_email",
    ) as mock_send:

        response = client.post(
            "/api/email/send-awareness",
            json={
                "recipient": "test@example.com",
                "subject": "Phishing Awareness Test",
                "body": "This is a test awareness email.",
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert (
        data["message"]
        == "Educational email sent successfully."
    )

    mock_send.assert_called_once_with(
        recipient="test@example.com",
        subject="Phishing Awareness Test",
        body="This is a test awareness email.",
    )


def test_send_awareness_email_invalid_recipient(
    client: TestClient,
) -> None:
    """
    Invalid email address should return HTTP 422.
    """

    response = client.post(
        "/api/email/send-awareness",
        json={
            "recipient": "not-an-email",
            "subject": "Test",
            "body": "Test body.",
        },
    )

    assert response.status_code == 422
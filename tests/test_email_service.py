"""
Tests for email service.
"""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from app.services import email_service


def test_missing_smtp_host() -> None:
    with patch.object(email_service, "SMTP_HOST", ""):
        with pytest.raises(RuntimeError, match="SMTP_HOST"):
            email_service.send_awareness_email(
                "user@example.com",
                "Subject",
                "Body",
            )


def test_missing_smtp_username() -> None:
    with patch.object(email_service, "SMTP_HOST", "smtp.gmail.com"):
        with patch.object(email_service, "SMTP_USERNAME", ""):
            with pytest.raises(RuntimeError, match="SMTP_USERNAME"):
                email_service.send_awareness_email(
                    "user@example.com",
                    "Subject",
                    "Body",
                )


def test_missing_smtp_password() -> None:
    with patch.object(email_service, "SMTP_HOST", "smtp.gmail.com"):
        with patch.object(email_service, "SMTP_USERNAME", "user"):
            with patch.object(email_service, "SMTP_PASSWORD", ""):
                with pytest.raises(RuntimeError, match="SMTP_PASSWORD"):
                    email_service.send_awareness_email(
                        "user@example.com",
                        "Subject",
                        "Body",
                    )


def test_missing_smtp_from() -> None:
    with patch.object(email_service, "SMTP_HOST", "smtp.gmail.com"):
        with patch.object(email_service, "SMTP_USERNAME", "user"):
            with patch.object(email_service, "SMTP_PASSWORD", "password"):
                with patch.object(email_service, "SMTP_FROM", ""):
                    with pytest.raises(RuntimeError, match="SMTP_FROM"):
                        email_service.send_awareness_email(
                            "user@example.com",
                            "Subject",
                            "Body",
                        )


def test_send_email_with_tls() -> None:
    smtp = MagicMock()

    with patch.object(email_service, "SMTP_HOST", "smtp.gmail.com"):
        with patch.object(email_service, "SMTP_PORT", 587):
            with patch.object(email_service, "SMTP_USERNAME", "user"):
                with patch.object(email_service, "SMTP_PASSWORD", "password"):
                    with patch.object(email_service, "SMTP_FROM", "from@example.com"):
                        with patch.object(email_service, "SMTP_USE_TLS", True):
                            with patch(
                                "app.services.email_service.smtplib.SMTP"
                            ) as smtp_class:
                                smtp_class.return_value.__enter__.return_value = smtp

                                email_service.send_awareness_email(
                                    "to@example.com",
                                    "Subject",
                                    "Body",
                                )

    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with(
        "user",
        "password",
    )
    smtp.send_message.assert_called_once()


def test_send_email_without_tls() -> None:
    smtp = MagicMock()

    with patch.object(email_service, "SMTP_HOST", "smtp.gmail.com"):
        with patch.object(email_service, "SMTP_PORT", 587):
            with patch.object(email_service, "SMTP_USERNAME", "user"):
                with patch.object(email_service, "SMTP_PASSWORD", "password"):
                    with patch.object(email_service, "SMTP_FROM", "from@example.com"):
                        with patch.object(email_service, "SMTP_USE_TLS", False):
                            with patch(
                                "app.services.email_service.smtplib.SMTP"
                            ) as smtp_class:
                                smtp_class.return_value.__enter__.return_value = smtp

                                email_service.send_awareness_email(
                                    "to@example.com",
                                    "Subject",
                                    "Body",
                                )

    smtp.starttls.assert_not_called()
    smtp.login.assert_called_once()
    smtp.send_message.assert_called_once()